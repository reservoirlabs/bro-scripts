##!  Detection of click-fraud botnets 

#
# Copyright 2014 Reservoir Labs, Inc.
# All rights reserved.
#

##!
##! This app identifies hosts that are bots from those that
##! are human by analyzing click histograms. The proper
##! way to run this app is by following a two step approach: 
##!
##!  (1) First, the app should be initially fed with purely
##!      human traffic. This stage can be seen as a training
##!      phase which allows to compute the click histograms of
##!      non-bot traffic. We call this the average human click 
##!      histogram.
##!  (2) Second, the app can then be fed with the actual live 
##!      traffic which is expected to have both human and bot 
##!      traffic. At this point the app will start emitting
##!      bot events whenever it detects a host that deviates
##!      too much from the average human click histogram.
##!
##! There is an implicit assumption in this app in that bot 
##! traffic is expected to be a minority of the total traffic.
##! 
##! Implementation notes: since modern browsers open
##! multiple connections in parallel and load balance
##! HTTP requests across, we cannot make the assumption that 
##! query-clicks will happen within the same connection;
##! rather, it is very likely that a click will happen
##! on a different connection from that of the query that
##! originated it.  This means that we need to search 
##! query-clicks in an agreggated manner, with three implications:
##!
##! (1) for a given click, it could be that we have several
##!     potential queries it came from.  We adopt by default
##!     the approach of taking all potential query-clicks as
##!     real.  This will generate false positives but statistically
##!     seems to be more fair.  
##! (2) by measuring the cardinality of the potential set of
##!     query-clicks, we can get an estimate of the accuracy
##!     of our algorithm (margin of error)
##! (3) a timer needs to be added to the list of potential 
##!     query-clicks (to avoid false positives growing exponentially)
##!     the inclusion of such timer can be responsible for 
##!     false negatives (actual query-clicks not detected)
##!
##! Another option that can be used to reduce false positives is
##! the referer (or referrer) field in HTTP headers.  Such field
##! is not always present, but it can certainly be used.
##!
##! TODO: detection of flashcrowds
##!

module ClickBot;

export {

	redef enum Log::ID += { LOG };

	redef enum Notice::Type += {
		## Indicates that a queryclick action was detected.
		Queryclick, 
		## Indicates that a host was classified as human.
		Human,
		## Indicates that a host was classified as a bot.
		Bot,
		## Indicates that a flash crowd situation was detected.
		Flashcrowd
	};

	type Info: record {
		## Timestamp.
		ts: time &log;
		## Event type.
		note: Notice::Type &log;
		## Host.
		host: string &log;
		## Query (only applicable to Queryclick events).
		query: string &optional &log;
		## Distance to the average human click histogram 
                ## (only applicable to Human and Bot events).
		distance: double &optional &log;
		## Location where the event took place.
		location: string &log;
	};

	## This apps's logging event.
	global log_clickbot: event(rec: Info);

	## The domain that needs to be analyzed. 
	const domain_to_track = "http://www.google.com" &redef;

	## The path within the domain that needs to be analyzed.
	const path_to_track = "/" &redef;
	
	## The minimum number of clicks on the domain/path 
	## that need to be seen to consider the analysis statistically relevant.
	const threshold_clicks = 70 &redef;

	## The minimum Euclidean threshold distance between a host click histogram
	## and the average human click histogram.
	const threshold_distance = 0.01 &redef;

	## An optional file name that can be used to specify where
	## we want to log a snapshot of the click histogram. This file
	## is used when invoking the function snap_click_histogram().
	const clickbot_qc_file = open_log_file("clickbot_qc_file.txt") &redef;

}

# Various tables needed to track click histograms
type   query_click_history : table[string] of table[string] of count;
global query_click_history_global : query_click_history;
global query_click_history_hosts : table[addr] of query_click_history;

# Table of potential hosts to track
global query_click_potential_hosts : table[addr] of table[string] of set[string] &create_expire = 90 secs;

# Sets to track hosts, human hosts and bot hosts
global hosts : set[addr];
global list_host_human : set[addr];
global list_host_bot : set[addr];

# Mapping of mime type to file extension
global ext_map: table[string] of string = {
    ["text/html"] = "html",
} &default ="";


# 
#   Investigates if a host is a bot or a human.
#   Reports the following events: {Human, Bot}
# 
function investigate_host(host: addr, query: string)
	{
	local distance = 0.0;
	local number_clicks = 0;
	local rec: ClickBot::Info;

	for ( click in query_click_history_global[query] )
		{
		if ( query_click_history_global[query][click] != 0 ) 
			{
			number_clicks = number_clicks + 1;
			}
		}  
	
	local total_global_clicks = 0.0;
	local total_host_clicks = 0.0;
	for ( click in query_click_history_global[query] )
		{
		total_global_clicks = total_global_clicks + query_click_history_global[query][click];
		}
	for ( click in query_click_history_hosts[host][query] )
		{
		total_host_clicks = total_host_clicks + query_click_history_hosts[host][query][click];
		}
  
	for ( click in query_click_history_hosts[host][query] )
		{
		# Use an Euclidean distance
    		distance = distance + 
				((query_click_history_hosts[host][query][click]/total_host_clicks - 
				  query_click_history_global[query][click]/total_global_clicks) * 
				 (query_click_history_hosts[host][query][click]/total_host_clicks - 
				  query_click_history_global[query][click]/total_global_clicks));
 
		}
	distance = distance / number_clicks;
	
	if ( total_host_clicks > threshold_clicks )
		{
		if ( distance > threshold_distance )
			{
			if (host !in list_host_bot)
				{
				add list_host_bot[host];
				rec =  [$ts = network_time(),
					$note = Bot,
					$host = fmt("%s", host),
					$distance = distance,
					$location = fmt("%s", lookup_location(host))];
				Log::write(ClickBot::LOG, rec);
				}
			}
		else
			{
			if (host !in list_host_human)
				{
				add list_host_human[host];
				rec =  [$ts = network_time(),
					$note = Human,
					$host = fmt("%s", host),
					$distance = distance,
					$location = fmt("%s", lookup_location(host))];
				Log::write(ClickBot::LOG, rec);
				}
			}
		}			  
	
	print fmt("distance for host %s is: %f", host, distance);
	print fmt("location: %s", lookup_location(host));

	}


#
# Given a connection that generated a file extraction of 
# an HTML body, this function processes the file and extracts
# the links in it.
#
function process_html_response(c: connection, mime_type : string)
	{	
	local ext = ext_map[mime_type];
	local fname = fmt("%s-%s-%s-%s.%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, ext);
	local links_list = html_parser_extract_links(fname);
	
	if ( |links_list| == 0 )
		return;
			
	# The set of returned links are potential clicks
	# so let's add them to the per-host list of potential
	# query-clicks
	if (c$id$orig_h !in query_click_potential_hosts)
		query_click_potential_hosts[c$id$orig_h] = table();
		
	for ( i in links_list ) 
		{
		if ( links_list[i] !in query_click_potential_hosts[c$id$orig_h] )
			query_click_potential_hosts[c$id$orig_h][links_list[i]] = set();
			
		if ( c$http$uri !in query_click_potential_hosts[c$id$orig_h][links_list[i]] )
			add query_click_potential_hosts[c$id$orig_h][links_list[i]][c$http$uri];
		}
	
	# Check if we need to initialize entries
	# within the per-host query-click history
	# and the global querthinky-click history
	if (c$id$orig_h !in query_click_history_hosts)
		query_click_history_hosts[c$id$orig_h] = table();
	
	if ( [c$http$uri] !in query_click_history_hosts[c$id$orig_h] )
		{
		query_click_history_hosts[c$id$orig_h][c$http$uri] = table();
		for ( i in links_list ) 
			query_click_history_hosts[c$id$orig_h][c$http$uri][links_list[i]] = 0;
		}

		
	if ( [c$http$uri] !in query_click_history_global ) 
		{
		query_click_history_global[c$http$uri] = table();
		for ( i in links_list ) 
			query_click_history_global[c$http$uri][links_list[i]] = 0;
    		}
	
	}


#
# The http_request event is used to catch the "clicks" 
# issued by a human or a bot host
#
event http_request(c: connection, method: string, original_URI: string,
			       unescaped_URI: string, version: string)	
	{
	local rec: ClickBot::Info;
	
	# If this host is still not in the list of potential
	# query-clicks, it's because it has not downloaded any page yet.
	# So this request will not generate any query-click and we
	# can skip it
	if ( c$id$orig_h !in query_click_potential_hosts )
		return;
		
	if ( c$id$orig_h !in hosts )
		add hosts[c$id$orig_h];
		
	# If this URI is in the list of potential query-clicks  
	# for this host, it means it came from clicking a page
	# that we are tracking.  If it's cardinality is non-zero,
	# then we got a query-click.  If the cardinality is larger
	# than one, then we are generating false positives
	#
	# The condition is to test if the potential click is
	# part of this request URI.  Being a subset is enough
	# since the URI could include the full path, whereas the
	# potential click may just be a relative path.  Notice
	# that this could also be a potential source of 
	# False positives.
	#
	# TODO: use the cardinality to measure the error probabilites
	#       of geobot.
	for ( click in query_click_potential_hosts[c$id$orig_h] )
		{
		# FIXME: some clicks are hyperlinks which 
		# include also the full host name; 
		# to match them, we need to check
		# if the URI matches the last part
		# of the click; regexes can do that 
		# with the special char $, the following
		# emulates such behavior by cating 
		# a special string at the end of both strings
		# Note: for geobot phase I demo, we use this 
		# trick of not including the trivial root link "/",
		# which seems to work the best among the 3 options below
		if ( original_URI in click && original_URI != "/")
#		if ( click in original_URI || click in cat(domain_to_track, original_URI)) 
#		|| cat(original_URI, "!@#$%^&*") in cat(click, "!@#$%^&*"))
			{
			for ( query in query_click_potential_hosts[c$id$orig_h][click] )
				{
				if(path_to_track == query)
					{
					rec =  [$ts = network_time(),
						$note = Queryclick,
						$host = fmt("%s", c$id$orig_h),
						$query = query,
						$location = fmt("%s", lookup_location(c$id$orig_h))];
					Log::write(ClickBot::LOG, rec);
                   			++query_click_history_hosts[c$id$orig_h][query][click];
	       		    		++query_click_history_global[query][click];
					investigate_host(c$id$orig_h, query);
					}
				}
			}
		}
	}


#
# The file_state_remove event is used to capture
# the writing of an HTML body into a file and trigger
# the processing of the links in it.
#
event file_state_remove(f: fa_file) &priority=-5
    {
    for ( cid in f$conns ) 
        process_html_response(f$conns[cid], f$mime_type);
    }


#
# The file_new event is used to attach the file extraction
# analyzer to a connection which is known to carry an HTML
# body reply.
# 
event file_new(f: fa_file)
    {
    if ( ! f?$mime_type )
        return;

    if ( f$mime_type !in ext_map )
        return;

    local ext = ext_map[f$mime_type];

    for ( cid in f$conns ) 
        {
        local fname = fmt("%s-%s-%s-%s.%s", cid$orig_h, cid$orig_p, cid$resp_h, cid$resp_p, ext);
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
        }
    }


event bro_init()
	{
	Log::create_stream(ClickBot::LOG, [$columns=Info, $ev=log_clickbot]);
	}


function snap_click_histogram()
	{
	local header = T;

	for ( query in query_click_history_global )
		{
		header = T;
		for ( click in query_click_history_global[query] )
			{
			if ( query_click_history_global[query][click] != 0 ) 
				{
				if(header) 
					{
					print clickbot_qc_file, "";
					print clickbot_qc_file, fmt("Query-click histogram for query %s", query);
					print clickbot_qc_file, fmt("------------------------------------------------------------------------");
					header = F;
					}		
				print clickbot_qc_file, fmt("query: %s; click: %s; hits: %d", query, click, query_click_history_global[query][click]);
				}
			}		
		}
	
	for ( host in hosts )
		{
		for ( query in query_click_history_hosts[host] )
			{
			if(path_to_track == query)
				investigate_host(host, query);
			header = T;
			for ( click in query_click_history_hosts[host][query] )
				{
				if( query_click_history_hosts[host][query][click] != 0 )
					{
					if(header) 
						{
						print clickbot_qc_file, "";
						print clickbot_qc_file, fmt("Query-click histogram for user %s on page %s", host, query);
						print clickbot_qc_file, fmt("------------------------------------------------------------------------");
						header = F;
						}		
					print clickbot_qc_file, fmt("query: %s; click: %s; hits: %d", query, click, query_click_history_hosts[host][query][click]);
					}
				}		
			}
		}
	
	print clickbot_qc_file, "";
	
	}
