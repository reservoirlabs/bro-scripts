##! Benchmark DNS 

# Contributed by Reservoir Labs, Inc.
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

module DnsTrack;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                timestamp: time              &log;
                worker: string               &log;
                id: count                    &log;
                sel_cap: double              &log;
                opcode: count                &log;
                query: string                &log;
        };

        global log_dns_track: event(rec: Info);
}

global dns_track_numconns: count;
global dns_track_numconns_last: count;
global dns_track_time_last: time;

const REPORTING_PERIOD = 1;

event bro_init() &priority=5
        {
        Log::create_stream(DnsTrack::LOG, [$columns=Info, $ev=log_dns_track]);
        dns_track_numconns = 0;
        dns_track_numconns_last = 0;
        dns_track_time_last = network_time();
        }

type dns_session_info: record
        {
        opcode: count &default=0;
        query: string &default="";
        };

global conn_info: table[conn_id] of dns_session_info
        &read_expire=5mins
        &redef;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
        {
        local this_timestamp: time;
        local this_sel_cap: double;
        local id = c$id;
        
        if ( c$id !in conn_info )
                {
                local x: dns_session_info;
                conn_info[c$id] = x;
                }

        local sess_ext = conn_info[c$id];
        sess_ext$opcode = msg$opcode;
        sess_ext$query = query;

        mcore_shunt_conn(addr_to_count(id$orig_h),
                         port_to_count(id$orig_p),
                         addr_to_count(id$resp_h),
                         port_to_count(id$resp_p));

        dns_track_numconns = dns_track_numconns + 1;

        if(modulo(dns_track_numconns, REPORTING_PERIOD) == 0)
                {

                this_sel_cap = (dns_track_numconns - dns_track_numconns_last) / (time_to_double(network_time())-time_to_double(dns_track_time_last));

                local this_worker : string;
                if(Cluster::node != "")
                        this_worker = Cluster::node;
                else
                        this_worker = "[Standalone worker]";

                this_timestamp = network_time();
                local rec: DnsTrack::Info = [$timestamp=this_timestamp,
                                             $worker=this_worker,
                                             $opcode=sess_ext$opcode,
                                             $query=sess_ext$query,
                                             $id=dns_track_numconns,
                                             $sel_cap=this_sel_cap];

                Log::write(DnsTrack::LOG, rec);
                dns_track_time_last = network_time();
                dns_track_numconns_last = dns_track_numconns;

                }

        }
