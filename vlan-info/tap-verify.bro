##! Generates vlan_data.log with periodic entries for all the expected VLANs in the network

# An additional seen flag indicates if the VLAN was observed in monitored traffic

@load ./tap-data.bro
# loads tap-data into vlanlist

module Conn;

# Every X minutes, print seen VLANs and reset $seen to F

export {
    redef enum Log::ID += { VLANLOG };

    const tap_report_interval = 1min &redef;

    type vlandata_info: record {
        ts: time &log;
        vid: int &log;
        vlan: vlandata &log;
    };

    # similar to net_to_vlan, but we're going to delete entries to help speed things up.
    global net_to_vlans_not_seen: table[subnet] of int;
}


event log_seen_vlans(last_ts: time){
    local vlan: int;
    local now = network_time();

    for (vlan in vlanlist){
        Log::write(VLANLOG,[$ts=now,$vid=vlan,$vlan=vlanlist[vlan]]);
        # Seen set to true in vlan-location.bro
		if(vlanlist[vlan]$seen == T){
            vlanlist[vlan]$seen = F; 
        }
    }
    schedule tap_report_interval { log_seen_vlans(network_time())};
}

event bro_init() &priority=5{
    Log::create_stream(VLANLOG, [$columns=vlandata_info, $path="vlan_data"]);
    schedule tap_report_interval { log_seen_vlans(network_time())};
}







