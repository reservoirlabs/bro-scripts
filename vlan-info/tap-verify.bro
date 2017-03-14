##! Verify that all tapping points are receiving traffic

# Reservoir Labs Inc. 2017 All Rights Reserved.

# This script is based on Michael Dopheide's script used at Supercomputing
# and has been modified by Reservoir Labs.

##! This script reports VLAN activity in the log vlanlocation.log.
##! The reporting frequency can be controlled via the parameter
##! vlan_report_interval.
##!
##! While this script can be used to verify that all monitoring
##! tapping points receive traffic, it can also be generically used
##! to track VLAN activity.

@load ./mappings.bro
@load ./vlan-location.bro

module VLANLocation;

export {

    ## The periodicity with which VLAN information is written to the logs
    const vlan_report_interval = 60sec &redef;

    ## If connections with a VLAN ID are not seen for this duration 
    ## then the VLAN is considered not seen.
	const vlan_not_seen_interval = 5min &redef;

    ## The log ID
    redef enum Log::ID += { LOG };

    ## The log record 
    type Info: record {
        ## The timestamp of when the log was written
        ts: time &log;

        ## VLAN ID
        vid: int &log;

        ## Location and IP Subnet information matching the specified VLAN ID
        vlan: vlandata &log;

        ## Flag to indicate whether data from this VLAN was observed 
        ## within the last vlan_not_seen_interval
        seen: bool &log &default=F;
    };
}

# The set of currently active VLANs
global active_vlans: set[int] &write_expire = vlan_not_seen_interval;

## Periodic event used to log VLAN information
event log_seen_vlans(){
    local vlan: int;
    local now = network_time();
    for (vlan in vlanlist){
        local seen = F;
        # Mark it as seen if it is in the list of active vlans
        if (vlan in active_vlans) {
            seen = T;
        }
        Log::write(VLANLocation::LOG,[$ts=now, $vid=vlan, $vlan=vlanlist[vlan], $seen=seen]);
    }
    schedule vlan_report_interval { log_seen_vlans()};
}

event bro_init() &priority=5{
    Log::create_stream(LOG, [$columns=Info]);
    schedule vlan_report_interval { log_seen_vlans()};
}

event connection_state_remove(c: connection){

    # While the outer VLAN is meant to help verify activity
    # on the tapping points, report activity from both
    # the inner and the outer VLANs as both provide
    # valuable information.
    if(c?$inner_vlan && c$inner_vlan in vlanlist)
        add active_vlans[c$inner_vlan];

    if(c?$vlan && c$vlan in vlanlist)
        add active_vlans[c$vlan];
}

