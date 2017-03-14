##! Geolocate network activity within private networks

# This script is based on Michael Dopheide's script used at Supercomputing
# and has been modified by Reservoir Labs.

# Reservoir Labs Inc. 2017 All Rights Reserved.

@load protocols/conn/vlan-logging
@load base/frameworks/input
@load base/frameworks/notice

@load misc/scan
@load misc/detect-traceroute
@load protocols/ssh/detect-bruteforcing

@load ./mappings.bro

module VLANLocation;

export {

    ## VLAN related fields added to notice.log
    redef record Notice::Info += {
        ## VLAN ID
        vlan: int         &log &optional;  
        ## Locations description
        location: string  &log &optional;   
        ## If true, VLAN information was obtained from the 
        ## msg and sub string fields in the notice and
        ## therefore it should be considered less reliable
        sampled: bool     &log &default=F; 
    };

    ## VLAN related fields added to each conn.log
    redef record Conn::Info += {
        ## Locations description
        location: string  &log &optional;
    };

    ## Stores a mapping of the subnets to VLAN IDs
    global net_to_vlan: table[subnet] of int = table();

    ## Returns the VLAN ID corresponding to an IP address, if known
    ##
    ## myaddr: The IP address
    ##
    ## Returns: the VLAN ID associated with the IP address, if known
    ##
    ## .. bro:see:: vlan_lookup_pair, vlan_lookup_conn, net_to_vlan 
    global vlan_lookup: function(myaddr: addr): int;

    ## Record returned by the supporting VLAN lookup functions
    type vlaninfo: record{
        vaddr: addr;
        vlan: int;
        location: string;
    };

    ## Returns the VLAN information corresponding to either the source or 
    ## destination IP addresses, if known. Gives arbitrary preference
    ## to the source IP address if known.
    ##
    ## mysrc: The source IP address
    ## mydst: The destination IP address
    ##
    ## Returns: A vlaninfo record containing the VLAN information
    ##
    ## .. bro:see:: vlan_lookup, vlan_lookup_conn, net_to_vlan 
    global vlan_lookup_pair: function(mysrc: addr, mydst: addr): vlaninfo;

    ## Lookup function to return VLAN information corresponding to 
    ## the connection information, if known
    ##
    ## c: The connection record
    ##
    ## Returns: A vlaninfo record containing the VLAN information
    ##
    ## .. bro:see:: vlan_lookup, vlan_lookup_conn, net_to_vlan 
    global vlan_lookup_conn: function(c: connection): vlaninfo;

    ## The set of notice types whose string message should be explored 
    ## to identify any VLAN information related to the notice
    global Notice::sampled_notes: set[Notice::Type] = {
        Scan::Address_Scan,
        Scan::Port_Scan,
        SSH::Password_Guessing
    } &redef;
 
}

event bro_init() {
    # once vlanlist is built we need to build the subnet lookup table 
    # for when we don't have the full conn info in Notices
    for (vlan in vlanlist) {
        if (vlanlist[vlan]?$ipv4net) {
            net_to_vlan[vlanlist[vlan]$ipv4net] = vlan;
        }
        if (vlanlist[vlan]?$ipv6net) {
            net_to_vlan[vlanlist[vlan]$ipv6net] = vlan;
        }
    }    
}


event connection_state_remove(c: connection) {

    # Add any VLAN information to the connection.
    # Preference is given to inner VLAN over outer VLAN. 
    if (c?$inner_vlan && c$inner_vlan in vlanlist) {
        c$conn$location = vlanlist[c$inner_vlan]$location;
    }

    if (c?$vlan && c$vlan in vlanlist) {
        c$conn$location = vlanlist[c$vlan]$location;
    }
}

function vlan_lookup(myaddr: addr): int {
    for (mynet in net_to_vlan) {
        if (myaddr in mynet) {
            return net_to_vlan[mynet];
        }
    }
    return 0;
}

function vlan_lookup_pair(mysrc: addr, mydst: addr): vlaninfo {
    local vr: vlaninfo;

    vr$vlan = vlan_lookup(mysrc);
    if (vr$vlan == 0) {
        vr$vlan = vlan_lookup(mydst);
        vr$vaddr = mydst;
    } else {
        vr$vaddr = mysrc;
    }
    if (vr$vlan != 0) {
        vr$location = vlanlist[vr$vlan]$location;
    }
    return vr;
}

function vlan_lookup_conn(c: connection): vlaninfo {
    local vr: vlaninfo;

    if (c?$vlan) {
        vr$vlan = c$vlan;
    } else if (c?$inner_vlan) {
        vr$vlan = c$inner_vlan;
    } else {
        return vlan_lookup_pair(c$id$orig_h,c$id$resp_h);
    }

    vr$location=vlanlist[vr$vlan]$location;

    if (c$id$orig_h in Site::local_nets) {
        vr$vaddr = c$id$orig_h;
    } else {
        vr$vaddr = c$id$resp_h;
    }

    return vr;
}

hook Notice::policy(n: Notice::Info)
{
    local dst_addrs: vector of string;
    local notice_msg: string;
    n$vlan = 0;
    n$location = "Unknown";

    # If the conn info exists, it already has the VLAN so use it
    if (n?$conn) {
        if (n$conn?$inner_vlan) {
            n$location = vlanlist[n$conn$inner_vlan]$location;
            n$vlan = n$conn$inner_vlan;    
        } else if (n$conn?$vlan) {
            n$location = vlanlist[n$conn$vlan]$location;
            n$vlan = n$conn$vlan;
        }
    }

    # We try to get the VLAN tag from the source or destination IP address.
    # We arbitrarily try first with the source IP address, then with the 
    # destination IP address.
    if (n?$src && n$vlan==0) {
        n$vlan = vlan_lookup(n$src);
        if (n$vlan != 0) {
            n$location = vlanlist[n$vlan]$location;
        }
    }

    if (n?$dst && n$vlan==0) {
        n$vlan = vlan_lookup(n$dst);
        if (n$vlan != 0) {
            n$location = vlanlist[n$vlan]$location;
        }
    }

    # We could not find any VLAN related information.
    # For those notices that are in sampled_notes,
    # Try as a last resort using any IP address present
    # in either the msg or the sub string fields of
    # the notice.
    if (n$note in Notice::sampled_notes && n$vlan == 0) {
       for (notice_msg in set(n$msg, n$sub)) {
            # Mark this record as 'sampled' to denote that the
            # VLAN information was used from arbitrarily sampling
            # an IP address from these fields, indicating that
            # the result might be unreliable.
            n$sampled = T;
            dst_addrs = extract_ip_addresses(notice_msg);
            for (dst_idx in dst_addrs) {
                n$vlan = vlan_lookup(to_addr(dst_addrs[dst_idx]));
                if (n$vlan != 0) {
                  n$location = vlanlist[n$vlan]$location;
                  break;
                }
            }
        }
    }
}


