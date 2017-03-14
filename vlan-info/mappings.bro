##! VLAN to location mappings

# This script is based on Michael Dopheide's script used at Supercomputing
# and has been modified by Reservoir Labs.

# Reservoir Labs Inc. 2017 All Rights Reserved.

module VLANLocation;

export {

    ## Record used to describe a VLAN tag
    type vlandata: record {
        ## Human readable description 
        description: string &log;

        ## Expected IPv4 subnet information if available.
        ipv4net: subnet &log &optional;

        ## Expected IPv6 subnet information if available
        ipv6net: subnet &log &optional;

        ## Location information (e.g., Building East, First Floor, etc.)
        location: string &log &optional;
    } &redef;

    global vlanlist: table[int] of vlandata = table() &redef;

}

#
# Modify and add here your own VLAN mappings:
#

# The following are example mappings used to locate network activity. 
# Usually this corresponds to inner tags (also known as C-tags)
redef vlanlist += {
[100] = [$description="north",
         $ipv4net=10.2.0.0/24,
         $ipv6net=[2001:0468:1f07:000b::]/64,
         $location="north"],
[101] = [$description="south",
         $ipv4net=10.12.0.0/24,
         $ipv6net=[2001:0468:1f07:000c::]/64,
         $location="south"],
[102] = [$description="west",
         $ipv4net=10.16.0.0/24,
         $ipv6net=[2001:0468:1f07:000d::]/64,
         $location="west"],
[103] = [$description="east",
         $ipv4net=10.10.0.0/24,
         $ipv6net=[2001:0468:1f07:f00e::]/64,
         $location="east"]
};

# The following are example mappings used to verify that all tapping 
# points are receiving data. Usually this corresponds to outer tags 
# (also known as S-tags)
redef vlanlist += {
[1001] = [$description="Gigamon Port 2/1/x1",
          $location="wifi-upper-level"],
[1002] = [$description="Gigamon Port 2/1/x2",
          $location="wifi-lower-level"],
};

