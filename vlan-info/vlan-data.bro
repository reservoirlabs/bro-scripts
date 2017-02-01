##! Information about vlans, mapping vlan-id to the expected ip address range and location information

# Loaded from the end of vlan-location.bro

# Reservoir Labs Inc. 2017 All Rights Reserved.
# vlan data 

module Conn;

# This must be customized to each environment
redef vlanlist += {
[100] = [$description="north",$ipv4net=10.2.0.0/24,$ipv6net=[2001:0468:1f07:000b::]/64,$location="north"],
[101] = [$description="south",$ipv4net=10.12.0.0/24,$ipv6net=[2001:0468:1f07:000c::]/64,$location="south"],
[102] = [$description="west",$ipv4net=10.16.0.0/24,$ipv6net=[2001:0468:1f07:000d::]/64,$location="west"],
[103] = [$description="east",$ipv4net=10.10.0.0/24,$ipv6net=[2001:0468:1f07:f00e::]/64,$location="east"]
};
