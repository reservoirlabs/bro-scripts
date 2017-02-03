##! Information about VLAN ids created at the packet broker/tap/span.

# Loaded from the end of tap-verify.bro

# Reservoir Labs Inc. 2016 All Rights Reserved.
# VLAN data 

module Conn;

# Useful for validating that all expected taps are generating data
# Ensure these VLAN ids are different from operational VLAN ids

redef vlanlist += {
[1001] = [$description="Gigamon Port 2/1/x1",$location="wifi-upper-level"],
[1002] = [$description="Gigamon Port 2/1/x2",$location="wifi-lower-level"],
};
