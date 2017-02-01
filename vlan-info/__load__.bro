##! This module provides mapping between VLAN id and the physical location where available

# Reservoir Labs Inc. 2017 All Rights Reserved.
# Periodically verfies if all configured taps are generating data
# Update vlan-data.bro with information about VLANs

@load ./vlan-location
@load ./tap-verify
