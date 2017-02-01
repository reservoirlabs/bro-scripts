This module provides mapping between VLAN id and the physical location where available.

It augments conn.log and notice.log with VLAN and corresponding location information.

It generates vlan_data.log containing periodic entries of all expected VLANs.

The seen flag indicates whether any connections with the corresponding VLAN tags were received.

Users are expected to modify the following
1. vlan-data.bro
2. tap-data.bro

in vlan-location
    
    Notice::sampled_notes - Add or remove additional notices that need to be augmented with VLAN information

in tap-verify
    
    tap_report_interval - The periodicity with which all tap information is added to vlan_data.log

