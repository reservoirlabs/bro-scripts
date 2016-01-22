module Roam;

export
{
    # Time after which observed MAC to IP mappings (and vice versa) expire.
    const alias_expiration = 1 day &redef;

    global ip_to_mac: table[addr] of string
        &read_expire = alias_expiration &synchronized;

    global mac_to_ip: table[string] of set[addr]
        &read_expire = alias_expiration &synchronized;
}

# Collect IP-to-MAC mappings and vice versa from DHCP ACKs.
event DHCP::dhcp_ack(c: connection, msg: dhcp_msg, mask: addr,
		router: dhcp_router_list, lease: interval, serv_addr: addr)
{
    local ip = msg$yiaddr;
    local mac = msg$h_addr;

    if (ip !in ip_to_mac)
        ip_to_mac[ip] = mac;

    if (mac !in mac_to_ip)
        mac_to_ip[mac] = set() &mergeable;

    add mac_to_ip[mac][ip];
}

# Collect IP-to-MAC mappings and vice versa from ARP replies.
event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string,
    TPA: addr, THA: string)
{
    local ip = SPA;
    local mac = mac_src;

    if (ip !in ip_to_mac)
        ip_to_mac[ip] = mac;

    if (mac !in mac_to_ip)
        mac_to_ip[mac] = set() &mergeable;

    add mac_to_ip[mac][ip];
}

