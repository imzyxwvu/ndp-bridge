# ndp-bridge

Bridge IPv6 between LAN and WAN, while IPv4 is still routed.

This is useful when you need to set up IPv4 LAN with a NAT gateway, but still require IPv6 addresses of LAN devices to be usable and reachable from WAN, as if LAN is bridged to WAN only for IPv6.

```
   -----+         2001:da1::/64        +-----
        |----------<ndp-bridge>--------|     
    WAN | 223.1.2.0/24     10.0.2.0/24 | LAN 
        |-------------<NAT>------------|     
   -----+                              +-----
```

## Usage

Assuming LAN is connected to eth1 and WAN is connected to eth0. Following command will allow LAN devices to get WAN IPv6 addresses and access WAN via IPv6. This requires superuser.
```
ndp-bridge -i eth1 -o eth0
```

## How it works
ndp-bridge works by forwarding ICMPv6 neighbor discovery packets between LAN and WAN, while replacing the source link-address and the destination link-address with the gateway's own MAC address. So the device will have a chance to route IPv6 traffic between LAN and WAN.

LAN IPv6 addresses are installed in kernel routing table, so IPv6 traffic is actually routed in kernel and there is no kernel-userspace copy overhead.

## License

[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
