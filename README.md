BypassFW
========

Connects a tap device to the network using pcap, bypassing the firewall.  This
is done by attaching libpcap to a network-connected interface and sending
sniffed packets to a tap device and injecting packets read from the tap device.

It's written for OpenBSD.  It'll probably work on other OSs with minor
modifications.

For legal use only.

Examples
--------
Bypass `em0` using `tap0`:
```bash
bypassfw /dev/tap0 em0
dhclient tap0
```

Bypass `em0` using `tap0` and only allow SSH to `tap0`:
```bash
bypassfw /dev/tap0 em0 'arp or (host 192.168.1.3 and tcp port 22)'
ifconfig tap0 192.168.1.3/24
```

Filtering
---------
For extra stealth (or to reduce CPU load) a BPF filter can be used to only pass
packets meant for the TAP device or even only packets which are meant for 
specific services/ports/such.  ARP messages will need to be explicitly allowed
by this filter in most circumstances.
