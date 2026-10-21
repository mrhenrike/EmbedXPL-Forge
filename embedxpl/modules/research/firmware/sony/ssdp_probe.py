#!/usr/bin/env python3
"""SSDP probe to identify 192.168.18.193."""
import socket
import time
import requests

SSDP_MSG = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST:239.255.255.250:1900\r\n"
    'MAN:"ssdp:discover"\r\n'
    "MX:3\r\n"
    "ST:ssdp:all\r\n\r\n"
)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
s.settimeout(5)
s.sendto(SSDP_MSG.encode(), ("239.255.255.250", 1900))
print("SSDP sent, listening 5s...")

deadline = time.time() + 5
seen = set()
while time.time() < deadline:
    try:
        data, addr = s.recvfrom(4096)
        key = addr[0]
        if key not in seen:
            seen.add(key)
            print(f"\n[{addr[0]}] SSDP response:")
            print(data.decode(errors="replace")[:400])
    except socket.timeout:
        break
s.close()

# Also probe port 5000 with various paths
print("\n=== Port 5000 probe ===")
for path in ["/", "/setup.xml", "/upnp/control", "/device.xml", "/info"]:
    try:
        r = requests.get(f"http://192.168.18.193:5000{path}", timeout=3, allow_redirects=False)
        print(f"  {path}: HTTP {r.status_code}  {r.text[:150]}")
    except Exception as e:
        print(f"  {path}: {e!s:.60}")

# Check MAC OUI
print("\n=== MAC OUI lookup (22-80-ab) ===")
print("OUI 22:80:AB -> Likely locally administered (randomized/VM) or specific vendor")
print("Check: https://maclookup.app/macaddress/2280AB")
