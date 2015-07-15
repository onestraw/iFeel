/*
**2014-11-8
**searchword.h
*/ 
#ifndef _RESOLVER_H
#define _RESOLVER_H
    
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
using namespace std;

 
#include "pcap.h"
    
#include"decode.h"

 
 
typedef unsigned char u_char;

typedef unsigned short u_short;

typedef unsigned long u_long;

//typedef unsigned __int64 u_int64;
    
#define ETHERNET_HEADER_LEN     14
#define ETHERNET_MTU            1500
#define ETHERNET_TYPE_IP        0x0800
#define ETHERNET_TYPE_ARP       0x0806
#define ETHERNET_TYPE_REVARP    0x8035
#define ETHERNET_TYPE_IPX       0x8137
    
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
    
#define TCPOPT_EOL      0
#define TCPOPT_NOP      1
#define TCPOPT_MAXSEG   2
    
#define L2TP_PORT 1701
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
    
#define SNAPLEN      1514
#define PROMISC      1
#define READ_TIMEOUT 500
    
#define ARPOP_REQUEST   1               /* ARP request                  */
#define ARPOP_REPLY     2               /* ARP reply                    */
#define ARPOP_RREQUEST  3               /* RARP request                 */
#define ARPOP_RREPLY    4               /* RARP reply                   */
    
 
#define ICMP_ECHOREPLY          0       /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH      4       /* Source Quench                */
#define ICMP_REDIRECT           5       /* Redirect (change route)      */
#define ICMP_ECHO               8       /* Echo Request                 */
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */
#define ICMP_PARAMETERPROB      12      /* Parameter Problem            */
#define ICMP_TIMESTAMP          13      /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14      /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15      /* Information Request          */
#define ICMP_INFO_REPLY         16      /* Information Reply            */
#define ICMP_ADDRESS            17      /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18      /* Address Mask Reply           */
#define NR_ICMP_TYPES           18
    
 
/* Codes for UNREACH. */ 
#define ICMP_NET_UNREACH        0       /* Network Unreachable          */
#define ICMP_HOST_UNREACH       1       /* Host Unreachable             */
#define ICMP_PROT_UNREACH       2       /* Protocol Unreachable         */
#define ICMP_PORT_UNREACH       3       /* Port Unreachable             */
#define ICMP_FRAG_NEEDED        4       /* Fragmentation Needed/DF set  */
#define ICMP_SR_FAILED          5       /* Source Route failed          */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_NET_ANO            9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13      /* Packet filtered */
#define ICMP_PREC_VIOLATION     14      /* Precedence violation */
#define ICMP_PREC_CUTOFF        15      /* Precedence cut off */
#define NR_ICMP_UNREACH         15      /* instead of hardcoding immediate value */
    
 
 
/*  D A T A  S T R U C T U R E S  *********************************************/ 
    
typedef struct _pcap_dev {
	
string name;
	
string desc;
	
string addr;
	
string mask;

} pcap_dev;

 
 
typedef struct _EtherHdr 
 {
	
unsigned char ether_dst[6];
	
 unsigned char ether_src[6];
	
 unsigned short ether_type;

} EtherHdr;

 
 
typedef struct _IPHdr 
 {
	
#if defined(WORDS_BIGENDIAN)
	u_char ip_ver:4, \
ip_hlen:4;
	
#else	/* 
 */
	u_char ip_hlen:4, \
ip_ver:4;
	
#endif	/* 
 */
	u_char ip_tos;
	
u_short ip_len;
	
u_short ip_id;
	
u_short ip_off;
	
u_char ip_ttl;
	
u_char ip_proto;
	
u_short ip_csum;
	
struct in_addr ip_src;
	
struct in_addr ip_dst;

} IPHdr;

 
 
typedef struct _TCPHdr 
 {
	
u_short th_sport;	/* source port */
	
u_short th_dport;	/* destination port */
	
u_long th_seq;		/* sequence number */
	
u_long th_ack;		/* acknowledgement number */
	
#ifdef WORDS_BIGENDIAN
	u_char th_off:4, /* data offset */ 
	th_x2:4;		/* (unused) */
	
#else	/* 
 */
	u_char th_x2:4, /* (unused) */ 
	th_off:4;		/* data offset */
	
#endif	/* 
 */
	u_char th_flags;
	
u_short th_win;	/* window */
	
u_short th_sum;	/* checksum */
	
u_short th_urp;	/* urgent pointer */

} TCPHdr;

 
 
typedef struct _UDPHdr 
 {
	
u_short uh_sport;
	
u_short uh_dport;
	
u_short uh_len;
	
u_short uh_chk;

} UDPHdr;

 
typedef struct _DNSHdr 
 {
	
u_short id;
	
u_short flags;
	
u_short qdcount;
	
u_short ancount;
	
u_short nscount;
	
u_short arcount;

} DNSHdr;

 
typedef struct _ICMPhdr 
 {
	
u_char type;
	
u_char code;
	
u_short csum;

} ICMPHdr;

 
 
typedef struct _ARPHdr 
 {
	
unsigned short ar_hrd;	/* format of hardware address   */
	
 unsigned short ar_pro;	/* format of protocol address   */
	
 unsigned char ar_hln;	/* length of hardware address   */
	
 unsigned char ar_pln;	/* length of protocol address   */
	
 unsigned short ar_op;	/* ARP opcode (command)         */

} ARPHdr;

 
 
 
typedef struct _EtherARP 
 {
	
ARPHdr ea_hdr;		/* fixed-size header */
	
unsigned char arp_sha[6];	/* sender hardware address */
	
 unsigned char arp_spa[4];	/* sender protocol address */
	
 unsigned char arp_tha[6];	/* target hardware address */
	
 unsigned char arp_tpa[4];	/* target protocol address */

} EtherARP;

typedef struct _AddrPort{
	struct in_addr saddr;
	struct in_addr daddr;
	u_short sport;
	u_short dport;
} AddrPort;

/*
** 搜索关键词监听
*/
typedef struct _Keyword{
	u_long saddr;
	string search_engine;
	string keyword;
}Keyword;
/*
** HTTP报文Host,url信息
*/
typedef struct _UrlInfo{
	long time;
	u_long saddr;
	string host;
	string url;
}UrlInfo;
/*
** 数据库连接参数
*/
typedef struct _DBinfo{
	string host;
	string user;
	string pass;
	string ids_db;
	string ids_data_table;
}DBinfo;

 
void searchword(char *param, struct pcap_pkthdr *pkthdr, u_char * pkt);
 
void RecordDomainName(u_long addr, const char *dname, int len);

void ResolveDomainName(const u_char *, int);

void RecordSearchWord(string, string, int);

int saveKeyword2db(vector < Keyword > &v);

 
#endif	/* 
 */
