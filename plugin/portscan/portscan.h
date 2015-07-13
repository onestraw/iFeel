#ifndef PORTSCAN_H
#define PORTSCAN_H

#include"snort.h"
//#define DEBUG 1

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <malloc.h>
#include <netinet/tcp.h>
#include <netinet/in_systm.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <syslog.h>
#include <linux/sockios.h>

#define LOG(info)	syslog(LOG_ALERT, "%s\n", info);fprintf(stdout,"%s",info)

#define PKTLEN 96		/* Should be enough for what we want */
#ifndef IP_MF
#define IP_MF    0x2000		/* Fragment bit */
#endif

/***** WATCH LEVELS ******/

#define MYSELFONLY    1
#define MYSUBNET    2
#define HUMANITARIAN    3

/***** REPORT LEVELS *****/

#define REPORTALL    1
#define REPORTDOS    2
#define REPORTSCAN    3

/******STRUCT******/
//third level
struct dportNode {
	u_short dport;
	u_short sport;
	struct dportNode *next;
};
//second level
struct saddrNode {
	u_long saddr;
	u_long diff_dport_cnt;
	u_long high_freq_sport_cnt;	//high frequency port, such as 80
	struct dportNode *dport;
	struct saddrNode *next;
};
//first level
struct daddrNode {
	u_long daddr;		//monitored ip addr
	struct saddrNode *tcp;	//for tcp scan
	struct saddrNode *udp;	//for udp scan
	struct daddrNode *next;
};
//main or monitored list
struct daddrNode *g_mlist = NULL;
struct daddrNode *g_pdaddr = NULL;

u_long g_my_addr;
time_t g_timer = 5, g_timein;

int g_portlimit = 7;
int g_hfreq_portlimit = 40;
int Gsynflood = 8;
int Gicmplimit = 5;
//int Gwatchlevel = MYSELFONLY;
int Gwatchlevel = HUMANITARIAN;
int Greportlevel = REPORTALL;
char *gProgramName;
char *gDev = "eth0";
time_t t = 0;
int init_flag = 0;
/******** IP packet info, global ********/

u_long g_saddr, g_daddr;
u_int g_iplen, g_isfrag, g_id;

/****** Externals *************/

extern int errno;
extern int optind, opterr;
extern char *optarg;

void process_packet(), do_tcp(), do_udp(), do_icmp(), print_info();
void addtcp(), addudp(), clear_saddrNode(), buildnet();
void do_args(), usage(), addfloodinfo(), rmfloodinfo();
struct daddrNode *doicare(), *addtarget();
char *ip_itos();
u_char *readdevice();
void portscan(char *user, struct pcap_pkthdr *pkthdr, u_char * pkt);

#endif
