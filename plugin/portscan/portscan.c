/*********************************************************************
Program: catcher
Function: detect tcp/udp port scan
***********************************************************************/
#include "portscan.h"

void get_if_ip()
{
	//new method get eth0's IP
	struct ifreq ifr;
	int fd;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, gDev, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	g_my_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}


void init_portscan()
{
	u_int pktlen = 0, i, netfd;
	u_char *pkt;
	char hostname[32];
	struct hostent *hp;
	time_t t;

	openlog("portscan", 0, LOG_DAEMON);

#ifdef DEBUG
	if (gethostname(hostname, sizeof(hostname)) < 0) {
		perror("gethostname()");
		exit(-1);
	}
	if ((hp = gethostbyname(hostname)) == NULL) {
		fprintf(stderr, "Cannot find local address\n");
		exit(-1);
	}
	memcpy((char *)&g_my_addr, hp->h_addr, hp->h_length);
	printf("[+ portscan] my_addr: %s\n",hp->h_addr);
	printf("[+ portscan] my_addr: %s\n",hp->h_name);
#endif
	get_if_ip();
	//g_my_addr = inet_addr("124.16.77.185");
	buildnet();

	if ((netfd = initdevice(O_RDWR, 0)) < 0)
		exit(-1);
}

void portscan(char *user, struct pcap_pkthdr *pkthdr, u_char * pkt)
{
	if (!init_flag) {
		init_portscan();
		init_flag = 1;
		t = time((time_t *) 0);
	}
	process_packet(pkt, pkthdr->len);
	if (time((time_t *) 0) - t > g_timer) {
		/* Times up.  Print what we found and clean out old stuff. */
#ifdef DEBUG
		printf("[+ portscan] time to print\n");
#endif
		for (g_pdaddr = g_mlist; g_pdaddr; g_pdaddr = g_pdaddr->next) {
			print_info();
			clear_saddrNode(g_pdaddr);
		}
		t = time((time_t *) 0);
	}
}

/**********************************************************************
Function: usage

Purpose:  Display the usage of the program
**********************************************************************/
void usage()
{
	printf("Usage: %s [options]\n", gProgramName);
	printf
	    ("  -d device       Use 'device' as the network interface device\n");
	printf
	    ("                  The first non-loopback interface is the default\n");
	printf
	    ("  -f flood        Assume a synflood attack occurred if more than\n");
	printf
	    ("                  'flood' uncompleted connections are received\n");
	printf("  -h              A little help here\n");
	printf
	    ("  -i icmplimit    Assume we may be part of a smurf attack if more\n");
	printf("                  than icmplimit ICMP ECHO REPLIES are seen\n");
	printf("  -m level        Monitor more than just our own host.\n");
	printf
	    ("                  A level of 'subnet' watches all addresses in our\n");
	printf("                  subnet and 'all' watches all addresses\n");
	printf
	    ("  -p portlimit    Logs a portscan alert if packets are received for\n");
	printf
	    ("                  more than portlimit ports in the timeout period.\n");
	printf
	    ("  -r reporttype   If reporttype is dos, only Denial Of Service\n");
	printf
	    ("                  attacks are reported.  If reporttype is scan\n");
	printf
	    ("                  then only scanners are reported.  Everything is\n");
	printf("                  reported by default.\n");
	printf
	    ("  -t timeout      Count packets and print potential attacks every\n");
	printf("                  timeout seconds\n");
	printf
	    ("  -w webcount     Assume we are being portscanned if more than\n");
	printf
	    ("                  webcount packets are received from port 80\n");
}

/**********************************************************************
Function: buildnet

Purpose:  Setup for monitoring of our host or entire subnet.
**********************************************************************/
void buildnet()
{
	u_long addr;
	u_char *p;
	int i;

	if (Gwatchlevel == MYSELFONLY) {	/* Just care about me */
		(void)addtarget(g_my_addr);
	} else if (Gwatchlevel == MYSUBNET) {	/* Friends and neighbors */
		addr = htonl(g_my_addr);
		addr = addr & 0xffffff00;
		for (i = 0; i < 256; i++)
			(void)addtarget(ntohl(addr + i));
	}

	struct daddrNode *di;
	for (di = g_mlist; di; di = di->next)
		printf("%s\n", ip_itos(di->daddr));

}

/**********************************************************************
Function: doicare
do I care ?
Purpose:  See if we monitor this address
**********************************************************************/
struct daddrNode *doicare(u_long addr)
{
	struct daddrNode *pdip;
	int i;

	for (pdip = g_mlist; pdip; pdip = pdip->next) {
		if (pdip->daddr == addr)
			return (pdip);
	}
	if (Gwatchlevel == HUMANITARIAN) {	/* Add a new address, we always care */
		pdip = addtarget(addr);
		return (pdip);
	}
	return (NULL);
}

/**********************************************************************
Function: addtarget

Purpose:  Adds a new IP address to the list of hosts to watch.
**********************************************************************/
struct daddrNode *addtarget(u_long addr)
{
	struct daddrNode *pdip;

	if ((pdip =
	     (struct daddrNode *)malloc(sizeof(struct daddrNode))) == NULL) {
		perror("malloc daddrNode");
		exit(-1);
	}
	pdip->daddr = addr;
	pdip->next = g_mlist;
	pdip->tcp = NULL;
	pdip->udp = NULL;
	g_mlist = pdip;
	return (pdip);
}

/**********************************************************************
Function: process_packet

Purpose:  Process raw packet and figure out what we need to to with it.

Pulls the packet apart and stores key data in global areas for reference
by other functions.
**********************************************************************/
void process_packet(pkt, pktlen)
u_char *pkt;
u_int pktlen;
{
	struct ethhdr *ep;
	struct iphdr *ip;
	static struct align {
		struct iphdr ip;
		char buf[PKTLEN];
	} a1;
	u_short off;

	g_timein = time((time_t *) 0);
	ep = (struct ethhdr *)pkt;
	if (ntohs(ep->h_proto) != ETH_P_IP) {
#ifdef DEBUG
		printf("[+ portscan] ep->h_proto != ETH_P_IP\n");
#endif
		return;
	}
	pkt += sizeof(struct ethhdr);
	pktlen -= sizeof(struct ethhdr);
	memcpy(&a1, pkt, pktlen);
	ip = &a1.ip;
	g_saddr = ip->saddr;
	g_daddr = ip->daddr;

	if ((g_pdaddr = doicare(g_daddr)) == NULL)
		return;

	off = ntohs(ip->frag_off);
	g_isfrag = (off & IP_MF);	/* Set if packet is fragmented */
	g_iplen = ntohs(ip->tot_len);
	g_id = ntohs(ip->id);
	pkt = (u_char *) ip + (ip->ihl << 2);
	g_iplen -= (ip->ihl << 2);
#ifdef DEBUG
	//printf("[+ portscan] ip->protocol:%d\n", ip->protocol);
#endif
	switch (ip->protocol) {
	case IPPROTO_TCP:
		do_tcp(ep, pkt);
		break;
	case IPPROTO_UDP:
		do_udp(ep, pkt);
		break;
	default:
		break;
	}
}

/**********************************************************************
Function: do_tcp

Purpose:  Process this TCP packet if it is important.
**********************************************************************/
void do_tcp(ep, pkt)
struct ethhdr *ep;
u_char *pkt;
{
#ifdef DEBUG
	//printf("[+ portscan] enter do_tcp()\n");
#endif
	struct tcphdr *thdr;
	u_short sport, dport;

	thdr = (struct tcphdr *)pkt;
	/*如果响应是RST包，可能说明被扫描的端口是关闭的 */
	if (thdr->rst)		/* RST generates no response */
		return;		/* Therefore can't be used to scan. */
	sport = ntohs(thdr->source);
	dport = ntohs(thdr->dest);

	u_short flags = 0;
	flags = thdr->syn << 2 + thdr->fin << 1 + thdr->ack;
	addtcp(sport, dport, flags, ep->h_source);
#ifdef DEBUG
	printf("[+ portscan] sport,dport=(%d,%d)\n",sport,dport);
#endif
}

/**********************************************************************
Function: createPortNode

Purpose:  create a new dportNode and add it to saddrNode.
**********************************************************************/
void createPortNode(struct saddrNode *psa, u_short sport, u_short dport)
{
	struct dportNode *pdp;
	if ((pdp =
	     (struct dportNode *)malloc(sizeof(struct dportNode))) == NULL) {
		perror("Malloc dportNode");
		exit(-1);
	}
	pdp->sport = sport;
	pdp->dport = dport;
	pdp->next = psa->dport;
	psa->dport = pdp;
}

/**********************************************************************
Function: addtcp

Purpose:  Add this TCP packet to our list.
**********************************************************************/
void addtcp(sport, dport, flags, eaddr)
u_short sport;
u_short dport;
u_char flags;
u_char *eaddr;
{
#ifdef DEBUG
	printf("[+ portscan] enter addtcp()\n");
#endif
	struct saddrNode *pi;
	struct dportNode *pdp;
	/* See if this packet relates to other packets already received. */

	for (pi = g_pdaddr->tcp; pi; pi = pi->next) {
		if (pi->saddr == g_saddr) {
			if (sport == 80)
				pi->high_freq_sport_cnt++;
			for (pdp = pi->dport; pdp; pdp = pdp->next)
				if (pdp->dport == dport)
					return;
			/* Must be new dport */
			createPortNode(pi, sport, dport);
			pi->diff_dport_cnt++;
			return;
		}
	}
	/* Must be new saddr */

	if ((pi = (struct saddrNode *)malloc(sizeof(struct saddrNode))) == NULL) {
		perror("Malloc saddrNode");
		exit(-1);
	}
	memset(pi, 0, sizeof(struct saddrNode));

	pi->saddr = g_saddr;
	pi->diff_dport_cnt = 1;
	pi->high_freq_sport_cnt = 1;
	pi->next = g_pdaddr->tcp;
	g_pdaddr->tcp = pi;

	/* Add a new dport */
	createPortNode(g_pdaddr->tcp, sport, dport);
}

/**********************************************************************
Function: do_udp

Purpose:  Process this udp packet.

Currently teardrop and all its derivitives put 242 in the IP id field.
This could obviously be changed.  The truly paranoid might want to flag all
fragmented UDP packets.  The truly adventurous might enhance the code to
track fragments and check them for overlaping boundaries.
**********************************************************************/
void do_udp(ep, pkt)
struct ethhdr *ep;
u_char *pkt;
{
	struct udphdr *uhdr;
	u_short sport, dport;

	uhdr = (struct udphdr *)pkt;

	sport = ntohs(uhdr->source);
	dport = ntohs(uhdr->dest);
	addudp(sport, dport, ep->h_source);
}

/**********************************************************************
Function: addudp

Purpose:  Add this udp packet to our list.
**********************************************************************/
void addudp(sport, dport, eaddr)
u_short sport;
u_short dport;
u_char *eaddr;
{
#ifdef DEBUG
	printf("[+ portscan] enter addudp()\n");
#endif
	struct saddrNode *pi;
	struct dportNode *pdp;
	for (pi = g_pdaddr->udp; pi; pi = pi->next) {
		if (pi->saddr == g_saddr) {
			if (sport == 80)
				pi->high_freq_sport_cnt++;
			for (pdp = pi->dport; pdp; pdp = pdp->next)
				if (pdp->dport == dport)
					return;

			/* Must be new dport */
			createPortNode(pi, sport, dport);
			pi->diff_dport_cnt++;
			return;
		}
	}
	/* Must be new entry */

	if ((pi = (struct saddrNode *)malloc(sizeof(struct saddrNode))) == NULL) {
		perror("Malloc saddrNode");
		exit(-1);
	}
	memset(pi, 0, sizeof(struct saddrNode));

	pi->saddr = g_saddr;
	pi->diff_dport_cnt = 1;
	pi->high_freq_sport_cnt = 1;
	pi->next = g_pdaddr->udp;
	g_pdaddr->udp = pi;

	/* Add a new dport */
	createPortNode(g_pdaddr->udp, sport, dport);
}

/**********************************************************************
Function: clear_saddrNode

Purpose:  Delete and free space for all packets.释放第二层和第三层
**********************************************************************/
void clear_saddrNode(di)
struct daddrNode *di;
{
	struct saddrNode *si;
	struct dportNode *pi, *tpi;

	while (di->tcp) {
		si = di->tcp;
		pi = si->dport;
		while (pi) {
			tpi = pi;
			pi = pi->next;
			free(tpi);
		}
		di->tcp = si->next;
		free(si);
	}
	while (di->udp) {
		si = di->udp;
		pi = si->dport;
		while (pi) {
			tpi = pi;
			pi = pi->next;
			free(tpi);
		}
		di->udp = si->next;
		free(si);
	}
}

/**********************************************************************
Function: print_info

Purpose:  Print out any alerts.
**********************************************************************/
void print_info()
{
	struct saddrNode *si;

	char buf[1024], abuf[16];

	strcpy(abuf, ip_itos(g_pdaddr->daddr));

	if (Greportlevel == REPORTALL || Greportlevel == REPORTSCAN) {

		for (si = g_pdaddr->tcp; si; si = si->next) {
			if ((si->diff_dport_cnt - si->high_freq_sport_cnt >
			     g_portlimit)
			    || si->high_freq_sport_cnt > g_hfreq_portlimit) {
				sprintf(buf,
					"Possible TCP port scan from %s (%lu ports) against %s\n",
					ip_itos(si->saddr), si->diff_dport_cnt,
					abuf);
				LOG(buf);
			}
		}
		for (si = g_pdaddr->udp; si; si = si->next) {
			if ((si->diff_dport_cnt - si->high_freq_sport_cnt >
			     g_portlimit)
			    || si->high_freq_sport_cnt > g_hfreq_portlimit) {
				sprintf(buf,
					"Possible UDP port scan from %s (%lu ports) against %s\n",
					ip_itos(si->saddr), si->diff_dport_cnt,
					abuf);
				LOG(buf);
			}
		}
	}

}

/************************************************************************
Function:  ip_itos

Description: convert ip address from u_long to char*.

**************************************************************************/
char *ip_itos(addr)
u_long addr;
{
	static char buf[16];
	inet_ntop(AF_INET, (void *)&addr, buf, 16);
	return (buf);
}

/************************************************************************
Function:  initdevice

Description: Set up the network device so we can read it.

**************************************************************************/
initdevice(fd_flags, dflags)
int fd_flags;
u_long dflags;
{
	struct ifreq ifr;
	int fd, flags = 0;

	if ((fd = socket(PF_INET, SOCK_PACKET, htons(0x0003))) < 0) {
		perror("Cannot open device socket");
		exit(-1);
	}

	/* Get the existing interface flags */
	strcpy(ifr.ifr_name, gDev);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		perror("Cannot get interface flags");
		exit(-1);
	}

	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("Cannot set interface flags");
		exit(-1);
	}

	return (fd);
}

/************************************************************************
Function:  readdevice

Description: Read a packet from the device.

**************************************************************************/
u_char *readdevice(fd, pktlen)
int fd;
int *pktlen;
{
	int cc = 0, from_len, readmore = 1;
	struct sockaddr from;
	static u_char pktbuffer[PKTLEN];
	u_char *cp;

	while (readmore) {
		from_len = sizeof(from);
		if ((cc =
		     recvfrom(fd, pktbuffer, PKTLEN, 0, &from,
			      &from_len)) < 0) {
			if (errno != EWOULDBLOCK)
				return (NULL);
		}
		if (strcmp(gDev, from.sa_data) == 0)
			readmore = 0;
	}
	*pktlen = cc;
	return (pktbuffer);
}
