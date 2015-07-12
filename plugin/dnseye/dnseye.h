#ifndef DNSEYE_H
#define DNSEYE_H

#include"snort.h"

void dnseye(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt);

/*  D N S 2014.6 ******************************************************/

typedef struct _DNSHdr
{
	u_short id;
	u_short flags;
	u_short qdcount;
	u_short ancount;
	u_short nscount;
	u_short arcount;
}DNSHdr;
//son of second level ,namely, third level damin
struct SSLD{
	char name[64];
	u_long cnt;
	struct SSLD *next;
};
//second level domain, its length < 64
struct SLD{
	char name[64];
	u_long cnt;
	struct SSLD *ssld;
	struct SLD *next;
};
//top level domain
struct TLD{
	char name[5];
	u_long cnt;
	struct SLD *sld;
	struct TLD *next;
};
//requester, namely,src addr
struct DNSRequest{
	u_long saddr;
	u_long cnt;
	struct TLD *tld;
	struct DNSRequest *next;
};
//struct TLD *g_dnlist=NULL;
struct DNSRequest *g_dnslist=NULL;
static u_int pcnt;
#define PCNT_THRESHOLD	5

void PrintDNlist(int level);
void ReleaseDNlist();
void RecordDomainName(u_long addr, char *dname);
void DecodeDNS(u_char *pkt, int len);

#endif
