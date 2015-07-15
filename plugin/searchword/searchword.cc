/*
**2014-11-8
**searchword.cc
*/
#include"searchword.h"

/*  G L O B A L S  ************************************************************/
vector<Keyword> vk;

vector<UrlInfo> vu;

u_char *pktidx;
long pkt_time;
long pre_time;
#define INTERVAL 5
AddrPort ap;					/* 记录一个数据包的IP和port四元组		*/
long g_daddr;
long g_saddr;

//static void DecodeEthPkt(u_char *, const struct pcap_pkthdr *, const u_char *);
static void DecodeIP(const u_char *, int);
static void DecodeTCP(const u_char *, int);
static void DecodeHTTP(string &, string&, int);

//void DecodeEthPkt(u_char *param, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
void searchword(char *param, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
	int pkt_len;  /* suprisingly, the length of the packet */
	int cap_len;  /* caplen value */
	int pkt_type; /* type of pkt (ARP, IP, etc) */
	long now_time;
	now_time = pkthdr->ts.tv_sec;
	pkt_time = now_time;
	if (pre_time == 0)
	{
		pre_time = now_time;
	}
	else if (now_time - pre_time >= INTERVAL)
	{
		pre_time = now_time;
		
		//saveKeyword2db(vk);
		vk.clear();

		vu.clear();
		//reset();
	}

	EtherHdr *eh; /* ethernet header pointer (thanks Mike!) */

	/* set the lengths we need */
	pkt_len = pkthdr->len;
	cap_len = pkthdr->caplen;


	/* do a little validation */
	if (cap_len < ETHERNET_HEADER_LEN)
	{
		fprintf(stderr, "Ethernet header length > cap len! (%d bytes)\n",cap_len);
		return;
	}

	/* lay the ethernet structure over the packet data */
	eh = (EtherHdr *)pkt;

	/* grab out the network type */
	pkt_type = ntohs(eh->ether_type);

	/* set the packet index pointer */
	pktidx = pkt;

	/* increment the index pointer to the start of the network layer */
	pktidx += ETHERNET_HEADER_LEN;

	switch (pkt_type)
	{
	case ETHERNET_TYPE_IP:
		DecodeIP(pktidx, pkt_len - ETHERNET_HEADER_LEN);
		return;
	default:
		return;
	}
	return;
}

void DecodeIP(const u_char *pkt, int len)
{
	IPHdr *iph;   /* ip header ptr */
	int ip_len; /* length from the start of the ip hdr to the pkt end */
	u_int hlen;   /* ip header length */
	u_int off;    /* data offset */

	/* lay the IP struct over the raw data */
	iph = (IPHdr *)pkt;

	/* do a little validation */
	if (len < sizeof(IPHdr)){
		fprintf(stderr, "Truncated header! (%d bytes)\n", len);
		return;
	}

	ip_len = ntohs(iph->ip_len);

	if (len < ip_len){
		fprintf(stderr,"Truncated packet!  Header says %d bytes, actually %d bytes\n",ip_len, len);
		return;
	}

	/* set the IP header length */
	hlen = iph->ip_hlen << 2;

	ap.daddr = iph->ip_dst;
	ap.saddr = iph->ip_src;

	g_daddr = iph->ip_dst.s_addr;
	g_saddr = iph->ip_src.s_addr;

	/* check for fragmented packets */
	ip_len -= hlen;
	off = ntohs(iph->ip_off);
	


	/* move the packet index to point to the transport layer */
	pktidx = pktidx + hlen;

	switch (iph->ip_proto)
	{
	case IPPROTO_TCP:
		//strncpy(pip.proto, "TCP", 3);
		DecodeTCP(pktidx, ip_len);//len - hlen);
		return;
	default:
		return;
	}
}


void getHost(const u_char *pkt, int len, string &host)
{
	string temp((char*)pkt);
	for (int i = 0; i < temp.size(); i++)
	{
		temp[i] = tolower(temp[i]);
	}
	int start = temp.find("host:") + 5;
	while (temp[start] == ' ')
	{
		start++;
	}
	int end = start;
	if (start < temp.size())
	{
		while (!(pkt[end] == '\r' && pkt[end + 1] == '\n') && end < temp.size())
		{
			end++;
		}
		if (end - start < 100)
		{
			host = temp.substr(start, end-start);
		}
	}
}

void DecodeTCP(const u_char *pkt, int len)
{
	TCPHdr *tcph;  /* TCP packet header ptr */
	u_char flags;

	tcph = (TCPHdr *)pkt;

	ap.sport = ntohs(tcph->th_sport);
	ap.dport = ntohs(tcph->th_dport);

	flags = tcph->th_flags;

	u_short hlen = tcph->th_off * 4;
	pktidx += hlen;

	if(len <= hlen){
		//fprintf(stderr, "len <= hlen in %s(%d):%s\n", __FILE__, __LINE__, __FUNCTION__);
		return;
	}
	char *hdata;
	hdata = new char[len - hlen];
	for (int i = 0; i + hlen + 1 < len; i++)
	{
		if (pktidx[i] == '\r' && pktidx[i + 1] == '\n')
		{
			hdata[i] = '\0';
			break;
		}
		hdata[i] = pktidx[i];
	}

	string s(hdata);
	delete hdata;
	if (s.find("HTTP")!=string::npos)
	{
		string host;
		getHost(pktidx, len - hlen, host);
		DecodeHTTP(host, s, len - hlen);
	}
}
void DecodeHTTP(string &host, string &pkt, int len)
{
	/*http method:
	GET, HEAD, PUT, POST, TRACE, OPTIONS,
	DELETE, LOCK, MKCOL, MOVE, COPY, PATCH, CONNECT
	*/
	if (pkt.find("GET") != string::npos){
		RecordSearchWord(host, pkt, len);
	}else if (pkt.find("CONNECT") != string::npos){
	//	feature.http_con_cnt += 1;
	}else if (pkt.find("HTTP") == 0){
	//	feature.http_rep_cnt += 1;
	}
}

void RecordSearchWord(string host, string pkt, int len)
{
	int end = pkt.find("HTTP");
	/* save host and url */
	UrlInfo item = { pkt_time, g_saddr, host, pkt.substr(5, end - 5) };
	vu.push_back(item);

	/* get keyword */
	string s = "http://" + host + "/" + pkt.substr(5, end - 5);
	string site;
	string keyword;
	if (host.find("suggestion.baidu.com") != string::npos)
	{
		return;
	}
	getInfo(s, site, keyword);
	if (site.size() > 0 && keyword.size() > 0)
	{
		cout << "[" <<inet_ntoa(ap.saddr)<<"]: " <<site.c_str() << ":" << keyword.c_str() << endl;
		Keyword item = { g_saddr, site, keyword };
		vk.push_back(item);
	}
}

