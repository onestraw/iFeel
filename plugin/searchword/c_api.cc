#include<iostream>

typedef unsigned char u_char;
extern void searchword(char *param, struct pcap_pkthdr *pkthdr, u_char *pkt);

extern "C" void c_searchword(char *param, struct pcap_pkthdr *pkthdr, u_char *pkt);
void c_searchword(char *param, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
	searchword(param, pkthdr, pkt);
}

