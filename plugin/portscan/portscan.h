#ifndef PORTSCAN_H
#define PORTSCAN_H

#include"snort.h"
void portscan(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt);

#endif
