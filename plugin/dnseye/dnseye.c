/*
** Copyright (C) 2015 geeksword <geeksword@163.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include"dnseye.h"
static void DecodeIP(u_char *, int);
static void DecodeUDP(u_char *, int);
static u_char* pktidx;
static PrintIP pip;
struct DNSRequest *g_dnslist=NULL;
static u_int pcnt;
#define PCNT_THRESHOLD	5

/****************************************************************************/

void dnseye(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
   int pkt_len;  /* suprisingly, the length of the packet */
   int pkt_type; /* type of pkt (ARP, IP, etc) */
   EtherHdr *eh; /* ethernet header pointer (thanks Mike!) */

   /* set the lengths we need */
   pkt_len = pkthdr->len;

   /* do a little validation */
   if(pkthdr->caplen < ETHERNET_HEADER_LEN){
      fprintf(stderr, "Ethernet header length < cap len! (%d bytes)\n", 
              pkthdr->caplen);
      return;
   }   

   /* lay the ethernet structure over the packet data */
   eh = (EtherHdr *) pkt;

   /* grab out the network type */
   pkt_type = ntohs(eh->ether_type);

   /* set the packet index pointer */
   pktidx = pkt;

   /* increment the index pointer to the start of the network layer */
   pktidx += ETHERNET_HEADER_LEN;

   switch(pkt_type)
   {
      case ETHERNET_TYPE_IP:
                      DecodeIP(pktidx, pkt_len-ETHERNET_HEADER_LEN);
             return;
      default:
             return;
   }
}


/****************************************************************************
 *
 * Function: DecodeIP(u_char *, int)
 *
 * Purpose: Decode the IP network layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeIP(u_char *pkt, int len)
{
   IPHdr *iph;   /* ip header ptr */
   u_int ip_len; /* length from the start of the ip hdr to the pkt end */
   u_int hlen;   /* ip header length */
   u_int off;    /* data offset */


   bzero((void *) &pip, sizeof(PrintIP));

   /* lay the IP struct over the raw data */
   iph = (IPHdr *) pkt;

   /* do a little validation */
   if(len < sizeof(IPHdr)){
      fprintf(stderr, "Truncated header! (%d bytes)\n", len);
      return;
   }
  
   ip_len = ntohs(iph->ip_len);

   if(len < ip_len){
      fprintf(stderr, 
              "Truncated packet!  Header says %d bytes, actually %d bytes\n", 
              ip_len, len);
      return;
   }

   /* set the IP header length */
   hlen = iph->ip_hlen * 4;      

   /* generate a timestamp */
   GetTime(pip.timestamp);

   /* start filling in the printout data structures */
   strncpy(pip.saddr, inet_ntoa(iph->ip_src), 15);
   strncpy(pip.daddr, inet_ntoa(iph->ip_dst), 15);

#ifdef DEBUG
   printf("Src addr = %s\n", pip.saddr);
   printf("Dst addr = %s\n", pip.daddr);
#endif
   
   pip.ttl = iph->ip_ttl;

   /* check for fragmented packets */
   ip_len -= hlen;
   off = ntohs(iph->ip_off);


   if((off & 0x1FFF) == 0){ 
      /* move the packet index to point to the transport layer */
      pktidx = pktidx + hlen;

      switch(iph->ip_proto)
      {
         case IPPROTO_TCP:
                strncpy(pip.proto, "TCP", 3);
                //DecodeTCP(pktidx, len-hlen);
                return;
         case IPPROTO_UDP:
         	strncpy(pip.proto, "UDP", 3);
                DecodeUDP(pktidx, len-hlen);
                return;
         default: 
                return;
      }
   }
}

void DecodeUDP(u_char *pkt, int len)
{
   UDPHdr *udph;
   udph = (UDPHdr *) pkt;

   pip.sport = ntohs(udph->uh_sport);
   pip.dport = ntohs(udph->uh_dport);

   pip.udp_len = ntohs(udph->uh_len);

   if(pip.dport==53){
   	pktidx = pktidx +8;
   	//fprintf(stdout,"dns packet, dns pkt len=%d\n",len-8);
   	//PrintNetData(stdout,(char *)pktidx, len-8);
   	DecodeDNS(pktidx, len-8);
   }
   SetFlow();

   if(pv.verbose_flag){
      PrintIPPkt(stdout, IPPROTO_UDP);

      if(pv.data_flag)
         PrintNetData(stdout, (char *) pkt + 8, len-8);
   }

   if(pv.log_flag){
      OpenLogFile();

      PrintIPPkt(log_ptr, IPPROTO_UDP);

      if(pv.data_flag)
         PrintNetData(log_ptr, (char *) pkt + 8, len-8);

      fclose(log_ptr);
   }
}

void PrintDNlist(int level)
{
	struct DNSRequest *dnsr;
	struct TLD *tld;
	struct SLD *sld;
	struct SSLD *ssld;
	struct in_addr saddr;
	for(dnsr=g_dnslist; dnsr; dnsr=dnsr->next){
		saddr.s_addr = dnsr->saddr;
		fprintf(stdout,"From: %s\tCount: %lu\n",inet_ntoa(saddr),dnsr->cnt);
		for(tld = dnsr->tld; tld; tld=tld->next){
			fprintf(stdout,"+%s\tCount:%lu\n",tld->name,tld->cnt);
			for(sld = tld->sld; sld; sld=sld->next){
				fprintf(stdout,"-+%s.%s\tCount:%lu\n",sld->name,tld->name,sld->cnt);
				for(ssld = sld->ssld; ssld && level>2; ssld=ssld->next)
					fprintf(stdout,"---%s.%s.%s\n",ssld->name,sld->name,tld->name);	
			}
		}
	}
}
void ReleaseDNlist()
{
	struct DNSRequest *dnsr;
	struct TLD *tld;
	struct SLD *sld;
	struct SSLD *ssld;
	while(dnsr = g_dnslist){
		while(tld = dnsr->tld){
			while(sld = tld->sld){
				while(ssld = sld->ssld){
					sld->ssld = ssld->next;
					free(ssld);
				}
				tld->sld = sld->next;
				free(sld);
			}
			dnsr->tld = tld->next;
			free(tld);
		}
		g_dnslist = dnsr->next;
		free(dnsr);
	}
}

void RecordDomainName(u_long saddr, char *dname)
{
	char name1[5],name2[64],name3[64];
	int i,j,k,len, idx[3];
	len= strlen(dname);
	
	for(i=0,j=0; i<len && j<3; i++){
		if(dname[i]=='.'){
			idx[j++]=i;
		}
	}
	if(j<1){
		return;
	}
	else if(j==3){
		for(i=len-1,j=2; i>-1 &&j>-1; i--){
			if(dname[i]=='.'){
				idx[j--]=i;
			}
		}
		j=3;
	}
	memset(name1,0,5);
	memset(name2,0,64);
	memset(name3,0,64);
	i=idx[--j]+1;
	k=0; 
	while(i<len){
		name1[k++] = dname[i++];
	}
	if(j<1){
		i=0;
		j=-1;
	}
	else{
		i=idx[--j]+1;
	}
	k=0;
	while(i<idx[j+1]){
		name2[k++] = dname[i++];
	}
	if(j<0){
		name3[0]='\0';
	}else{
		for(i=0,k=0; i<idx[j]; i++){
			name3[k++] = dname[i];
		}
	}
	printf("%s\t%s\t%s\n",name1,name2,name3);
	/* insert the domain name into g_dnlist */
	//first level
	struct DNSRequest *dnsr;
	for(dnsr=g_dnslist; dnsr; dnsr=dnsr->next){
		if(saddr = dnsr->saddr){
			break;
		}
	}
	if(!dnsr){
		if((dnsr = (struct DNSRequest*)malloc(sizeof(struct DNSRequest)))==NULL){
			fprintf(stderr,"malloc DNSRequest error\n");
			exit(-1);
		}
		memset(dnsr,0,sizeof(struct DNSRequest));
		dnsr->saddr = saddr;
		dnsr->next = g_dnslist;
		g_dnslist = dnsr;
	}
	dnsr->cnt++;
	//second level
	struct TLD *tld;
	for(tld=dnsr->tld; tld; tld=tld->next){
		if(strcmp(tld->name, name1)==0){
			break;
		}
	}
	//create a new TLD node
	if(!tld){
		if((tld = (struct TLD*)malloc(sizeof(struct TLD)))==NULL){
			fprintf(stderr,"malloc TLD error\n");
			exit(-1);
		}
		memset(tld,0,sizeof(struct TLD));
		strcpy(tld->name, name1);
		tld->next = dnsr->tld;
		dnsr->tld = tld;
	}
	tld->cnt ++;
	//third level
	struct SLD *sld;
	for(sld = tld->sld; sld; sld=sld->next){
		if(strcmp(sld->name, name2)==0){
			break;
		}
	}
	if(!sld){
		if((sld = (struct SLD*)malloc(sizeof(struct SLD)))==NULL){
			fprintf(stderr,"malloc SLD error\n");
			exit(-1);
		}
		memset(sld,0,sizeof(struct SLD));
		strcpy(sld->name, name2);
		sld->next = tld->sld;
		tld->sld = sld;
	}
	sld->cnt++;
	if(name3[0]=='\0'){
		return;
	}
	//fourth level
	struct SSLD *ssld;
	for(ssld=sld->ssld; ssld; ssld=ssld->next){
		if(strcmp(ssld->name, name3)==0){
			break;
		}
	}
	if(!ssld){
		if((ssld = (struct SSLD*)malloc(sizeof(struct SSLD)))==NULL){
			fprintf(stderr,"malloc SSLD error\n");
			exit(-1);
		}
		memset(ssld,0,sizeof(struct SSLD));
		strcpy(ssld->name, name3);
		ssld->next = sld->ssld;
		sld->ssld = ssld;
	}
	ssld->cnt++;
}

void DecodeDNS(u_char *pkt, int len)
{
	u_int qlen,cnt;
	qlen = len - 12;
	u_char *quest;
	u_char dname[qlen];

	quest = pkt + 12;
	u_short i = 0;
	//PrintNetData(stdout,(char *)quest, len);
	while(cnt=(int)(*quest)){
		for(cnt; cnt >0; cnt--){
			quest ++;
			dname[i++] = *quest;
		}
		quest++;
		dname[i++]='.';
	}
	dname[i-1]='\0';
	fprintf(stdout,"%s\tsrc ip: %s\turl: %s\n",pip.timestamp, pip.saddr, dname);
	/*
	RecordDomainName(inet_addr(pip.saddr),dname);
	if((++pcnt) > PCNT_THRESHOLD)
	{//print once every 100 requests
		printf("|----------------------------|\n");
		PrintDNlist(2);
		pcnt = 0;
	}
	*/
}

