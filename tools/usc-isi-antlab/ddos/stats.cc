#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#include <pcap.h>

#define PCAP_BUF_SIZE	1024
#define PCAP_SRC_FILE	2

int icmpCount = 0;
int tcpCount = 0;
int udpCount = 0;
int dnsCount = 0;
int synCount[PCAP_BUF_SIZE];
int synIdx = 0;
char synIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];
int httpCount[PCAP_BUF_SIZE];
int httpIdx = 0;
char httpIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char **argv) {

    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    int i, maxCountSyn = 0, maxCountHttp = 0, maxIdxSyn = 0, maxIdxHttp = 0;

    if(argc != 2) {
        printf("usage: %s filename\n", argv[0]);
        return -1;
    }

    struct bpf_program ffp;
    
    /*fp = pcap_open_offline_with_tstamp_precision(argv[0], PCAP_TSTAMP_PRECISION_NANO, errbuf);*/
    fp = pcap_open_offline(argv[1], errbuf);
    if (fp == NULL) {
	    fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
	    return 0;
    }


    if(pcap_compile(fp,&ffp,"src port not 53 and dst port 53",0,0) == -1)
      { fprintf(stderr,"Error calling pcap_compile\n"); return 1; }

    /* set the compiled program as the filter */
    if(pcap_setfilter(fp,&ffp) == -1)
      { fprintf(stderr,"Error setting filter\n"); return 1; }
    
    
    if (pcap_loop(fp, 0, packetHandler, NULL) < 0) {
        fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
        return 0;
    }

    return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

  double ts = pkthdr->ts.tv_sec + pkthdr->ts.tv_usec/1000000.0;
  int caplen = pkthdr->caplen;
  const struct ether_header* ethernetHeader;
  const struct ip* ipHeader;
  const struct ip6_hdr* ipHeader6;
  const struct tcphdr* tcpHeader;
  const struct udphdr* udpHeader;
  char sourceIP[INET6_ADDRSTRLEN];
  char destIP[INET6_ADDRSTRLEN];
  u_int sport, dport;
  u_char *data;
  int dataLength = 0;
  int i;
  unsigned int ttl;
  unsigned int plen;
  int proto;
  unsigned char* payload = 0;
  std::string query = "";
  int isquery = 0;
  int size_payload = 0;
  
  ethernetHeader = (struct ether_header*)packet;
  if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP || ntohs(ethernetHeader->ether_type) == ETHERTYPE_IPV6) {

    int size_ip;
    int ip_len;
    
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP)
      {
	ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
	inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
	ttl = ipHeader->ip_ttl;
	plen = ntohs(ipHeader->ip_len);
	proto = ipHeader->ip_p;
	size_ip = ipHeader->ip_hl*4;
	ip_len = ntohs(ipHeader->ip_len);
	//std::cout<<"IP packet "<<caplen<<" ip len "<<ip_len<<" proto "<<proto<<" time "<<ts<<std::endl;
      }
    else
      {
	//std::cout<<"IP6 packet "<<std::endl;
	ipHeader6 = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
	inet_ntop(AF_INET6, &(ipHeader6->ip6_src), sourceIP, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(ipHeader6->ip6_dst), destIP, INET6_ADDRSTRLEN);
	ttl = ipHeader6->ip6_ctlun.ip6_un1.ip6_un1_hlim; 
	plen = ntohs(ipHeader6->ip6_ctlun.ip6_un1.ip6_un1_plen);
	proto = ipHeader6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	size_ip = sizeof(ip6_hdr);
	ip_len = plen + size_ip; // in ip6 plen is just payload, not IP header
      }
    int opcode;
    if (proto == IPPROTO_TCP)
      {
	tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + size_ip);
	int size_tcp = tcpHeader->th_off*4;
	size_payload = ip_len - (size_ip + size_tcp);
	//cout<<"Payload "<<size_payload<<endl;
	sport = ntohs(tcpHeader->source);
	dport = ntohs(tcpHeader->dest);
	if (size_payload > 8) // size of DNS header
	  {	    
	    payload = (u_char*)(packet + sizeof(struct ether_header) + size_ip + size_tcp);
	    opcode = payload[2]>>4;
	    if (opcode == 0)	      
	      isquery = 1;
	  }
      }
    else if (proto == IPPROTO_UDP)
      {
	udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + size_ip);
	int size_udp = 8;
	sport = ntohs(udpHeader->source);
	dport = ntohs(udpHeader->dest);
	size_payload = ip_len - (size_ip + size_udp);
	if (size_payload > 8) // size of DNS header
	  {
	    payload = (u_char*)(packet + sizeof(struct ether_header) + size_ip + size_udp);
	    opcode = payload[2]>>4;
	    //std::cout<<"UDP packet opcode "<<opcode<<" payload size "<<size_payload<<" ip len "<<size_ip<<" udp len "<<size_udp<<std::endl;
	    if (opcode == 0)
	      isquery = 1;
	  }	    
      }

    //std::cout<<std::fixed<<ts<<" proto "<<proto<<" caplen "<<caplen<<" plen "<<plen<<" payload size "<<size_payload<<" opcode "<<opcode<<" payload ";

    if (size_payload > 8 && opcode == 0)
      {
	//for (int i=0; i<size_payload; i++)
	//{
	// std::cout<<(int)payload[i]<<" ";
	//}
	//std::cout<<std::endl;
	for (int i=12; i<size_payload; i++)
	  {
	    int j = (int)payload[i];
	    if (j == 0)
	      break;
	    //std::cout<<" length of chunk "<<j<<" i is "<<i<<std::endl;
	    char chunk[256];
	    i++;
	    if (i+j > size_payload)
	      {
		//std::cout<<"This is malformed query "<<std::endl;
		isquery = 0;
		query = "";
		break;
	      }
	    strncpy(chunk, payload+i, j);
	    chunk[j] = 0;
	    //std::cout<<chunk<<std::endl;
	    if (query == "")
	      query = chunk;
	    else
	      {
		std::string tmp = chunk;
		query = query + "." + tmp;
	      }
	    //for (int k = 0; k < j; k++)
	    // std::cout<<(char)payload[i+k];
	    i += (j-1);
	    //std::cout<<std::endl;
	  }
      }
    //    std::cout<<std::fixed<<std::endl<<ts<<" source "<<sourceIP<<" dst "<<destIP<<" ttl "<<ttl<<" plen "<<plen<<" proto "<<proto<<" isquery "<<isquery<<" payload "<<query<<std::endl;
    if (query == "")
	isquery = 2;
    //std::cout<<"Query is "<<query<<" len "<<query.length()<<" is query "<<isquery<<std::endl;
    char retval[1500];
    char recordID[200];
    sprintf(recordID, "%lf-%s-%d-%s-%d", ts, sourceIP, sport, destIP, dport);
    sprintf(retval, "%s %lf %d %s %d %d %s", recordID, ts, size_payload, sourceIP, ttl, isquery, query.c_str());
    std::cout<<retval<<std::endl;
  }
  else
    std::cout<<""<<std::endl;
}
