#ifndef H_PACKETS_H_FILE
#define H_PACKETS_H_FILE

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include "uthash.h"
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include "packets.h"
#include "arp.h"
#include "rules.h"

#define MINUTE 60
#define ARP_REPLY 2


void pass_packet(struct interface* iface, struct ip_header* h_ip,u_char* data, struct pcap_pkthdr* hdr);

void handle_tcp(struct eth_header* h_ether, struct ip_header* h_ip, struct tcp_header* h_tcp, struct interface* iface, const struct pcap_pkthdr *hdr, u_char* data);

void handle_udp(struct eth_header* h_ether, struct ip_header* h_ip, struct udp_header* h_udp, struct interface* iface, const struct pcap_pkthdr *hdr, u_char* data);

void handle_icmp(struct eth_header* h_ether, struct ip_header* h_ip, struct icmp_header* h_icmp, struct interface* iface, const struct pcap_pkthdr *hdr, u_char* data);

#endif
