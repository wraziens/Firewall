#ifndef PACKETS_H_FILE
#define PACKETS_H_FILE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
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

#define TCP_PROTO_ID 6
#define ICMP_PROTO_ID 1
#define UDP_PROTO_ID 17

// START Similar to
// https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut6.html
struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

struct ip_header {
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    u_char saddr[4];        //Source IP address
    u_char daddr[4];        //Destination IP adddress
};
// END Similar to
// https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut6.html

// START Similar to www.tcpdump.org/pcap.html
struct eth_header {
    u_char dest[6]; //destination mac address
    u_char src[6];  //source mac address
    u_short type;
};

struct tcp_header {
    u_short src_port;
    u_short dst_port;

    u_int seq;
    u_int ack;
    
    u_char offset_res;
    u_char flags;

    u_short window_size;
    u_short checksum;
    u_short urgent;
};
// END Similar to www.tcpdump.org/pcap.html

struct udp_header {
    u_short src_port;
    u_short dst_port;

    u_short length;
    u_short checksum;
};

struct icmp_header {
    u_char type;
    u_char code;
    u_short checksum;
   
    u_int rest;
};

struct arp_header {
    u_short htype;
    u_short ptype;
    
    u_char hlen;
    u_char plen;

    u_short oper;

    u_char src_mac[6];
    u_char src_ip[4];

    u_char dest_mac[6];
    u_char dest_ip[4];
};

//Interfaces
struct interface {
    pcap_t* pcap;
    u_int subnet;
    char* name;
    u_char ip_addr[4];
};

//hash table for all interfaces
struct interfaces_map {
    u_char ip_addr[4];//Key
    struct interface* iface; //Value
    UT_hash_handle hh;
};


//formerly process
void print_ip_address(struct ip_header* h_ip);

int ip_in_subnet(u_char* ip, u_char* subnet, u_char* base_addr);

/*GLOBAL VARIABLE DECLARATIONS*/

//Global hash map to store all interfaces
struct interfaces_map* i_dict = NULL;

/*END GLOBAL VARIABLE DECLARATIONS*/


#endif
