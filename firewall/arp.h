#ifndef ARP_H_FILE
#define ARP_H_FILE

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

#define MINUTE 60
#define ARP_REPLY 2

//ARP Table
struct arp_table {
    u_char dest_ip[4]; //Key
    struct arp_entry *arp_ent;//Value
    UT_hash_handle hh;
};

//An entry in the Arp Table
struct arp_entry {
    u_char dest_mac[6];
    time_t time;
    struct interface iface;
};

struct wait_packet {
    u_char * data;
    u_int len;
    struct pcap_pkthdr* hdr;
    struct wait_packet* next;
};

//Unresolved Hash
//This is where we will store packets that are waitng
//for ARP responses.
struct unresolved{
    u_char ip[4]; //Hash Key
    struct wait_packet* packet; //Hash Value, packet waiting to be sent
    int num_packets;
    struct wait_packet* last_packet;
    UT_hash_handle hh;
};


void dispatch_arp(struct interface *src_iface, struct wait_packet* wait, u_char *src_ip, u_char* dest_ip);

void add_to_arp_table(u_char* ip, u_char* dest_mac);

void forward_arp(struct interface* iface, struct arp_header *h_arp, const struct pcap_pkthdr* hdr, u_char* data);

void handle_arp_packet(struct arp_header * arp_h,struct interface* iface,const struct pcap_pkthdr* hdr, u_char* data);


void construct_arp(struct interface *iface, u_char *dest_ip);

void send_packet(struct arp_entry* a_ent, u_char *data, const struct pcap_pkthdr *hdr);

struct interface* get_interface(u_char* ip);
/*GLOABAL VARIABLE DECLARATIONS*/

//Global unresolved hash
struct unresolved* waiting;
//Global arp table to store arp entries
struct arp_table* arp_tbl;

struct rule *rule_list;
/* END GLOBAL DECLARATIONS */


#endif
