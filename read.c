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
#define MINUTE 60
#define ARP_REPLY 2
#define MAX_LINE_LEN 256

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
    u_char saddr[4]; //Source IP address
    u_char daddr[4]; //Destination IP adddress
};
// END Similar to
// https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut6.html

// START Similar to www.tcpdump.org/pcap.html
struct eth_header {
    u_char dest[6];
    u_char src[6];
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

//Data Structures
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

//Global hash map to store all interfaces
struct interfaces_map* i_dict = NULL;
//Global arp table to store arp entries
struct arp_table* arp_tbl = NULL;
//Global unresolved hash
struct unresolved* waiting = NULL;

pcap_dumper_t* fo = NULL;
pcap_t* fi, *fo2= NULL;

void dispatch_arp(struct interface *src_iface, struct wait_packet* wait, u_char *src_ip, u_char* dest_ip);

void process_packet_dump(u_char *dumpfile, const struct pcap_pkthdr *hdr,const u_char *data) {
    pcap_dump(dumpfile, hdr, data);
}
int ip_in_subnet(u_char* ip, u_char* subnet, u_char* base_addr) {
    for (int i = 0; i < 4; i++) {
        if ((ip[i] & subnet[i]) != (base_addr[i] & subnet[i])){
            printf("ip_test %i, sub %i, iface %i\n",ip[i], subnet[i], base_addr[i] );
            return 0;
        }
    }
    return 1;
}

void send_packet(struct arp_entry* a_ent, u_char *data, const struct pcap_pkthdr *hdr){
    u_int offset = 0;

    printf("Sending a packet onto the %s interface\n", a_ent->iface.name);
    // Get the ethernet header which is the start of the array.
    struct eth_header *h_ether = (struct eth_header *) data;
    
    if(h_ether-> type != 8){
        //If this is not an ARP packet or IPV4 return.
        return;
    }
    
    //change the destination MAC address
    //to the correct MAC address to forward
    //the packet appropriately.
    memcpy(&h_ether->dest, a_ent->dest_mac, sizeof(h_ether->dest));
    memcpy(data, h_ether, sizeof(struct eth_header)); 
    
    for (int j=0; j< 6; j++){
        printf("%.2X", (u_char)a_ent->dest_mac[j]);
    }
    printf("\ncopied version\n");
     for (int j=0; j< 6; j++){
        printf("%.2X", (u_char)h_ether->dest[j]);
    }
     printf("\n*******\n");


    while(pcap_inject(a_ent->iface.pcap, data, hdr->caplen)==1){
        fprintf(stdout,"Error, trying again..");
    }
    //process_packet_dump((u_char*)fo, hdr, data);
}
/* TO GET INTERFACE
struct interfaces_map *cur_imap, *tmp; 
        struct interface *channel;
        HASH_ITER(hh, i_dict, cur_imap, tmp){
            u_char i_ip[4];
            memcpy(&i_ip, cur_imap->ip_addr, 4);
            u_char d_ip[4];
            memcpy(&d_ip, ip, 4);
            u_char sub[4];
            memcpy(&sub, &cur_imap->iface->subnet,4);
            int send = ip_in_subnet(d_ip,sub,i_ip);
            if(send ==1){
                channel = cur_imap->iface;
                printf("Will send over interface %s\n", cur_imap->iface->name);
            }else{
                printf("Will NOT send over interface %s\n", cur_imap->iface->name);
            }
        }

*/
void add_to_arp_table(u_char* ip, u_char* dest_mac){
    printf("ADD to arp destination ip:\n");
    for (int j=0; j< 6; j++){
        printf("%.2X", (u_char)dest_mac[j]);
    }
     printf("\n");

    //Check to see if already in ARP table
    struct arp_table* at = NULL;
    HASH_FIND(hh, arp_tbl, ip, sizeof(u_char)*4,at);
    //Already in the arp table
    if(at){
        //update time if it exists
        at->arp_ent->time = time(NULL);
    }else{
        //get the interface to send over
        struct interfaces_map *cur_imap, *tmp; 
        struct interface *channel=NULL;
        HASH_ITER(hh, i_dict, cur_imap, tmp){
            u_char i_ip[4];
            memcpy(&i_ip, cur_imap->ip_addr, 4);
            u_char d_ip[4];
            memcpy(&d_ip, ip, 4);
            u_char sub[4];
            memcpy(&sub, &cur_imap->iface->subnet,4);
            int send = ip_in_subnet(d_ip,sub,i_ip);
            if(send ==1){
                channel = cur_imap->iface;
                printf("Will send over interface %s\n", cur_imap->iface->name);
            }else{
                printf("Will NOT send over interface %s\n", cur_imap->iface->name);
            }
        }
        if(channel!=NULL){
            printf("Adding ARP Entry\n");
            struct arp_entry* a_ent = malloc(sizeof(struct arp_entry));
            memcpy(&a_ent->dest_mac, dest_mac, sizeof(a_ent->dest_mac));
            a_ent->time = time(NULL);
            a_ent->iface=*channel;
            printf("After adding to arp_tbl:\n");
            for (int j=0; j< 6; j++){
                printf("%.2X", (u_char)a_ent->dest_mac[j]);
            }
            printf("\n*******\n");

            //Add the arp entry to the arp table
            struct arp_table* a = (struct arp_table*)malloc(sizeof(struct arp_table));
            memcpy(&a->dest_ip, ip, sizeof(a->dest_ip));
            a->arp_ent = a_ent;
            HASH_ADD(hh, arp_tbl, dest_ip,sizeof(u_char) * 4,a);

            //check to see if there are any waiting packages for this ip.
            struct unresolved* send = NULL;
            HASH_FIND(hh,waiting, ip, sizeof(u_char) * 4,send);
            if(send){
                for(int j=0; j < (sizeof(send->packet)/sizeof(u_char*)); j++){
                    send_packet(a_ent, send->packet[j].data, send->packet[j].hdr);
                    HASH_DEL(waiting, send);
                    free(send);
                }
            }
        }
    }
}

void process(struct ip_header* h_ip){
    fprintf(stdout, "IP Address: %i.%i.%i.%i\n", 
            h_ip->saddr[0],
            h_ip->saddr[1],
            h_ip->saddr[2],
            h_ip->saddr[3]);
    fprintf(stdout, "Destination IP Address: %i.%i.%i.%i\n", 
            h_ip->daddr[0],
            h_ip->daddr[1],
            h_ip->daddr[2],
            h_ip->daddr[3]);
}


//Figure out whether the ARP packet needs to be forwarded onwards
void forward_arp(struct interface* iface, struct arp_header *h_arp, const struct pcap_pkthdr* hdr, u_char* data) {
    printf("Forwarding an ARP packet from %s\n", iface->name);
    printf("IFace IP: %i.%i.%i.%i\n",iface->ip_addr[0], iface->ip_addr[1], iface->ip_addr[2],iface->ip_addr[3]);
    //check to see if this is an ARP REPLY
    if(h_arp->oper == ARP_REPLY){
        struct arp_table* atble= NULL;
        HASH_FIND(hh, arp_tbl, h_arp->dest_ip, sizeof(u_char) * 4, atble);
        //if there is a matching arp_entry in
        //out arp_table
        int found = 0;
        if (atble){
            time_t current = time(NULL);
            //check to see if ARP_entry is out of date
            //Entry is expired
            if(current - atble->arp_ent->time > MINUTE){
                //Remove the arp_entry
                HASH_DEL(arp_tbl, atble);
                free(atble);
            //Arp entry is valid; can send packet
            }else{
                found = 1;
                //update time in ARP Table
                atble->arp_ent->time = current;
                //send the packet.
                send_packet(atble->arp_ent, data, hdr);
            }
        } 
        //we did not find a valid arp entry
        if (found == 0) {
            printf("No valid ARP ip\n");
            //construct the wait_packet
            struct wait_packet* w = (struct wait_packet*)malloc(sizeof(struct wait_packet));
            w->data = data;
            w->len = (u_int)hdr->caplen;
            w->hdr = hdr;
            w->next = NULL;

            //check to see if the IP already exists in the waiting hash
            //before adding
            struct unresolved* unre;
            HASH_FIND(hh, waiting, h_arp->dest_ip, sizeof(u_char) * 4, unre);

            //The IP exists append wait element to list
            if (unre){
                unre->num_packets = unre->num_packets + 1;
                unre->packet->next = w;
                unre->last_packet = w;
            }else{
                //add the wait_packet to the waiting hash
                struct unresolved* u = (struct unresolved*)malloc(sizeof(struct unresolved));
                memcpy(&u->ip,&h_arp->dest_ip, sizeof(u_char)*4);
                u->packet = w;
                u->num_packets = 0;
                u->last_packet = w;
                HASH_ADD(hh, waiting, ip,sizeof(u_char) * 4,u);
            }
            
            //send the ARP packet
            dispatch_arp(iface, w, h_arp->src_ip, h_arp->dest_ip);
        }
    //Is an ARP request: Broadcast Message, figure out which interface to send on
    }else{
        printf("ARP Request");
        //check to see if src and dest ip are on same subnet, if so don't do anything.
        u_char i_ip[4];
        memcpy(&i_ip, h_arp->src_ip, 4);
        u_char d_ip[4];
        memcpy(&d_ip, h_arp->dest_ip, 4);
        u_char sub[4];
        memcpy(&sub, &iface->subnet,4);
        int send = ip_in_subnet(d_ip,sub,i_ip);

        
        if(send ==1){
            return;
        //Check all other interfaces listening on
        }else{
            struct interfaces_map *cur_imap, *tmp; 
            HASH_ITER(hh, i_dict, cur_imap, tmp){
                memcpy(&i_ip, cur_imap->ip_addr, 4);
                memcpy(&d_ip, h_arp->dest_ip, 4);
                memcpy(&sub, &cur_imap->iface->subnet,4);
                int send = ip_in_subnet(d_ip,sub,i_ip);
                if(send ==1){
                    printf("sending the packet on %s\n", cur_imap->iface->name);
                    //Send the ARP Packet
                    if(pcap_inject(cur_imap->iface->pcap, data, hdr->caplen)==-1){
                        pcap_perror(iface->pcap, 0);//send the packet over the wire.
                    }
                    printf("Sent the packet\n");
                }
            }
        }
    }
}

void handle_arp_packet(struct arp_header * arp_h,struct interface* iface,const struct pcap_pkthdr* hdr, u_char* data){
    //always add the sender's IP and MAC addres to the ARP table

    add_to_arp_table(arp_h->src_ip, arp_h->src_mac);
    //Check to see if this is an ARP Reply, If so then add values 
    //to ARP table
    if(arp_h->oper == ARP_REPLY){   
        add_to_arp_table(arp_h->dest_ip, arp_h->dest_mac);
    }
    forward_arp(iface,arp_h, hdr, data);
}

void construct_arp(struct interface *iface, u_char *dest_ip) {
  
    struct ip_address* ip_test = (struct ip_address*)dest_ip;
    printf("Constructing an ARP packet for a packet from %s to ip %i.%i.%i.%i\n", iface->name,ip_test->byte1, ip_test->byte2, ip_test->byte3, ip_test->byte4); 
    //construct the ethernet header
    struct eth_header h_ether;
    memset(&h_ether.dest, 0xFF, 6);
    
    //obtain the source mac address
    int s;
    struct ifreq buffer, buffer2;
    s = socket(PF_INET, SOCK_DGRAM, 0);
    strcpy(buffer.ifr_name, iface->name);
    ioctl(s, SIOCGIFHWADDR, &buffer);

    for (int j=0; j< 6; j++){
        printf("%.2X", (u_char)buffer.ifr_hwaddr.sa_data[j]);
    }
    printf("\n");
    memcpy(h_ether.src, buffer.ifr_hwaddr.sa_data, sizeof(buffer.ifr_hwaddr.sa_data));
    h_ether.type=htons(0x0806);
    for (int j=0; j< 6; j++){
        printf("%.2X", (u_char)h_ether.src[j]);
    }
    printf("\n");

    //construct the arp header
    struct arp_header arp_hdr;
    arp_hdr.htype = htons(ARPHRD_ETHER);
    arp_hdr.ptype = htons(ETH_P_IP);
    arp_hdr.hlen = ETHER_ADDR_LEN;
    arp_hdr.plen = sizeof(in_addr_t);
    arp_hdr.oper = htons(ARPOP_REQUEST);
    memset(&arp_hdr.dest_mac, 0, 6);
    
    memcpy(arp_hdr.dest_ip, dest_ip,4);
    close(s);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(buffer2.ifr_name, iface->name);

    if(ioctl(s, SIOCGIFADDR, &buffer2)<0){
        printf("Failing.");
        return;
        //exit(2);
    }

    //Copy the source ip into the ARP header
    struct sockaddr_in* src_ip_addr = (struct sockaddr_in *)&buffer2.ifr_addr;
    memcpy(&arp_hdr.src_ip, &src_ip_addr->sin_addr.s_addr, sizeof(arp_hdr.src_ip));
    
    //copy the source mac address into the ARP header
    memcpy(&arp_hdr.src_mac,buffer.ifr_hwaddr.sa_data, sizeof(arp_hdr.src_mac));

    //combine the ARP and Ethernet headers
    u_char *packet = malloc(sizeof(struct eth_header)+sizeof(struct arp_header));
    memcpy(packet, &h_ether, sizeof(struct eth_header));
    memcpy(packet+sizeof(struct eth_header), &arp_hdr, sizeof(struct arp_header));
    close(s);

    //send the packet over the wire.
    if(pcap_inject(iface->pcap, packet, sizeof(struct eth_header)+sizeof(struct arp_header))==-1){
        pcap_perror(iface->pcap, 0);
    }
}


//Figure out which interface(s) to send the arp 
//packet out on.
void dispatch_arp(struct interface *src_iface, struct wait_packet* wait, u_char *src_ip, u_char* dest_ip) {
    int sent=0;
   //check to see if src and dest ip are on same subnet, if so don't do anything.
    if(((u_int)src_ip & src_iface->subnet) == ((u_int)dest_ip & src_iface->subnet)){
        return;
    //Figure out which interfaces to broadcast onto.
    }else{
        struct interfaces_map *cur_imap, *tmp; 
        HASH_ITER(hh, i_dict, cur_imap, tmp){
            if((cur_imap->iface->subnet & (u_int)cur_imap->ip_addr) == (cur_imap->iface->subnet & (u_int)dest_ip)){
                //Send the ARP Packet
                construct_arp(cur_imap->iface, dest_ip);
                sent=1;       
            }
        }
        if (sent == 1){
            //Add the packet to the wait list until we get a response from ARP
                       //check to see if the IP already exists in the waiting hash
            struct unresolved* unre;
            HASH_FIND(hh, waiting, dest_ip, sizeof(u_char) * 4, unre);

            //The IP exists append to list
            if (unre){
                unre->num_packets = unre->num_packets + 1;
                unre->packet->next = wait;
                unre->last_packet = wait;
            }else{
                //add the wait_packet to the waiting hash
                struct unresolved* u = (struct unresolved*)malloc(sizeof(struct unresolved));
                memcpy(&u->ip,dest_ip, sizeof(u_char)*4);
                u->packet = wait;
                u->num_packets = 0;
                u->last_packet = wait;
                HASH_ADD(hh, waiting, ip,sizeof(u_char) * 4,u);
            }
        }
    }
}


//Processes a packet read from an interface
void process_packet_inject(struct interface* iface,const struct pcap_pkthdr *hdr, const u_char *data) {
    u_int offset = 0;

    // Get the ethernet header which is the start of the array.
    struct eth_header *h_ether = (struct eth_header *) data;
    
    //check to see if this is an ARP packet
    if (h_ether->type == htons(0x0806)) {
        //handle arp packets here
        offset += sizeof(struct eth_header);
        struct arp_header *arp_h = (struct arp_header *) (data + offset);
        printf("ARP packet\n");
        
        fprintf(stdout, "ARP SRC IP Address: %i.%i.%i.%i\n", 
            arp_h->src_ip[0],
            arp_h->src_ip[1],
            arp_h->src_ip[2],
            arp_h->src_ip[3]);
        fprintf(stdout, "ARP DEST IP Address: %i.%i.%i.%i\n", 
            arp_h->dest_ip[0],
            arp_h->dest_ip[1],
            arp_h->dest_ip[2],
            arp_h->dest_ip[3]);
        handle_arp_packet(arp_h, iface,hdr, data);
        return;
    }else if(h_ether-> type != 8){
        //If this is not an ARP packet or IPV4 return.
        return;
    }

    // IP header is next (after the size of h_ether)
    offset += sizeof(struct eth_header);
    struct ip_header *h_ip = (struct ip_header *) (data + offset);
    process(h_ip);
    //check to see if dest mac is in ARP table 
    struct arp_table* atble= NULL;
    HASH_FIND(hh, arp_tbl, h_ip->daddr, sizeof(u_char) * 4, atble);
    //if there is a matching arp_entry in
    //out arp_table
    int found = 0;
    if (atble){
        time_t current = time(NULL);
        //check to see if ARP_entry is out of date
        //Entry is expired
        if(current - atble->arp_ent->time > MINUTE){
            //Remove the arp_entry
            HASH_DEL(arp_tbl, atble);
            free(atble);
        //Arp entry is valid; can send packet
        }else{
            printf("Has current ARP entry\n");
            found = 1;
            //update time in ARP Table
            atble->arp_ent->time = current;
            //send the packet.
            send_packet(atble->arp_ent, data, hdr);
        }
    } 
    //we did not find a valid arp entry
    if (found == 0) {
        printf("sending an ARP request to get MAC address\n");
        //construct the wait_packet
        struct wait_packet* w = (struct wait_packet*)malloc(sizeof(struct wait_packet));
        w->data = data;
        w->len = hdr->caplen;
        w->hdr = hdr;
        w->next = NULL;
        //send the ARP packet
        printf("CHECK PPI\n");
        process(h_ip);
        dispatch_arp(iface, w, h_ip->saddr, h_ip->daddr);
    }
}

enum rule_action { BLOCK = 0, PASS = 1, REJECT = 2 };

struct rule {
    u_char *src_iface;
    u_char *dst_iface;
    struct in_addr src_ip;
    struct in_addr dst_ip;

    struct rule *next;
};

struct rule *make_rule(u_char *src_iface, u_char *dst_iface, struct in_addr src_ip, struct in_addr dst_ip) {
    struct rule *r = malloc(sizeof(struct rule));
    r->src_iface = src_iface;
    r->dst_iface = dst_iface;
    r->src_ip = src_ip;
    r->dst_ip = dst_ip;

    return r;
}


//Reads the rules for the firewall from a file 
//named rules.conf
void construct_rules(){
    FILE *fh = fopen("rules.conf", "rt");
    char line[MAX_LINE_LEN];

    while (fgets(line, MAX_LINE_LEN, fh) != NULL) {
        if (strlen(line) > 1 && line[0] != '#') {
            struct rule *r = malloc(sizeof(struct rule));
            char *src_iface = strtok(line, " ");
            char *dst_iface = strtok(NULL, " ");
            char *src_ip = strtok(NULL, " ");
            char *dst_ip = strtok(NULL, " ");
            char *action = strtok(NULL, " ");
            
            r->src_iface = src_iface;
            r->dst_iface = dst_iface;
            
            if (inet_aton(src_ip, &r->src_ip) == 0) {
                printf("Invalid source IP address %s\n", src_ip);
                exit(-1);
            }

            if (inet_aton(dst_ip, &r->dst_ip) == 0) {
                printf("Invalid destination IP address %s\n", dst_ip);
                exit(-2);
            }
        }
    }
}

int main(int argc, char **argv) {
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *pch;

    //Make sure the arguments are correcet.
    if (argc < 3) {
        printf("usage:  ./firewall interface  interface\n");
        return 0;
    }

    char pcap_errbuff[PCAP_ERRBUF_SIZE];
    pcap_errbuff[0]='\0';
    struct interfaces_map* im = NULL;

    int file_in = 0;
    int file_out = 0;

    //open pcap file for writing
    for (int x=1; x<argc; x++){
        printf("%s\n", argv[x]);  
        printf("%i\n", strcmp(argv[x], "-fileout"));
        struct interface *i =(struct interface*)malloc(sizeof(struct interface));
        i->pcap= pcap_open_live(argv[x],65535,0,0, pcap_errbuff);
        printf("Opening interface %s..\n", argv[x]);
        
        //get the subnet of the interface
        bpf_u_int32 netp, mask;
        pcap_lookupnet(argv[x], &netp, &mask,err);
        i->subnet=(u_int)mask;
        u_char r[4];
        memcpy(&r,&mask,4); 
        printf("orig subnet: %i.%i.%i.%i\n", r[0],r[1],r[2],r[3]);
        
        //get the IP of the interface
        struct ifreq buffer;
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        strcpy(buffer.ifr_name, argv[x]);
        memcpy(&i->name, &argv[x], sizeof(argv[x]));

        if(ioctl(s, SIOCGIFADDR, &buffer)<0){
            printf("Could not populate buffer.");
            exit(1);
        }
        struct sockaddr_in* src_ip_addr = (struct sockaddr_in *)&buffer.ifr_addr;
        memcpy(&i->ip_addr, &src_ip_addr->sin_addr.s_addr, sizeof(i->ip_addr));
     
        //Add the interface to the interface Hash table
        im = (struct interfaces_map*)malloc(sizeof(struct interfaces_map));
        
        memcpy(&im->ip_addr, &i->ip_addr, sizeof(im->ip_addr));
        printf("%d\n", im->ip_addr);
        im->iface=i;
        printf("%d\n", i->ip_addr);
        HASH_ADD(hh, i_dict, ip_addr,sizeof(u_char) * 4,im);
    }
    struct interfaces_map *current_iface, *iface_tmp;
    const u_char* pkt_data=NULL;
    struct pcap_pkthdr hdr;
    
    //play up to 256 packets from the file on the interfaces
    //listed
    //if(fi != NULL){
     //   int i = 0;
     //   while(i<256){
     //       pkt_data = pcap_next(fi, &hdr);
     //       if(pkt_data){
     //           process_packet_inject(NULL, &hdr, pkt_data);
     //       }
     //   }
   // }
    
    //indefinately read from the interfaces 
    while(1){
        HASH_ITER(hh, i_dict, current_iface, iface_tmp){
            pcap_t* t = current_iface->iface->pcap;
            printf("Reading from interface: %s\n", current_iface->iface->name);
            pkt_data = pcap_next(t , &hdr);
            if(pkt_data){
                process_packet_inject(current_iface->iface, &hdr, pkt_data);
            }
            printf("\n\n=====================================\n");
            //print ARP table
            printf("ARP TABLE:\n");
            struct arp_table *tbl, *tmp;
            HASH_ITER(hh,arp_tbl,tbl, tmp){
            printf("ARP IP: %i.%i.%i.%i\n",tbl->dest_ip[0], tbl->dest_ip[1], tbl->dest_ip[2],tbl->dest_ip[3]);
            for(int j=0; j<6; j++){
                printf("%.2X", (u_char)tbl->arp_ent->dest_mac[j]);
            }
        }
        
    }
}
    printf("\n\n=====================================\n");
    //print ARP table
    struct arp_table *tbl, *tmp;
    HASH_ITER(hh,arp_tbl,tbl, tmp){
        printf("ARP IP: %i.%i.%i.%i\n",tbl->dest_ip[0], tbl->dest_ip[1], tbl->dest_ip[2],tbl->dest_ip[3]);
        for(int j=0; j<6; j++){
            printf("%.2X", (u_char)tbl->arp_ent->dest_mac[j]);
        }
        printf("\n");
    }

    return 0;
}

