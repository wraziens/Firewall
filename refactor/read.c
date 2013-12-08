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
#include "reject.h"

#define TCP_PROTO_ID 6
#define ICMP_PROTO_ID 1
#define UDP_PROTO_ID 17
#define MAX_LINE_LEN 256

pcap_dumper_t* fo = NULL;
pcap_t* fi, *fo2= NULL;

//void process_packet_dump(u_char *dumpfile, const struct pcap_pkthdr *hdr,const u_char *data) {
 //   pcap_dump(dumpfile, hdr, data);
//}

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

    // IP header is next after the size of h_ether)
    offset += sizeof(struct eth_header);
    struct ip_header *h_ip = (struct ip_header *) (data + offset);
    offset += (h_ip->ver_ihl & 0x0f) * 4;

    u_char* data8= malloc(sizeof(u_char)*8);
    printf("OFFSET: %d\n",(h_ip->ver_ihl & 0x0f) * 4);
    memcpy(data8, (u_char*)data+offset, 8); 
    printf("TOTAL LEN:%d\n",ntohs(h_ip->tlen));
    print_ip_address(h_ip);
    printf("POST TESTER:%d\n",ntohs(*(u_short*)(data+offset)));
    printf("POST TESTER2:%d\n",ntohs(*(u_short*)data8));


    printf("\n\nProtocol Type: %d\n\n", h_ip->proto);
    
    //handle ICMP packets
    if(h_ip->proto ==ICMP_PROTO_ID){
        struct icmp_header* h_icmp = (struct icmp_header *) (data + offset);
    //handle TCP packets
    }else if(h_ip->proto == TCP_PROTO_ID){
        struct tcp_header* h_tcp = (struct tcp_header *)(data + offset);
        printf("\nsrc_port %d\n", ntohs(h_tcp->src_port)); 
        printf("\ndst_port %d\n", ntohs(h_tcp->dst_port));
        struct interface* i = get_interface(h_ip->daddr);
        char* sadr = ip_string(h_ip->saddr);
        char* dadr = ip_string(h_ip->daddr);
        printf("SADDR2: %s\n",sadr); 

        rule_type_t rt = get_firewall_action(rule_list,iface->name,i->name, sadr, dadr, ntohs(h_tcp->src_port), ntohs(h_tcp->dst_port));
        //free memory no longer needed.
        free(i);
        free(sadr);
        free(dadr);
        printf("\n\nRule Type: %i\n", rt);

    //handle UPD packets
    }else if(h_ip-> proto == UDP_PROTO_ID){
        printf("UDP\n");
        struct udp_header* h_udp = (struct udp_header *)(data+offset);
        printf("\nsrc_port %d\n", ntohs(h_udp->src_port)); 
        printf("\ndst_port %d\n", ntohs(h_udp->dst_port));

        struct interface* i = get_interface(h_ip->daddr);
        char* sadr = ip_string(h_ip->saddr);
        char* dadr = ip_string(h_ip->daddr);
        printf("SADDR2: %s\n",sadr); 

        rule_type_t rt = get_firewall_action(rule_list,iface->name,i->name, sadr, dadr, ntohs(h_udp->src_port), ntohs(h_udp->dst_port));
        //free memory no longer needed.
        free(i);
        free(sadr);
        free(dadr);
        printf("\n\nRule Type: %i\n", rt);
        if(rt == REJECT){
            printf("Rejected. Sending ICMP message.\n");
            printf("ip chck: %i\n", h_ip->crc);
            //h_ip->crc= 0;
            u_short v= checksum(h_ip,ntohs(h_ip->tlen));
            printf("Calculated: %i\n", v);
            icmp_reject(iface, h_ip, h_ether, data8);
            return;
        }else if(rt == BLOCK){
            printf("Blocked. Dropping the packet.\n");
        }else if(rt==PASS){
            printf("Pass, the packet is allowed through\n"); 
        }
    }else{
        //If not one of the above mentioned packets, we do nothing.
        return;
    }

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
        print_ip_address(h_ip);
        dispatch_arp(iface, w, h_ip->saddr, h_ip->daddr);
    }
}

int main(int argc, char **argv) {
    //intiialize globals
    i_dict = NULL;    
    waiting = NULL;
    arp_tbl = NULL;

    char err[PCAP_ERRBUF_SIZE];
    pcap_t *pch;

    //Make sure the arguments are correcet.
    if (argc < 2) {
        printf("To hookup to interfaces:  ./firewall interface_1  interface_2 [interface_3, ...] \n");
        printf("To play a pcap file: ./firewall file.pcap\n");
      
        return 0;
    }

    char pcap_errbuff[PCAP_ERRBUF_SIZE];
    pcap_errbuff[0]='\0';
    struct interfaces_map* im = NULL;

    int file_in = 0;
    int file_out = 0;

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
   
    //Read in the rules and populate the 
    //rules list
    rule_list = malloc(sizeof(struct rule));
    parse_rules(&rule_list);
    print_rules(rule_list);
    
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

