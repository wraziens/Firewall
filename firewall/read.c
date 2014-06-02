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
#include "file_handle.h"
#include "state.h"

#define TCP_PROTO_ID 6
#define ICMP_PROTO_ID 1
#define UDP_PROTO_ID 17
#define MAX_LINE_LEN 256

//Processes a packet read from an interface
void process_packet_inject(struct interface* iface,const struct pcap_pkthdr *hdr, const u_char *data) {
    
    u_int offset = 0;
    
    //expunge_expired();
    
    // Get the ethernet header which is the start of the array.
    struct eth_header *h_ether = malloc(sizeof(struct eth_header));
    memcpy(h_ether,(struct eth_header *) data, sizeof(struct eth_header));
    
    //check to see if this is an ARP packet
    if (h_ether->type == htons(0x0806)) {
        //handle arp packets here
        //Only handle arp packets if it is a live file read
        //it doesn't make sense when replaying a file.
        if(live==1){
            offset += sizeof(struct eth_header);
            struct arp_header *arp_h = (struct arp_header *) (data + offset);
            //printf("ARP packet\n");
            /*
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
            */
            handle_arp_packet(arp_h, iface, hdr, data);
            //Free memory before returning
        }
        free(h_ether);
        return;
    }else if(h_ether-> type != 8){
        //If this is not an ARP packet or IPV4 return.
        //Free memory
        free(h_ether);
        return;
    }

    // IP header is next after the size of h_ether)
    offset += sizeof(struct eth_header);
    struct ip_header *h_ip = malloc(sizeof(struct ip_header)); 
    memcpy(h_ip, (struct ip_header *) (data + offset), sizeof(struct ip_header));
    offset += (h_ip->ver_ihl & 0x0f) * 4;

    printf("\n\nProtocol Type: %d\n\n", h_ip->proto);
    
    //handle ICMP packets
    if(h_ip->proto ==ICMP_PROTO_ID){
        struct icmp_header* h_icmp = malloc(sizeof(struct icmp_header));
        memcpy(h_icmp, (struct icmp_header *) (data + offset), sizeof(struct icmp_header));
       
        handle_icmp(h_ether, h_ip, h_icmp, iface, hdr, data);
        return;
        //handle TCP packets
    }else if(h_ip->proto == TCP_PROTO_ID){
        struct tcp_header* h_tcp = malloc(sizeof(struct tcp_header));
        memcpy(h_tcp, (struct tcp_header *)(data + offset), sizeof(struct tcp_header));
        //printf("\nsrc_port %d\n", ntohs(h_tcp->src_port)); 
        //printf("\ndst_port %d\n", ntohs(h_tcp->dst_port));
        handle_tcp(h_ether, h_ip, h_tcp, iface, hdr, data); 
        return;
    //handle UPD packets
    }else if(h_ip-> proto == UDP_PROTO_ID){
        struct udp_header* h_udp =  malloc(sizeof(struct udp_header));
        memcpy(h_udp,(struct udp_header *)(data+offset), sizeof(struct udp_header));
        //printf("\nsrc_port %d\n", ntohs(h_udp->src_port)); 
        //printf("\ndst_port %d\n", ntohs(h_udp->dst_port));
        handle_udp(h_ether, h_ip, h_udp, iface, hdr, data); 
        return;
    }else{
        //If not one of the above mentioned packets, we do nothing.
        return;
    }
}

int main(int argc, char **argv) {
    //intiialize globals
    //from arp.h
    i_dict = NULL;    
    waiting = NULL;
    arp_tbl = NULL;
    //from file_handle.h
    live = 1;
    //from state.h
    state_tbl = NULL;
    first_state = NULL;
    last_state = NULL;

    char err[PCAP_ERRBUF_SIZE];
    pcap_t *pch;

    //Make sure the arguments are correcet.
    if (argc < 2) {
        printf("To hookup to interfaces:  ./firewall interface_1  interface_2 [interface_3, ...] \n");
        printf("To play a pcap file: ./firewall file.pcap\n");
      
        return 0;
    }
    
    //Read in the rules and populate the 
    //rules list
    rule_list = malloc(sizeof(struct rule));
    parse_rules(&rule_list);
    print_rules(rule_list);
    
    //initialize the error buffer
    char pcap_errbuff[PCAP_ERRBUF_SIZE];
    pcap_errbuff[0]='\0';

    //initialize structures for packet data.
    const u_char* pkt_data=NULL;
    struct pcap_pkthdr hdr;

    //Pcap File
    if(argc ==2){
        live = 0;
        //check to make sure its the correct
        //type of file
        if(is_file(argv[1])!=1){
            printf("The file must be a pcap file.\n Cannot open a file of type %s.\n", get_extension(argv[1]));
            exit("EXIT_FAILURE");
        }
        //open the file to read from
        if((file_in = pcap_open_offline(argv[1], pcap_errbuff))==NULL){
            fprintf(stderr, "Pcap returned error: %s\n", pcap_errbuff);
            exit("EXIT_FAILURE");
        }
        
        //Open the file to write to
        if((dumpfile = pcap_dump_open(file_in, "firewall_dump.pcap"))==NULL){
            fprintf(stderr, "Error opening save file for writing.\n");
            exit("EXIT_FAILURE");
        };

        //Read in packets from the file.
        while((pkt_data = pcap_next(file_in , &hdr)) != NULL){
            process_packet_inject(NULL, &hdr, pkt_data);
        }

        //close the file
        pcap_dump_close(dumpfile);
        pcap_close(file_in);
        return 0;

    //Read from Live interfaces
    }else{
        struct interfaces_map* im = NULL;

        for (int x=1; x<argc; x++){
            struct interface *i =(struct interface*)malloc(sizeof(struct interface));
            i->pcap= pcap_open_live(argv[x],65535,0,20, pcap_errbuff);
            printf("Opening interface %s..\n", argv[x]);
            
            //get the subnet of the interface
            bpf_u_int32 netp, mask;
            pcap_lookupnet(argv[x], &netp, &mask,err);
            i->subnet=(u_int)mask;
            u_char r[4];
            memcpy(&r,&mask,4); 
            
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
       
       
        //indefinately read from the interfaces 
        while(1){
            HASH_ITER(hh, i_dict, current_iface, iface_tmp){
                pcap_t* t = current_iface->iface->pcap;
                printf("Reading from interface: %s\n", current_iface->iface->name);
                pkt_data = pcap_next(t , &hdr);
                if(pkt_data){
                    process_packet_inject(current_iface->iface, &hdr, pkt_data);
                }
            }
        }
        return 0;
    }
}

