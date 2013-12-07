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

//construct the ARP packet
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

void handle_arp_packet(struct arp_header * arp_h,struct interface* iface,const struct pcap_pkthdr* hdr, u_char* data){
    //always add the sender's IP and MAC addres to the ARP table
    add_to_arp_table(arp_h->src_ip, arp_h->src_mac);
    
    //Check to see if this is an ARP Reply, If so then add values 
    //to ARP table
    if(arp_h->oper == ARP_REPLY){   
        add_to_arp_table(arp_h->dest_ip, arp_h->dest_mac);
    }

    //forward the arp packet onto its intended destination
    forward_arp(iface,arp_h, hdr, data);
}

void send_packet(struct arp_entry* a_ent, u_char *data, const struct pcap_pkthdr *hdr){
    u_int offset = 0;

    fprintf("Sending a packet onto the %s interface\n", a_ent->iface.name);
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
        printf(stdout,"Error, trying again..");
    }
    //process_packet_dump((u_char*)fo, hdr, data);
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


