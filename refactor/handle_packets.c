#include "handle_packets.h"

void pass_packet(struct interface* iface, struct ip_header* h_ip,u_char* data, struct pcap_pkthdr* hdr){
    if(live ==1){
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
                free(h_ip);
                return;
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
            dispatch_arp(iface, w, h_ip->saddr, h_ip->daddr);
        }
    //This is not a live interface, output to a file instead
    }else{
        process_packet_dump(hdr, data); 
    }
}

//Appropriately handles TCP packets seen
//By the Firewall
void handle_tcp(struct eth_header* h_ether, struct ip_header* h_ip, struct tcp_header* h_tcp, struct interface* iface, const struct pcap_pkthdr *hdr, u_char* data){

    expunge_expired();
    struct interface* i =NULL;
    rule_type_t rt;
    if(live ==1){
        i = get_interface(h_ip->daddr);
        //get the Rule that applies to this packet
        rt = process_with_state(iface->name, i->name, h_ip, h_tcp);
        
        //Free interface memory
        free(i);
    }else{
        rt = process_with_state(NULL, NULL, h_ip, h_tcp);
    }
    //rt = REJECT;
    printf("\n\nRule Type: %i\n", rt);
    if(rt == REJECT){
        printf("TCP: Rejecting the Packet.\n"); 
        tcp_reset(iface, h_ip, h_tcp, h_ether);
        //Free the packets
        free(h_ether);
        free(h_tcp);
        return;
    }else if(rt == BLOCK){
        printf("TCP: Blocking the packet.\n");
        //Free the packets
        free(h_ether);
        free(h_tcp);
        return;
    }else if(rt == PASS){
        printf("TCP: Forwarding the packet.\n");
        pass_packet(iface, h_ip, data, hdr);
        //free the packets
        //free(h_ip);
        free(h_ether);
        free(h_tcp);
        //h_ip is freed in pass_packet when it is done being used.
        return;
    }
}

//Appropriately handles UDP packets seen
//By the Firewall
void handle_udp(struct eth_header* h_ether, struct ip_header* h_ip, struct udp_header* h_udp, struct interface* iface, const struct pcap_pkthdr *hdr, u_char* data){
    
    struct interface* i =NULL;
    char* sadr = ip_string(h_ip->saddr);
    char* dadr = ip_string(h_ip->daddr);
    rule_type_t rt;
    if(live ==1){
        i = get_interface(h_ip->daddr);
        //get the Rule that applies to this packet
        rt = get_firewall_action(rule_list,iface->name,i->name, sadr, dadr, ntohs(h_udp->src_port), ntohs(h_udp->dst_port));
        //Free interface memory
        free(i);
    }else{
        rt = get_firewall_action(rule_list,NULL,NULL, sadr, dadr, ntohs(h_udp->src_port), ntohs(h_udp->dst_port));
    }
    
    //free memory no longer needed.
    free(sadr);
    free(dadr);
    printf("\n\nRule Type: %i\n", rt);
   
    if(rt == REJECT){
        printf("UDP: Rejecting the packet\n");
        //get the first 8 bytes of the payload from the udp header
        int offset = sizeof(struct eth_header) + (h_ip->ver_ihl & 0x0f) * 4;
        u_char* data8 = malloc(8);
        memcpy(data8, (u_char*)data+offset, 8); 
        icmp_reject(iface, h_ip, data8, h_ether);
        free(h_udp);
        free(h_ether);
        return;
    }else if(rt == BLOCK){
        printf("UDP: Blocking the packet.\n");
        free(h_udp);
        free(h_ether);
        return;
    }else if(rt==PASS){
        printf("UDP: Forwarding the packet.\n"); 
        pass_packet(iface, h_ip, data, hdr);
        //free the packets
        free(h_ether);
        free(h_udp);
        //h_ip is freed in pass_packet when it is done being used.
        return;
    }
}

//Appropriately handles ICMP packets seen
//By the Firewall
void handle_icmp(struct eth_header* h_ether, struct ip_header* h_ip, struct icmp_header* h_icmp, struct interface* iface, const struct pcap_pkthdr *hdr, u_char* data){
 
    struct interface* i =NULL;
    char* sadr = ip_string(h_ip->saddr);
    char* dadr = ip_string(h_ip->daddr);
    rule_type_t rt;
    if(live ==1){
        i = get_interface(h_ip->daddr);
        //get the Rule that applies to this packet
        rt = get_firewall_action(rule_list,iface->name,i->name, sadr, dadr, NULL, NULL);
        //Free interface memory
        free(i);
    }else{
        rt = get_firewall_action(rule_list,NULL,NULL, sadr, dadr, NULL, NULL);
    }
    
    //free memory no longer needed.
    free(sadr);
    free(dadr);
    printf("\n\nRule Type: %i\n", rt);
   
   if(rt == REJECT){
        printf("ICMP: Rejecting the packet\n");
        //get the first 8 bytes of the payload from the udp header
        int offset = sizeof(struct eth_header) + (h_ip->ver_ihl & 0x0f) * 4;
        u_char* data8 = malloc(8);
        memcpy(data8, (u_char*)data+offset, 8); 
        icmp_reject(iface, h_ip, data8, h_ether);
        free(h_ether);
        free(h_icmp);
        return;
    }else if(rt == BLOCK){
        printf("ICMP: Blocking the packet.\n");
        free(h_ether);
        free(h_icmp);
        return;
    }else if(rt==PASS){
        printf("ICMP: Forwarding the packet.\n"); 
        pass_packet(iface, h_ip, data, hdr);
        //free the packets
        free(h_icmp);
        free(h_ether);
        //h_ip is freed in pass_packet when it is done being used.
        return;
    }
}
