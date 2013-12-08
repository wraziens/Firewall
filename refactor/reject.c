#include "reject.h"
#include "packets.h"

//Similar to http://tools.ietf.org/html/rfc1071
/*
 * Computer Checksum for count bytes beggining at location ip_hdr
 */
u_short checksum(void* ip_hdr, int count){
    long sum = 0;
    void* p = ip_hdr;
    while(count > 0){
        //sum+= *((u_short*) ip_hdr)++;
        sum+=*(u_short*)p;
        p+=2;
        count -= 2;
    }

    //Add left over byte, if any
    if(count>0){
        sum+= *((u_char*) ip_hdr);
    }

    //Fold 32-bit sums into 16 bits
    while(sum>>16){
        sum = (sum & 0xffff) + (sum >>16);
    }

    return (~sum);
}
//end Similar to http://tools.ietf.org/html/rfc1071

//Construct and Send an ICMP Port Unreachable packet
void icmp_reject(struct interface *iface, struct ip_header* ip_hdr, u_char *data8, struct eth_header *eth_hdr){

    //construct the ethernet header
    struct eth_header h_ether;
    memcpy(h_ether.dest,eth_hdr->src, 6);
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
    h_ether.type=htons(0x08000);
    for (int j=0; j< 6; j++){
        printf("%.2X", (u_char)h_ether.src[j]);
    }
    printf("\n");
 
    //construct the ICMP header
    struct icmp_header icmp_hdr;
    icmp_hdr.type = 3;
    icmp_hdr.code = 3;
    icmp_hdr.checksum = 0;
    icmp_hdr.unused = 0;
    icmp_hdr.mtu = 0;

    int ip_len = (ip_hdr->ver_ihl & 0x0f) * 4;

    printf("IPLEN: %i\n", ip_len);
    u_char* total_pack = malloc(sizeof(struct icmp_header) + ip_len + 8);

    memcpy(total_pack, &icmp_hdr, sizeof(struct icmp_header));
    memcpy(total_pack+sizeof(struct icmp_header), ip_hdr, ip_len);
    
    memcpy(total_pack+sizeof(struct icmp_header)+ip_len, data8, 8);
    
    icmp_hdr.checksum = checksum((void*)total_pack, sizeof(struct icmp_header)+ip_len+8);
    memcpy(total_pack, &icmp_hdr, sizeof(struct icmp_header));


    //construct the IP header
    struct ip_header h_ip;
    h_ip.ver_ihl=(4<<4) + 5;
    printf("LENGTH: %d\n", (h_ip.ver_ihl & 0x0f) *4); 
    h_ip.tos = 0;
    h_ip.flags_fo = 0;
    h_ip.tlen = htons(sizeof(struct icmp_header) + ip_len + 8 + 20);
    printf("IP TLEN: %i", sizeof(struct icmp_header) + ip_len + 8 + 20);
    h_ip.identification = 0;
    h_ip.ttl = 32;
    h_ip.proto = ICMP_PROTO_ID;
    h_ip.crc = 0;
    memcpy(h_ip.saddr, ip_hdr->daddr, 4);
    memcpy(h_ip.daddr, ip_hdr->saddr,4);

    h_ip.crc = checksum((void*)&h_ip,20);


    //combine the ICMP, IP, and Ethernet headers
    u_char *packet = malloc(sizeof(struct eth_header)+sizeof(struct icmp_header) + sizeof(struct ip_header) + ip_len +8); 
    
    memcpy(packet, eth_hdr, sizeof(struct eth_header));

    memcpy(packet+sizeof(struct eth_header), &h_ip, sizeof(struct ip_header));
    memcpy(packet+sizeof(struct eth_header) +sizeof(struct ip_header), total_pack, sizeof(struct icmp_header) + ip_len+8);
    //close(s);

    //send the packet over the wire
    if(pcap_inject(iface->pcap, packet, sizeof(struct eth_header)+sizeof(struct ip_header)+ip_len + 8 + sizeof(struct icmp_header))==-1){
        pcap_perror(iface->pcap, 0);
    }
    //Free memory
    free(total_pack);
    free(packet);
}

//Construct and Send a TCP RESET packet
void tcp_reset(struct interface *iface, struct ip_header* ip_hdr, struct tcp_header* tcp_hdr, struct eth_header *eth_hdr){

    //construct the ethernet header
    struct eth_header h_ether;
    memcpy(h_ether.dest,eth_hdr->src, 6);
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
    h_ether.type=htons(0x08000);
    for (int j=0; j< 6; j++){
        printf("%.2X", (u_char)h_ether.src[j]);
    }
    printf("\n");
 
    //Construct the TCP header
    struct tcp_header tcp_h;
    printf("Porty port: %i\n", ntohs(tcp_hdr->dst_port));
    tcp_h.src_port=tcp_hdr->dst_port;
    tcp_h.dst_port=tcp_hdr->src_port;
    tcp_h.window_size=tcp_hdr->window_size;
    tcp_h.flags = 4;
    tcp_h.ack = 0;
    tcp_h.seq=tcp_hdr->seq;
    tcp_h.offset_res = (5<<4); 
    
    tcp_h.checksum = checksum((void*)&tcp_h,20);
    
    //construct the IP header
    struct ip_header h_ip;
    h_ip.proto=TCP_PROTO_ID;
    h_ip.ver_ihl=(4<<4) + 5;
    printf("LENGTH: %d\n", (h_ip.ver_ihl & 0x0f) *4); 
    h_ip.tos = 0;
    h_ip.flags_fo = 0;
    h_ip.tlen = htons(sizeof(struct tcp_header) + 20);
    h_ip.identification = 0;
    h_ip.ttl = 32;
    h_ip.crc = 0;
    memcpy(h_ip.saddr, ip_hdr->daddr, 4);
    memcpy(h_ip.daddr, ip_hdr->saddr,4);

    h_ip.crc = checksum((void*)&h_ip,20);

    //combine the TCP, IP, and Ethernet headers
    u_char *packet = malloc(sizeof(struct eth_header)+sizeof(struct tcp_header) + sizeof(struct ip_header)); 
    
    memcpy(packet, eth_hdr, sizeof(struct eth_header));

    memcpy(packet+sizeof(struct eth_header), &h_ip, sizeof(struct ip_header));
    memcpy(packet+sizeof(struct eth_header) +sizeof(struct ip_header), &tcp_h, sizeof(struct tcp_header));

    printf("sending the packet over the wire..%s\n", iface->name);
    
    //send the packet over the wire
    if(pcap_inject(iface->pcap, packet, sizeof(struct eth_header)+sizeof(struct ip_header)+sizeof(struct tcp_header))==-1){
        pcap_perror(iface->pcap, 0);
    }

    //Free memory
    free(packet);
}

