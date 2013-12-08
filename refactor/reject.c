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
void icmp_reject(struct interface *iface, struct ip_header* ip_hdr, struct eth_header* eth_hdr, u_char* data8){

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
    icmp_hdr.type = htons(3);
    icmp_hdr.code = htons(3);
    icmp_hdr.checksum = htons(0);
    icmp_hdr.unused = 0;
    icmp_hdr.mtu = 0;

    int ip_len = (ip_hdr->ver_ihl & 0x0f) * 4;

    u_char* total_pack = malloc(sizeof(struct icmp_header) + ip_len + 8);

    memcpy(total_pack, &icmp_hdr, sizeof(struct icmp_header));
    memcpy(total_pack+sizeof(struct icmp_header), ip_hdr, ip_len);
    
    printf("POST TESTER22:%d\n",ntohs(*(u_short*)data8));
    memcpy(total_pack+sizeof(struct icmp_header)+ip_len, (void*)data8, 8);

    u_short crc = checksum((void*)&icmp_hdr, sizeof(struct icmp_header) + ip_len + 8);
    icmp_hdr.checksum = crc;

    //construct the IP header
    struct ip_header h_ip;
    h_ip.proto=htons(ICMP_PROTO_ID);
    h_ip.ver_ihl=4<<4 & 5;
    h_ip.tos = 0;
    h_ip.tlen = sizeof(struct icmp_header) + ip_len+8 + 20;
    h_ip.identification = 0;
    h_ip.flags_fo = 0;
    h_ip.ttl = 32;
    h_ip.proto = ICMP_PROTO_ID;
    h_ip.crc = 0;
    memcpy(&h_ip.saddr, ip_hdr->daddr, 4);
    memcpy(&h_ip.daddr, ip_hdr->saddr,4);

    h_ip.crc = checksum((void*)&h_ip,20);

    //combine the ICMP, IP, and Ethernet headers
    u_char *packet = malloc(sizeof(struct eth_header)+sizeof(struct icmp_header) + sizeof(struct ip_header) + ip_len +8); 
    memcpy(packet, eth_hdr, sizeof(struct eth_header));

    memcpy(packet+sizeof(struct eth_header), &total_pack, sizeof(struct ip_header) + ip_len +8);
    memcpy(packet+sizeof(struct ip_header)+ip_len +8 , &icmp_hdr, sizeof(struct icmp_header));
    //close(s);

    //send the packet over the wire.
    if(pcap_inject(iface->pcap, packet, sizeof(struct eth_header)+sizeof(struct ip_header) + sizeof(struct icmp_header))==-1){
        pcap_perror(iface->pcap, 0);
    }
}

