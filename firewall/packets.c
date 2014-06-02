#include "packets.h"

void print_ip_address(struct ip_header* h_ip){
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

char* ip_string(u_char* ip_addr){
    char* buffer= (char*)malloc(sizeof(char) * 20);
    sprintf(buffer, "%d.%d.%d.%d", ip_addr[0],ip_addr[1], ip_addr[2], ip_addr[3]);
    return buffer;
}
char* port_string(u_short prt){
    printf("PROT: %d\n",prt);
    char* buffer= (char*)malloc(sizeof(char) * 6);
    sprintf(buffer, "%d",prt);
    return buffer;
}

