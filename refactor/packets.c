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

