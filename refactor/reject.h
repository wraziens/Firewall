#ifndef REJECT_H_FILE
#define REJECT_H_FILE

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>
#include "packets.h"
#include "file_handle.h"

void icmp_reject(struct interface *iface, struct ip_header* ip_hdr, u_char *data8, struct eth_header* eth_hdr);


void tcp_reset(struct interface *iface, struct ip_header* ip_hdr, struct tcp_header* tcp_hdr, struct eth_header *eth_hdr);

#endif
