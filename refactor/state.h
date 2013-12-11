#ifndef STATE_H_INCLUDED
#define STATE_H_INCLUDED

#include <time.h>
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
#include "rules.h"
#include "arp.h"

#define EXPIRE_STATE 60

//OPEN=SYN, HALF=SYNACK, ESTABLISHED=ACK
//CLOSED=NOT in state table
typedef enum{OPEN, HALF, ESTABLISHED, CLOSED} state_t;

//need to free ip_string when done with node

struct state_node {
    u_char src_ip[4];
    u_short src_prt;
    u_char dst_ip[4];
    u_short dst_prt;
    time_t time; //The last time this connection was active
    state_t state; //The current state of the node
    char ip_string[50]; //The generated ip string
    struct state_node* next;//The next state_node in the list
    struct state_node* prev;//the rpevious node in the list
};

struct state_table {
    char ip_string[50]; //key for state table
    struct state_node* node; //value for state table
    UT_hash_handle hh;
};

char* get_ip_key(u_char* src_ip, u_short src_prt, u_char* dst_ip, u_short dst_prt);

char* get_key(struct ip_header* h_ip, struct tcp_header* h_tcp);

void append_to_list(struct state_node* sn);

void remove_from_list(struct state_node* sn);

void update_time(struct state_node* sn);

void expunge_expired();

void add_to_hash(struct state_node* sn);

void remove_from_hash(char* ip_string);

void delete_node(struct state_node* sn);

void close_connection(char* ipstring);
    
void create_node(struct ip_header* h_ip, struct tcp_header* h_tcp);

rule_type_t process_with_state(char* iface1,char* iface2, struct ip_header* h_ip, struct tcp_header* h_tcp);

void update_state(char* ip_key, state_t state);

state_t get_state(char* ip_key);


/*GLOBALS*/
struct state_node* first_state;
struct state_node* last_state;

struct state_table* state_tbl;

/*END GLOBALS*/
#endif
