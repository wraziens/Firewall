#ifndef RULES_H_INCLUDED
#define RULES_H_INCLUDED
#include "packets.h"

typedef enum{PASS, REJECT, BLOCK} rule_type_t;

struct rule {
    u_char* src_iface; //the source interface
    u_char* dst_iface; //the destination interface
    u_char* src_ip; //source ip
    u_char* dst_ip; //destination ip
    u_char* src_port; //source port
    u_char* dst_port; //destination port
    rule_type_t rule_type; //the rule type
    struct rule* next; //pointer to the next rule in the list
};

struct rule *parse_rules();
#endif
