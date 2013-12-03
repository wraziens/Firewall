#ifndef RULES_H_INCLUDED
#define RULES_H_INCLUDED

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

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

void parse_rules(struct rule *rule_val);
void print_rules(struct rule *rule_chain);
void print_all_rules(struct rule *rule_chain);

#endif
