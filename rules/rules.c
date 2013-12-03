#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rules.h"

#define MAX_LINE_LEN 256

// Reads the rules from the file 'rules.conf'
// and returns a rule struct
void parse_rules(struct rule* rule_val){
    FILE *fh = fopen("rules.conf", "rt");
    char line[MAX_LINE_LEN];

    struct rule *r = rule_val;
    struct rule *last = NULL;
    while (fgets(line, MAX_LINE_LEN, fh) != NULL) {
        if (strlen(line) > 1 && line[0] != '#') {
            char *src_iface = strtok(line, " ");
            char *dst_iface = strtok(NULL, " ");
            char *src_ip = strtok(NULL, " ");
            char *src_port = strtok(NULL, " ");
            char *dst_ip = strtok(NULL, " ");
            char *dst_port = strtok(NULL, " ");
            char *action = strtok(NULL, " ");
            
            r->src_iface = malloc(strlen(src_iface));
            memcpy(r->src_iface, src_iface, strlen(src_iface));
            
            r->dst_iface = malloc(strlen(dst_iface));
            memcpy(r->dst_iface, dst_iface, strlen(dst_iface));
            
            r->src_ip = malloc(strlen(src_ip));
            memcpy(r->src_ip, src_ip, strlen(src_ip));
            
            r->dst_ip = malloc(strlen(dst_ip));
            memcpy(r->dst_ip, dst_ip, strlen(dst_ip));
            
            r->src_port = malloc(strlen(src_port));
            memcpy(r->src_port, src_port, strlen(src_port));
            
            r->dst_port = malloc(strlen(dst_port));
            memcpy(r->dst_port, dst_port, strlen(dst_port));
            
            char* t_val = malloc(strlen(action));
            memcpy(t_val, action, strlen(action));
            
            r->next = NULL;
            // parse the actions in the 
            // rules file.
            char pass[] = "pass\n";
            char reject[] = "reject\n";
            char block[] = "block\n";
            if(strcmp(t_val, pass)==0){
                r->rule_type = PASS;
            } else if(strcmp(t_val, reject)==0){
                r->rule_type = REJECT;
            } else if(strcmp(t_val, block)==0){
                r->rule_type = BLOCK;
            }else{
                printf("Invalid action `%s` specified.\n", action);
                exit(-1);
            }


            /*
            //error checking  for source and destination IPs
            if (inet_aton(src_ip, &r->src_ip) == 0) {
                printf("Invalid source IP address %s\n", src_ip);
                exit(-1);
            }

            if (inet_aton(dst_ip, &r->dst_ip) == 0) {
                printf("Invalid destination IP address %s\n", dst_ip);
                exit(-2);
            }
            */
            if(last != NULL){
                //memcpy(r->next, last, sizeof(struct rule));
                r->next = last;
                //memcpy(last, r, sizeof(struct rule));
            }
            last = r;
            //print_rules(last);
            r = malloc(sizeof(struct rule));
        }
    }
//    r=last;
    memcpy(rule_val, last, sizeof(struct rule));
    //rule_val = last;
    print_rules(rule_val);
}

//Prints our the rules in the list rule_chain
void print_rules(struct rule *rule_chain){
    struct rule *r = rule_chain;
    while( r!=NULL ) {
        printf("Source Interface: %s\n", r->src_iface);
        printf("Destination Interface: %s\n", r->dst_iface);
        printf("Source IP: %s\n", r->src_ip);
        printf("Destination IP: %s\n", r->dst_ip);
        printf("Source Port: %s\n", r->src_port);
        printf("Destination Port: %s\n", r->dst_port);
        printf("Rule: %d\n", (int)r->rule_type);
        printf("================================\n\n");
        r=r->next;
    }
}

void print_all_rules(struct rule *rule_chain){
    printf("*****************************\n");
    do {
        print_rules(rule_chain);
        printf("~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    }while((rule_chain = rule_chain->next) != NULL);
}

