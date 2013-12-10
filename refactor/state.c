#include "state.h"

/*
 * Returns a string with the source and 
 * destination Ips and ports
 *
 */

u_char* get_key(struct ip_header* h_ip, struct tcp_header* h_tcp){
    return get_ip_key(h_ip->saddr, ntohs(h_tcp->src_port), h_ip->daddr, ntohs(h_tcp->dst_port));
}

u_char* get_ip_key(u_char* src_ip, u_short src_prt, u_char* dst_ip, u_short dst_prt){
    char* src_i = ip_string(src_ip);
    char* dst_i = ip_string(dst_ip);
    char* src_pt = port_string(src_prt);
    char* dst_pt = port_string(dst_prt);
    
    u_char* key=malloc(50);

    if(strcmp(src_i, dst_i) < 0){
        memcpy(key, src_i, strlen(src_i));
        strcat(key, src_pt);
        strcat(key, dst_i);
        strcat(key, dst_pt);
        int len = strlen(key);
        while (len < 50){
            strcat(key, " ");
            len++;
        }
    }else{
        memcpy(key, dst_i, strlen(dst_i));
        strcat(key, dst_pt);
        strcat(key, src_i);
        strcat(key, src_pt);
        int len = strlen(key);
        while (len < 50){
            strcat(key, " ");
            len++;
        }
    }
    printf("strlen %i\n", strlen(key));
    free(src_i);
    free(dst_i);
    free(src_pt);
    free(dst_pt);
    return key;
}

void append_to_list(struct state_node* sn){
    if(first_state == NULL){
        printf("FIRST state in list\n");
        first_state=sn;
        last_state=sn;
    }else{
        printf("Adding to List\n");
        printf("%s\n", sn->ip_string);
        printf("%s\n", first_state->ip_string);
        printf("%s\n", last_state->ip_string);
        last_state->next = sn;
        sn->prev = last_state;
        last_state = sn;
    }
}

void remove_from_list(struct state_node* sn){
    printf("REMOVE\n");
    if(sn->prev != NULL && sn->next!=NULL){
        sn->prev->next = sn->next;
        sn->next->prev = sn->prev;
        sn->next = NULL;
        sn->prev = NULL;
        return;
    }
    if(sn->prev == NULL && sn->next == NULL){
        if(last_state == sn){
            last_state = NULL;
        }
        if(first_state == sn){
            first_state = NULL;
        }
        return;
    }
    if(sn->prev == NULL){
        first_state = sn->next;
        sn->next = NULL;
        return;
    }
    if(sn->next == NULL){
        last_state = sn->prev;
        sn->prev=NULL;
        return;
    }
}

void update_time(struct state_node* sn){
    sn->time = time(NULL);
    if(first_state != sn && last_state!=sn){
        remove_from_list(sn);
        append_to_list(sn);
    }
}


//Since our list is ordered by time 
//we only need to check until we find
//one that is not expired.
void expunge_expired(){
    time_t current = time(NULL);

    struct state_node* st = first_state;
    int stop = 0;
    while((st != NULL) && (stop == 1)){
        if(difftime(st->time, current) > EXPIRE_STATE){
            struct state_node* temp = st->next;
            remove_from_list(st);
            remove_from_hash(st->ip_string);
            delete_node(st);
            st = temp;
        }else{
            stop = 1;
        }
    }
}

void add_to_hash(struct state_node* sn){

    struct state_table* st = (struct state_table*)malloc(sizeof(struct state_table));
    strcpy(st->ip_string, sn->ip_string);
    st->node = sn;
    HASH_ADD_STR(state_tbl, ip_string, st);

}

void remove_from_hash(char* ip_str){
    struct state_table* st = NULL;
    HASH_FIND_STR(state_tbl,ip_str, st);
    //if the ip string is in our state hash
    if(st){
        HASH_DEL(state_tbl, st);
        free(st);
    }
}

void delete_node(struct state_node* sn){
    printf("deleteing Node..\n");
    free(sn->ip_string);
    free(sn);
}

void close_connection(char* ip_str){
    struct state_table* st = NULL;
    HASH_FIND_STR(state_tbl,ip_str,st);
    //if the ip string is in our state hash
    if(st){
        HASH_DEL(state_tbl, st);
        struct state_node* n = st->node;
        remove_from_list(n);
        delete_node(n);
        free(st);
    }
}

void create_node(struct ip_header* h_ip, struct tcp_header* h_tcp){
    printf("Creating Node\n");
    struct state_node* sn = malloc(sizeof(struct state_node));
    memcpy(sn->src_ip, h_ip->saddr,4);
    sn->src_prt=h_tcp->src_port;
    memcpy(sn->dst_ip, h_ip->daddr,4);
    sn->dst_prt = h_tcp->dst_port;
    sn->time = time(NULL);
    sn->state = OPEN;
    u_char* k = get_key(h_ip, h_tcp);
    sn->ip_string = k;
    //strcpy(sn->ip_string, k);

    add_to_hash(sn);
    append_to_list(sn);
}

//Checks the state of the node if available
//and checks with the rules is necessary.
//Returns the action the firewall should take 
//for the packet.
rule_type_t process_with_state(char* iface1,char* iface2, struct ip_header* h_ip, struct tcp_header* h_tcp){

    print_ip_address(h_ip);
    u_char* key = get_key(h_ip, h_tcp);
    //close the connection RST or FIN flag is set
    printf("Process:\n");
    if(h_tcp->flags & 0x01 || h_tcp->flags & 0x04){
        close_connection(key);
        printf("FYN / RST packet.\n");
    }else if(h_tcp->flags & 0x02){
        printf("SYN set.\n");
        printf("KEY %s\n",key);
        //SYN ACK Packet
        if(h_tcp->flags & 0x10){
            printf("SYN ACK packet.\n");
            printf("KEY %s\n",key);
            state_t s = get_state(key);
            printf("STATE %i\n", s);
            if(s==OPEN){
                printf("OPEN state\n");
                
                char* sadr = ip_string(h_ip->saddr);
                char* dadr = ip_string(h_ip->daddr);
                rule_type_t rt=  get_firewall_action(rule_list,iface1, iface2, sadr, dadr, ntohs(h_tcp->src_port), ntohs(h_tcp->dst_port));    
                free(sadr);
                free(dadr);
                printf("RT TYPE: %i\n", rt);
                if(rt == PASS){
                    update_state(key, HALF);
                }else{
                    close_connection(key);
                }
                return rt;
            }else{
                return BLOCK;
            }
        //SYN Packet
        }else{
            printf("SYN packet recieved.\n");
            char* sadr = ip_string(h_ip->saddr);
            char* dadr = ip_string(h_ip->daddr);

            rule_type_t rt=  get_firewall_action(rule_list,iface1, iface2, sadr, dadr, ntohs(h_tcp->src_port), ntohs(h_tcp->dst_port));    
            free(sadr);
            free(dadr);
            if(rt==PASS){
                create_node(h_ip, h_tcp);
            }
            return rt;
        }
    //ACK Packet
    }else if(h_tcp->flags & 0x10){
        printf("ACK PACKET\n");
        state_t s = get_state(key);
        if(s == ESTABLISHED){
            struct state_table* st = NULL;
            HASH_FIND_STR(state_tbl,key,st );
            //if the ip string is in our state hash
            if(st){
                update_time(st->node);
            }
            return PASS;
        }else if(s==HALF){
            update_state(key, ESTABLISHED);
            return PASS;
        }else{
            //A connection is not established so we block the 
            //packet
            return BLOCK;
        }
    }
}

void update_state(char* ip_key, state_t state){
    struct state_table* st = NULL;
    HASH_FIND_STR(state_tbl,ip_key,st );
    //if the ip string is in our state hash
    if(st){
        st->node->state = state;
        update_time(st->node);
    }
}

state_t get_state(char* ip_key){
    struct state_table* st = NULL;
    HASH_FIND_STR(state_tbl,ip_key,st );
    //if the ip string is in our state hash
    if(st){
        return st->node->state;
    }else{

        printf("~~~~~~~~~~~~~~~~~~~~~~~~\n");
        struct state_table *cur_imap, *tmp; 
        //struct interface *channel=NULL;
        HASH_ITER(hh, state_tbl, cur_imap, tmp){
            printf("key: |%s|\n",cur_imap->ip_string);
            printf("STATE: %i\n", cur_imap->node->state);
        }
        printf("``````````````````````````````````````\n");
        return CLOSED;
    }
}
