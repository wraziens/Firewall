#include "rules.h"

int main(int argc, char **argv) {
    
    struct rule *r = malloc(sizeof(struct rule));
    parse_rules(r);
    printf("........................\n");
    print_rules(r);
    return 0;
}
