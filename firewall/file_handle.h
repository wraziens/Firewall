#ifndef FILE_H_INCLUDED
#define FILE_H_INCLUDED

#include <string.h>
#include <stdio.h>
#include <pcap.h>

const char *get_extension(const char *filename);

int is_file(const char* name);

void process_packet_dump(const struct pcap_pkthdr *hdr,const u_char *data);

/*GLOBAL VARIABLE DECLARATIONS*/
//if 1 read from live if 0 read from file
int live;

pcap_t* file_in;
pcap_dumper_t* dumpfile;
/*END GLOBAL VARIABLES*/


#endif
