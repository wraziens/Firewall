#include <string.h>
#include <stdio.h>
/*
returns the extension of the file if one exists, otherwise returns "" 
*/
const char *get_extension(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if(!dot || dot == filename){
        return "";
    }else{
        return dot + 1;
    }
}

int is_file(const char* name){
    if(strcmp(get_extension(name), "pcap")==0){
        return 1;
    }else{
        return 0;
    }
}
