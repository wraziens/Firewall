#include <stdlib.h>
#include <stdio.h>
#include "file_handle.h"


int main(int argc, char** argv){
    for(int x=1; x<argc; x++){
        printf("%i\n", is_file(argv[x]));
        printf("%s\n", get_extension(argv[x]));
    }
    return 0;
}
