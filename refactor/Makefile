GXX=/usr/bin/clang
GCC=/usr/bin/gcc
FLAGS=-lpcap -std=gnu99 -ggdb 
FILES=read.c arp.c packets.c rules.c reject.c handle_packets.c
OUTPUT=read

make :
	${GCC} ${FILES} ${FLAGS} -o ${OUTPUT}
