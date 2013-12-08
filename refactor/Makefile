GXX=/usr/bin/clang
GCC=/usr/bin/gcc
FLAGS=-lpcap -std=gnu99 -ggdb 
FILES=read.c arp.c packets.c rules.c reject.c
OUTPUT=read

make :
	${GXX} ${FILES} ${FLAGS} -o ${OUTPUT}
