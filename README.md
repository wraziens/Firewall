Firewall
========

to Make: 
=========
In the directory firewall type
'make'

to run:
=========
(1) With Pcap files:
---------------------
When the program runs with a pcap file provided by the
user, the results of the traffic it lets through can be found
in firewall_dump.pcap.

'./firewall file_name.pcap'

(2) With Live interfaces
------------------------
The user must supply at least 2 interfaces for the
firewall to listen on. The user can supply more interfaces
if he chooses to but it us unnecessary for the program to run.

'./firewall interface1 interface2 [interfaces...]'


Description
=============
A Stateful Firewall implementation in C. The Firewall can interpret rules such as
pass, reject and block. All rules should be specified in a 'rules.conf' file before
the firewall is started. The rules should be specified from less specific to more specific
with the less specific(default) rules at the top of the file.
For more detailed description of the firewall, please see the firewall.pdf
document.

Files
=======
arp.c -  Handles the ARP table and packets
file_handle.c - Handles reading and writing to a pcap file
handle_packets.c - Handles UDP, TCP, and ICMP packets
reject.c - Handles the reject packets
rule.c - Handles the firewall rules
state.c - Handles the state table
read.c
-------------
Header Files
-------------
arp.h
file_handle.h
handle_packets.h
packets.h
reject.h
rule.h
state.h
uthash.h (External Library for Hash Tables)

