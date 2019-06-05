Jesslyn Hernawan
A14210503
jhernawa@ucsd.edu
jhernawa

~I am NOT competing for the George Varghese Espresso prize~

Description:
I structured the sr_handlePacket() method by handling a packet 
delivered to the router's interfaces or entries in the routing 
table. The handling of arp and ip packets are done accordingly
whether they are sent to the router or needed to be forwarded.

To reduce the verbosity of the sr_handlePacket() method, I 
created fews helper method, such as handle_ICMP_response()
to handle ICMP response from router to client, handle_ARP_send_reply()
to send ARP reply from client's request , handle_ARP_send_request() 
to send ARP request form router to server, and
handle_ARP_send_process_reply() to process the ARP reply sent back
from the server, and handle_arpreq(). These functions are defined in
the sr_router.h

The tradeoff of using this kind of simple design is that the sr_router.c
looks really long. I think a better design would be to make some separate files
that handle the packets delivered to the router's interfaces or 
entries in the routing table. I think this kind of design would make the
entire project looks cleaner.
