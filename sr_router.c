/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
int count_prefix( struct in_addr* mask)
{
  int count = 0;
  uint32_t curr_mask = mask->s_addr;
  while(curr_mask != 0){
      count += (curr_mask & 1);
      curr_mask >>= 1;
  }
  return count;

}
void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent (full packet that contain the ethernet header as well)*/,
        unsigned int len,
        char* interface/* lent (name of the receiving interface of the router's)*/)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  /*printf("\n\n*** -> Received packet of length %d \n",len);*/

  /* fill in code here */
  /*check the longest prefix to see where it is destined to*/
  int forRouter = 0;
  int forwarding = 0;
  struct sr_if * longestInterface = NULL;
  struct sr_rt * longestRoutingTable = NULL;
  if( ethertype(packet) == ethertype_arp ) /*arp packet is only handled by the router*/
  {
        /*get the arp_hdr*/
 	uint8_t * arpHeader_tmp = packet + sizeof(struct sr_ethernet_hdr);
  	sr_arp_hdr_t * arp_hdr_tmp = (sr_arp_hdr_t *) arpHeader_tmp;

        /*check against each router's interface*/
        struct sr_if * currIf = sr->if_list;
        while( currIf != NULL )
        {
            if(currIf->ip == arp_hdr_tmp->ar_tip)
            {
              forRouter = 1;
              longestInterface = currIf;
              break;
            }
            currIf = currIf->next;
        }

  }
  else if( ethertype(packet) == ethertype_ip) /*ip packet can be for router, servers, or client*/
  {
    uint8_t * ipHeader_tmp = packet + sizeof(sr_ethernet_hdr_t);
    sr_ip_hdr_t * ip_hdr_tmp = (sr_ip_hdr_t *) ipHeader_tmp;

    uint32_t ip_dst = ip_hdr_tmp->ip_dst;


    /*check against each router's interface*/
    struct sr_if * currIf = sr->if_list;
    while( currIf != NULL )
    {
        if(currIf->ip == ip_dst)
        {
          forRouter = 1;
          longestInterface = currIf;
          break;
        }
        currIf = currIf->next;
    }

    /*check against the entries in the routing table by using longest prefix match*/
    if(!forRouter)
    {
        int longest = 0;
        struct sr_rt * currRoutingTable = sr->routing_table;
        uint32_t subnet = 0;

        while( currRoutingTable != NULL )
        {
            subnet = currRoutingTable->mask.s_addr & ip_dst;

          	if( subnet == currRoutingTable->dest.s_addr )
          	{
                   int newLongest = count_prefix(&currRoutingTable->mask);
                  /*int newLongest = longestPrefixMatch(ip_dst, (uint32_t)currRoutingTable->dest.s_addr);*/
                   if( longest < newLongest )
                   {
                     	forwarding = 1;
          		longest = newLongest;
          		longestRoutingTable = currRoutingTable;
                   }
          	}
          	currRoutingTable = currRoutingTable->next;
        }
    }

  }


  /*printf("forRouter: %d", forRouter);
  printf("forwarding: %d", forwarding);*/
  if(forRouter == 0 && forwarding == 0) /*ip_dst has no match in the routing table entries*/
  {
      /* pointer to the Eth Header */
      sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
      /* pointer to the Arp Header */
      sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

      /*handle ICMP response (destination net unreachable - Type: 3, Code: 0)*/

      handle_ICMP_response( sr, packet, len, 3, 0, eth_hdr, ip_hdr, interface, NULL);
  }
  else if(forRouter && longestInterface != NULL) /*1) destined to one of router's ip*/
  {


	uint16_t etherType= ethertype(packet);

  	if(etherType == ethertype_arp)/*handle ARP packet*/
  	{
		/* pointer to the Eth Header */
       		sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
		/* pointer to the Arp Header */
  		sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

		/*printf("ALERT: THIS IS ARP\n\n");*/
  		if(ntohs(arp_hdr->ar_op) == arp_op_request)
  		{
			/*printf("ALERT: THIS IS ARP REQUEST\n\n");*/
			handle_ARP_send_reply(sr, len, eth_hdr, arp_hdr,interface);
  		}
		else if(ntohs(arp_hdr->ar_op) == arp_op_reply)
		{
			/*printf("ALERT: THIS IS ARP REPLY\n\n");*/
			handle_ARP_process_reply(sr, packet, len, interface);
		}

 	}
	else if(etherType == ethertype_ip)/*handle IP packet*/
  	{
		/*printf("this is an IP packet\n\n");*/
		/* pointer to the Eth Header */
      		sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
		/* pointer to the Ip Header */
  		sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));


		/*check ip version in ip*/
		if(ip_hdr->ip_v != 4)
		{
			fprintf(stderr, "ERROR: IP VERSION IS NOT IP_V4");
		}

   		/*check checksum in ip*/
    		uint16_t ip_sum_ori = ip_hdr->ip_sum;
    		ip_hdr->ip_sum = 0;
    		uint16_t ip_sum_recalculate = cksum(ip_hdr, sizeof(sr_ip_hdr_t) );
    		if( ip_sum_ori != ip_sum_recalculate )
    		{
      			fprintf(stderr, "ERROR: Checksum is invalid");
   		}
   		printf("\n\n---CHECKING THE ORI PACKET----\n\n");
   		print_hdrs(packet,len);
		if(ip_hdr->ip_p == ip_protocol_icmp)/*handle ICMP response (PING - Type:0)*/
		{

			/*check len of the entire packet*/
			if( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t) + ICMP_DATA_SIZE )
			{
				fprintf(stderr, "ERROR: LEN PACKET IS INCORRECT");
			}
			/*printf("\n\nthis is an ICMP echo(ping) message\n\n");*/
			handle_ICMP_response(sr,packet,len, 0, -1, eth_hdr, ip_hdr, interface, longestInterface->name);

		}
		else if(ip_hdr->ip_p == 17 || ip_hdr->ip_p == 6 ) /*handle ICMP response(IP without ICMP) (TRACEROUTE - Type: 3, Code: 3)*/
		{
			/*check len of the entire packet*/
			if( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) )
			{
				fprintf(stderr, "ERROR: LEN PACKET IS INCORRECT");
			}
			/*printf("this is TRACEROUTING packet");*/
			handle_ICMP_response(sr, packet, len + sizeof(sr_icmp_t11_hdr_t) + ICMP_DATA_SIZE, 3, 3, eth_hdr, ip_hdr, interface, longestInterface->name);

		}
        }

   }/*for router*/
   else if( forwarding && longestRoutingTable != NULL )
   {
		/*printf("This is forwarded packet");*/
		/* pointer to the Eth Header */
      		sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
		/* pointer to the Ip Header */
  		sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));


		/*Handle ICMP response (Time exceeded - Type: 11, Code: 0) */
		if(ip_hdr->ip_ttl-1 == 0)
		{
			/*printf("---------------SEND TIME EXCEEDED~~~~~~~~~~~~~~~");*/
			handle_ICMP_response( sr, packet, len, 11, 0, eth_hdr, ip_hdr, interface, NULL );
		}
		/*check ip version in ip*/
		if(ip_hdr->ip_v != 4)
		{
			fprintf(stderr, "ERROR: IP VERSION IS NOT IP_V4");
		}

   		/*check checksum in ip*/
    		uint16_t ip_sum_ori = ip_hdr->ip_sum;
    		ip_hdr->ip_sum = 0;
    		uint16_t ip_sum_recalculate = cksum(ip_hdr, sizeof(sr_ip_hdr_t) );
    		if( ip_sum_ori != ip_sum_recalculate )
    		{
      			fprintf(stderr, "ERROR: Checksum is invalid");
   		}

   		printf("\n\n---CHECKING THE ORI PACKET----\n\n");
   		print_hdrs(packet,len);
		if( ip_hdr->ip_p == ip_protocol_icmp || (ip_hdr->ip_p == 17 || ip_hdr->ip_p == 6) )/*forward ICMP packet (PING - Type:0)*/
		{
			if(ip_hdr->ip_p == ip_protocol_icmp)
			{
				/*printf("This is a PING FORWARD packet");*/
				/*check len of the entire packet*/
				if( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t) + ICMP_DATA_SIZE )
				{
					fprintf(stderr, "ERROR: LEN PACKET IS INCORRECT");
				}
			}
			else
			{
				/*printf("This is a TRACEROUTE FORWARD packet");*/
				if( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) )
				{
					fprintf(stderr, "ERROR: LEN PACKET IS INCORRECT");
				}

			}


			/*check the ARP cache for the next-hop MAC address corresponding to the next-hop IP*/
			struct sr_arpentry * mapping = sr_arpcache_lookup(&(sr->cache), (uint32_t) longestRoutingTable->dest.s_addr);
			if( mapping != NULL )
			{
				/*printf("\n\n\nALERT: Mapping EXIST!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n\n");*/
				/*decrement the TTL by 1, recompute the packet checksumm over the modified header*/
				ip_hdr->ip_ttl -= 1;
				ip_hdr->ip_sum = 0;
				ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

				/*get the next_hop_ip->mac address to send the packet*/
				struct sr_if * outgoing_If = sr_get_interface( sr, longestRoutingTable->interface );

				memcpy(eth_hdr->ether_dhost, mapping->mac, ETHER_ADDR_LEN);
				memcpy(eth_hdr->ether_shost, outgoing_If->addr , ETHER_ADDR_LEN);

				sr_send_packet(sr, packet, len, outgoing_If->name);

				/*free the mapping*/
				free(mapping);
			}
			else
			{
				/*queue the packet and get the arp request*/
				/*printf("\n\n\nALERT: Mapping NOT EXITS!!!!\n\n\n");*/
				struct sr_arpreq * arp_req = sr_arpcache_queuereq(&(sr->cache), (uint32_t) longestRoutingTable->dest.s_addr, packet, len, longestRoutingTable->interface);
				handle_arpreq(sr, arp_req);

			}
		}



   }/*forwarding*/

   /*printf("\n\n---CHECKING THE ORI PACKET----\n\n");
   print_hdrs(packet,len);*/

}/* end sr_ForwardPacket */

void handle_arpreq( struct sr_instance * sr, struct sr_arpreq * arp_req)
{
	pthread_mutex_lock(&(sr->cache.lock));

	/*get the current time*/
	time_t now;
	time(&now);

	if( difftime(now, arp_req->sent) > 1.0 )
	{
		if( arp_req->times_sent >= 5 ) /*destination host is unreachable*/
		{
		        /*printf("\n\n\nICMP SENT TO CLIENT: DESTINATION HOST IS unreachable\n\n\n");*/
			struct sr_packet * currPkt = arp_req->packets;

			while( currPkt != NULL )
			{
				/*Handle ICMP response (destination host unreachable - Type: 3, Code: 1)*/
				uint8_t * packet = currPkt->buf;
        			sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
				sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) ( packet + sizeof(sr_ethernet_hdr_t) );
				handle_ICMP_response(sr, packet, currPkt->len, 3,1, eth_hdr, ip_hdr, currPkt->iface, NULL  );

				currPkt = currPkt->next;
			}

			/*destroy the arp_req*/
			sr_arpreq_destroy( &(sr->cache), arp_req );
		}
		else
		{
			/*printf("\n\n\nSEND ARP REQUEST\n\n\n");*/
			handle_ARP_send_request(sr, arp_req);
			time(&now);
			arp_req->sent = now;
			arp_req->times_sent++;
		}
	}

	pthread_mutex_unlock(&(sr->cache.lock));
}

void handle_ARP_send_request( struct sr_instance * sr, struct sr_arpreq * arp_req)
{
	uint8_t * arp_request = (uint8_t *) malloc( sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t) );

	sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) arp_request;
	sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *) ( arp_request + sizeof(sr_ethernet_hdr_t) );

	/*create the ethernet header*/
	/*extract the ip_dst from the packet in the queue of this arp_req*/
	struct sr_packet * waitingPkt = arp_req->packets;
	struct sr_if * outgoing_If = sr_get_interface( sr, waitingPkt->iface );

	memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, outgoing_If->addr, ETHER_ADDR_LEN);
	eth_hdr->ether_type = htons(ethertype_arp);

	/*create the arp header*/
	arp_hdr->ar_hrd = htons(arp_hrd_ethernet); /*CHECK YG INI*/
	arp_hdr->ar_pro = htons(ethertype_ip);
	arp_hdr->ar_hln = ETHER_ADDR_LEN;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = htons(arp_op_request);
	memcpy(arp_hdr->ar_sha, outgoing_If->addr, ETHER_ADDR_LEN);
	arp_hdr->ar_sip = outgoing_If->ip;
	memset(arp_hdr->ar_tha, 0xff, ETHER_ADDR_LEN); /*CHECK 0XFF*/
	arp_hdr->ar_tip = arp_req->ip;


  	/*cheking the APR packet to server*/
	/*print_hdrs(arp_request, sizeof(sr_ethernet_hdr_t)+ sizeof(sr_arp_hdr_t));*/

	/*send the packet*/
	sr_send_packet(sr, arp_request, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), outgoing_If->name);


}
void handle_ARP_process_reply(struct sr_instance* sr,
        uint8_t * packet/* lent (full packet that contain the ethernet header as well)*/,
        unsigned int len,
        char* interface/* lent (name of the receiving interface of the router's)*/)
{
	/* Insert the IP->MAC mapping into the cache and mark it as valid*/
	sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
	sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *) ( packet + sizeof(sr_ethernet_hdr_t) );

	struct sr_arpreq * arp_req = sr_arpcache_insert( &(sr->cache), eth_hdr->ether_shost, arp_hdr->ar_sip );

	if( arp_req != NULL )
	{
		/*send all packet on the req->packet linked list*/
		struct sr_packet * currPacket = arp_req->packets;

		while(currPacket != NULL )
		{
			uint8_t * forward_pkt = currPacket->buf;

			sr_ethernet_hdr_t * eth_hdr_fwd = (sr_ethernet_hdr_t *) forward_pkt;
			sr_ip_hdr_t * ip_hdr_fwd = (sr_ip_hdr_t *) ( forward_pkt + sizeof(sr_ethernet_hdr_t) );

			/*modify the ethernet header*/
			memcpy( eth_hdr_fwd->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
			memcpy( eth_hdr_fwd->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);

			/*modify the ip header*/
			/*decrement the TTL by 1, recompute the packet checksumm over the modified header*/
			ip_hdr_fwd->ip_ttl -= 1;
			ip_hdr_fwd->ip_sum = cksum(ip_hdr_fwd, sizeof(sr_ip_hdr_t));


      			/*check the send packet to the server*/
      			/*printf("\n\n\n------------CHECK THE FORWARDED PACKET-----------------\n\n");
      			print_hdrs(forward_pkt, currPacket->len);*/

			/*forward the packet*/
			sr_send_packet( sr, forward_pkt, currPacket->len, interface );

			currPacket = currPacket->next;
		}

		/*destroy the arp_req*/
		sr_arpreq_destroy( &(sr->cache), arp_req );
	}



}

void handle_ARP_send_reply(struct sr_instance * sr, unsigned int len, sr_ethernet_hdr_t * eth_hdr,
		      sr_arp_hdr_t * arp_hdr, char * interface)
{

			struct sr_if* recvIf = sr_get_interface(sr, interface);

        		sr_ethernet_hdr_t * ethHdr_rep = (sr_ethernet_hdr_t *) malloc(sizeof(sr_ethernet_hdr_t));
        		memcpy(ethHdr_rep->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
        		memcpy(ethHdr_rep->ether_shost, recvIf->addr, ETHER_ADDR_LEN);
			ethHdr_rep->ether_type = htons(ethertype_arp);

			/*Create ARP header*/
			sr_arp_hdr_t * arpHdr_rep = (sr_arp_hdr_t *) malloc(sizeof(sr_arp_hdr_t));
        		memcpy(arpHdr_rep, arp_hdr, sizeof(sr_arp_hdr_t));
        		arpHdr_rep->ar_op = htons(arp_op_reply);
        		memcpy(arpHdr_rep->ar_sha, recvIf->addr, ETHER_ADDR_LEN);
        		arpHdr_rep->ar_sip = recvIf->ip;
        		memcpy(arpHdr_rep->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        		arpHdr_rep->ar_tip = arp_hdr->ar_sip;

			/*Send ARP REPLY*/
        		uint8_t * rep_packet = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t)+ sizeof(sr_arp_hdr_t));
        		memcpy(rep_packet, (uint8_t*)ethHdr_rep, sizeof(sr_ethernet_hdr_t));
        		memcpy(rep_packet + sizeof(sr_ethernet_hdr_t), (uint8_t*)arpHdr_rep, sizeof(sr_arp_hdr_t));

        		/*printf("----CHECKING THE REPLY PACKET----\n\n");
  			print_addr_eth(ethHdr_rep->ether_dhost);
        		print_addr_eth(ethHdr_rep->ether_shost);
        		print_hdrs(rep_packet,len);

			printf("\n\n---CHECKING THE ORI PACKET----\n\n");
        		print_hdrs(packet,len);*/

        		sr_send_packet(sr, rep_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);






}

void handle_ICMP_response(struct sr_instance * sr, uint8_t * packet, unsigned int len, int type, int code,
			  sr_ethernet_hdr_t * eth_hdr, sr_ip_hdr_t * ip_hdr,
			  char * interface, char * longestInterface)
{
			/*printf("@@@@@@@@@@@@get into handle_icmp_response");*/
			/*Create ethernet header*/
			struct sr_if* recvIf = sr_get_interface(sr, interface);
			struct sr_if * hitIf = NULL;
			if( longestInterface != NULL )
				hitIf = sr_get_interface(sr, longestInterface);

      			sr_ethernet_hdr_t * ethHdr_rep = (sr_ethernet_hdr_t *) malloc(sizeof(sr_ethernet_hdr_t));
      			memcpy(ethHdr_rep->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
      			memcpy(ethHdr_rep->ether_shost, recvIf->addr, ETHER_ADDR_LEN);
			ethHdr_rep->ether_type = htons(ethertype_ip);

			/*printf("------------check ethernet header--------------\n\n");
			print_hdr_eth(eth_hdr);*/

			/*Create IP header*/
			sr_ip_hdr_t * ipHdr_rep = (sr_ip_hdr_t *) malloc(sizeof(sr_ip_hdr_t));
      			memcpy(ipHdr_rep, ip_hdr, sizeof(sr_ip_hdr_t) );
			ipHdr_rep->ip_len = htons( sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t ) + ICMP_DATA_SIZE);
			ipHdr_rep->ip_src = recvIf->ip;
			ipHdr_rep->ip_dst = ip_hdr->ip_src;
			/*ipHdr_rep->ip_ttl = ip_hdr->ip_ttl - 1;*/
			if( type == 0 && code == -1 )
			{
				ipHdr_rep->ip_src = hitIf->ip;
				ipHdr_rep->ip_ttl = 100;
			}                                                                 
			if( (type == 3 && code == 1) || (type == 3 && code == 3) ||  (type == 11 && code == 0) || (type == 3 && code == 0) )
      			{
				ipHdr_rep->ip_ttl = INIT_TTL;
      			}

        		if( (type == 3 && code == 3) || (type == 11 && code == 0) )
			{
				ip_hdr->ip_ttl = 0;
			}
			ipHdr_rep->ip_p = ip_protocol_icmp;
			ipHdr_rep->ip_sum = 0;
			ipHdr_rep->ip_sum = cksum(ipHdr_rep, sizeof(sr_ip_hdr_t));

			/*Create ICMP header*/
			sr_icmp_t11_hdr_t * icmpHdr_rep = NULL;
         
			if( (type == 0 && code == -1) || (type == 3 && code == 1) )
			{
				sr_icmp_t11_hdr_t * icmp_hdr = (sr_icmp_t11_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

				icmpHdr_rep = (sr_icmp_t11_hdr_t *) malloc( sizeof(sr_icmp_t11_hdr_t) + ICMP_DATA_SIZE );
      				memcpy(icmpHdr_rep, icmp_hdr, sizeof(sr_icmp_t11_hdr_t) + ICMP_DATA_SIZE);

				if( type != -1 )
				{
					icmpHdr_rep->icmp_type = type;
				}
				if( code != -1 )
				{
					icmpHdr_rep->icmp_code = code;
				}
				memcpy(icmpHdr_rep->data, icmp_hdr->data, ICMP_DATA_SIZE); /*CHECK: FOR T:3, C:3, -ICMP datanya bnr ato ga?
														  -Perlu unused = 0?*/
				icmpHdr_rep->icmp_sum = 0;
				icmpHdr_rep->icmp_sum = cksum(icmpHdr_rep, sizeof(sr_icmp_t11_hdr_t) + ICMP_DATA_SIZE);
			}                                                                    
			else if( (type == 3 && code == 3) || (type == 11 && code == 0)  || (type == 3 && code == 0) )
			{
				/*        
        			if( (type == 3 && code == 3) || (type == 11 && code == 0) )
				{
				    ip_hdr->ip_ttl = 0;
				}*/
				icmpHdr_rep = (sr_icmp_t11_hdr_t *) malloc( sizeof(sr_icmp_t11_hdr_t) + ICMP_DATA_SIZE );
				memset(icmpHdr_rep, 0 , sizeof(sr_icmp_t11_hdr_t) + ICMP_DATA_SIZE);

				icmpHdr_rep->icmp_type = type;
				icmpHdr_rep->icmp_code = code;
				icmpHdr_rep->unused = 0;
				memcpy(icmpHdr_rep->data, ip_hdr, ICMP_DATA_SIZE);
				icmpHdr_rep->icmp_sum = 0;
				icmpHdr_rep->icmp_sum = cksum(icmpHdr_rep, sizeof(sr_icmp_t11_hdr_t) + ICMP_DATA_SIZE);


			}
			/*Send ICMP REPLY*/
			uint8_t * rep_packet_icmp = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t) + ICMP_DATA_SIZE);
      			memcpy(rep_packet_icmp, (uint8_t*)ethHdr_rep, sizeof(sr_ethernet_hdr_t));
      			memcpy(rep_packet_icmp + sizeof(sr_ethernet_hdr_t), (uint8_t*)ipHdr_rep, sizeof(sr_ip_hdr_t));
			memcpy(rep_packet_icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), (uint8_t*)icmpHdr_rep, sizeof(sr_icmp_t11_hdr_t) + ICMP_DATA_SIZE);

			/*printf("\n\n------CHECKING THE ICMP HEADER-----\n\n");
			print_hdr_icmp( (uint8_t *) (rep_packet_icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) );*/


      			printf("\n\n----CHECKING THE REPLY PACKET----\n\n");
			printf("\n\noioioi\n\n");
      			print_hdrs(rep_packet_icmp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t) + ICMP_DATA_SIZE);
			printf("\n\nioioio\n\n");

			/*send*/
        		sr_send_packet(sr, rep_packet_icmp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t) + ICMP_DATA_SIZE, interface);

}
