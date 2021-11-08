#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>

#define ETHER_ADDR_LEN 6
struct libnet_ethernet_hdr
{
    uint8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
};

#pragma once

#pragma pack(push, 1)
struct libnet_ipv4_hdr final
{

    uint8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */

    uint8_t ip_tos;       /* type of service */

    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;

    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;         /* checksum */
    //struct in_addr ip_src, ip_dst; /* source and dest address */
};
typedef libnet_ipv4_hdr Ipv4_hdr;
#pragma pack(pop)

#pragma once

#pragma pack(push, 1)
struct libnet_tcp_hdr final
{
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;          /* sequence number */
    uint32_t th_ack;          /* acknowledgement number */
    uint8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
    uint8_t  th_flags;       /* control flags */

    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */
    
    uint16_t srcport(){
    	return ntohs(th_sport);
    }
    uint16_t dstport(){
    	return ntohs(th_dport);
    }
};
typedef libnet_tcp_hdr Tcp_hdr;
#pragma pack(pop)

uint16_t con16 (uint8_t i, uint8_t j){
	return (i<<8)+j;
}
uint32_t con32 (uint8_t a, uint8_t b, uint8_t c, uint8_t d){
	return (a<<24) + (b<<16) + (c<<8) + d;
}



void init_ether(struct libnet_ethernet_hdr *ethernet,const u_char* packet)
{
	for(int i=0;i<ETHER_ADDR_LEN;i++){
	ethernet->ether_dhost[i] = packet[i];
	ethernet->ether_shost[i] = packet[i+ETHER_ADDR_LEN];
	}
	
	ethernet->ether_type = con16(packet[12],packet[13]);
}

void init_ip(struct libnet_ipv4_hdr *ip,const u_char* packet)
{
	ip->ip_hl=packet[0]&0x0f;     
        ip->ip_v=packet[0]>>4;     

    	ip->ip_tos=packet[1];      

   	 ip->ip_len=con16(packet[2],packet[3]);        
    	ip->ip_id=con16(packet[4],packet[5]);        
   	 ip->ip_off=con16(packet[6],packet[7]);

   	 ip->ip_ttl=packet[8];          
   	 ip->ip_p=packet[9];         
   	 ip->ip_sum=con16(packet[10],packet[11]); 
   	 ip->ip_src.s_addr =htonl(con32(packet[12],packet[13],packet[14],packet[15]));
   	 ip->ip_dst.s_addr =htonl(con32(packet[16],packet[17],packet[18],packet[19]));
    
}

void init_tcp(struct libnet_tcp_hdr *tcp,const u_char* packet)
{
	tcp->th_sport= con16(packet[0],packet[1]);      
    tcp->th_dport=con16(packet[2],packet[3]);       
    tcp->th_seq=con32(packet[4],packet[5],packet[6],packet[7]);         
    tcp->th_ack=con32(packet[8],packet[9],packet[10],packet[11]);        
    tcp->th_x2=packet[12]&0x0f;       
           tcp->th_off=packet[12] >> 4; 
    tcp->th_flags=packet[13];       

    tcp->th_win=con16(packet[14],packet[15]);      
    tcp->th_sum=con16(packet[16],packet[17]);        
    tcp->th_urp=con16(packet[18],packet[19]);  
}

int pkt_cap(struct pcap_pkthdr* header,const u_char* packet)
{
 struct libnet_ethernet_hdr ethernet;
 struct libnet_ipv4_hdr ip;
 struct libnet_tcp_hdr tcp;

 init_ether(&ethernet,packet);

	if(ethernet.ether_type == 0x0800)
	{
		init_ip(&ip,packet+14);

		const uint8_t ip_hdr_size = ip.ip_hl * 4;

		if(ip.ip_p == 0x06)
		{
			init_tcp(&tcp,packet+14+ip_hdr_size);
			
			const uint8_t tcp_hdr_size = tcp.th_off * 4;
			
			char mac_add[18] = {0};
			char payload[9] = {0};

			puts("Ethernet Header");

			sprintf(mac_add,"%02X:%02X:%02X:%02X:%02X:%02X",ethernet.ether_shost[0],ethernet.ether_shost[1],ethernet.ether_shost[2],ethernet.ether_shost[3],ethernet.ether_shost[4],ethernet.ether_shost[5]);
			printf("Src Mac : %s\n",mac_add);

			sprintf(mac_add,"%02X:%02X:%02X:%02X:%02X:%02X",ethernet.ether_dhost[0],ethernet.ether_dhost[1],ethernet.ether_dhost[2],ethernet.ether_dhost[3],ethernet.ether_dhost[4],ethernet.ether_dhost[5]);
			printf("Dst Mac : %s\n",mac_add);
			
			puts("IP Header");

			printf("Src IP : %s\n",inet_ntoa(ip.ip_src));
			printf("Dst IP : %s\n",inet_ntoa(ip.ip_dst));

			puts("TCP Header");

			printf("Src Port : %u\n",tcp.th_sport);
			printf("Dst Port : %u\n",tcp.th_dport);

			puts("Payload");
			int payload_len = ip.ip_len - ip_hdr_size - tcp_hdr_size;
			
			for(int i=0;i<payload_len;i++) //최대 8바이트까지만
			{
				if(i>=8) break;
				printf("%02X ",packet[14+ip_hdr_size+tcp_hdr_size+i]);
			}
			puts("\n");
			
		}
		
	}

	return 0;
}
