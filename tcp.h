#pragma once

#pragma pack(push, 1)
struct tcp_hdr final
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
typedef tcp_hdr *TCP_hdr;
#pragma pack(pop)
