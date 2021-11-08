#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sqlite3.h> // use SQLite in C or C++
#include "ip1.h"
#include "tcp.h"


char* db;
const char* methods[] = {"GET","HEAD","POST","PUT","DELETE","CONNECT","OPTIONS","TRACE","PATCH"};

/* returns packet id */


void usage()
{
	printf("syntax : 1m-block <site list file>\n");
	printf("sample : 1m-block top-1m.txt\n");
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}


static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}
	
	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		printf("payload_len=%d\n", ret);
		dump(data,ret);
	}

	fputc('\n', stdout);
	
	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, // report fix point
	      struct nfq_data *nfa, void *data)
{
	int id, dum, total_len, ip_len, offset, rc, step; // rc, step are use in SQL 
	unsigned char *packet;
	unsigned char *payload;
	char* tmp;
	bool check = false;
	uint16_t protocol;
	struct nfqnl_msg_packet_hdr *nmph;
	IP_hdr ip;
	TCP_hdr tcp;
	sqlite3* db;
	sqlite3_stmt* res;
	char* sql = "SELECT* FROM top1m WHERE address LIKE ?";
	
	nmph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(nmph->packet_id);
	dum = nfq_get_payload(nfa, &packet);
	
	ip = (IP_hdr) packet;
	if(ip->ip_p != 0x06)
		return nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL);
	total_len = ip->ip_total_len();
	ip_len = ((ip->ip_hl)&0x0f)<<2;
	tcp = (TCP_hdr)(packet+ip_len);
	if(tcp->srcport() != 80 && tcp->dstport() != 80)
		return nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL);
	offset = ip_len + ((tcp->th_off)<<2);
	if(total_len - offset ==0) // check the text are there after TCP??
		return nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL);
	payload = packet + offset;
	tmp = strtok((char*)payload,"\r\n");
	if(tmp == NULL)
		return nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL);
	check = false;
	for(int i=0;i<sizeof(methods)/sizeof(char*);i++) // check method is there
	{
		if(strncmp(tmp,methods[i],strlen(methods[i])) == 0)
		{
			check = true;
			break;
		}	
	}
	
	if(!check) 
		return nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL);
	tmp = strtok(NULL,"\r\n");
	if(tmp == NULL)
		return nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL);
	
	// start here 1m-block~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	tmp = tmp + 6;// using sql, so don't need host
	if(strncmp(tmp,"www.",4) == 0)
		tmp = tmp + 4;
	
	rc = sqlite3_open("./top1m.db",&db);
	if(rc != SQLITE_OK){
		fprintf(stderr, "Cannot open database: %s\n",sqlite3_errmsg(db));
		sqlite3_close(db);
		return nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL); //false
	}
	rc = sqlite3_prepare_v2(db,sql,-1,&res,0);
	if(rc == SQLITE_OK)
		sqlite3_bind_text(res,1,tmp,strlen(tmp),SQLITE_STATIC);
	else
		fprintf(stderr,"Failed to execute statement: %s\n",sqlite3_errmsg(db));
	step = sqlite3_step(res);
	if(step == SQLITE_ROW){
		printf("%s: ",sqlite3_column_text(res,0));
		printf("%s\n",sqlite3_column_text(res,1));
		printf("netfilter working\n");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	sqlite3_finalize(res);
	sqlite3_close(db);
	
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	
	//printf("netfilter working\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	
	if(argc != 2)
	{
		usage();
		return -1;
	}
	else db = argv[1]; // check is there db

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

