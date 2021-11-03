#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <linux/netfilter.h> /* constants */
#include <libnetfilter_queue/libnetfilter_queue.h>


#define WOL_HOST_MAC_FILE "/var/wol_host_mac"
#define BUFSIZE 1024

typedef enum
{
	PKT_ACCEPT,
	PKT_DROP
}pkt_decision_enum;

struct wol_mac{
	unsigned char mac[12];
};

struct nfq_handle *h;
struct nfq_q_handle *qh;
char macAddr[20];

int wol_packet_handle(struct nfq_data *payload, unsigned short listen_port){
	char *data;
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	struct wol_mac *ptr = NULL;
	char host_mac[20];
	char sync_stream[20];
	int status;
	FILE *fp = NULL;
	int data_len;
	
	memset(host_mac, 0, sizeof(host_mac));
	memset(sync_stream, 0, sizeof(sync_stream));
	
	data_len = nfq_get_payload(payload, &data);
	
	if( data_len == -1 )
	{
		printf("get payload fail !!\n");
		exit(1);
	}
	
	iph = (struct iphdr *)data;
	udph = (struct udphdr *)(data + sizeof(struct iphdr));
	
	if(ntohs(udph->uh_dport) != listen_port){
		fprintf(stderr, "WARNING: wrong Wol packet is received !!!\n");
		goto done;
	}
	
	/* check magic packet sync stream */
	ptr = (struct wol_mac *)(data + sizeof(struct iphdr) + sizeof(struct udphdr));
	sprintf(sync_stream, "%02X:%02X:%02X:%02X:%02X:%02X", ptr->mac[0], ptr->mac[1], ptr->mac[2], ptr->mac[3], ptr->mac[4], ptr->mac[5]);
	if(strcmp(sync_stream, "FF:FF:FF:FF:FF:FF")){
		fprintf(stderr, "WARNING: Wrong WOL magic sync stream: %s\n", sync_stream);
		goto done;
	}
	
	/* parse host MAC */
	if((fp = fopen(WOL_HOST_MAC_FILE, "w")) == NULL ){
		fprintf(stderr, "fail to open WOL mac file !!\n");
		goto done;
	}
	
	fprintf(fp, "%02X:%02X:%02X:%02X:%02X:%02X", ptr->mac[6], ptr->mac[7], ptr->mac[8], ptr->mac[9], ptr->mac[10], ptr->mac[11]);
	fclose(fp);
	
	printf("WOL: ready to wake up host %02X:%02X:%02X:%02X:%02X:%02X\n", ptr->mac[6], ptr->mac[7], ptr->mac[8], ptr->mac[9], ptr->mac[10], ptr->mac[11]);
	system("/sbin/startWol");

done:					
	/* let go the queued packet after the corresponding rules are set, default action is DROP */
	return PKT_DROP;
}

/*
 * callback function for handling packets
 */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	struct nfqnl_msg_packet_hdr *ph;
	int decision, id=0;
	struct nfqnl_msg_packet_hw *m;
	
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph)
	{
		id = ntohl(ph->packet_id);
	}
	
	m=nfq_get_packet_hw(nfa);

#if 0 /* system will segementation fault due to obtain source mac on PPPoE. so remove it */
	sprintf(macAddr, "%02x:%02x:%02x:%02x:%02x:%02x", 
                 m->hw_addr[0], m->hw_addr[1], m->hw_addr[2], m->hw_addr[3], m->hw_addr[4], m->hw_addr[5]);
#endif
	
   /* check if we should block this packet */
	decision = wol_packet_handle(nfa, *((unsigned short *)data));
	
	if( decision == PKT_ACCEPT)
	{
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	else
	{
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
}


/*
 * Open a netlink connection and returns file descriptor
 */
int netlink_open_connection(void *data)
{
	struct nfnl_handle *nh;

//printf("opening library handle\n");
	h = nfq_open();
	if (!h) 
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

//printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) 
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

//printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) 
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

//printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, data);
	if (!qh) 
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

//printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) 
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	nh = nfq_nfnlh(h);
	return nfnl_fd(nh);
}

int main(int argc, char *argv[])
{
	unsigned char buf[BUFSIZE];
	int fd;
	int rv;
	FILE *fp = NULL;
	
	unsigned short WOL_Port = atoi(argv[1]);
	
	/* open a netlink connection to get packet from kernel */
	fd = netlink_open_connection((void *)&WOL_Port);
    memset(buf, 0, sizeof(buf));
    
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) 
	{
//printf("pkt received\n");
		nfq_handle_packet(h, buf, rv);
		memset(buf, 0, sizeof(buf));
	}

//printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);
	nfq_close(h);
	
	return 0;
}
