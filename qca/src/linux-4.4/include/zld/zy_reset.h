#ifndef  _ZY_RESET_H
#define  _ZY_RESET_H

#include <generated/autoconf.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#ifdef ZLDCONFIG_SSL_INSPECTION
#include <zld/zld_sslinsp_common.h>
#endif

#define OBVERSE_DIRECTION 	1
#define REVERSE_DIRECTION 	2
#define TWO_DIRECTION		3

#define TCPOPT_SACK_SIZE    12

#define ZY_RESET_DEFAULT_WINDOW_SIZE	32767

#define RESET_TIMEOUT	(3 * HZ)
#define TCP_OPTION_SACK_SUPPORT			0x00000001
#define TCP_OPTION_SSL_INSPECTION_REQ	0x00000002
#define TCP_HDR_SEQ_ACK_MANUAL_SET		0x00000020
#define TCP_HDR_ACK_BIT_MANUAL_SET		0x00000040
#define TCP_HDR_FIN_BIT_MANUAL_SET		0x00000080

typedef struct zy_tcpip_info_s {
	uint32_t flags;
	uint32_t tcp_opt_len;

	union {
		int32_t seq_offset;	/* Will be used when TCP_HDR_SEQ_ACK_MANUAL_SET bit had not been set */
		struct {			/* Will be used when TCP_HDR_SEQ_ACK_MANUAL_SET bit had been set */
			__be32 ack_seq;
			__be32 seq;
		};
	} seqack;

	__u16	rst:1,
			ack:1,			/* Will be used when TCP_HDR_ACK_BIT_MANUAL_SET bit had been set */
			fin:1;			/* Will be used when TCP_HDR_FIN_BIT_MANUAL_SET bit had been set */
	__be16  window;
	struct {				/* Will be used when TCP_OPTION_SACK_SUPPORT bit had been set */
		__be32 start_seq;
		__be32 end_seq;
	} sack;

	uint32_t iphdr_id;
} zy_tcpip_info_t;

extern struct net_bridge_port *zy_has_bridge_parent(const struct net_device *dev);
extern struct net_device *zy_bridge_parent(const struct net_device *dev);
extern void __zy_send_tcp_data_with_flags(struct sk_buff *oldskb, int dir, int hook, void *data_buf, int data_len, int psh, int fin, zy_tcpip_info_t *tcpinfo);
extern void __zy_send_tcp_data(struct sk_buff *oldskb, int dir, int hook, void *data, int len, int seq_offset);
extern void __zy_send_tcp_no_data(struct sk_buff *oldskb, int dir, int hook, zy_tcpip_info_t *tcpinfo);
extern void zy_send_tcp_data(struct sk_buff *oldskb, int dir, int hook, void *data, int len);
extern void zy_send_tcp_reset(struct sk_buff *oldskb, int dir, int hook, int seq_offset);
extern void zy_send_icmp_unreach(struct sk_buff *oldskb, int code, int hook);
extern void zy_send_reset(struct sk_buff *oldskb, int dir, int code, int hook);
extern void zy_send_ack_dup_pkt(struct sk_buff *oldskb, int fri_seq,int fri_ack_seq, int16_t fri_window,int hook,int id_offset, int start_seq, int end_seq);
extern int zy_check_is_bridge_dst(struct sk_buff *skb);
extern __be32 zy_packet_get_lsrc(struct sk_buff *skb, int reverse_dir);

#ifdef ZLDCONFIG_SSL_INSPECTION
extern int (*__sslinsp_send_encrypt_pkts)(struct ssl_insp_session *sslinsp_session,
		struct ssl_insp_trans_encrypt_pkts_params *sslinsp_trans_encrypt_pkts_params,
		enum ip_conntrack_dir dir);
#endif
/* Enable to debug zy_send_tcp_reset */
#define DEBUG_ZY_TCP_RESET 1

#endif  /* _ZY_RESET_H */
