/* Copyright 2012-2035, ZyXEL Communications Corp. All rights reserved. */

#ifndef _ZLD_CB_DATA_H
#define _ZLD_CB_DATA_H

//#include "zld-spec.h"

#define ZLDCONFIG_ZLD_SKB_ZLD_CB 1

#ifdef ZLDCONFIG_ZLD_SKB_ZLD_CB
#include <linux/skbuff.h>
#include <linux/types.h>

#ifdef ZLDCONFIG_SSL_INSPECTION
#include <zld/zld_sslinsp_common.h>
#endif

/* Note: Please ensure that each element of this structure is naturally aligned as possible. */
struct zld_cb_data_struct {
/* #ifdef ZLDCONFIG_SSL_INSPECTION */
	union {
		struct ssl_insp_skb_appdata *appdata;
		struct ssl_insp_skb_hsdata *hsdata;
	} sslinsp_skbdata;
	uint32_t seq;
	uint32_t end_seq;
	uint32_t mod_ack_seq;	
	uint8_t sslinsp_flag;
	uint8_t sslinsp_ssl_content_type;
	uint16_t zldflag;
/*#endif  ENDIF_ZLDCONFIG_SSL_INSPECTION */
	uint32_t from_vpn_id;
	uint32_t from_vpn_spi;
/* #ifdef ZLDCONFIG_RTCOMPL */
	uint32_t fasthookid;
/*#endif */
	uint8_t l4_protocol;
	uint8_t zldmark;
/*#ifdef ZLDCONFIG_ZYSSO */
	uint16_t ssomark;
/*#endif */
/* #ifdef ZLDCONFIG_ZYPKTORDER */
	int (*zypktorder_okfn)(struct sk_buff *);
/*#endif */
/*#ifdef ZLDCONFIG_VIRTUAL_IF_ENHANCEMENT */
	uint32_t virtual_if_rcv;
	uint32_t virtual_if_xmit;
/*#endif */	
};

#if 0 //Disable it. Avoid to add the parameter in common structure directly.  
#define ZLD_CB_DATA(skb) ((struct zld_cb_data_struct *) ((skb)->zld_cb))
#define ZLD_CB_DATA_SIZE (sizeof(struct zld_cb_data_struct))
#endif

#else	/* ELSE_ZLDCONFIG_ZLD_SKB_ZLD_CB */
#error "Please enable ZLD_SKB_ZLD_CB feature first!!!"
#endif	/* ENDIF_ZLDCONFIG_ZLD_SKB_ZLD_CB */

#endif  /* _ZLD_CB_DATA_H */
