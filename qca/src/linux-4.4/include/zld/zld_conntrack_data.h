/* Copyright 2012-2035, ZyXEL Communications Corp. All rights reserved. */

#ifndef _ZLD_CONNTRACK_DATA_H
#define _ZLD_CONNTRACK_DATA_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#include <linux/autoconf.h>
#else
#include <generated/autoconf.h>
#endif

#include <net/netfilter/nf_conntrack.h>

//#include <zld-spec.h>

#include <zld/zy_ssu.h> /* ZLDCONFIG_SESSION_STATUS_UPDATE */
#ifdef ZLDCONFIG_SSL_INSPECTION
#include <zld/zld_sslinsp_common.h>
#endif

#ifdef ZLDCONFIG_RTCOMPL
#include <zld/rtcompl.h>
#endif

//#ifndef CONFIG_ZLD_CONNTRACK_DATA
//#error "Kernel must be compiled with CONFIG_ZLD_CONNTRACK_DATA!"
//#endif

#if 0
#define NF_CT_EXT_CONNTRACK_DATA_TYPE struct zld_nf_conn
#else
#define NF_CT_EXT_CONNTRACK_DATA_TYPE struct zld_conn_data_ext
#endif
/*** add what you want in this data structure ***/

#ifdef ZLDCONFIG_NAC

#define ZYNAC_IP_HTABLE_SIZE 256
#define	ZYNAC_ACCEPT_MARK						0x00000001
#define	ZYNAC_DROP_MARK							0x00000002
#define	ZYNAC_PASS_MARK							0x00000004
#define ZYNAC_WEBAUTH_MARK                      0x00000008  /*1<<3*/
#define ZYNAC_SESSION_MASK						0x0000000F
#define ZYNAC_IPV4_VALID_HOOKS (1 << NF_INET_FORWARD)
#if defined(ZLDCONFIG_WEBAUTH_IPV6)
#define ZYNAC_IPV6_VALID_HOOKS (1 << NF_INET_FORWARD)
#endif
#endif

/* ZY_CT_XXX_SCANNED_SET is set when hit, ZY_CT_XXX_SESSION_SET is set when scanned */
#if defined(ZLDCONFIG_UTM_DASHBOARD)
#define ZY_CT_SCANNED_SET					0x0001
#define ZY_CT_BOTNET_SESSION_SET			0x0002
#define ZY_CT_BOTNET_SCANNED_SET			0x0004
#define ZY_CT_SANDBOX_SCANNED_SET			0x0008
#define ZY_CT_ANTIMALWARE_SCANNED_SET		0x0010
#define ZY_CT_IPS_SCANNED_SET				0x0020
#define ZY_CT_CONTENTFILTER_SCANNED_SET		0x0040
#define ZY_CT_EMAIL_SCANNED_SET				0x0080

#define ZY_CT_NOT_MALICIOUS					(ZY_CT_SCANNED_SET | ZY_CT_BOTNET_SESSION_SET)
#endif

struct zld_nf_conn
{
	/* zld routing mark */
	u_int32_t nfmarks[IP_CT_DIR_MAX];
	/*** for multipath routing ***/
	struct{
		int ct_oif[IP_CT_DIR_MAX];
		u_int32_t ct_gw[IP_CT_DIR_MAX];
	} route;

#if defined(ZLDCONFIG_IPSEC_QUICKSEC) || defined(ZLDCONFIG_SSLVPN_SUPPORT)
	u_int32_t from_vpn_id[IP_CT_DIR_MAX];
	u_int32_t to_vpn_id[IP_CT_DIR_MAX];
#endif
#if defined(ZLDCONFIG_IPSEC_QUICKSEC)
	u_int32_t from_vpn_spi[IP_CT_DIR_MAX];
	u_int32_t to_vpn_spi[IP_CT_DIR_MAX];
#endif

#ifdef ZLDCONFIG_NF_CT_FORWARD_HOOK /* ZyXEL, shunchao@2008.1.16 */
	long unsigned int start_jiffies;
	char rxif[IFNAMSIZ+1];	/* record the rx interface for 1st pkt */
	char txif[IFNAMSIZ+1];	/* record the tx interface for 1st pkt */
#endif
#ifdef ZLDCONFIG_NAC
	u_int32_t zynac_mark;
#endif
#ifdef ZLDCONFIG_WEBAUTH_ENHANCEMENT /*Different from zynac_mark*/
	u_int32_t zynac_webauth_mark;
#endif
#ifdef ZLDCONFIG_DSCP_V1
	u_int8_t dscp_code[2];
#endif

#ifdef ZLDCONFIG_BWM_STANDALONE
	struct {
		unsigned int bwm_rule_id;
		unsigned int bwm_proto_id;
		unsigned int bwm_cfg_ver;
		unsigned int tc_dir_out_class_id;
		unsigned int tc_dir_in_class_id;
#ifdef ZLDCONFIG_DSCP_V1
		u_int8_t	dscp_marking[2];
#endif
#ifdef ZLDCONFIG_BWM_PER_IP
		u_int8_t	bwm_type;
#endif
		u_int8_t	bwm_sip_direct_queue:1,
					bwm_app_any:1,
					bwm_srv_obj:1,
					bwm_app_id_unknow:1,
					bwm_reserved:4;
	} zld_bwm;
#endif

#ifdef ZLDCONFIG_GEO_IP_SUPPORT
	char src_country_code[4];
	u_int32_t src_country_flag;
	char dst_country_code[4];
	u_int32_t dst_country_flag;
#endif

	u_int8_t zldmark;
	
	unsigned char conn_original_source_mac[6];
	
	u_int32_t secure_policy_rule_id; /* cli_index */
	
	unsigned int zyipv6_frag_size;
	
#define DHA_SYNC_ZLD_CONN_SIZE (size_t)(&((struct zld_nf_conn*)0)->zld_syn_checksum)
 	uint64_t        zld_syn_checksum; /* sync dha */
  
  /* ZyXEL: traffic detection */
	unsigned long traffic_detect_next_notify;
	int traffic_detect_interval;
	int enable_traffic_detect;
	/* Traffic Detection */

	/* Connectivity check */
	pid_t conn_check_daemon_pid;
	
	/* SSL inspection */
#ifdef ZLDCONFIG_SSL_INSPECTION
	struct ssl_insp_ct_data sslinsp_ct_data;
#endif /* ENDIF_ZLDCONFIG_SSL_INSPECTION */

#ifdef ZLDCONFIG_RTCOMPL
	struct checklist_s rtcompl_info[IP_CT_DIR_MAX];
#endif
#ifdef ZLDCONFIG_RTCOMPL_DBG
	unsigned long conn_timestamp;
#endif

	long unsigned int zytable_jiffies[ZLD_TOTAL_TABLE]; /* ZLDCONFIG_SESSION_STATUS_UPDATE */
	u_int8_t zy_send_arp[ZLD_TOTAL_TABLE];
  
#ifdef ZLDCONFIG_ZYPKTORDER
	void *zypktorder;
#endif

#if defined(ZLDCONFIG_APP_PATROL)
	unsigned int	app_patrol_active:1,
					app_patrol_bwm_active:1,
					app_patrol_first_http:1, //quick detect for CF
					app_patrol_first_smtp:1, //quick detect for AS
					app_patrol_first_pop3:1, //quick detect for AS
					app_patrol_log_by_profile:1,
					app_patrol_final:1,
					app_patrol_control_session:1,
					app_patrol_statisticsed:1,
					app_patrol_logged:1,
					app_patrol_turnkey_error:2,
					app_patrol_reserved:4,
					app_patrol_profile_id:16;
	unsigned int 	app_id;
#if defined(ZLDCONFIG_APP_PATROL_QOSMOS)
	unsigned int 	previous_app_id;
    unsigned char   qmdpi_result;
#endif   
#endif

//#if defined(ZLDCONFIG_CONTENT_FILTER)
	unsigned int	cf_active:1,
					cf_log_by_profile:1,
					cf_warn_msg_count:4,
					cf_reserved:10,
					cf_profile_id:16;
//#endif

#if defined(ZLDCONFIG_ANTISPAM)
	unsigned int	as_active:1,
					as_log_by_profile:1,
					as_detected:1,
					as_reserved:13,
					as_profile_id:16;
#endif

#if defined(ZLDCONFIG_SSL_INSPECTION)
	unsigned int	ssl_inspection_active:1,
					ssl_inspection_log_by_profile:1,
					ssl_inspection_detected:2,
					ssl_inspection_reserved:12,
					ssl_inspection_profile_id:16;
#endif

#if defined(ZLDCONFIG_ANTIVIRUS)
	unsigned int	av_active:1,
					av_log_by_profile:1,
					av_turnkey_error:2,
					av_work_queue:1,
					av_detected:1,
					av_malicious_detected:1,
					av_suspicious_detected:1,
					av_cloud_threat_detected:1,
					av_sandbox_destroy:1,
					av_reserved:6,
					av_profile_id:16;
#endif

#if defined(ZLDCONFIG_IDP)
	unsigned int	idp_active:1,
					idp_log_by_profile:1,
					idp_action_drop:1,
					idp_turnkey_error:2,
					idp_reserved:11,
					idp_profile_id:16;
#endif
#if defined(ZLDCONFIG_ADP)
	unsigned int	adp_active:1,
					adp_reserved:7,
					adp_rule_id:12,
					adp_profile_id:12;
#endif

#if defined(ZLDCONFIG_ZYPARSER)
	unsigned int	zyparser_active:1;
	void			*zyparser_session;
#endif

#if defined(ZLDCONFIG_ANTIBOTNET)
	unsigned int	antibotnet_active:1,
					antibotnet_clear:1;
	void			*zybotnet_session;
#endif

#if defined(ZLDCONFIG_SANDBOX)
	unsigned int	sandbox_active: 1,
					sandbox_running: 1;
	void			*sandbox_session;
#endif

#if defined(ZLDCONFIG_IDP_ZYIDP)
	void			*sil_session;
#endif

#if defined(ZLDCONFIG_ANTIVIRUS_ZYAV)
	spinlock_t      zyav_lock;
	void			*zyav_session;
#endif

//#if defined(ZLDCONFIG_CONTENT_FILTER)
	spinlock_t cf_lock;	/* Check if ct will be released by ??? */
	uint32_t cfilter_state:16,
		 cf_http_len:3,
		 cf_http_needcompose: 1,
		 cf_reserved2: 12;
	uint16_t cf_msg_para;
	uint16_t cf_category_info_idx;
	int user_profile_id;
	int	event_class;
	uint32_t redirect_ip;
	uint16_t redirect_port;
	char *cf_warn_msg;
	char cf_http_method[8];
#if defined(ZLDCONFIG_CF_SAFESEARCH)
	spinlock_t offset_lock;
	struct list_head offset_list;
	uint32_t cf_seq_forward_offset;
	int acked_count;
  int safesearch_flag;
#endif
//#endif

#ifdef ZLDCONFIG_ANTISPAM
	void *as_session;
	spinlock_t as_session_lock;
	uint16_t server_tcp_mss;
	uint16_t client_tcp_mss;
	uint8_t	server_tcp_winscale;
	uint8_t	client_tcp_winscale;
	int32_t	as_seq_forward_offset;
	int32_t	as_seq_backward_offset;
	uint8_t as_send_ack[3];
#endif
	
#if defined(ZLDCONFIG_UTM_DISPATCHER)
	//void *utm_dispatcher_session;
#endif
#if defined(ZLDCONFIG_PROTOENFORCE)
	unsigned int proto_enforce_blocked : 1;
	unsigned int proto_enforce_init: 1;
	unsigned int proto_enforce_reserved: 30;
#endif
#if defined(ZLDCONFIG_UTM_DISPATCHER)
	union {
		unsigned long rawbits;
		struct {
			unsigned long av_detach: 1;
			unsigned long as_detach: 1;
			unsigned long cf_detach: 1;
			unsigned long ips_detach: 1;
			unsigned long antibotnet_ip_detach: 1;
			unsigned long antibotnet_url_detach: 1;
			unsigned long sandbox_detach: 1;
            unsigned long app_detach: 1;
			unsigned long zypktorder_active: 1;
			unsigned long utm_session_enable: 1;
			unsigned long service_flag: 1;
			unsigned long reserved: 53;
		} result;
	} security_ally;
#endif

#if defined(ZLDCONFIG_SSL_INSPECTION) && defined(ZLDCONFIG_SEARCH_ENGINE_SUPPORT_BROADWEB_IDP)
	struct {
		spinlock_t lock;
		struct list_head list;
		struct timer_list timer;
	}bw_ssl_session;
	unsigned int	bw_ssl_session_defragment_detected:1,
					bw_ssl_session_reserved:31;
#endif

#if defined(ZLDCONFIG_WEB_LOG_SUPPORT)
	struct {
   		uint32_t state:8,
		  			http_method_len:3,
		   			http_needcompose: 1,
					http_header_len: 16,
					http_queue_deep: 2,
					reserved: 2;
		char http_method[8];
		char *http_header;
	} weblog;
#if defined(ZLDCONFIG_WEB_LOG_HTTPS_SUPPORT)
	 u_int32_t zyweblog_mark;
#endif
#endif
#if defined(ZLDCONFIG_ADP_ZYADP)
	/*time_t zy_adp_block_time;*/
	void* zy_adp_tcpflowInfo;
#endif
        
#if defined(ZLDCONFIG_ZYFILE_STREAM_DECOMPRESSION)
    void *zyfsd_session;//zyfile stream decompression
#endif

#if defined(ZLDCONFIG_TLS_IDENT)
    unsigned int	zytsi_active:1,
					tsi_ssl_parser_finish:1,
					tsi_ssl_session_ok:1,
					tsi_ssl_client_hello:1,
					tsi_ssl_server_hello:1,
					tsi_ssl_final_version:16,
					tsi_ssl_alpn_type:8,
					reserved:3;
	void* zy_TSI_sessionInfo;
#endif

	/* For session scanned */
#if defined(ZLDCONFIG_UTM_DASHBOARD)
	unsigned short	zy_ct_utm_scanned;
#endif
};
struct zld_conn_data_ext {
    struct zld_nf_conn *zld_ct_data;
};

typedef int (*zld_conn_destroy_hookfn_t)( struct nf_conn* ct);

#define ZLD_CONN_DESTROY_HOOK_NAME_MAX_LEN	(32)

struct zld_conn_destroy_hooks_ops
{
    struct list_head list;

    /* User fills in from here down. */
    char name[ZLD_CONN_DESTROY_HOOK_NAME_MAX_LEN];
    zld_conn_destroy_hookfn_t hook;
    struct module *owner;
    /* Hooks are ordered in ascending priority. */
    int priority;
};

/* every registed cb function should has unique priority */
/* the small priority will run first */
enum zld_destroy_priority{
    ZLD_DESTROY_ZYSESSIONLIMIT = 0,
/* Add your priority here */

/* Don't move ZLD_DESTROY_ANY_PRIORITY */
/* If you don't care the sequence, use it*/
    ZLD_DESTROY_PRIORITY_ANY,
};

int zld_register_conn_destroy_hook(struct zld_conn_destroy_hooks_ops* reg);
void zld_unregister_conn_destroy_hook(struct zld_conn_destroy_hooks_ops* reg);
struct zld_nf_conn *zld_conn_data_find(struct nf_conn *ct);
struct zld_nf_conn *zld_conn_data_get(struct nf_conn *ct);

/*
	   ct      rule    jiffies
	   90      100+3   100        if( (ct != rule) && rule && ( jiffies > rule) ) ZLD_SESSION_NEED_UPDATE
*/
static inline int zld_check_session_time(long unsigned int zld_ct_jiffies, int zy_rule_table)
{
	if( (zld_rule_update_time[zy_rule_table] != zld_ct_jiffies) && (zld_rule_update_time[zy_rule_table])
		&& ( time_after(jiffies,zld_rule_update_time[zy_rule_table]) ) ) {
		return ZLD_SESSION_NEED_UPDATE;
	}
	return ZLD_SESSION_NO_NEED_UPDATE;
}

extern unsigned int zld_free_artificial_skb(struct sk_buff *skb, unsigned int result);
extern unsigned int zld_zynac_mark_transform(unsigned int zynac_mark);
extern unsigned int zld_result_update(struct sk_buff *skb, struct nf_conn *ct, struct zld_nf_conn *zld_ct,  int zy_rule_table, unsigned int result);
extern unsigned int zld_ignore_confirmed_skb(struct sk_buff *skb, int zy_rule_table);
extern int zld_synchronization_rule_update_time(int zy_rule_table);
extern unsigned int
zld_pre_ipt_do_table(struct sk_buff *skb,
		 struct nf_conn *ct,
		 struct zld_nf_conn *zld_ct,
	     unsigned int hook,
	     const struct net_device *in,
	     const struct net_device *out,
		 int zy_rule_table );

extern struct sk_buff *new_zynac_skb(int pkt_len, struct nf_conn *ct);
#ifdef ZLD_ZYSSU_DEBUG_PRINT
extern int zld_dbg(struct sk_buff *skb,
	           const struct net_device *in,
			   const struct net_device *out,
			   int zy_rule_table,
			   int printk_flag, unsigned int index);
#endif

#if defined(ZLDCONFIG_UTM_DASHBOARD)
static inline void set_ct_utm_scanned_bit(struct zld_nf_conn *zld_ct)
{
	zld_ct->zy_ct_utm_scanned |= ZY_CT_SCANNED_SET;
}

static inline void set_ct_utm_botnet_session_bit(struct zld_nf_conn *zld_ct)
{
	zld_ct->zy_ct_utm_scanned |= ZY_CT_BOTNET_SESSION_SET;
}
#endif

#endif  /* _ZLD_CONNTRACK_DATA_H */
