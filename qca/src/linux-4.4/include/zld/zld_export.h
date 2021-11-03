/* Copyright 2012-2035, ZyXEL Communications Corp. All rights reserved. */

#ifndef _ZLD_EXPORT_H
#define _ZLD_EXPORT_H

#ifdef CONFIG_IPV6
#include <linux/in6.h>
#endif
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/usb.h>
#include <net/ip_fib.h>

//#include <zld-spec.h>

//#ifdef CONFIG_ZLD_CONNTRACK_DATA
#include <zld/zld_conntrack_data.h>
//#endif

#ifdef CONFIG_BRIDGE
#include "../net/bridge/br_private.h"
#endif
#ifdef CONFIG_ZLD_8021Q_VLAN_ENHANCE
#include "../net/8021q/vlan.h"
#endif

#if defined(CONFIG_ZLD_CONNTRACK_DATA) && defined(CONFIG_ZLD_KERNEL_ALG_SUPPORT)
#include <net/netfilter/nf_conntrack_expect.h>
#endif
typedef struct zld_export_s {
#if 1 /* WAS: CONFIG_IFACENAME_CHANGE, IS: the flag is removed. */
	int (*k_eth_to_user_define)(char *iface, char *ud_iface);
	int (*interface_get_property_by_iface_name)(char *internal_name);
#endif

	int (*zyklog)(char *fac, int pri, unsigned int srcip, unsigned int srcport, unsigned int dstip, unsigned int dstport, const char *fmt, ...);
#ifdef CONFIG_IPV6
	int (*zyklog6)(char *fac, int pri, struct in6_addr *srcip, unsigned int srcport, struct in6_addr *dstip, unsigned int dstport, const char *fmt, ...);
#endif
	void (*zyfib_select_multipath)(const struct flowi *flp, struct fib_result *res, struct sk_buff *skb);
#if 1 // hack for packet trace
	int (*zyinetpkt_skb_dump)(unsigned int verdict, struct nf_hook_ops *elem,
					   struct sk_buff *skb, const struct net_device *nf_indev,
					   const struct net_device *nf_outdev, unsigned long jtick);
	int zyinetpkt_enable;
#endif
//#ifdef CONFIG_ZLD_CONNTRACK_DATA
	struct zld_nf_conn *(*zld_conn_data_get)(struct nf_conn *ct);
	struct zld_nf_conn *(*zld_conn_data_find)(struct nf_conn *ct);
//#endif
} zld_export_t;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
extern struct ctl_table_header *zld_register_sysctl(struct net *zld_net,
	const char *zld_path, struct ctl_table *zld_table);
    
extern struct device *zld_device_create(struct class *class, struct device *parent,
			     dev_t devt, void *drvdata, const char *fmt, ...);

extern void zld_device_destroy(struct class *class, dev_t devt);
extern struct class *zld_class_create(struct module *owner, const char *name,
			     struct lock_class_key *key);
extern void zld_class_destroy(struct class *cls);
extern struct nf_conntrack_tuple_hash *
    zld_nf_conntrack_find_get(struct net *net, u16 zone,
		      const struct nf_conntrack_tuple *tuple);
#endif
extern zld_export_t zld_export_cb;
extern int zld_enable_as_ssi_except_ports;

#ifdef CONFIG_ZLD_BOARD_SPEC
extern void zld_hw_cpld_restart(void);
#endif

#if defined(ZLDSYSPARM_SUPPORT_USB_STORAGE) || defined(ZLDSYSPARM_BUILD_USB_HUB)
extern struct usb_device *zld_usb_find_device(u16 vendor_id, u16 product_id);
#endif
extern void printk_hex(const char *title, const void *data, size_t data_len, const char *level);
extern void skb_info(const struct sk_buff *skb);
extern void __ct_nul_debug(const struct sk_buff *skb, const char *func_name, int line_no, const char *fmt, ...)
	__attribute__((format (printf, 4, 5)));
extern void __zld_ct_nul_debug(const struct sk_buff *skb, const char *func_name, int line_no, const char *fmt, ...)
	__attribute__((format (printf, 4, 5)));
#ifdef CONFIG_BRIDGE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
extern struct net_bridge_fdb_entry *(*__br_fdb_get_hook)(struct net_bridge *br, const unsigned char *addr, __u16 vid);
#else
extern struct net_bridge_fdb_entry *(*__br_fdb_get_hook)(struct net_bridge *br, const unsigned char *addr);
#endif
#endif
#ifdef CONFIG_ZLD_8021Q_VLAN_ENHANCE
extern struct net_device *zld_find_vlan_dev(struct net_device *real_dev,unsigned short VID);
extern struct net_device *zld_get_realdev_from_vlandev(struct net_device *dev);
extern uint16_t  zld_get_vlanId_from_vlandev(struct net_device *dev);
#endif
extern int zld_nf_ct_is_untracked(struct sk_buff *skb);
extern bool zld_nf_ct_kill(struct nf_conn *ct);

void zld_show_all_task(void);

#ifdef CONFIG_ZLD_MULTIPATH_TRUNK
static __inline__ int
zyinet_ifa_match(__be32 addr, struct in_ifaddr *ifa)
{
	return !((addr ^ ifa->ifa_local) & ifa->ifa_mask);
}

__be32 zyconfirm_addr_indev(struct in_device *in_dev, __be32 dst, __be32 local, int scope);
__be32 zyinet_confirm_addr(const struct net_device *dev, __be32 dst, __be32 local, int scope);
#endif

#if defined(CONFIG_ZLD_CONNTRACK_DATA) && defined(CONFIG_ZLD_KERNEL_ALG_SUPPORT)
extern void zld_hack_conntrack_core(struct nf_conn *ct,struct nf_conntrack_expect *exp);
#endif

#define ct_nul_debug(skb, dbg_on, fmt, args...) \
	do { \
		if (unlikely(dbg_on)) { \
			__ct_nul_debug(skb, __FUNCTION__, __LINE__, KERN_DEBUG fmt, ##args); \
		} \
	} while (0)

#define zld_ct_nul_debug(skb, dbg_on, fmt, args...) \
	do { \
		if (dbg_on) { \
			__zld_ct_nul_debug(skb, __FUNCTION__, __LINE__, KERN_DEBUG fmt, ##args); \
		} \
	} while (0)

#if defined(ZLDCONFIG_CPU_CORE_LOCK)
void init_timer_key_cpu_lock(struct timer_list *timer,
		    const char *name,
		    struct lock_class_key *key);

#define init_timer_cpu_lock(timer)\
	init_timer_key_cpu_lock((timer), NULL, NULL)
#endif

#endif  /* _ZLD_EXPORT_H */
