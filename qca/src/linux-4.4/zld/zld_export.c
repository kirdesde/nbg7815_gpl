/* Copyright 2012-2035, ZyXEL Communications Corp. All rights reserved. */

//#include <zld-spec.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#include <linux/autoconf.h>
#else
#include <generated/autoconf.h>
#endif
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/sched.h>
#ifdef ZLDSYSPARM_SUPPORT_USB_STORAGE
#include <linux/usb.h>
#endif /* ZLDSYSPARM_SUPPORT_USB_STORAGE */
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sysctl.h>
#include <linux/percpu.h>
#ifdef CONFIG_ZLD_KERNEL_TIME_PROFILING
#include <linux/timex.h>
#include <linux/time.h>
#endif /* CONFIG_ZLD_KERNEL_TIME_PROFILING */
#ifdef CONFIG_ZLD_IMAGE_RECOVERY_POINT_SUPPORT
#include <linux/reboot.h>
#include <linux/oom.h>
#include <linux/notifier.h>
#endif
#ifdef ZLDCONFIG_IPV6
#include <linux/ipv6.h>
#include <net/ipv6.h>
#endif
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,0,0)
	#include <net/netfilter/nf_conntrack_zones.h>
#endif
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/version.h>
#include <asm/atomic.h>

#include <zld/zld_export.h>
#ifdef CONFIG_ZLD_WDT_SUPPORT
#include <zld/zld_bsp.h>
#endif /* ENDIF_CONFIG_ZLD_WDT_SUPPORT */
#include <zld/zld_common.h>
//#include <cpld_defs.h>
//#include <gpio_defs.h>
//#include <asm/octeon/cvmx-gpio.h>
#include <linux/of.h>
extern unsigned int irq_create_of_mapping(struct of_phandle_args *irq_data);

#ifdef CONFIG_ZLD_8021Q_VLAN_ENHANCE
int (*switch_port_rx_vlan_hook)(struct sk_buff *skb) = NULL;
int (*switch_port_tx_vlan_hook)(struct sk_buff *skb) = NULL;
struct net_device *zld_find_vlan_dev(struct net_device *real_dev,unsigned short VID);
struct net_device *zld_get_realdev_from_vlandev(struct net_device *dev);
uint16_t  zld_get_vlanId_from_vlandev(struct net_device *dev);
#endif
#ifdef CONFIG_BRIDGE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
struct net_bridge_fdb_entry *(*__br_fdb_get_hook)(struct net_bridge *br, const unsigned char *addr, __u16 vid) __read_mostly = NULL;
#else
struct net_bridge_fdb_entry *(*__br_fdb_get_hook)(struct net_bridge *br, const unsigned char *addr) __read_mostly = NULL;
#endif
#endif

zld_export_t zld_export_cb;

#ifdef CONFIG_ZLD_WDT_SUPPORT
kicCb_t infocollector_cb;

int reboot_on_oom __read_mostly = 30;
int reboot_on_hang __read_mostly = 30;
int disklog_retry_thresh __read_mostly = 3;

int softlockup_next_collect_interval __read_mostly = 60;
int softlockup_raise_console_loglevel_enable __read_mostly = 0;

static int softlockup_next_check_interval_min __read_mostly = 1;
#if 1
extern int softlockup_thresh;
EXPORT_SYMBOL(softlockup_thresh);
#else
static int softlockup_next_check_interval_max = 120;
#endif

DEFINE_PER_CPU(atomic_t, softlockup_hang_count) = ATOMIC_INIT(0);

char fwVersion[128];
extern void show_slab_info(void);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
extern void show_mem(void);
#else
extern void show_mem(unsigned int);
#endif
extern void show_state_filter(unsigned long state_filter);
extern void show_regs(struct pt_regs *regs);
zld_hw_wd_t hw_wd_op;
EXPORT_SYMBOL(hw_wd_op);
#endif /* ENDIF_CONFIG_ZLD_WDT_SUPPORT */

#ifdef CONFIG_ZLD_DISK_LOG_SUPPORT
logDiskCB_t logDisk_cb;
void (*zld_storage_hw_reset)(void);
#endif /* CONFIG_ZLD_DISK_LOG_SUPPORT */
#ifdef CONFIG_ZLD_REALLOG_MMC
extern struct gendisk *get_gendisk(dev_t devt, int *partno);
#endif /* CONFIG_ZLD_REALLOG_MMC */


struct us_data *zld_usb_stor_p1 = NULL;
EXPORT_SYMBOL(zld_usb_stor_p1);

#ifdef CONFIG_ZLD_FORCE_KSOFTIRQD
#ifdef CONFIG_ZLD_SYSCTL_MAX_SOFTIRQ_RESTART

#ifdef CONFIG_ZLD_MAX_SOFTIRQ_RESTART
#define MAX_SOFTIRQ_RESTART CONFIG_ZLD_MAX_SOFTIRQ_RESTART
#else
#define MAX_SOFTIRQ_RESTART 10
#endif

atomic_t max_softirq_restart __read_mostly = ATOMIC_INIT(MAX_SOFTIRQ_RESTART);

static int max_softirq_restart_min = 1;
static int max_softirq_restart_max = 32;

#endif /* ENDIF_CONFIG_ZLD_SYSCTL_MAX_SOFTIRQ_RESTART */
#endif /* ENDIF_CONFIG_ZLD_FORCE_KSOFTIRQD */

static int zld_conntrack_null_debug = 0;
static int zld_nf_ct_is_untracked_debug = 0;
static struct ctl_table_header *zld_ctl_table_header = NULL;
int zld_enable_as_ssi_except_ports  __read_mostly = 1;
#ifdef ZLDCONFIG_ICSA_FIREWALL_PATCH
int zld_icsa_icmp_destroy_session __read_mostly = 1;
#endif
#ifdef CONFIG_ZLD_IMAGE_RECOVERY_POINT_SUPPORT
/* For watchdog-1.0-module/zld_wdt_core.c */
int is_recovery = 0;
EXPORT_SYMBOL(is_recovery);
/* oom will auto reboot */
static int recovery_point_oom_notify_sys(struct notifier_block *this, unsigned long code, void *data);
struct notifier_block recovery_point_oom_notifier = {
        .notifier_call = recovery_point_oom_notify_sys,
        .priority = 1,
};
EXPORT_SYMBOL(recovery_point_oom_notifier);
/* panic and oops will auto reboot */
static int recovery_point_panic_notify_sys(struct notifier_block *this, unsigned long code, void *data);
struct notifier_block recovery_point_panic_notifier = {
        .notifier_call = recovery_point_panic_notify_sys,
        .priority = 1,
};
EXPORT_SYMBOL(recovery_point_panic_notifier);
int boot_ok = 0;
#endif
#ifdef CONFIG_ZLD_VIRTUAL_IF_ENHANCEMENT
int virtual_if_qdisc_flag = 0;
EXPORT_SYMBOL(virtual_if_qdisc_flag);
#endif

static struct ctl_table zld_kernel_ctl_table[] = {
#if defined(CONFIG_ZLD_FORCE_KSOFTIRQD) && defined(CONFIG_ZLD_SYSCTL_MAX_SOFTIRQ_RESTART)
	{
		.procname		= "max_softirq_restart",
		.data			= &max_softirq_restart,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1			= &max_softirq_restart_min,
		.extra2			= &max_softirq_restart_max,
	},
#endif
#ifdef CONFIG_ZLD_WDT_SUPPORT
	{
		.procname		= "reboot_on_oom",
		.data			= &reboot_on_oom,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname		= "reboot_on_hang",
		.data			= &reboot_on_hang,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname		= "disklog_retry_thresh",
		.data			= &disklog_retry_thresh,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname		= "softlockup_next_collect_interval",
		.data			= &softlockup_next_collect_interval,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1			= &softlockup_next_check_interval_min,
		.extra2			= &softlockup_thresh,
	},
	{
		.procname		= "softlockup_raise_console_loglevel_enable",
		.data			= &softlockup_raise_console_loglevel_enable,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif /* ENDIF_CONFIG_ZLD_WDT_SUPPORT */
#ifdef CONFIG_ZLD_IMAGE_RECOVERY_POINT_SUPPORT
        {
                .procname               = "boot_ok",
                .data                   = &boot_ok,
                .maxlen                 = sizeof(int),
                .mode                   = 0644,
                .proc_handler   = &proc_dointvec,
        },
#endif
	{
		.procname		= "zld_conntrack_null_debug",
		.data			= &zld_conntrack_null_debug,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname		= "zld_nf_ct_is_untracked_debug",
		.data			= &zld_nf_ct_is_untracked_debug,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname		= "zld_enable_as_ssi_except_ports",
		.data			= &zld_enable_as_ssi_except_ports,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
	},
#ifdef ZLDCONFIG_ICSA_FIREWALL_PATCH
	{
		.procname		= "zld_icsa_icmp_destroy_session",
		.data			= &zld_icsa_icmp_destroy_session,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
#ifdef CONFIG_ZLD_VIRTUAL_IF_ENHANCEMENT
	{
		.procname		= "virtual_if_qdisc_flag",
		.data			= &virtual_if_qdisc_flag,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{ }
};

#if defined(CONFIG_ZLD_CONNTRACK_DATA) && defined(CONFIG_ZLD_KERNEL_ALG_SUPPORT)
void
zld_hack_conntrack_core(struct nf_conn *ct, struct nf_conntrack_expect *exp)
{
	do {
		struct zld_nf_conn *zld_ct, *zld_ct_master;
		typeof(zld_export_cb.zld_conn_data_get) zld_conn_data_get_fn;
		typeof(zld_export_cb.zld_conn_data_find) zld_conn_data_find_fn;
		rcu_read_lock();
		zld_conn_data_get_fn = rcu_dereference(zld_export_cb.zld_conn_data_get);
		zld_conn_data_find_fn = rcu_dereference(zld_export_cb.zld_conn_data_find);
		if (unlikely(zld_conn_data_get_fn == NULL || zld_conn_data_find_fn == NULL)) {
			printk(KERN_DEBUG "%s [%d]: ZLD conntrack data module isn't ready!\n", __FUNCTION__, __LINE__);
		}
		else {
			zld_ct_master = zld_conn_data_get_fn(ct->master);
			if (likely(zld_ct_master)) {
				zld_ct = zld_conn_data_find_fn(ct);
				if (likely(zld_ct)) {
					if (exp->dir) {
						zld_ct->nfmarks[0] = zld_ct_master->nfmarks[1];
						zld_ct->nfmarks[1] = zld_ct_master->nfmarks[0];
#ifdef CONFIG_ZLD_DSCP_V1
						zld_ct->dscp_code[0] = zld_ct_master->dscp_code[1];
						zld_ct->dscp_code[1] = zld_ct_master->dscp_code[0];
#endif
					}
					else {
						zld_ct->nfmarks[0] = zld_ct_master->nfmarks[0];
						zld_ct->nfmarks[1] = zld_ct_master->nfmarks[1];
#ifdef CONFIG_ZLD_DSCP_V1
						zld_ct->dscp_code[0] = zld_ct_master->dscp_code[0];
						zld_ct->dscp_code[1] = zld_ct_master->dscp_code[1];
#endif
					}
				}
			}
		}
		rcu_read_unlock();
	} while (0);
}
#endif

static void __init
zld_kernel_ctl_init(void)
{
	struct ctl_path kernel_ctl_path[] = {
		{ .procname = "kernel",
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,0,0)
			.ctl_name = CTL_KERN,
#endif
			},
		{ },
	};
	zld_ctl_table_header = register_sysctl_paths(kernel_ctl_path, zld_kernel_ctl_table);
	if (!zld_ctl_table_header) {
		printk(KERN_ERR "%s [%d]: register_sysctl_paths() failed!\n", __FUNCTION__, __LINE__);
		return;
	}
}

#ifdef ZLDCONFIG_IPSEC_QUICKSEC
int (*vpn_find_tunnel_name_by_tunnel_id)(
	u_int32_t zy_tunnel_id,
	unsigned char *tunnel_name,
	int tunnel_name_len);
#endif /* ZLDCONFIG_IPSEC_QUICKSEC */

#if defined(ZLDSYSPARM_SUPPORT_USB_STORAGE) || defined(ZLDSYSPARM_BUILD_USB_HUB)
struct usb_device *
zld_match_device(struct usb_device *dev, u16 vendor_id, u16 product_id)
{
	struct usb_device *ret_dev = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	struct usb_device *childdev = NULL;
#endif
	int child;

	if (dev == NULL) {
		printk(KERN_ERR "usb dev is NULL\n");
		goto exit;
	}

	if (vendor_id != 0 && product_id != 0) {
		/* see if this device matches */
		if ((vendor_id == le16_to_cpu(dev->descriptor.idVendor)) &&
	    	(product_id == le16_to_cpu(dev->descriptor.idProduct))) {
			ret_dev = usb_get_dev(dev);
			goto exit;
		}
	} else {
	if((dev->product != NULL) && (dev->manufacturer != NULL)){
		/* see if this device matches */
		if (!strncmp(dev->product, ZLD_FIXED_DISK_PRODUCT_ID, 10) &&
	    		!strncmp(dev->manufacturer, ZLD_FIXED_DISK_VENDOR_ID, 5)) {
			ret_dev = usb_get_dev(dev);
			goto exit;
		}
	}
	}

	/* look through all of the children of this device */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
		usb_hub_for_each_child(dev, child, childdev) {
		usb_lock_device(childdev);
		ret_dev = zld_match_device(childdev, vendor_id, product_id);
		usb_unlock_device(childdev);
		if (ret_dev)
			goto exit;
	}
#else
	for (child = 0; child < dev->maxchild; ++child) {
		if (dev->children[child]) {
			usb_lock_device(dev->children[child]);
			ret_dev = zld_match_device(dev->children[child], vendor_id, product_id);
			usb_unlock_device(dev->children[child]);
			if (ret_dev)
				goto exit;
		}
	}
#endif
exit:
	return ret_dev;
}

extern struct mutex usb_bus_list_lock;
extern struct list_head usb_bus_list;

struct usb_device *
zld_usb_find_device(u16 vendor_id, u16 product_id)
{
	struct list_head *buslist;
	struct usb_bus *bus;
	struct usb_device *dev = NULL;

	mutex_lock(&usb_bus_list_lock);
	for (buslist = usb_bus_list.next; buslist != &usb_bus_list; buslist = buslist->next) {
		bus = container_of(buslist, struct usb_bus, bus_list);
		if (!bus->root_hub)
			continue;
		usb_lock_device(bus->root_hub);
		dev = zld_match_device(bus->root_hub, vendor_id, product_id);
		usb_unlock_device(bus->root_hub);
		if (dev)
			goto exit;
	}
exit:
	mutex_unlock(&usb_bus_list_lock);
	return dev;
}
#endif /* ZLDSYSPARM_SUPPORT_USB_STORAGE */

void
printk_hex(const char *title, const void *data, size_t data_len, const char *level)
{
	int i;
	int line_num;
	/*
	 * NOTE: Kernel stack is 4K/8K, be careful!
	 * Besides, I use 'sprintf()' instead of 'snprintf()' in this function,
	 * make sure that buffer's size is enough.
	 */
#define BUF_LEN 128
	char buf[BUF_LEN];
#undef BUF_LEN
	const char *ptr;
	char *ascii_buf_ptr;

	/* Print title */
	if (title) {
		printk("%s%s: data = %p, data_len = %zu\n", level, title, data, data_len);
	}
	else {
		printk("%sdata = %p, data_len = %zu\n", level, data, data_len);
	}

	if (unlikely(data_len == 0)) {
		return;
	}

	for (ptr = data, line_num = 1; data_len >= 16; ptr += 16, data_len -= 16, line_num++) {
		sprintf(buf, ZLD_HEX_FMT, line_num, line_num, ZLD_HEX(ptr));
		/* ascii_buf_ptr = buf + strlen(buf); */
		ascii_buf_ptr = buf + ZLD_HEX_FMT_SIZE;
		for (i = 0; i < 16; i++) {
			if (isascii(ptr[i]) && isprint(ptr[i])) {
				*ascii_buf_ptr = ptr[i];
			}
			else {
				*ascii_buf_ptr = '.';
			}
			ascii_buf_ptr++;

			if (i == 7) {
				*ascii_buf_ptr = ' ';
				ascii_buf_ptr++;
			}
		}
		*ascii_buf_ptr = '\0';
		printk("%s   %s\n", level, buf);
	}

	if (data_len > 0) {
		char *buf_ptr;
		memset(buf, ' ', sizeof(buf));
		sprintf(buf, ZLD_HEX_LINE_INFO_FMT, line_num, line_num);
		for (i = 0, buf_ptr = buf + ZLD_HEX_LINE_INFO_FMT_SIZE, ascii_buf_ptr = buf + ZLD_HEX_FMT_SIZE; i < data_len; i++, ptr++, buf_ptr += 3) {
			if (unlikely(i == 8)) {
				sprintf(buf_ptr, "-%02hhX", *((const unsigned char *) ptr));
				*ascii_buf_ptr = ' ';
				ascii_buf_ptr++;
			}
			else {
				sprintf(buf_ptr, " %02hhX", *((const unsigned char *) ptr));
			}
			if (isascii(*ptr) && isprint(*ptr)) {
				*ascii_buf_ptr = *ptr;
			}
			else {
				*ascii_buf_ptr = '.';
			}
			ascii_buf_ptr++;
		}
		*buf_ptr = ' ';
		*ascii_buf_ptr = '\0';
		printk("%s   %s\n", level, buf);
	}
	printk("%s\n", level);
}

void
skb_info(const struct sk_buff *skb)
{
	unsigned char *cp;

	if (!skb || (atomic_read(&skb->users) <= 0)) {
		return;
	}

	if (skb->protocol == __constant_htons(ETH_P_IP)) {
		struct iphdr *iph = ip_hdr(skb);

		switch(iph->protocol) {
		case IPPROTO_TCP:
			{
				struct tcphdr *tcph = tcp_hdr(skb);

				printk("%s(): IP skb= <%p> nfct= %p (info= %d)\n" \
						"  TCP, %pI4:%u->%pI4:%u\n",
						__func__, skb, skb->nfct, skb->nfctinfo,
						&iph->saddr, ntohs(tcph->source),
						&iph->daddr, ntohs(tcph->dest));
				break;
			}
		case IPPROTO_UDP:
			{
				struct udphdr *udph = udp_hdr(skb);

				printk("%s(): IP skb= <%p> nfct= %p (info= %d)\n" \
						"  UDP, %pI4:%u->%pI4:%u\n",
						__func__, skb, skb->nfct, skb->nfctinfo,
						&iph->saddr, ntohs(udph->source),
						&iph->daddr, ntohs(udph->dest));
				break;
			}
		case IPPROTO_ICMP:
			{
				cp = skb_transport_header(skb);

				printk("%s(): IP skb= <%p> nfct= %p (info= %d)\n" \
						"  ICMP, %pI4->%pI4 type %u code %u\n",
						__func__, skb, skb->nfct, skb->nfctinfo,
						&iph->saddr, &iph->daddr,
						*cp, *(cp + 1));
				break;
			}
		default:
			printk("%s(): IP skb= <%p> nfct= %p (info= %d)\n" \
					"  protocol= %u, %pI4->%pI4\n",
					__func__, skb, skb->nfct, skb->nfctinfo, iph->protocol,
					&iph->saddr, &iph->daddr);
			break;
		}
#ifdef ZLDCONFIG_IPV6
	}
	else if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = ipv6_hdr(skb);
		u8 nexthdr = ip6h->nexthdr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
  __be16 fragoff;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
		ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &nexthdr, &fragoff);
#else
		ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &nexthdr);
#endif
		switch(nexthdr) {
		case IPPROTO_TCP:
			{
				struct tcphdr *tcph = tcp_hdr(skb);

				printk("%s(): IPv6 skb= <%p> nfct= %p (info= %d)\n" \
						"  TCP, %pI6:%u->%pI6:%u\n",
						__func__, skb, skb->nfct, skb->nfctinfo,
						&ip6h->saddr, ntohs(tcph->source),
						&ip6h->daddr, ntohs(tcph->dest));
				break;
			}
		case IPPROTO_UDP:
		case IPPROTO_UDPLITE:
			{
				struct udphdr *udph = udp_hdr(skb);

				printk("%s(): IPv6 skb= <%p> nfct= %p (info= %d)\n" \
						"  %s, %pI6:%u->%pI6:%u\n",
						__func__, skb, skb->nfct, skb->nfctinfo,
						(nexthdr == IPPROTO_UDPLITE) ? "UDP-Lite" : "UDP",
						&ip6h->saddr, ntohs(udph->source),
						&ip6h->daddr, ntohs(udph->dest));
				break;
			}
		case IPPROTO_ICMPV6:
			{
				cp = skb_transport_header(skb);

				printk("%s(): IPv6 skb= <%p> nfct= %p (info= %d)\n" \
						"  ICMPv6, %pI6->%pI6 type %u code %u\n",
						__func__, skb, skb->nfct, skb->nfctinfo,
						&ip6h->saddr, &ip6h->daddr,
						*cp, *(cp + 1));
				break;
			}
		default:
			printk("%s(): IPv6 skb= <%p> nfct= %p (info= %d)\n" \
					"  protocol= %u, %pI6->%pI6\n",
					__func__, skb, skb->nfct, skb->nfctinfo, nexthdr,
					&ip6h->saddr, &ip6h->daddr);
			break;
		}
#endif /* ZLDCONFIG_IPV6 */
	} else {
		printk("%s(): skb= <%p> protocol= 0x%x\n", __func__, skb, skb->protocol);
	}

	return;
}

void
__ct_nul_debug(const struct sk_buff *skb, const char *func_name, int line_no, const char *fmt, ...)
{
	if (zld_conntrack_null_debug) {
		va_list args;

		printk(KERN_DEBUG "%s [%d]: Cannot find the conntrack\n", func_name, line_no);

		va_start(args, fmt);
		vprintk(fmt, args);
		va_end(args);

		printk_hex(NULL, skb->data, skb_headlen(skb), KERN_DEBUG);
		skb_info(skb);
	}
}

void
__zld_ct_nul_debug(const struct sk_buff *skb, const char *func_name, int line_no, const char *fmt, ...)
{
	if (zld_conntrack_null_debug) {
		va_list args;
#if 1
		struct nf_conn *ct = (struct nf_conn *) skb->nfct;
#else
		enum ip_conntrack_info ctinfo;
		struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
		if (!nf_ct_is_untracked(ct))
#else
		if (!nf_ct_is_untracked(skb))
#endif
		{
			unsigned long status;

			if (likely(ct)) {
				status = ct->status;
			}
			else {
				status = 0xFFFFFFFF;
			}
			printk(KERN_DEBUG "%s [%d]: Cannot find the ZLD conntrack data, ct's status = 0x%lx\n", func_name, line_no, status);

			va_start(args, fmt);
			vprintk(fmt, args);
			va_end(args);

			printk_hex(NULL, skb->data, skb_headlen(skb), KERN_DEBUG);
			skb_info(skb);
		}
#if 0
		else {
			printk(KERN_DEBUG "%s [%d]: This skb's ct is untracked\n", func_name, line_no);
			printk_hex(NULL, skb->data, skb_headlen(skb), KERN_DEBUG);
			skb_info(skb);
		}
#endif
	}
}
#if 0
static const char zld_stat_nam[] = TASK_STATE_TO_CHAR_STR;

static void
__zld_show_task(struct task_struct *p)
{
	unsigned state;
	char buf[TASK_COMM_LEN + 2];

	state = p->state ? __ffs(p->state) + 1 : 0;
	snprintf(buf, sizeof(buf), "[%s]", p->comm);

	printk("%-18.18s   state = %c, ", buf, (state < sizeof(zld_stat_nam) - 1)? zld_stat_nam[state]: '?');
	printk("PID = %5d, TGID = %5d, PPID = %5d, flags = 0x%08lx\n",
			task_pid_nr(p), task_tgid_nr(p),
			p->real_parent? task_pid_nr(p->real_parent): 0,
			(unsigned long) task_thread_info(p)->flags);
}

static void
__zld_show_task_meminfo(struct mm_struct *mm)
{
	unsigned long size, text, data, stack, shared, rss, lib, pte;

	size = mm->total_vm << (PAGE_SHIFT - 10);
	text = (PAGE_ALIGN(mm->end_code) - (mm->start_code & PAGE_MASK)) >> 10;
	data = (mm->total_vm - mm->shared_vm - mm->stack_vm) << (PAGE_SHIFT - 10);
	stack = mm->stack_vm << (PAGE_SHIFT - 10);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
	shared = get_mm_counter(mm, file_rss) << (PAGE_SHIFT - 10);
	rss = shared + (get_mm_counter(mm, anon_rss) << (PAGE_SHIFT - 10));
#else
	shared = get_mm_counter(mm, MM_FILEPAGES) << (PAGE_SHIFT - 10);
	rss = shared + (get_mm_counter(mm, MM_ANONPAGES) << (PAGE_SHIFT - 10));
#endif
	lib = (mm->exec_vm << (PAGE_SHIFT - 10)) - text;
	pte = (PTRS_PER_PTE * sizeof(pte_t) * mm->nr_ptes) >> 10;

	printk("     Size:   %8lu kB, Text: %8lu kB, Data: %8lu kB, Stack: %8lu kB\n"
		   "     Shared: %8lu kB, RSS:  %8lu kB, Lib:  %8lu kB, PTE:   %8lu kB\n",
			size, text, data, stack,
			shared, rss, lib, pte);
}

void
zld_show_all_task(void)
{
	int retries = 0;
	struct task_struct *g, *p;

#if 1
	while (!read_trylock(&tasklist_lock)) {
		touch_all_softlockup_watchdogs();
		mdelay(1000);
		if (retries++ >= 10) {
			printk(KERN_EMERG "%s [%d]: Cannot hold tasklist_lock!\n", __FUNCTION__, __LINE__);
			return;
		}
	}
#else
	read_lock(&tasklist_lock);
#endif

	/* XXX: Need to dump info. of LWP? */
	do_each_thread(g, p) {
		struct mm_struct *mm;

		__zld_show_task(p);

		mm = get_task_mm(p);
		if (mm) {
			__zld_show_task_meminfo(mm);
			mmput(mm);
		}
		printk("\n");

		touch_all_softlockup_watchdogs();
	} while_each_thread(g, p);

	read_unlock(&tasklist_lock);
}
#endif
#ifdef CONFIG_ZLD_WDT_SUPPORT
static void __init
zld_wdt_init(void)
{
	kicCb_t *kiccb_p;

	memset(&infocollector_cb, 0, sizeof(kicCb_t));
	kiccb_p = &infocollector_cb;
	kiccb_p->kic_process = NULL;
}
#endif /* ENDIF_CONFIG_ZLD_WDT_SUPPORT */

#ifdef CONFIG_ZLD_KERNEL_TIME_PROFILING
#define MAX_ZLD_KERNEL_DEBUG_CNT 10000
typedef struct zld_kernel_dbg_s {
	void *id;
	struct timespec time;
	unsigned long data[4];
} zld_kernel_dbg_t;

zld_kernel_dbg_t zld_kernel_dbg[MAX_ZLD_KERNEL_DEBUG_CNT];
int zld_dbg_index = 0;
int zld_dbg_enable = 0;

void
disp_zld_kernel_dbg( int start, int end )
{
	zld_kernel_dbg_t *dbg;
	unsigned long long diff;
	int i;
	if ( start < 0 || start > MAX_ZLD_KERNEL_DEBUG_CNT ) {
		printk("<0> end our of range<0-%d>\n",MAX_ZLD_KERNEL_DEBUG_CNT-1);
		goto fail;
	}
	if ( end < 0 || end > MAX_ZLD_KERNEL_DEBUG_CNT ) {
		printk("<0> end our of range<0-%d>\n",MAX_ZLD_KERNEL_DEBUG_CNT-1);
		goto fail;
	}

	dbg =  &(zld_kernel_dbg[start]);
	printk("<0>current = %d\n",zld_dbg_index );
	printk("<0>Enable = %d\n",zld_dbg_enable );
	for ( i = start; i <= end; i ++,dbg++ ) {
		diff = timespec_to_ns(&(dbg+1)->time) - timespec_to_ns(&(dbg->time));
		if ( dbg->id != NULL ) {
			printk("<0>%5d %12llu %8llu %8lx %8lx %8lx %8lx %s\n", i,  timespec_to_ns(&(dbg->time)), diff,
				dbg->data[0],dbg->data[1],dbg->data[2],dbg->data[3], (char *)dbg->id);
		}
		else {
			printk("<0>%5d %12llu %8llu %8lx %8lx %8lx %8lx %x\n", i,  timespec_to_ns(&(dbg->time)), diff,
				dbg->data[0],dbg->data[1],dbg->data[2],dbg->data[3], 0);
		}
	}
fail:
	return;
}

void
zld_kernel_dbg_log(void *id, unsigned long data0, unsigned long data1, unsigned long data2, unsigned long data3)
{
	zld_kernel_dbg_t *dbg;

	if ( !zld_dbg_enable ) {
		return;
	}
	dbg = &(zld_kernel_dbg[zld_dbg_index++]);
	if ( zld_dbg_index >= MAX_ZLD_KERNEL_DEBUG_CNT ) {
		zld_dbg_index = 0;
	}

	dbg->id = id;
	dbg->data[0] = data0;
	dbg->data[1] = data1;
	dbg->data[2] = data2;
	dbg->data[3] = data3;
	getnstimeofday(&(dbg->time));
}

void
enable_zld_kernel_dbg( int enable )
{
	zld_dbg_enable = enable;
}

uint32_t
get_zld_kernel_dbg_idx( int idx )
{
	if ( idx < 0 ) {
		zld_dbg_index = 0;
	}
	return zld_dbg_index;
}

#define ZLD_KERNEL_DBG_LOG(data0, data1, data2, data3 ) \
	zld_kernel_dbg_log(__FUNCTION__,data0,data1,data2,data3)

#endif /* CONFIG_ZLD_KERNEL_TIME_PROFILING */

#if 0

#if defined(ZLDSYSPARM_BOARD_ZW110V2)
struct gpio_config gpio_configs[] = {
//	pin num,	connect,		int en, 	int type,	irq num,		in/out,	def val,	act value, 
	{0,		CONNECT, 		0,		  0,	 0,	   GIO_IN,	DEF_HI,  ACT_LO},
	{1,			  0,		0,		  0,	 0,	   		0,		 0,  	  0},
	{2,			  0,		0,		  0,	 0,	   		0,		 0,  	  0},
	{3,			  0,		0,		  0,	 0,	   		0,		 0,  	  0},
	{4,		CONNECT,   INT_EN, TYPE_FALL,	 0,	   GIO_IN,	DEF_HI,  ACT_LO}, // RTL8370MB interrupt
	{5,		CONNECT,   INT_EN, TYPE_FALL,	 0,	   GIO_IN,	DEF_HI,  ACT_LO}, // RTL8211FS interrupt
	{6,			  0,		0,		  0,	 0,	   		0,		 0,  	  0},
	{7,		CONNECT,		0,		  0,	 0,	   GIO_IN,  DEF_HI,  ACT_LO}, // Reset to default
	{8,		CONNECT,		0,		  0,	 0,	  GIO_OUT,  DEF_LO,  ACT_HI}, // eMMC Flash reset
	{9,		CONNECT,		0,		  0,	 0,	  GIO_OUT,  DEF_LO,  ACT_HI}, // Nor flash reset
	{10, 	CONNECT,   INT_EN, TYPE_LOW,	 0,	   GIO_IN,	DEF_HI,  ACT_LO}, // CPLD interrupt
	{11, 		  0,		0,	  	  0,	 0,	   		0,		 0,  	  0},
	{12, 	CONNECT,		0,		  0,	 0,	  GIO_OUT,  DEF_HI,  ACT_LO}, // I2C SCL
	{13, 	CONNECT,		0,		  0,	 0,	  GIO_OUT,  DEF_HI,  ACT_LO}, // I2C SDA
	{14, 	CONNECT,   INT_EN,TYPE_FALL,	 0,	   GIO_IN,	DEF_HI,  ACT_LO}, // ADT7463 interrupt
	{15, 		  0,		0,		  0,	 0,	   		0,		 0,  	  0},
	{16, 	CONNECT,		0,		  0,	 0,	  GIO_OUT,  DEF_LO,  ACT_HI}, // CPLD reset out
	{GPIO_END, 	  0,		0,		  0,	 0,			0, 		 0,  	  0},
};
EXPORT_SYMBOL(gpio_configs);
#elif defined(ZLDSYSPARM_BOARD_USG60V2)
struct gpio_config gpio_configs[] = {
//	pin num,	connect,		int en, 	int type,	irq num,		in/out,	def val,	act value, 
	{0,			  0, 		0,		  0,	 0,	    	0,		 0,  	  0},
	{1,			  0,		0,		  0,	 0,	   		0,		 0,  	  0},
	{2,			  0,		0,		  0,	 0,	   		0,		 0,  	  0},
	{3,			  0,		0,		  0,	 0,	   		0,		 0,  	  0},
	{4,		CONNECT,   INT_EN, TYPE_FALL,	 0,	   GIO_IN,	DEF_HI,  ACT_LO}, // RTL8370MB interrupt
	{5,		CONNECT,   INT_EN, TYPE_FALL,	 0,	   GIO_IN,	DEF_HI,  ACT_LO}, // RTL8211FS interrupt
	{6,			  0,		0,		  0,	 0,	   		0,		 0,  	  0},
	{7,		CONNECT,		0,		  0,	 0,	   GIO_IN,  DEF_HI,  ACT_LO}, // Reset to default
	{8,		CONNECT,		0,		  0,	 0,	  GIO_OUT,  DEF_LO,  ACT_HI}, // eMMC Flash reset
	{9,		CONNECT,		0,		  0,	 0,	  GIO_OUT,  DEF_LO,  ACT_HI}, // Nor flash reset
	{10, 	CONNECT,   INT_EN, TYPE_LOW,	 0,	   GIO_IN,	DEF_HI,  ACT_LO}, // CPLD interrupt
	{11, 		  0,		0,	  	  0,	 0,	   		0,		 0,  	  0},
	{12, 		  0,		0,		  0,	 0,			0, 		 0,  	  0}, // I2C SCL
	{13, 		  0,		0,		  0,	 0,			0, 		 0,  	  0}, // I2C SDA
	{14, 	CONNECT,   INT_EN,TYPE_FALL,	 0,	   GIO_IN,	DEF_HI,  ACT_LO}, // ADT7463 interrupt
	{15, 		  0,		0,		  0,	 0,	   		0,		 0,  	  0},
	{16, 		  0,		0,		  0,	 0,			0, 		 0,  	  0}, // CPLD reset out
	{GPIO_END, 	  0,		0,		  0,	 0,			0, 		 0,  	  0},
};
EXPORT_SYMBOL(gpio_configs);
#elif defined(ZLDSYSPARM_BOARD_ZW1100V2)
struct gpio_config gpio_configs[] = {
//	pin num,	connect,		int en, 	int type,	irq num,		in/out,	def val,	act value, 
	{0,		CONNECT, 		0,		  0,	 0,	   GIO_IN,	DEF_HI,  ACT_LO}, // For HW test
	{1,			  0,		0,		  0,	 0,	   		0,		 0,  	  0}, //
	{2,			  0,		0,		  0,	 0,	   		0,		 0,  	  0}, //
	{3,			  0,		0,		  0,	 0,	   		0,		 0,  	  0}, //
	{4,		CONNECT,   INT_EN, TYPE_FALL,	 0,	   GIO_IN,	DEF_HI,  ACT_LO}, // BCM53346 PCIe interrupt
	{5,		CONNECT,   INT_EN, TYPE_FALL,	 0,	   GIO_IN,	DEF_HI,  ACT_LO}, // B50220S interrupt
	{6,			  0,		0,		  0,	 0,	   		0,		 0,  	  0}, //
	{7,		CONNECT,		0,		  0,	 0,	   GIO_IN,  DEF_HI,  ACT_LO}, // Reset to default
	{8,		CONNECT,		0,		  0,	 0,	  GIO_OUT,  DEF_LO,  ACT_HI}, // eMMC Flash reset
	{9,		CONNECT,		0,		  0,	 0,	  GIO_OUT,  DEF_LO,  ACT_HI}, // Nor flash reset
	{10, 	CONNECT,   INT_EN, TYPE_LOW,	 0,	   GIO_IN,	DEF_HI,  ACT_LO}, // CPLD interrupt
	{11, 	CONNECT,		0,	  	  0,	 0,	  GIO_OUT,	DEF_HI,  ACT_LO}, // EJTAG reset
	{12, 	      0,		0,		  0,	 0,	        0,       0,       0}, // 
	{13, 	      0,		0,		  0,	 0,	        0,       0,       0}, // 
	{14, 	CONNECT,   INT_EN,TYPE_FALL,	 0,	   GIO_IN,	DEF_HI,  ACT_LO}, // ADT7463 interrupt
	{15, 	CONNECT,		0,		  0,	 0,	  GIO_OUT,	DEF_HI,  ACT_LO}, // CPLD system HW reset
	{16, 	CONNECT,		0,		  0,	 0,	   GIO_IN,  DEF_HI,  ACT_LO}, // CPU self-reset
	{17, 	      0,		0,		  0,	 0,	        0,       0,       0}, // 
	{18, 	CONNECT,		0,		  0,	 0,	   GIO_IN,  DEF_HI,  ACT_LO}, // SODIMM DDR4
	{19, 	      0,		0,		  0,	 0,	        0,       0,       0}, // 
	{20, 	CONNECT,		0,		  0,	 0,	   GIO_IN,  DEF_HI,  ACT_LO}, // HW test
	{GPIO_END, 	  0,		0,		  0,	 0,			0, 		 0,  	  0},
};
EXPORT_SYMBOL(gpio_configs);
#endif

int
octeon_gpio_operation(int bits, unsigned char write, unsigned char value)
{
	uint32_t word;
	int retval = 0;

	word = cvmx_gpio_read();

	if( write == GPIO_OP_WRITE ) {
		if( value == 1 ) {
			word |= (1ULL << bits);
		}
		else {
			word &= ~(1ULL << bits);
		}
		cvmx_gpio_set(word);
	}
	else {
		if( word & (1ULL << bits) ) {
			retval = 1;
		}
	}
	return retval;
} /* octeon_gpio_operation */


int 
init_gpio( void )
{
#if defined(ZLDSYSPARM_BOARD_ZW110V2) || defined(ZLDSYSPARM_BOARD_USG60V2) || defined(ZLDSYSPARM_BOARD_ZW1100V2)
	cvmx_gpio_bit_cfgx_t gpio_bit_cfgx;
	int i = 0;
	struct device_node* dn;
	struct of_phandle_args irq_data;	

	do {
		//printk("GPIO %d\n", gpio_configs[i].pin_num);
		gpio_bit_cfgx.u64 = cvmx_read_csr(CVMX_GPIO_BIT_CFGX(gpio_configs[i].pin_num));
		if (gpio_configs[i].connect == CONNECT) {
			if (gpio_configs[i].is_interrupt == INT_EN) {
				if (gpio_configs[i].interrupt_type == TYPE_RISE) {
					gpio_bit_cfgx.s.int_type	= 1;	/* 0:level, 1:edge */
					gpio_bit_cfgx.s.rx_xor		= 0;	/* 0:high/rising, 1:low/falling */
				} else if (gpio_configs[i].interrupt_type == TYPE_FALL) {
					gpio_bit_cfgx.s.int_type	= 1;	/* 0:level, 1:edge */
					gpio_bit_cfgx.s.rx_xor		= 1;	/* 0:high/rising, 1:low/falling */
				} else if (gpio_configs[i].interrupt_type == TYPE_LOW) {
					gpio_bit_cfgx.s.int_type	= 0;	/* 0:level, 1:edge */
					gpio_bit_cfgx.s.rx_xor		= 1;	/* 0:high/rising, 1:low/falling */
				} else if (gpio_configs[i].interrupt_type == TYPE_HIGH) {
					gpio_bit_cfgx.s.int_type	= 0;	/* 0:level, 1:edge */
					gpio_bit_cfgx.s.rx_xor		= 0;	/* 0:high/rising, 1:low/falling */
				}
				else {
					printk(KERN_EMERG "Invalid interrupt type !!");
				}
				gpio_bit_cfgx.s.tx_oe 	= 0;
				gpio_bit_cfgx.s.int_en 	= 0;
				#if defined(ZLDSYSPARM_BOARD_ZW110V2) || defined(ZLDSYSPARM_BOARD_ZW1100V2) 
				/* Find gpio controller device node and get irq num. */
				dn = of_find_node_by_name(NULL, GPIO_CONTROLLER_DEVICE_NODE_NAME);
				if (dn) {
					irq_data.np = dn;
					irq_data.args_count = 2;
					irq_data.args[0] = gpio_configs[i].pin_num;
					irq_data.args[1] = gpio_configs[i].interrupt_type;
					gpio_configs[i].irq_num = irq_create_of_mapping(&irq_data);
					if (gpio_configs[i].irq_num == 0) {
						printk(KERN_EMERG "GPIO %d get irq num fail !!\n", gpio_configs[i].pin_num);
					}else {
					//	printk("Get GPIO %d irq num: %d\n", gpio_configs[i].pin_num, gpio_configs[i].irq_num);
					}
				}
				else {
					printk(KERN_EMERG "Can't find %s device node !!", GPIO_CONTROLLER_DEVICE_NODE_NAME);
				}
				#else
				gpio_configs[i].irq_num = gpio_configs[i].pin_num + OCTEON_IRQ_GPIO0;
				//printk("Get GPIO %d linear irq num: %d\n", gpio_configs[i].pin_num, gpio_configs[i].irq_num);
				#endif
			}
			else {
				gpio_bit_cfgx.s.int_type 	= 0;	/* 0:level, 1:edge */
				gpio_bit_cfgx.s.rx_xor 		= 0;	/* 0:high/rising, 1:low/falling */
				gpio_bit_cfgx.s.int_en 		= 0;	/* 0:disable interrupt, 1:enable interrupt */
				if (gpio_configs[i].output == GIO_OUT) {
					gpio_bit_cfgx.s.tx_oe 	= 1;	/* 0: input, 1: output */
					if (gpio_configs[i].default_value == DEF_HI) {
						octeon_gpio_operation(gpio_configs[i].pin_num, GPIO_OP_WRITE, 1);
					}
					else {
						octeon_gpio_operation(gpio_configs[i].pin_num, GPIO_OP_WRITE, 0);
					}
				}
				else {
					gpio_bit_cfgx.s.tx_oe = 0;	/* 0: input, 1: output */
				}
			}
		}
		else {
			gpio_bit_cfgx.s.int_type	= 0;	/* 0:level, 1:edge */
			gpio_bit_cfgx.s.rx_xor		= 0;	/* 0:high/rising, 1:low/falling */
			gpio_bit_cfgx.s.int_en		= 0;	/* 0:disable interrupt, 1:enable interrupt */
			gpio_bit_cfgx.s.tx_oe 		= 1;	/* 0: input, 1: output */
		}
		cvmx_write_csr(CVMX_GPIO_BIT_CFGX(gpio_configs[i].pin_num), gpio_bit_cfgx.u64);	
		i ++;
	} while (gpio_configs[i].pin_num != 0xff);

#elif defined (ZLDSYSPARM_PLATFORM_MIPS_CAVIUM_OCTEON_CN6XXX)
	/*CN6XXX has different GPIO definition with CN50XX*/
	cvmx_gpio_bit_cfgx_t gpio_bit_cfgx;
	
	/* set GPIO restore_default button pin as input pin */
	gpio_bit_cfgx.u64 = cvmx_read_csr(CVMX_GPIO_BIT_CFGX(GPIO_BIT_RESTORE_DEFAULT_BUTTON));
	gpio_bit_cfgx.s.tx_oe = 0;
	cvmx_write_csr(CVMX_GPIO_BIT_CFGX(GPIO_BIT_RESTORE_DEFAULT_BUTTON), gpio_bit_cfgx.u64);
	
	/* set GPIO HTM pin as input pin */
	gpio_bit_cfgx.u64 = cvmx_read_csr(CVMX_GPIO_BIT_CFGX(GPIO_BIT_HTM_PIN));
	gpio_bit_cfgx.s.tx_oe = 0;
	cvmx_write_csr(CVMX_GPIO_BIT_CFGX(GPIO_BIT_HTM_PIN), gpio_bit_cfgx.u64);
#elif defined (ZLDSYSPARM_PLATFORM_MIPS_CAVIUM_OCTEON_CN7XXX)
	/*CN6XXX has different GPIO definition with CN50XX*/
	cvmx_gpio_bit_cfgx_t gpio_bit_cfgx;
	
	/* set GPIO restore_default button pin as input pin */
	gpio_bit_cfgx.u64 = cvmx_read_csr(CVMX_GPIO_BIT_CFGX(GPIO_BIT_RESTORE_DEFAULT_BUTTON));
	gpio_bit_cfgx.s.tx_oe = 0;
	cvmx_write_csr(CVMX_GPIO_BIT_CFGX(GPIO_BIT_RESTORE_DEFAULT_BUTTON), gpio_bit_cfgx.u64);
	
	/* set GPIO HTM pin as input pin */
	gpio_bit_cfgx.u64 = cvmx_read_csr(CVMX_GPIO_BIT_CFGX(GPIO_BIT_HTM_PIN));
	gpio_bit_cfgx.s.tx_oe = 0;
	cvmx_write_csr(CVMX_GPIO_BIT_CFGX(GPIO_BIT_HTM_PIN), gpio_bit_cfgx.u64);

#else
	/* set GPIO restore_default button and HTM pin as input pin */
	cvmx_write_csr(CVMX_GPIO_XBIT_CFGX(GPIO_BIT_RESTORE_DEFAULT_BUTTON), 0);
	cvmx_write_csr(CVMX_GPIO_XBIT_CFGX(GPIO_BIT_HTM_PIN), 0);
	
	/* set NAND_WRITE_PROCTECT NOR_WRITE_PROCTECT as output pin */
	cvmx_write_csr(CVMX_GPIO_BIT_CFGX(GPIO_BIT_NAND_WRITE_PROCTECT), 1);
	cvmx_write_csr(CVMX_GPIO_BIT_CFGX(GPIO_BIT_NOR_WRITE_PROCTECT), 1);
#endif
	return 0;
} /* init_gpio */


void exit_gpio ( void )
{
	int i = 0;

#if defined(ZLDSYSPARM_BOARD_ZW110V2) || defined(ZLDSYSPARM_BOARD_ZW1100V2)
	do {
		if (gpio_configs[i].irq_num != 0) {
			irq_dispose_mapping(gpio_configs[i].irq_num);
		}
		i++;
	} while (gpio_configs[i].pin_num != 0xff);
#endif
}

#endif
#if 0
//#define CPLD_PHY_MAP_ADDR 0x01d010000ull 
uint8_t *cpld_base_addr = NULL;
uint8_t *zld_cpld_base_p;
#define CPLD_BASE_ADDR cpld_base_addr

int init_cpld( void )
{
	cpld_base_addr = (unsigned char*)ioremap(CPLD_PHY_MAP_ADDR, 16);
	if ( cpld_base_addr == NULL ) {
		return -1;
	}
	zld_cpld_base_p = cpld_base_addr;
	return 0;
} /* init_cpld */

void exit_cpld ( void )
{
	if ( cpld_base_addr != NULL ) {
		iounmap(cpld_base_addr);
	}
}


#if defined(ZLDSYSPARM_PLATFORM_MIPS_CAVIUM_OCTEON_CN6XXX) || defined(ZLDSYSPARM_PLATFORM_MIPS_CAVIUM_OCTEON_CN50XX) || defined(ZLDSYSPARM_PLATFORM_MIPS_CAVIUM_OCTEON_CN7XXX)
uint8_t getCPLDReg(int offset)
{
	uint8_t retVal = 0;
	char *ptr_p;
	uint8_t word = 0, *rp;

	if(zld_cpld_base_p){
		ptr_p = (char *)(zld_cpld_base_p + (offset * 1));
		rp = (uint8_t *)ptr_p;
		word = (uint8_t)*rp;
		retVal = (uint8_t)(word & 0xff);
	}
	return retVal;
}

void setCPLDReg(int offset,uint8_t value)
{
	uint8_t word = 0, *wp;
	char *ptr_p;

	if(zld_cpld_base_p){
		word = (uint8_t)(value & 0xff);
		ptr_p = (char *)(zld_cpld_base_p + (offset * 1));
		wp = (uint8_t *)ptr_p;
		*wp = word;
	}
}

#else /* 16 bits */
uint8_t getCPLDReg(int offset)
{
	uint8_t retVal = 0;
	char *ptr_p;
	uint16_t word = 0, *rp;

	if(zld_cpld_base_p){
		ptr_p = (char *)(zld_cpld_base_p + (offset * 2));
		rp = (uint16_t *)ptr_p;
		word = (uint16_t)*rp;
		retVal = (uint8_t)(word & 0xff);
	}
	return retVal;
}

void setCPLDReg(int offset,uint8_t value)
{
	uint16_t word = 0, *wp;
	char *ptr_p;

	if(zld_cpld_base_p){
		word = (uint16_t)(value & 0xff);
		ptr_p = (char *)(zld_cpld_base_p + (offset * 2));
		wp = (uint16_t *)ptr_p;
		*wp = word;
	}
}
#endif
EXPORT_SYMBOL(getCPLDReg);
EXPORT_SYMBOL(setCPLDReg);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
struct ctl_table_header *zld_register_sysctl(struct net *zld_net,
	const char *zld_path, struct ctl_table *zld_table)
{
	return __register_sysctl_table(&zld_net->sysctls, zld_path, zld_table);
}
EXPORT_SYMBOL(zld_register_sysctl);

struct device *zld_device_create(struct class *class, struct device *parent,
			     dev_t devt, void *drvdata, const char *fmt, ...)
{
	va_list vargs;
	struct device *dev;

	va_start(vargs, fmt);
	dev = device_create_vargs(class, parent, devt, drvdata, fmt, vargs);
	va_end(vargs);
	return dev;
}
EXPORT_SYMBOL(zld_device_create);

static int __match_devt(struct device *dev, const void *data)
{
	const dev_t *devt = data;

	return dev->devt == *devt;
}

void zld_device_destroy(struct class *class, dev_t devt)
{
	struct device *dev;

	dev = class_find_device(class, NULL, &devt, __match_devt);
	if (dev) {
		put_device(dev);
		device_unregister(dev);
	}
}
EXPORT_SYMBOL(zld_device_destroy);

static void class_create_release(struct class *cls)
{
	pr_debug("%s called for %s\n", __func__, cls->name);
	kfree(cls);
}

struct class *zld_class_create(struct module *owner, const char *name,
			     struct lock_class_key *key)
{
	struct class *cls;
	int retval;

	cls = kzalloc(sizeof(*cls), GFP_KERNEL);
	if (!cls) {
		retval = -ENOMEM;
		goto error;
	}

	cls->name = name;
	cls->owner = owner;
	cls->class_release = class_create_release;

	retval = __class_register(cls, key);
	if (retval)
		goto error;

	return cls;

error:
	kfree(cls);
	return ERR_PTR(retval);
}
EXPORT_SYMBOL(zld_class_create);

void zld_class_destroy(struct class *cls)
{
	if ((cls == NULL) || (IS_ERR(cls)))
		return;

	class_unregister(cls);
}
EXPORT_SYMBOL(zld_class_destroy);

struct nf_conntrack_tuple_hash *
zld_nf_conntrack_find_get(struct net *net, u16 zone,
		      const struct nf_conntrack_tuple *tuple)
{
	return nf_conntrack_find_get(net, zone, tuple);
}
EXPORT_SYMBOL(zld_nf_conntrack_find_get);

#endif

#ifdef CONFIG_ZLD_MULTIPATH_TRUNK
__be32
zyconfirm_addr_indev(struct in_device *in_dev, __be32 dst,
		__be32 local, int scope)
{
	int same = 0;
	__be32 addr = 0;

	for_ifa(in_dev) {
		if (!addr &&
				(local == ifa->ifa_local || !local) &&
				ifa->ifa_scope <= scope) {
			addr = ifa->ifa_local;
			if (same)
				break;
		}
		if (!same) {
			same = (!local || zyinet_ifa_match(local, ifa)) &&
				(!dst || zyinet_ifa_match(dst, ifa));
			if (same && addr) {
				if (local || !dst)
					break;
				/* Is the selected addr into dst subnet? */
				if (zyinet_ifa_match(addr, ifa))
					break;
				/* No, then can we use new local src? */
				if (ifa->ifa_scope <= scope) {
					addr = ifa->ifa_local;
					break;
				}
				/* search for large dst subnet for addr */
				same = 0;
			}
		}
	} endfor_ifa(in_dev);

	return same ? addr : 0;
}

/*
 * Confirm that local IP address exists using wildcards:
 * - dev: only on this interface, 0=any interface
 * - dst: only in the same subnet as dst, 0=any dst
 * - local: address, 0=autoselect the local address
 * - scope: maximum allowed scope value for the local address
 */
__be32
zyinet_confirm_addr(const struct net_device *dev, __be32 dst, __be32 local, int scope)
{
	__be32 addr = 0;
	struct in_device *in_dev;
	/*	struct net *net; */

	if (dev) {
		rcu_read_lock();
		if ((in_dev = __in_dev_get_rcu(dev)))
			addr = zyconfirm_addr_indev(in_dev, dst, local, scope);
		rcu_read_unlock();

		return addr;
	}

	read_lock(&dev_base_lock);
	rcu_read_lock();

	/* FIXME 'net' should become an argument */
	for_each_netdev(&init_net, dev) {
		if ((in_dev = __in_dev_get_rcu(dev))) {
			addr = zyconfirm_addr_indev(in_dev, dst, local, scope);
			if (addr)
				break;
		}
	}

	rcu_read_unlock();
	read_unlock(&dev_base_lock);

	return addr;
}
#endif

int
zld_nf_ct_is_untracked(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
	struct nf_conn* ct;
	enum ip_conntrack_info info;

	ct = nf_ct_get(skb, &info);
	if (unlikely(!ct))
		return 0;

	if (nf_ct_is_untracked(ct)) 
#else
	if (nf_ct_is_untracked(skb)) 
#endif
	{
		if (unlikely(zld_nf_ct_is_untracked_debug)) {
			printk_hex(NULL, skb->data, skb_headlen(skb), KERN_DEBUG);
			skb_info(skb);
		}
		return 1;
	}
	else {
		return 0;
	}
}

bool
zld_nf_ct_kill(struct nf_conn *ct)
{
	return nf_ct_kill(ct);
}

#ifdef CONFIG_ZLD_IMAGE_RECOVERY_POINT_SUPPORT
static int __init recovery_image_setup(char *str)
{
        if( 0 == strcmp("Y", str) )
                is_recovery = 1;
        else if( 0 == strcmp("y", str) )
                is_recovery = 1;

	return 0;
}
__setup("recovery=", recovery_image_setup);

static int
recovery_point_oom_notify_sys(struct notifier_block *this, unsigned long code, void *data)
{
        emergency_restart();
        return NOTIFY_DONE;
}

static int
recovery_point_panic_notify_sys(struct notifier_block *this, unsigned long code, void *data)
{
        emergency_restart();
        return NOTIFY_DONE;
}

static void __init
image_recovery_point_init(void)
{
        if( is_recovery )
        {
                register_oom_notifier(&recovery_point_oom_notifier);
                atomic_notifier_chain_register(&panic_notifier_list, &recovery_point_panic_notifier);
        }
}
#endif

void
zld_export_init(void)
{
	memset(&zld_export_cb, 0, sizeof(zld_export_t));
	//zld_kernel_ctl_init();
#ifdef CONFIG_ZLD_WDT_SUPPORT
	zld_wdt_init();
#endif /* ENDIF_CONFIG_ZLD_WDT_SUPPORT */
#ifdef CONFIG_ZLD_DISK_LOG_SUPPORT
	zld_storage_hw_reset = NULL;
#endif /* CONFIG_ZLD_DISK_LOG_SUPPORT */
#ifdef CONFIG_BRIDGE
	__br_fdb_get_hook = __br_fdb_get;
#endif /* ENDIF_CONFIG_BRIDGE */
	//init_cpld();
	//init_gpio();
#ifdef CONFIG_ZLD_IMAGE_RECOVERY_POINT_SUPPORT
        image_recovery_point_init();
#endif
}

#ifdef CONFIG_ZLD_BOARD_SPEC
void
zld_hw_cpld_restart(void)
{
	unsigned char b8value;
	
	#if defined(ZLDSYSPARM_BOARD_ZW2200)
	/* reset BCM84833 and BCM84727 Phy */
	b8value = getCPLDReg(OCTEON_CPLD_REG0);
	b8value &= ~(OCTEON_CPLD_BIT6 | OCTEON_CPLD_BIT7);
	setCPLDReg(OCTEON_CPLD_REG0, b8value);	
	mdelay(5);
	#endif

	/* reboot by CPLD */
	#if defined(OCTEON_CPLD_CPU_RESET_REG)
	b8value = getCPLDReg(OCTEON_CPLD_CPU_RESET_REG);
	b8value &= ~(OCTEON_CPLD_CPU_RESET_BIT); /*CPU_RESET*/
	setCPLDReg(OCTEON_CPLD_CPU_RESET_REG, b8value);	
	mdelay(100);
	#else
	/* reboot by CPLD */
	b8value = getCPLDReg(0);
	b8value &= ~(1 << 1); /*CPU_RESET*/
	setCPLDReg(0, b8value);
	mdelay(100);
	#endif
}

EXPORT_SYMBOL(zld_hw_cpld_restart);
#endif


#if defined(ZLDCONFIG_CPU_CORE_LOCK)
int cpu_lock_core = ZLDSYSPARM_WLAN_CPU_LOCK_CORE;
int zyxel_sched_setaffinity(pid_t pid)
{
   cpumask_t cpu_mask;

   cpus_clear(cpu_mask);
   cpu_set(cpu_lock_core, cpu_mask);

   if (sched_setaffinity(pid, (struct cpumask *)&cpu_mask) != 0) {
      printk("sched_setaffinity fail!");
   }

   return 0;
}

void init_timer_key_cpu_lock(struct timer_list *timer,
		    const char *name,
		    struct lock_class_key *key)
{
	if(!(in_irq() || in_softirq() || in_interrupt())) {
		zyxel_sched_setaffinity(current->pid);
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	init_timer_key(timer, name, key);
#else
	init_timer_key(timer, 0, name, key);
#endif	
}
EXPORT_SYMBOL(zyxel_sched_setaffinity);
EXPORT_SYMBOL(init_timer_key_cpu_lock);
#endif

#ifdef CONFIG_ZLD_8021Q_VLAN_ENHANCE
/*ZyXEL vlan enhancement for switchdev module*/
/*Wapper function for VLAN hook function to get vlan device*/
struct net_device *zld_find_vlan_dev(struct net_device *real_dev,
                                   unsigned short VID)
{
        return __find_vlan_dev(real_dev,VID);
}

struct net_device *zld_get_realdev_from_vlandev(struct net_device *dev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
	struct vlan_dev_priv *dev_info = netdev_priv(dev);
#else
	struct vlan_dev_info *dev_info = netdev_priv(dev);
#endif
	return dev_info->real_dev;
}

uint16_t  zld_get_vlanId_from_vlandev(struct net_device *dev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
	struct vlan_dev_priv *dev_info = netdev_priv(dev);
#else
	struct vlan_dev_info *dev_info = netdev_priv(dev);
#endif
	return dev_info->vlan_id;
}
#endif
EXPORT_SYMBOL(zld_export_init);
EXPORT_SYMBOL(zld_export_cb);
#ifdef CONFIG_ZLD_WDT_SUPPORT
EXPORT_SYMBOL(infocollector_cb);
EXPORT_SYMBOL(reboot_on_oom);
EXPORT_SYMBOL(reboot_on_hang);
EXPORT_SYMBOL(disklog_retry_thresh);
EXPORT_PER_CPU_SYMBOL(softlockup_hang_count);
EXPORT_SYMBOL(fwVersion);
EXPORT_SYMBOL(show_slab_info);
EXPORT_SYMBOL(show_mem);
EXPORT_SYMBOL(show_state_filter);
EXPORT_SYMBOL(show_regs);
#endif /* ENDIF_CONFIG_ZLD_WDT_SUPPORT */
#ifdef CONFIG_ZLD_DISK_LOG_SUPPORT
EXPORT_SYMBOL(logDisk_cb);
EXPORT_SYMBOL(zld_storage_hw_reset);
#endif /* CONFIG_ZLD_DISK_LOG_SUPPORT */
#ifdef CONFIG_ZLD_REALLOG_MMC
EXPORT_SYMBOL(get_gendisk);
#endif

#if defined(ZLDSYSPARM_SUPPORT_USB_STORAGE) || defined(ZLDSYSPARM_BUILD_USB_HUB)
EXPORT_SYMBOL(zld_usb_find_device);
EXPORT_SYMBOL(zld_match_device);
#endif /* ZLDSYSPARM_SUPPORT_USB_STORAGE */
#ifdef ZLDCONFIG_IPSEC_QUICKSEC
EXPORT_SYMBOL(vpn_find_tunnel_name_by_tunnel_id);
#endif /* ZLDCONFIG_IPSEC_QUICKSEC */
EXPORT_SYMBOL(printk_hex);
EXPORT_SYMBOL(skb_info);
EXPORT_SYMBOL(__ct_nul_debug);
EXPORT_SYMBOL(__zld_ct_nul_debug);
#ifdef CONFIG_ZLD_8021Q_VLAN_ENHANCE
/*Add two hook function into transmit and receive function*/
EXPORT_SYMBOL(switch_port_rx_vlan_hook);
EXPORT_SYMBOL(switch_port_tx_vlan_hook);
EXPORT_SYMBOL(zld_find_vlan_dev);
EXPORT_SYMBOL(zld_get_realdev_from_vlandev);
EXPORT_SYMBOL(zld_get_vlanId_from_vlandev);
#endif
#ifdef CONFIG_ZLD_KERNEL_TIME_PROFILING
EXPORT_SYMBOL(zld_kernel_dbg_log);
EXPORT_SYMBOL(disp_zld_kernel_dbg);
EXPORT_SYMBOL(enable_zld_kernel_dbg);
EXPORT_SYMBOL(get_zld_kernel_dbg_idx);
#endif
#ifdef CONFIG_ZLD_MULTIPATH_TRUNK
EXPORT_SYMBOL(zyconfirm_addr_indev);
EXPORT_SYMBOL(zyinet_confirm_addr);
#endif
#ifdef CONFIG_BRIDGE
EXPORT_SYMBOL(__br_fdb_get_hook);
#endif
#ifdef ZLDCONFIG_DUALZYSH_LOCALWTP_SUPPORT
EXPORT_SYMBOL(netdev_run_todo);
#endif
//EXPORT_SYMBOL(zld_show_all_task);
EXPORT_SYMBOL(zld_nf_ct_is_untracked);
EXPORT_SYMBOL(zld_nf_ct_kill);
EXPORT_SYMBOL(zld_enable_as_ssi_except_ports);
