/* Copyright 2012-2035, ZyXEL Communications Corp. All rights reserved. */

#ifndef _ZLD_UTM_MANAGER_COMMON_H
#define _ZLD_UTM_MANAGER_COMMON_H

#ifdef __KERNEL__
#include <linux/rcupdate.h>
#include <linux/list.h>
#endif

//#include "zld-spec.h"

/* ----- Definitions for 'sysctl' entries ----- */
#define ZLD_UTM_MANAGER_SYSCTL_ROOT				"utm_manager"
#define ZLD_UTM_MANAGER_SYSCTL_ROOT_PATH		"/proc/sys/net/"ZLD_UTM_MANAGER_SYSCTL_ROOT

#define ZLD_UTM_MANAGER_CUSTOM_SYSCTL_NAME		"enable_custom"
#define ZLD_UTM_MANAGER_CUSTOM_SYSCTL_PATH		ZLD_UTM_MANAGER_SYSCTL_ROOT_PATH"/"ZLD_UTM_MANAGER_CUSTOM_SYSCTL_NAME

#define ZLD_UTM_MANAGER_AS_WHITE_LIST_SYSCTL_NAME	"zld_enable_as_except_ports"
#define ZLD_UTM_MANAGER_AS_WHITE_LIST_SYSCTL_PATH	ZLD_UTM_MANAGER_SYSCTL_ROOT_PATH"/"ZLD_UTM_MANAGER_AS_WHITE_LIST_SYSCTL_NAME

#define ZLD_UTM_MANAGER_PORTLESS_SYSCTL_NAME		"enable_portless"
#define ZLD_UTM_MANAGER_PORTLESS_SYSCTL_PATH		ZLD_UTM_MANAGER_SYSCTL_ROOT_PATH"/"ZLD_UTM_MANAGER_PORTLESS_SYSCTL_NAME

#define LOG		0x00000001
#define ALERT	0x00000010

#ifdef __KERNEL__  /* Only for kernel */
extern int zld_utm_enable_custom;
extern int zld_utm_enable_as_white_list_ports;
extern int zld_utm_enable_portless;

long zld_utm_as_whitelist_ioctl(unsigned int cmd, void __user *arg);
long zld_utm_cf_ioctl(unsigned int cmd, void __user *port);
long zld_utm_as_ioctl(unsigned int cmd, void __user *port);
long zld_utm_av_ioctl(unsigned int cmd, void __user *port);
long zld_utm_ssi_ioctl(unsigned int cmd, void __user *port);
long zld_utm_sandbox_ioctl(unsigned int cmd, void __user *port);
long zld_utm_ab_ip_ioctl(unsigned int cmd, void __user *port);
long zld_utm_ab_url_ioctl(unsigned int cmd, void __user *port);

int zld_utm_check_as_white_list_exist(__be16 dport);
int zld_utm_check_cf_defaultports(__be16 dport);
int zld_utm_check_as_defaultports(__be16 dport);
int zld_utm_check_av_defaultports(__be16 dport);
int zld_utm_check_ssi_defaultports(__be16 dport);
int zld_utm_check_sandbox_defaultports(__be16 dport);
int zld_utm_check_ab_ip_defaultports(__be16 dport);
int zld_utm_check_ab_url_defaultports(__be16 dport);

struct zld_utm_port_entry {
	struct list_head list;
#if 0	/* GPL issue */
	struct rcu_head rcu;
#endif
	__be16 port;
};

struct zld_utm_feature_head {
	struct list_head portlist;
	struct mutex mutex;
	int port_count;
};

enum utm_manager_port_list {
	UTM_AS_WHITE_PORTLIST = 0,
	UTM_CF_PORTLIST_TYPE,
	UTM_AS_PORTLIST_TYPE,
	UTM_AV_PORTLIST_TYPE,
	UTM_SSI_PORTLIST_TYPE,
	UTM_SANDBOX_PORTLIST_TYPE,
	UTM_AB_IP_PORTLIST_TYPE,
	UTM_AB_URL_PORTLIST_TYPE,
	/* You can add items before here. */
	MAX_UTM_PORTLIST_TYPE
};

#endif /* ENDIF___KERNEL__ */

/* ioctl struct */
struct zld_utm_ioctl_port_list {
	uint16_t portlist[64];
	uint32_t len;
} __attribute__((packed));

#define ZLD_UTM_PORT_SAMBA	445

#endif  /* _ZLD_UTM_MANAGER_COMMON_H */
