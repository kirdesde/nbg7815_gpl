#ifndef _RTCOMPL_H
#define _RTCOMPL_H

#define RTCOMPL_MAX_PREHOOKS 32

#ifdef CONFIG_ZLD_RTCOMPL
#define SET_FASTPATH_NOENTRY(ret) ((ret) |= NF_FASTPATH_NOENTRY)
#define SET_FASTPATH_ENTRY(ret) ((ret) |= NF_FASTPATH_ENTRY)
#define SET_FASTPATH_MARK(ret, mark) ((ret) |= mark)
#define RET_FASTPATH_NOENTRY(verdict) ((verdict) | NF_FASTPATH_NOENTRY)
#define RET_FASTPATH_ENTRY(verdict) ((verdict) | NF_FASTPATH_ENTRY)
#define RET_FASTPATH_MARK(verdict, mark) ((verdict) | mark)
#else
#define SET_FASTPATH_NOENTRY(ret)
#define SET_FASTPATH_ENTRY(ret)
#define SET_FASTPATH_MARK(ret, mark)
#define RET_FASTPATH_NOENTRY(verdict) (verdict) 
#define RET_FASTPATH_ENTRY(verdict) (verdict)
#define RET_FASTPATH_MARK(verdict, mark) (verdict)
#endif

#ifdef CONFIG_ZLD_RTCOMPL
#define RTCOMPL_REGISTER_HOOKS rtcompl_nf_register_hooks
#define RTCOMPL_UNREGISTER_HOOKS rtcompl_nf_unregister_hooks
#define RTCOMPL_REGISTER_ONLYONE_HOOK rtcompl_nf_register_hook
#define RTCOMPL_UNREGISTER_ONLYONE_HOOK rtcompl_nf_unregister_hook
#else
#define RTCOMPL_REGISTER_HOOKS nf_register_hooks
#define RTCOMPL_UNREGISTER_HOOKS nf_unregister_hooks
#define RTCOMPL_REGISTER_ONLYONE_HOOK nf_register_hook
#define RTCOMPL_UNREGISTER_ONLYONE_HOOK nf_unregister_hook
#endif

#define FAST_NF_HOOK_THRESH fastpath_nf_hook_thresh
#define FAST_NF_HOOK_RESETFASTID fastpath_nf_hook_resetfastid
#ifdef CONFIG_ZLD_RTCOMPL_DBG
#define FAST_SET_TIMESTAMP fastpath_settimestamp
#endif

#ifdef CONFIG_ZLD_RTCOMPL
struct rtcompl_nf_hook_ops
{
        struct nf_hook_ops nf_ops;
        nf_hookfn *fast_hook;
};

struct rtcompl_prehookmap_s
{
        int priority;
        nf_hookfn *fast_hook;
};
extern struct rtcompl_prehookmap_s prehooks[NF_INET_NUMHOOKS][RTCOMPL_MAX_PREHOOKS];
extern int rtcompl_prehookmap_num[NF_INET_NUMHOOKS];

struct checklist_s {
	unsigned int rtcompl_array_bitmap[NF_INET_NUMHOOKS]; /* BITMAP for fast path pre-allocate array */
	int confirm;
	int regs[NF_INET_NUMHOOKS];
};

struct rtcompl_map_ops
{
        struct list_head hash_list;
        struct nf_hook_ops *ops;
        nf_hookfn *fast_hook;
};

extern int rtcompl_nfhook_prio[NF_INET_NUMHOOKS];
extern int rtcompl_enable;

struct rtcompl_map_ops *rtcompl_rtc_hookmap_lookup(struct nf_hook_ops *key);
int rtcompl_nf_register_hooks(struct rtcompl_nf_hook_ops *reg, unsigned int n);
int rtcompl_nf_register_hook(struct rtcompl_nf_hook_ops *reg);
void rtcompl_nf_unregister_hooks(struct rtcompl_nf_hook_ops *reg, unsigned int n);
void rtcompl_nf_unregister_hook(struct rtcompl_nf_hook_ops *reg);

/* FP MASK */
#define NF_FASTPATH_ENTRY (1<<30)
#define NF_FASTPATH_NOENTRY (1<<29)
#define NF_FASTPATH_MASK (NF_FASTPATH_ENTRY|NF_FASTPATH_NOENTRY)

/* Maximum size <= uint8_t packet_data[96] */
struct rtcompl_s
{
	unsigned int hooknum;
	int slow;
	struct sk_buff *skb;
	struct net_device *in;
	struct net_device *out;
	int (*okfn)(struct sk_buff *);
};

struct rtcompl_cklist_data_s
{
	/* conntrack */
	struct nf_conn *ct;
	int ctinfo;
	struct zld_nf_conn *zld_ct;
	int pkt_count;

	/* skb */
	unsigned int skb__len;
	struct net_device* skb__dev;

	/* iph */
	__be32 iph__saddr;
	__be32 iph__daddr;
	__u8 iph__ihl;
	__u8 iph__protocol;
	__u8 iph__tos;
};

extern void (*rtcompl_register)(struct nf_conn *ct, int dir, int hook, struct sk_buff *skb,
    struct rtcompl_prehookmap_s *func_array, int num_hooks, unsigned int verdict);
extern void rtcompl_register_dummy(struct nf_conn *ct, int dir, int hook, struct sk_buff *skb,
    struct rtcompl_prehookmap_s *func_array, int num_hooks, unsigned int verdict);
extern int (*rtcompl_destroy_ct)(struct nf_conn *ct);

extern int (*fastpath_nf_hook_thresh)(u_int8_t pf, unsigned int hook, struct sk_buff *skb,
       struct net_device *indev, struct net_device *outdev, int (*okfn)(struct sk_buff *),
       int thresh, int priority_flag);
extern int (*fastpath_nf_hook_resetfastid)(struct sk_buff *skb);
#if defined(CONFIG_ZLD_RTCOMPL_DBG)
extern int (*fastpath_settimestamp)(void);
#endif
#endif /* CONFIG_ZLD_RTCOMPL */
#endif /* _RTCOMPL_H */
