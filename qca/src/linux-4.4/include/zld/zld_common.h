/* Copyright 2012-2035, ZyXEL Communications Corp. All rights reserved. */

#ifndef _ZLD_COMMON_H
#define _ZLD_COMMON_H
#include <linux/version.h>
#ifdef __KERNEL__
#include <linux/list.h>

#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

#endif	/* ENDIF___KERNEL__ */

/* ----- For printk_hex() & print_hex() ----- */
#define ZLD_HEX_LINE_INFO_FMT \
	"%05X(%5d)"
#define ZLD_HEX_LINE_INFO_FMT_SIZE \
	((sizeof(ZLD_HEX_LINE_INFO_FMT) - 1) + 1 + 2)

#define ZLD_HEX_DATA_FMT \
	" %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX-%02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX     "
#define ZLD_HEX_DATA_FMT_SIZE \
	((sizeof(ZLD_HEX_DATA_FMT) - 1) - 4 * 16)

#define ZLD_HEX_FMT \
	ZLD_HEX_LINE_INFO_FMT ZLD_HEX_DATA_FMT
#define ZLD_HEX_FMT_SIZE \
	(ZLD_HEX_LINE_INFO_FMT_SIZE + ZLD_HEX_DATA_FMT_SIZE)

#define ZLD_HEX(addr) \
	(((unsigned char *) (addr))[0]), \
	(((unsigned char *) (addr))[1]), \
	(((unsigned char *) (addr))[2]), \
	(((unsigned char *) (addr))[3]), \
	(((unsigned char *) (addr))[4]), \
	(((unsigned char *) (addr))[5]), \
	(((unsigned char *) (addr))[6]), \
	(((unsigned char *) (addr))[7]), \
	(((unsigned char *) (addr))[8]), \
	(((unsigned char *) (addr))[9]), \
	(((unsigned char *) (addr))[10]), \
	(((unsigned char *) (addr))[11]), \
	(((unsigned char *) (addr))[12]), \
	(((unsigned char *) (addr))[13]), \
	(((unsigned char *) (addr))[14]), \
	(((unsigned char *) (addr))[15])

/* For Kerenl return value change about checkentry of xt_match */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
#define ZLD_XT_CHECKENTRY_PASS 0
#define ZLD_XT_CHECKENTRY_ERROR -EINVAL
#else
#define ZLD_XT_CHECKENTRY_PASS true
#define ZLD_XT_CHECKENTRY_ERROR false
#endif	/* ENDIF LINUX_VERSION_CODE */

#endif  /* _ZLD_COMMON_H */
