/* Copyright 2012-2035, ZyXEL Communications Corp. All rights reserved. */

#ifndef _ZLD_IOCTL_H
#define _ZLD_IOCTL_H

#ifdef __KERNEL__
#include <linux/in.h>
#include <linux/ioctl.h>
#include <linux/socket.h>
#else /* ELSE___KERNEL__ */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#endif /* ENDIF___KERNEL__ */

#include <linux/sockios.h>

/* =================================== Macros for debug =================================== */
#ifdef __KERNEL__
/* #define ZLD_IOCTL_DBG */

#ifdef ZLD_IOCTL_DBG
#define ZLD_IOCTL_DBG_MSG(fmt, arg...) \
	printk(KERN_DEBUG "%s [%d]: "fmt, __FUNCTION__, __LINE__, ##arg)
#else
#define ZLD_IOCTL_DBG_MSG(fmt, arg...)
#endif

#endif /* ENDIF___KERNEL__ */

/* =================================== Definitions for Misc. device =================================== */
#define ZLD_IOCTL_MISCDEV_MAGIC 'C'

/* ============== Begin: ZLD ARP ============== */
/* Delete a ZLD ARP proxy table entry */
#define ZLD_SIOCDARP	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 1)

/* Set a ZLD ARP proxy table entry */
#define ZLD_SIOCSARP	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 2)

/* Get a ZLD ARP proxy table entry */
#define ZLD_SIOCGARP	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 3)

/* Flush ZLD ARP proxy table entries */
#define ZLD_SIOCFARP	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 4)
/* ============== End: ZLD ARP ============== */

/* ============== Begin: connectivity check ============== */
/* Send a connectivity check request */
#define ZLD_IOC_CONN_CHECK_REQ	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 5)
/* ============== End: connectivity check ============== */

/* ============== Begin: SSL inspection ============== */
/* Add a SSL inspection port */
#define ZLD_IOC_SSLINSP_ADDPORT			_IO(ZLD_IOCTL_MISCDEV_MAGIC, 6)

/* Delete a SSL inspection port */
#define ZLD_IOC_SSLINSP_DELPORT			_IO(ZLD_IOCTL_MISCDEV_MAGIC, 7)

/* Show SSL inspection ports */
#define ZLD_IOC_SSLINSP_SHOWPORTS		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 8)

/* Flush SSL inspection ports */
#define ZLD_IOC_SSLINSP_FLUSHPORTS		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 9)

/* Set PID of SSL inspection daemon */
#define ZLD_IOC_SSLINSP_SETDAEMONPID	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 10)
/* ============== End: SSL inspection ============== */

/* ============== Begin: ZLD FTP ALG ============== */
/* Add a ZLD FTP ALG port */
#define ZLD_IOC_FTP_ALG_ADDPORT			_IO(ZLD_IOCTL_MISCDEV_MAGIC, 11)

/* Delete a ZLD FTP ALG port */
#define ZLD_IOC_FTP_ALG_DELPORT			_IO(ZLD_IOCTL_MISCDEV_MAGIC, 12)

/* Show ZLD FTP ALG ports */
#define ZLD_IOC_FTP_ALG_SHOWPORTS		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 13)

/* Flush ZLD FTP ALG ports */
#define ZLD_IOC_FTP_ALG_FLUSHPORTS		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 14)
/* ============== End: ZLD FTP ALG ============== */

/* ============== Begin: UTM manager ==============*/
/* Add a UTM manager port */
#define ZLD_IOC_UTM_AS_WHITELIST_ADDPORT			_IO(ZLD_IOCTL_MISCDEV_MAGIC, 15)

/* Delete a UTM manager port */
#define ZLD_IOC_UTM_AS_WHITELIST_DELPORT			_IO(ZLD_IOCTL_MISCDEV_MAGIC, 16)

/* Show UTM manager ports */
#define ZLD_IOC_UTM_AS_WHITELIST_SHOWPORTS			_IO(ZLD_IOCTL_MISCDEV_MAGIC, 17)

/* Flush UTM manager ports */
#define ZLD_IOC_UTM_AS_WHITELIST_FLUSHPORTS			_IO(ZLD_IOCTL_MISCDEV_MAGIC, 18)

/* Add a UTM manager port-based-list port */
#define ZLD_IOC_UTM_CF_PORT_BASED_LIST_ADDPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 19)
#define ZLD_IOC_UTM_AS_PORT_BASED_LIST_ADDPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 20)
#define ZLD_IOC_UTM_AV_PORT_BASED_LIST_ADDPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 21)
#define ZLD_IOC_UTM_SSI_PORT_BASED_LIST_ADDPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 22)
#define ZLD_IOC_UTM_SANDBOX_PORT_BASED_LIST_ADDPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 23)
#define ZLD_IOC_UTM_AB_IP_PORT_BASED_LIST_ADDPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 24)
#define ZLD_IOC_UTM_AB_URL_PORT_BASED_LIST_ADDPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 25)

/* Delete a UTM manager port-based-list port */
#define ZLD_IOC_UTM_CF_PORT_BASED_LIST_DELPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 26)
#define ZLD_IOC_UTM_AS_PORT_BASED_LIST_DELPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 27)
#define ZLD_IOC_UTM_AV_PORT_BASED_LIST_DELPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 28)
#define ZLD_IOC_UTM_SSI_PORT_BASED_LIST_DELPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 29)
#define ZLD_IOC_UTM_SANDBOX_PORT_BASED_LIST_DELPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 30)
#define ZLD_IOC_UTM_AB_IP_PORT_BASED_LIST_DELPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 31)
#define ZLD_IOC_UTM_AB_URL_PORT_BASED_LIST_DELPORT		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 32)

/* Show UTM manager port-based-list port */
#define ZLD_IOC_UTM_CF_PORT_BASED_LIST_SHOWPORTS	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 33)
#define ZLD_IOC_UTM_AS_PORT_BASED_LIST_SHOWPORTS	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 34)
#define ZLD_IOC_UTM_AV_PORT_BASED_LIST_SHOWPORTS	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 35)
#define ZLD_IOC_UTM_SSI_PORT_BASED_LIST_SHOWPORTS	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 36)
#define ZLD_IOC_UTM_SANDBOX_PORT_BASED_LIST_SHOWPORTS	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 37)
#define ZLD_IOC_UTM_AB_IP_PORT_BASED_LIST_SHOWPORTS		_IO(ZLD_IOCTL_MISCDEV_MAGIC, 38)
#define ZLD_IOC_UTM_AB_URL_PORT_BASED_LIST_SHOWPORTS	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 39)

/* Show UTM manager port-based-list port */
#define ZLD_IOC_UTM_CF_PORT_BASED_LIST_FLUSHPORTS	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 40)
#define ZLD_IOC_UTM_AS_PORT_BASED_LIST_FLUSHPORTS	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 41)
#define ZLD_IOC_UTM_AV_PORT_BASED_LIST_FLUSHPORTS	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 42)
#define ZLD_IOC_UTM_SSI_PORT_BASED_LIST_FLUSHPORTS	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 43)
#define ZLD_IOC_UTM_SANDBOX_PORT_BASED_LIST_FLUSHPORTS	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 44)
#define ZLD_IOC_UTM_AB_IP_PORT_BASED_LIST_FLUSHPORTS	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 45)
#define ZLD_IOC_UTM_AB_URL_PORT_BASED_LIST_FLUSHPORTS	_IO(ZLD_IOCTL_MISCDEV_MAGIC, 46)
/* ============== End: UTM manager ============== */

/* ============== Begin: ZLD VTI ==============*/
/* Add */
#define ZLD_IOC_VTI_ADD_INTERFACE   _IO(ZLD_IOCTL_MISCDEV_MAGIC, 47)
/* Del */
#define ZLD_IOC_VTI_DEL_INTERFACE   _IO(ZLD_IOCTL_MISCDEV_MAGIC, 48)
/* ============== End: ZLD VTI ============== */

/* ============== Begin: CF HTTPS Domain Filter ==============*/
#define ZLD_IOC_CF_HDF_BLOCK_PAGE_MESSAGE			_IO(ZLD_IOCTL_MISCDEV_MAGIC, 49)
#define ZLD_IOC_CF_HDF_WARNING_CONTINUE				_IO(ZLD_IOCTL_MISCDEV_MAGIC, 50)
#define ZLD_IOC_CF_HDF_CACHE_FLUSH					_IO(ZLD_IOCTL_MISCDEV_MAGIC, 51)
/* ============== End: CF HTTPS Domain Filter ============== */

/* ============== Begin: FQDN Object ==============*/
#define ZLD_IOC_FQDN_OBJECT_MESSAGE			_IO(ZLD_IOCTL_MISCDEV_MAGIC, 52)
#define ZLD_IOC_FQDN_OBJECT_DATA			_IO(ZLD_IOCTL_MISCDEV_MAGIC, 53)
/* ============== End: FQDN Object ============== */

/* ----- NOTE: Don't forget to change this value if you add new ioctl commands ----- */
#define ZLD_IOCTL_MISCDEV_IOC_MAXNR 53

#define ZLD_IOCTL_MISCDEV "/dev/zld_ioctl" 

#endif  /* _ZLD_IOCTL_H */
