#ifndef __EXPORTS_H__
#define __EXPORTS_H__

#ifndef __ASSEMBLY__
#ifdef CONFIG_PHY_AQUANTIA
#include <miiphy.h>
#include <phy.h>
#endif

#ifdef CONFIG_ZYXEL
#include <mmc.h>
#include <spi_flash.h>
#include <asm/arch-qca-common/smem.h>
#endif

struct spi_slave;

/* These are declarations of exported functions available in C code */
unsigned long get_version(void);
int  getc(void);
int  tstc(void);
void putc(const char);
void puts(const char*);
int printf(const char* fmt, ...);
void install_hdlr(int, interrupt_handler_t, void*);
void free_hdlr(int);
void *malloc(size_t);
#if !CONFIG_IS_ENABLED(SYS_MALLOC_SIMPLE)
void free(void*);
#endif
void __udelay(unsigned long);
unsigned long get_timer(unsigned long);
int vprintf(const char *, va_list);
unsigned long simple_strtoul(const char *cp, char **endp, unsigned int base);
int strict_strtoul(const char *cp, unsigned int base, unsigned long *res);
char *getenv (const char *name);
int setenv (const char *varname, const char *varvalue);
long simple_strtol(const char *cp, char **endp, unsigned int base);
int strcmp(const char *cs, const char *ct);
unsigned long ustrtoul(const char *cp, char **endp, unsigned int base);
unsigned long long ustrtoull(const char *cp, char **endp, unsigned int base);
#if defined(CONFIG_CMD_I2C) && \
		(!defined(CONFIG_DM_I2C) || defined(CONFIG_DM_I2C_COMPAT))
int i2c_write (uchar, uint, int , uchar* , int);
int i2c_read (uchar, uint, int , uchar* , int);
#endif
#ifdef CONFIG_PHY_AQUANTIA
struct mii_dev *mdio_get_current_dev(void);
struct phy_device *phy_find_by_mask(struct mii_dev *bus, unsigned phy_mask,
		phy_interface_t interface);
struct phy_device *mdio_phydev_for_ethname(const char *ethname);
int miiphy_set_current_dev(const char *devname);
#endif

void app_startup(char * const *);

#endif    /* ifndef __ASSEMBLY__ */

struct jt_funcs {
#define EXPORT_FUNC(impl, res, func, ...) res(*func)(__VA_ARGS__);
#include <_exports.h>
#undef EXPORT_FUNC
};


#define XF_VERSION	8

#if defined(CONFIG_X86)
extern gd_t *global_data;
#endif

#if defined(CONFIG_ZYXEL)
void fake_sys_halt(void);
unsigned int get_appsbl_active_partition(void);
unsigned int get_rootfs_active_partition(void);
int getpart_offset_size(char *part_name, uint32_t *offset, uint32_t *size);
struct mmc *init_mmc_device(int dev, bool force_init);
unsigned int md5_check(unsigned char *buf, unsigned int len, const char *hash);
int smem_bootconfig_info(void);
void smem_bootconfig_retrieve_info(qca_smem_bootconfig_info_t *info);
int snprintf(char *buf, size_t size, const char *fmt, ...);
unsigned int zyxel_get_model_name(char *name, unsigned int size);
int zyxel_get_part_info_efi_by_name(const char* name, disk_partition_t *info);
#if defined(CONFIG_MISC_INIT_F) && defined(CONFIG_ZYXEL_RESET_BTN)
int zyxel_get_reset_button(void);
#endif
int zyxel_imxtract_fit(const unsigned char *buf, const char *name, unsigned int *addr, unsigned int *size);
#endif

#endif	/* __EXPORTS_H__ */
