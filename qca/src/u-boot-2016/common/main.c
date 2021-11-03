/*
 * (C) Copyright 2000
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

/* #define	DEBUG	*/

#include <common.h>
#include <autoboot.h>
#include <cli.h>
#include <console.h>
#include <version.h>

DECLARE_GLOBAL_DATA_PTR;

/*
 * Board-specific Platform code can reimplement show_boot_progress () if needed
 */
__weak void show_boot_progress(int val) {}

static void modem_init(void)
{
#ifdef CONFIG_MODEM_SUPPORT
	debug("DEBUG: main_loop:   gd->do_mdm_init=%lu\n", gd->do_mdm_init);
	if (gd->do_mdm_init) {
		char *str = getenv("mdm_cmd");

		setenv("preboot", str);  /* set or delete definition */
		mdm_init(); /* wait for modem connection */
	}
#endif  /* CONFIG_MODEM_SUPPORT */
}

static void run_preboot_environment_command(void)
{
#ifdef CONFIG_PREBOOT
	char *p;

	p = getenv("preboot");
	if (p != NULL) {
# ifdef CONFIG_AUTOBOOT_KEYED
		int prev = disable_ctrlc(1);	/* disable Control C checking */
# endif

		run_command_list(p, -1, 0);

# ifdef CONFIG_AUTOBOOT_KEYED
		disable_ctrlc(prev);	/* restore Control C checking */
# endif
	}
#endif /* CONFIG_PREBOOT */
}

#if defined(CONFIG_ZYXEL)
void fake_sys_halt(void)
{
	int i = 0;
	char passwd[]={'q','u','i','t'}, ch;
	ulong timer;

	puts("Reset your board! system halt...");

	timer = get_timer(0);
	do {
		if (tstc()) {
			ch = getc();
			if (ch == passwd[i]) {
				i++;
				timer = get_timer(0);
			} else {
				i = 0;
			}
		}
		if (get_timer(timer) > CONFIG_SYS_HZ) {
			i = 0;
			timer = get_timer(0);
		}
	} while (i < sizeof(passwd));
	putc('\n');
}

unsigned int zyxel_get_model_name(char *name, unsigned int size)
{
	const char *model = NULL;
	unsigned int len = 0;

	model = fdt_getprop(gd->fdt_blob, 0, "model", NULL);
	if (model) {
		char *p, model_name[64], *delim = ",";

		memset(model_name, 0, 64);
		snprintf(model_name, 60, "%s", model);

		p = strtok(model_name, delim);
		p = strtok(NULL, delim);
		while (*p == ' ') p++;
		len = snprintf(name, size, "%s", p);
	}

	return len;
}
#endif /* CONFIG_ZYXEL */

#if defined(CONFIG_ZYXEL_EXEC_ZLOADER) && defined(CONFIG_ZYXEL_ZLOADER_BOOTCMD)
static void zyxel_exec_zloader(void)
{

	if (smem_bootconfig_info() == 0) {
		unsigned int active_part;

		active_part = get_appsbl_active_partition();

		if (active_part)
			setenv("zld_addr", CONFIG_ZYXEL_ZLOADER1_ADDR);
		else
			setenv("zld_addr", CONFIG_ZYXEL_ZLOADER_ADDR);
	} else
		setenv("zld_addr", CONFIG_ZYXEL_ZLOADER_ADDR);

	setenv("boot_zld", CONFIG_ZYXEL_ZLOADER_BOOTCMD);
	if (run_command("run boot_zld", 0)) {
		puts("\n!!!!! fail to boot zloader !!!!!\n");
		/* should not return here */
		fake_sys_halt();
	}
}
#endif /* CONFIG_ZYXEL_EXEC_ZLOADER */

/* We come here after U-Boot is initialised and ready to process commands */
void main_loop(void)
{
	const char *s;

	bootstage_mark_name(BOOTSTAGE_ID_MAIN_LOOP, "main_loop");

#ifndef CONFIG_SYS_GENERIC_BOARD
	puts("Warning: Your board does not use generic board. Please read\n");
	puts("doc/README.generic-board and take action. Boards not\n");
	puts("upgraded by the late 2014 may break or be removed.\n");
#endif

	modem_init();
#ifdef CONFIG_VERSION_VARIABLE
	setenv("ver", version_string);  /* set version variable */
#endif /* CONFIG_VERSION_VARIABLE */

	cli_init();

	run_preboot_environment_command();

#if defined(CONFIG_UPDATE_TFTP)
	update_tftp(0UL, NULL, NULL);
#endif /* CONFIG_UPDATE_TFTP */

#if defined(CONFIG_ZYXEL_EXEC_ZLOADER)
#ifdef CONFIG_QCA_APPSBL_DLOAD
	/*
	 * If kernel has crashed in previous boot,
	 * jump to crash dump collection.
	 */
	if (apps_iscrashed()) {
		printf("Crashdump magic found, initializing dump activity..\n");
		s = getenv("dump_to_flash");
		if (!s)
			s = getenv("dump_minimal");
			if (s) {
				do_dumpqca_minimal_data(s);	/* write core dump data to flash */
				run_command("reset", 0);
			}
		else {
			if (getenv("zyxelcrashdump") != NULL)
				dump_func(FULL_DUMP);
			else {
				printf("variable zyxelcrashdump not exists, dump activity will not start... reset system...\n");
				run_command("reset", 0);
			}
		}
		return;
	}
#endif

	zyxel_exec_zloader();
#else
	s = bootdelay_process();
	if (cli_process_fdt(&s))
		cli_secure_boot_cmd(s);

	autoboot_command(s);
#endif /* CONFIG_ZYXEL_EXEC_ZLOADER */

	cli_loop();
}
