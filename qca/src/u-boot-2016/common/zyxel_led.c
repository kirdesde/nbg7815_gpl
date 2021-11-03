#ifdef CONFIG_ZYXEL_LED && CONFIG_CMD_I2C

#include <common.h>
#include <exports.h>

#define CONFIG_LP5569_ADDR_GLOBAL	0x40
#define CONFIG_LP5569_ADDR_1		0x32
#define CONFIG_LP5569_ADDR_2		0x35

#define LP5569_REG_PROG_MEM		0x50
#define LP5569_PROGRAM_PAGES		16
#define LP5569_PROGRAM_LENGTH		32

#define PWM_ON	0xFF
#define PWM_OFF	0x0

typedef enum e_zled_type {
	LED_R1,
	LED_G1,
	LED_B1,
	LED_R2,
	LED_G2,
	LED_B2,
	LED_R3,
	LED_G3,
	LED_B3,
} zled_type_e;

typedef enum e_zled_val {
	OFF_LED,
	ON_LED,
} zled_val_e;

typedef struct s_zled_t {
	zled_type_e  type;
	zled_val_e   defVal;
	unsigned short reg;
} zled_t;

static zled_t allLEDs[] = {
	{LED_R1, ON_LED, 0x16},
	{LED_G1, ON_LED, 0x17},
	{LED_B1, ON_LED, 0x18},
	{LED_R2, ON_LED, 0x19},
	{LED_G2, ON_LED, 0x1A},
	{LED_B2, ON_LED, 0x1B},
	{LED_R3, ON_LED, 0x1C},
	{LED_G3, ON_LED, 0x1D},
	{LED_B3, ON_LED, 0x1E},
};

static bool zyxel_led;

static int dm_i2c_dev(void) {
	char cmd[255];

	if (!zyxel_led) return 1;

	snprintf(cmd, 255, "i2c dev 0");
	if (run_command(cmd, 0) != CMD_RET_SUCCESS) {
		zyxel_led = false;
		return 1;
	}

	return 0;
}

static int dm_i2c_probe(void) {
	char cmd[255];

	if (!zyxel_led) return 1;

	snprintf(cmd, 255, "i2c probe %x", CONFIG_LP5569_ADDR_GLOBAL);
	if (run_command(cmd, 0) != CMD_RET_SUCCESS) {
		zyxel_led = false;
		return 1;
	}

	return 0;
}

static int dm_i2c_write(unsigned int chip, unsigned char addr, unsigned char val)
{
	char cmd[255];

	if (!zyxel_led) return 1;

	snprintf(cmd, 255, "i2c mw %x %x %x 1", chip, addr, val);
	if (run_command(cmd, 0) != CMD_RET_SUCCESS) {
		zyxel_led = false;
		return 1;
	}

	return 0;
}

inline static void led_set(zled_type_e type, zled_val_e val)
{
	uint8_t byte;

	if (val == ON_LED){
		byte = PWM_ON;
		dm_i2c_write(CONFIG_LP5569_ADDR_GLOBAL, allLEDs[type].reg, byte);
	} else{
		byte = PWM_OFF;
		dm_i2c_write(CONFIG_LP5569_ADDR_GLOBAL, allLEDs[type].reg, byte);
	}
}


static void led_init(int bDef)
{
	int i, num;
	uint addr;
	uint8_t byte;

	num = sizeof(allLEDs)/sizeof(zled_t);

	addr = 0x02; byte = 0x00; // stop all engines
	dm_i2c_write(CONFIG_LP5569_ADDR_GLOBAL, addr, byte);

	for (i=0; i<num ; i++) {
		if (bDef)
			led_set(allLEDs[i].type, allLEDs[i].defVal);
		else
			led_set(allLEDs[i].type, OFF_LED);
	}
}

static int zled_init(void)
{
	uint addr;
	uint8_t byte;

	zyxel_led = true;

	if (dm_i2c_dev()) {
		zyxel_led = false;
		return 1;
	}
	if (dm_i2c_probe()) {
		zyxel_led = false;
		return 1;
	}
	udelay(1000);

	addr = 0x3F; byte = 0xFF; // reset device
	dm_i2c_write(CONFIG_LP5569_ADDR_GLOBAL, addr, byte);
	udelay(10000);

	addr = 0x00; byte = 0x40; // device enabled
	dm_i2c_write(CONFIG_LP5569_ADDR_GLOBAL, addr, byte);
	udelay(1000);

	addr = 0x2F; byte = 0x7D; // select internal clock
	dm_i2c_write(CONFIG_LP5569_ADDR_1, addr, byte);
	addr = 0x2F; byte = 0x7C; // select external clock
	dm_i2c_write(CONFIG_LP5569_ADDR_2, addr, byte);

	addr = 0x3D; byte = 0x0A; // set EN_CLK_OUT bit = 1 in the IO_CONTROL register
	dm_i2c_write(CONFIG_LP5569_ADDR_1, addr, byte);

	// turn on all LED
	led_init(1);

	return 0;
}


int zyxel_led_init(void) {

	zyxel_led = true;

	if (zled_init()) return 1;

	return 0;
}

bool zyxel_led_available(void) {
	return zyxel_led;
}

#endif /* CONFIG_ZYXEL_LED */
