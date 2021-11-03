#ifndef _IPT_PORTTRIGGER_H_target
#define _IPT_PORTTRIGGER_H_target

#define TRIGGER_TIMEOUT 120
#define IPT_MULTI_PORTS	15

enum porttrigger_mode
{
	MODE_DNAT,
	MODE_FORWARD_IN,
	MODE_FORWARD_OUT
};

struct ipt_mport
{
	u_int16_t pflags;					/* Port flags */
	u_int16_t ports[IPT_MULTI_PORTS];	/* Ports */
};

struct ipt_porttrigger_info {
	u_int16_t mode;
	u_int16_t trigger_proto;
	u_int16_t forward_proto;
	unsigned int timer;
	struct ipt_mport trigger_ports;
	struct ipt_mport forward_ports;
};

#endif /*_IPT_PORTTRIGGER_H_target*/

