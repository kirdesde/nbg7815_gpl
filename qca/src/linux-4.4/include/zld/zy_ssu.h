#ifndef  _ZY_SSU_H
#define  _ZY_SSU_H


#define __ZYSSU_ZLD_STR(x) #x
#define ZYSSU_ZLD_STR(x) __ZYSSU_ZLD_STR(x)

#define ZLD_SESSION_STATUS_UPDATE_DISABLE 0
#define ZLD_SESSION_STATUS_UPDATE_ENABLE  1

/* #define ZLD_ZYSSU_DEBUG_TEST_REPLY        1  */ /* Open this flag, it will only allow reply skb into zld_pre_ipt_do_table(). */
/* #define ZLD_ZYSSU_DEBUG_PRINT             1  */ /* Open this flag, it will show dbg printk message. */
#define ZLD_ZYSSU_DEBUG_SRC_IP            33 /* It will printk src ip is xx.xx.xx.33's skb information. */
#define ZLD_ZYSSU_DEBUG_DST_IP            65 /* It will printk dst ip is xx.xx.xx.65's skb information. */

#ifdef ZLD_ZYSSU_DEBUG_PRINT
enum zld_dbg_list{
    ZLD_JIFFIES_DIFFERENT = 0,
	ZLD_ZLDMARK,
	ZLD_RESULT,
	ZLD_RESULT_RETURN,
	ZLD_BRIDGE,
	ZLD_REPLY,
	ZLD_MASTER,
	ZLD_PRINTK_TOTAL
};
#endif

extern long unsigned int zld_rule_update_time[];
extern int zld_reply_time;
extern int zld_alg_model;

enum zld_table_list{
    ZLD_ZYFILTER_TABLE = 0,
    ZLD_ZYNAC_TABLE,
    ZLD_ZYPING,
	ZLD_ZYVPN_TABLE,	
	ZLD_TOTAL_TABLE
};

#define ZLD_MIN_REPLY_TIME 5
#define ZLD_MAX_REPLY_TIME 300
#define ZLD_DEFAULT_REPLY_TIME 60
#define ZLD_JIFFIES_DELAY                 3*HZ
#define ZLD_WAITING_ARP_REPLY_TIME        5*HZ
#define ZLD_NOT_SEND_ARP                  0
#define ZLD_HAS_SEND_ARP                  1
#define ZLD_SESSION_NO_NEED_UPDATE        0
#define ZLD_SESSION_NEED_UPDATE           1
#define ZLD_NO_FIND_THE_IP			      0
#define ZLD_FIND_THE_IP			          1
#define ZLD_NF_PASS                       NF_MAX_VERDICT + 100
#define ZLD_SKB_MASTER_PASS               ZLD_NF_PASS + 1

#define ZLD_IGNORE_ZYNAC_MARK	          1

#define ZLD_SKB_IS_GENERAL                0
#define ZLD_SKB_IS_IGNORE_COMFIRED        1

#define ZLD_ALG_ENABLE                    1
#define ZLD_ALG_DISABLE                   0
#define ZLD_SKB_LEN                       64

#define ZLD_UPDATE_ZYFILTER_ZYNAC        301 /* ZLD_MAX_REPLY_TIME + 1 */
#define ZLD_UPDATE_ZYFILTER              302 /* ZLD_MAX_REPLY_TIME + 2 */
#define ZLD_UPDATE_ZYNAC                 303 /* ZLD_MAX_REPLY_TIME + 3 */
#define ZLD_UPDATE_ZYPING                304 /* ZLD_MAX_REPLY_TIME + 4 */
#define ZLD_ALG_ACTIVE                   305 /* ZLD_MAX_REPLY_TIME + 5 */
#define ZLD_ALG_INACTIVE                 306 /* ZLD_MAX_REPLY_TIME + 6 */
#define ZLD_UPDATE_ZYVPN                 307 /* ZLD_MAX_REPLY_TIME + 7 */

#define ZYSSU_PROC_PATH                  "/proc/net/nf_rule_update_time"
#define ZYSSU_UPDATE_ZYFILTER_ZYNAC      "echo " ZYSSU_ZLD_STR(ZLD_UPDATE_ZYFILTER_ZYNAC) " > " ZYSSU_PROC_PATH
#define ZYSSU_UPDATE_ZYFILTER            "echo " ZYSSU_ZLD_STR(ZLD_UPDATE_ZYFILTER) " > " ZYSSU_PROC_PATH
#define ZYSSU_UPDATE_ZYNAC               "echo " ZYSSU_ZLD_STR(ZLD_UPDATE_ZYNAC) " > " ZYSSU_PROC_PATH
#define ZYSSU_UPDATE_ZYPING              "echo " ZYSSU_ZLD_STR(ZLD_UPDATE_ZYPING) " > " ZYSSU_PROC_PATH
#define ZYSSU_ALG_ACTIVE                 "echo " ZYSSU_ZLD_STR(ZLD_ALG_ACTIVE) " > " ZYSSU_PROC_PATH
#define ZYSSU_ALG_INACTIVE               "echo " ZYSSU_ZLD_STR(ZLD_ALG_INACTIVE) " > " ZYSSU_PROC_PATH
#define ZYSSU_UPDATE_ZYVPN               "echo " ZYSSU_ZLD_STR(ZLD_UPDATE_ZYVPN) " > " ZYSSU_PROC_PATH

#endif  /* _ZY_SSU_H */
