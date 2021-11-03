#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>

#include "dpu.h"
#include "endian.h"
#include "mymalloc.h"

#define DECOMP_VERSION		"20091123"
#define LC_IOCTL_DECOMP_INIT	0x20
#define LC_IOCTL_DECOMP_HOOK	0x21

#undef DUMP_DECOMP_SERVER_LOG

#ifdef LOOP_DEBUG
int loop_idx = 0;
#endif

int drv_fd = -1;
char *mptr = NULL;

char arg[3][256];
unsigned int g_decomp_debug_mask = 0;

#ifdef AV_MULTI_LAYER_DECOMP
unsigned char zip_header_signature[] = { 0x50, 0x4B, 0x03, 0x04 };
unsigned char gzip_header_signature[] = { 0x1F, 0x8B };
unsigned char rar_header_signature[] = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 };
decomp_session_extend *sess_extend;
#endif

#ifdef DETECT_DECOMP_BOMB_SUPPORT
unsigned int g_decomp_bomb_ratio = 0;
#endif

lc_init_info g_init_info;
const char default_nodename[] = "/dev/decomp";
char g_strNodeName[32];
int session_max;
decomp_session *sess;
int print_switch = 0;
int g_init_complete = 0;

#ifdef DUMP_DECOMP_SERVER_LOG
FILE *fpout;
#endif

static char *rx_buffer = NULL;
static char *rx_buffer_header = NULL;
static char *tx_buffer_header = NULL;
static char *tx_buffer = NULL;
int do_again_count = 0;

unsigned int *rar_sess_status_ptr = NULL;
volatile unsigned int rar_sess_status;

#ifdef DECOMP_MODULE_RAR5
unsigned int *rar5_sess_status_ptr = NULL;
volatile unsigned int rar5_sess_status;
#endif

char *buf = NULL;

int lc_hw_decomp_init(void);
int init_decomp_session(lc_init_info *init_info);

static int session_id;
static int keep_status;
void dumpRARStructure(int session_id);
void dumpZIPStructure(int session_id);

void cmpTxRxDataID(char *cfun, int cline )
{
	lc_decomp_info *srci;
	lc_decomp_info *dsti;

	srci = (lc_decomp_info *) (rx_buffer_header);
	dsti = (lc_decomp_info *) (tx_buffer_header);

	if ( dsti->data_id != srci->data_id )
	{
		printf("!! (%s %d):dsti->data_id = %llx, srci->data_id = %llx\n", cfun, cline, dsti->data_id, srci->data_id);
	}
}

void dumpStructures(void) /* debug */
{
	lc_decomp_info *srci;
	lc_decomp_info *dsti;

	srci = (lc_decomp_info *) (rx_buffer_header);
	dsti = (lc_decomp_info *) (tx_buffer_header);

	decomp_session *ss;
	ss = &(sess[session_id]);
	/* print out all fields of ss */
	#ifdef LOOP_DEBUG
	fprintf(stderr, "Killed, loop idx = %d, keep_status = %d\n", loop_idx, keep_status);
	#endif

	fprintf(stderr, "srci->flag %x error %x, dsti->flag %x error %x\n", srci->flag, srci->err, dsti->flag, dsti->err);

	fprintf(stderr, "Decomp session %d, method %d, fmethod %d\n"	\
		"avail in/out = %d/%d, flag %x, fflag %x\n"		\
		"next in/out = %p/%p, pack size %u, unpack size %u\n"	\
		"file cnt %d, file state %x, has_dd %d, in_buf_len %d\n",
		session_id, ss->decomp_method, ss->file_decomp_method,
		ss->avail_in, ss->avail_out, ss->flag, ss->file_flag,
		ss->next_in, ss->next_out,
		ss->pack_size, ss->unpack_size, ss->file_count,
		ss->file_state, ss->has_dd, ss->in_buf_len);

	if (ss->decomp_method == LC_RAR)
	{
		dump_RAR_structure(session_id);
	}
	#ifdef DECOMP_MODULE_RAR5
	else if (ss->decomp_method == LC_RAR5)
	{
		dump_RAR5_structure(session_id);
	}
	#endif
	else
	{
		dump_ZIP_structure(session_id);
	}
}

/* Signal handlers */
void dbgsignal(int signo)
{
	pid_t pid;

	if (signo == SIGUSR1)
	{
		fprintf(stderr, "Version is %s\n", DECOMP_VERSION);
		listMem();
	}
	else if (signo == SIGUSR2)
	{
		fprintf(stderr, "Version is %s\n", DECOMP_VERSION);
		dumpStructures();
		print_switch = 1;
		//usedMem();
	}
	else if ((signo == SIGKILL) || (signo == SIGTERM))
	{
		dumpStructures();
		cleanupMem();
		exit(-1);
	}
	else if (signo == SIGRTMAX) //Disable Decomp Debug
	{
		g_decomp_debug_mask = 0;
	}
	else if (signo == SIGRTMIN)
	{
		g_decomp_debug_mask |= D_MULTI_LAYER;
	}
	else if (signo == SIGRTMIN + 1)
	{
		g_decomp_debug_mask |= D_BOMB;
	}
	else
	{
		syslog(LOG_ERR|LOG_USER, "[ERROR] signal %d decompress crash", signo);

		if (mptr)
		{
			munmap(mptr, DECOMP_BUFFER_LEN);
		}
		if (drv_fd >= 0)
		{
			close(drv_fd);
		}

		// cleanupMem();

		pid = fork();
		if (pid < 0)
		{
			exit(0);
		}
		else
		if (pid > 0)
		{
			exit(0);
		}
		else
		{
			sleep(1);
			execlp(arg[0], arg[0], arg[1], arg[2], (char *)0);
			exit(0);
		}
	}
}

void initsignal(void)
{
	struct sigaction act;

	act.sa_handler = dbgsignal;
	act.sa_flags = SA_NODEFER;
	sigemptyset(&act.sa_mask);

	sigaction(SIGBUS,  &act, NULL);
	sigaction(SIGSYS,  &act, NULL);

	sigaction(SIGILL,  &act, NULL);
	sigaction(SIGFPE,  &act, NULL);
	sigaction(SIGSEGV, &act, NULL);

	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGKILL, &act, NULL);		/* 9 */
	sigaction(SIGUSR1, &act, NULL);		/* 10 */
	sigaction(SIGUSR2, &act, NULL);		/* 12 */

	sigaction(SIGRTMAX, &act, NULL);	/* 64 */
	sigaction(SIGRTMIN, &act, NULL);	/* 34 */
	sigaction(SIGRTMIN + 1, &act, NULL);	/* 35 */
}

#ifdef AV_MULTI_LAYER_DECOMP
int dcps_detect_comp_type(int decomp_method, unsigned char *p_sig)
{
	if (decomp_method == LC_RAR5)
	{
		return LC_AUTO;
	}
	else if (memcmp(p_sig, zip_header_signature, sizeof(zip_header_signature)) == 0)
	{
		return LC_ZIP;
	}
	else if (memcmp(p_sig, gzip_header_signature, sizeof(gzip_header_signature)) == 0)
	{
		return LC_GZIP;
	}
	else if (memcmp(p_sig, rar_header_signature, sizeof(rar_header_signature)) == 0)
	{
		return LC_RAR;
	}

	return LC_AUTO; /* Unsupported type */
}

void copy_sess_extend(int session_id, int decomp_method, int file_begin, lc_decomp_info *srci, u16 data_len, u16 filename_offset)
{
	sess_extend[session_id].srci->data_id = srci->data_id;
	sess_extend[session_id].srci->decomp_method = decomp_method;
	sess_extend[session_id].srci->data_len = data_len;
	sess_extend[session_id].srci->flag = 0;

	if (file_begin)
	{
		sess_extend[session_id].srci->flag |= LC_DECOMP_FLG_FILE_BEGIN;
	}

	if (data_len)
	{
		memcpy(sess_extend[session_id].rx_buffer, tx_buffer + filename_offset, data_len);
	}
}

void free_sess_extend(int session_id)
{
	if (sess_extend[session_id].sess)
	{
		free(sess_extend[session_id].sess);
	}

	if (sess_extend[session_id].srci)
	{
		free(sess_extend[session_id].srci);
	}

	if (sess_extend[session_id].rx_buffer_pre)
	{
		free(sess_extend[session_id].rx_buffer_pre);
	}

	memset(&(sess_extend[session_id]), 0, sizeof(decomp_session_extend));
}

int malloc_sess_extend(int session_id, int decomp_method)
{
	if (decomp_method == LC_RAR && rar_session_actvie_num >= rar_session_actvie_max)
	{
		return 0; /* 2set rar */
	}

	if (sess_extend[session_id].srci || sess_extend[session_id].sess )
	{
		// Code review: issue, fast path after rx not enough
		fprintf(stderr, "[DEC] Close old extend session\n");
		free_sess_extend(session_id);
		//goto MALLOCTWICE;
	}

	sess_extend[session_id].sess = (decomp_session *)malloc(sizeof(decomp_session));
	if (sess_extend[session_id].sess == NULL)
	{
		goto MALLOCERR;
	}
	memset(sess_extend[session_id].sess, 0, sizeof(decomp_session));

	sess_extend[session_id].srci = (lc_decomp_info *)malloc(sizeof(lc_decomp_info));
	if (sess_extend[session_id].srci == NULL)
	{
		goto MALLOCERR;
	}
	memset(sess_extend[session_id].srci, 0, sizeof(lc_decomp_info));

	sess_extend[session_id].rx_buffer_pre = (u8 *)malloc(RX_BUFFER_LEN + TX_BUFFER_LEN);
	if (sess_extend[session_id].rx_buffer_pre == NULL)
	{
		goto MALLOCERR;
	}
	sess_extend[session_id].rx_buffer = sess_extend[session_id].rx_buffer_pre + RX_BUFFER_LEN;

	return 1;//success
/*
MALLOCTWICE:
	fprintf(stderr, "[DEC]REPEAT MALLOC\n");
	return 0;//fail
*/

MALLOCERR:
	free_sess_extend(session_id);
	fprintf(stderr, "[DEC]MALLOC ERR\n");
	return 0; /* fail */
}

/*
The hexdump of decompressed file will be :

03 00 xx xx xx yy yy yy ...
yy yy yy yy yy yy yy yy...

03 is the length of filename
xx = filename
yy = decompressed file

ex: We have a "B.zip"  and there is a "B.txt" in "B.zip".  "B.txt" = "BCDEF"
The hexdump of TX_BUFER will be:

05 00 42 2e 74 78 74 42 43 44 45 46
            B    .    T    X   T   B   C    D   E   F

If we want to get the real pointer of decompressed content....
HERE is :

txbuffer + *((unsigned short *)tx_buffer) + 2
                   ~~~~~~~~~~~~~~~~~~       ~~~
                            FILENAME_SIZE             SIZE of FILENAME_SIZE


Here is another case:

02 00 qq qq pp pp pp 03 00 xx xx xx yy yy yy
~~~~~~~~~~~~~
out_buf_reserved

out_buf_reserved  is previous tx_buffer

If we want get the real pointer of decompressed content....
we must add "out_buf_reserved_len" :

txbuffer + out_buf_reserved_len + *((unsigned short *)tx_buffer) + 2
						                   ~~~~~~~~~~~~~~~~~~     ~~~
                                                                   FILENAME_SIZE             SIZE of FILENAME_SIZE
*/
/*
min_len  is minimal lengh for decompress server to send ioctl to TALOS
min_len is filename_size + 2 +8

*/
/*
MULTI_LAYER_EXIST = decompress layer2
MULTI_LAYER_NONE = decompress layer1
MULTI_LAYER_REMAIN = decompress layer1, because layer2 havn't dec done, so dec lv1 and re decomp lv2 afer decomp lv1


code flow:
+(CCCC)
open session
+(NNNN)
decomp session
+(EEEE)
+(RRRR)
+(TTTT)
+(XXXX)
+(AAAA)
+(BBBB)

zip/rar:  AE, B AE,TTB AE,TTAE,TAX B CAE,TARA NAXB CB B AE
gz: E,BE,BBE,BTBBE...

gz do not have A, THIS IS VERY IMPORTANT, gz do not have R, too
*/
/*
	dsti = tx_buffer will be clean at start, so we don't need backup them.
	ss will be clean too, but we need  set null to it.
	you can see what value need to be backupped in copy_sess_extend function
*/

/* ----------------------------------------------------- */
int uncomp2 (int status, u8 *ioctl_send)
{
	lc_decomp_info *srci;
	lc_decomp_info *dsti;
	int err;
	decomp_session *ss;
	int min_len = 0;
	int filename_offset = 0;
	int decomp_method;
	int pre_out_buf_reserved_len = 0;
	decomp_session_extend *ss_ext;
	u8 *RX_B;
	int decomp_ml_on = 0;

	keep_status = status;
	session_id = ((lc_decomp_info *) (rx_buffer_header))->session_id;
	srci = (lc_decomp_info *) (rx_buffer_header);

	ss_ext = &(sess_extend[session_id]);

	// Code review: issue, fast path after rx not enough
	if (srci->flag & LC_DECOMP_FLG_FILE_BEGIN)
	{
		if (ss_ext)
		{
			DEBUG_DECOMP(D_MULTI_LAYER, "detected exists seesion id %d\n", session_id);
			ss_ext->exists = MULTI_LAYER_NONE;
		}
	}

	/* switch to another level, decompress lv2 data, so you must set lv2 rx before this */
	if (ss_ext->exists == MULTI_LAYER_EXIST)
	{
		srci = ss_ext->srci;
		RX_B = ss_ext->rx_buffer;
		ss = ss_ext->sess;

		if (srci == NULL || ss == NULL)
		{
			free_sess_extend(session_id);
			srci = (lc_decomp_info *) (rx_buffer_header);
			RX_B = (u8 *)rx_buffer;
			ss = &(sess[session_id]);

			/* switch to lv1 */
			ss_ext->exists = MULTI_LAYER_NONE;
		}
	}
	else
	{
		srci = (lc_decomp_info *) (rx_buffer_header);
		RX_B = (u8 *)rx_buffer;
		ss = &(sess[session_id]);
	}
	/*---->*/
	DEBUG_DECOMP(D_MULTI_LAYER, "--------------LV%d--------%d----%d----\n", ss_ext->exists, ss->decomp_method, session_id);
	dsti = (lc_decomp_info *) (tx_buffer_header);

	if (srci->flag & LC_DECOMP_FLG_MULTI_LAYER)
	{
		decomp_ml_on = 1;
	}
	memcpy(dsti, srci, sizeof(lc_decomp_info));

	dsti->flag = LC_DECOMP_FLG_OK;
	dsti->err  = 0;
	dsti->data_len = 0;

	if (session_id >= session_max)
	{
		fprintf(stderr, "Error: invalid session_id=%d session_max=%d\n", session_id, session_max);
		err = LC_DECOMP_ERR_INVALID_SID;
		goto error_happened;
	}

	ss->next_out = (u8 *)tx_buffer; /* point to start of tx buffer */
	ss->avail_out = TX_BUFFER_LEN;

	/*
	status : LC_UNCOMP2_OK    /    LC_UNCOMP2_DO_AGAIN
	LC_UNCOMP2_OK means we have to send block_end in this phase in lv1 case and get new data in next phase
	LC_UNCOMP2_DO_AGAIN means packet has not decompressed done, so do it again

	so
	        lv1->lv2 ==>OK	//do not need send block_end, but still need use LC_UNCOMP2_OK
	        lv2->lv1 ==>OK
	        B ==>OK
	        A ==>DO_AGAIN
	        E ==>OK
	        T==>DO_AGAIN
	        X==>OK
	*/
	if (status == LC_UNCOMP2_OK)
	{
		do_again_count = 0;
		ss->decomp_method = srci->decomp_method;

		/* New input arrived */
		/*
		last phase is A case: srci->flag & LC_DECOMP_FLG_FILE_BEGIN
		last phase is B case: ss->in_buf_len == 0
		*/
		if (srci->flag & LC_DECOMP_FLG_FILE_BEGIN || ss->in_buf_len == 0)
		{
			/*There no previous input left */
			ss->next_in = RX_B + srci->skip_len;
			ss->avail_in = srci->data_len - srci->skip_len;
			ss->in_buf_len = 0;
		}
		else
		{
			/* We have to attach our last left input in front of this */
			/* Also move srci to new place */
			/*
				last phase is  XB,  so if X exist==> XBC
			*/
			//1 //CCCCCCCCCCCCCCCCCCCCCCCC
			unsigned char *p;
			p = RX_B + srci->skip_len - ss->in_buf_len ;
			memcpy(p, ss->in_buf, ss->in_buf_len);
			ss->next_in = p;
			ss->avail_in = ss->in_buf_len + srci->data_len - srci->skip_len;
			/*---->*/
			DEBUG_DECOMP(D_MULTI_LAYER, "FILE_CONN srci->data_len=%d, ss->in_buf_len=%d  srci->flag =%d\n", srci->data_len, ss->in_buf_len, srci->flag);//3
			ss->in_buf_len = 0;
		}
	}
	else
	{
		do_again_count++;
	}

	err = LC_DECOMPSERVER_OK;
	ss->flag = LC_DECOMPSERVER_FLG_NONE;
	status = LC_UNCOMP2_OK;

	if (srci->flag & LC_DECOMP_FLG_FILE_BEGIN)
	{
		srci->flag &= (~LC_DECOMP_FLG_FILE_BEGIN);
		ss->file_count = 0;
		ss->check_decomp_bomb = 0;

		#ifdef DETECT_DECOMP_BOMB_SUPPORT
		//check_decomp_bomb is file-based-scope, not pkt-based-scope
		if (ss_ext->exists == MULTI_LAYER_NONE)
		{
			//setup outer session
			if (srci->flag & LC_DECOMP_FLG_CHECK_BOMB)
			{
				ss->check_decomp_bomb = 1;
			}
		}
		else if (ss_ext->exists == MULTI_LAYER_EXIST)
		{
			//propagate outer session into inner session
			ss->check_decomp_bomb = sess[session_id].check_decomp_bomb;
		}
		//MULTI_LAYER_REMAIN follows MULTI_LAYER_EXIST setting

		//inflate/gz will make use of it. zip/rar no need it.
		ss->pack_size = 0;
		ss->unpack_size = 0;
		#endif

		switch (ss->decomp_method)
		{
		case LC_INFLATE:
			err = inflate_session_open (session_id, ss_ext->exists);
			break;
		case LC_ZIP:
			err = zip_session_open (session_id, ss_ext->exists);
			break;
		case LC_GZIP:
			err = gzip_session_open (session_id, ss_ext->exists);
			break;
		#ifdef DECOMP_MODULE_RAR5
		case LC_RAR5:
			err = rar5_session_open(session_id);
			break;
		#endif

		case LC_RAR:
			if (ss_ext->exists == MULTI_LAYER_NONE)
			{
				rar_sess_status = *rar_sess_status_ptr;
				rar_session_update(rar_sess_status);	//free rar->window, this code will only run once..
			}
			err = rar_session_open(session_id, ss_ext->exists);
			break;

		default:
			// Unknown format error
			err      = LC_DECOMP_ERR_INVALID_METHOD;
			break;
		}

		if (err != LC_DECOMPSERVER_OK)
		{
			goto error_happened;
		}
	}

	#if 1
	/* Restore flags & preserved buffer */
	/*
		last phase is  RB or RA,	so if R exist==> RBN or RAN
	*/
	//1 //NNNNNNNNNNNNNNNNNNNNNNNNNNNN
	#endif

	switch (ss->decomp_method)
	{
	case LC_ZIP:
		err = zip_session_decomp (session_id, ss_ext->exists);
		break;
	case LC_INFLATE:
		err = inflate_session_decomp (session_id, ss_ext->exists);
		break;
	case LC_GZIP:
		err = gzip_session_decomp (session_id, ss_ext->exists);
		break;
	case LC_RAR:
		err = rar_session_decomp (session_id, ss_ext->exists);
		break;
	#ifdef DECOMP_MODULE_RAR5
	case LC_RAR5:
		err = rar5_session_decomp (session_id);
		break;
	#endif
	default:
		// Unknown format error
		err = LC_DECOMP_ERR_INVALID_METHOD;
	}

	if (err != LC_DECOMPSERVER_OK)
	{
		goto error_happened;
	}
	//1 ---------decompress OVER----------

	/* check file begin */
	if (ss->flag & LC_DECOMPSERVER_FLG_FILE_BEGIN)
	{
		if ((sess[session_id]).file_count == 1 && ss->file_count == 1)
		{
			/* first file */
			dsti->flag |= LC_DECOMP_FLG_FILE_BEGIN;
		}
		else
		{
			/* not first one, also imply previous file is finished */
			dsti->flag |= LC_DECOMP_FLG_NEXT_FILE;
		}

		/* check if filename is embedded */

	}
	else
	{
		/*
			this case is for:
			bNa, ANa, aNa
			if condition is BNa  set pre_out_buf_reserved_len 0
			if condition is aNa or Ana tx+=pre_out_buf_reserved_len;
			gz has only one file, so do not need this
		*/
		pre_out_buf_reserved_len = 0;//not file begin, gz has only one file
	}

	if (ss->flag & LC_DECOMPSERVER_FLG_HAS_FILENAME)
	{
		dsti->flag |= LC_DECOMP_FLG_FILE_NAME;
	}

	dsti->data_len = TX_BUFFER_LEN - (ss->avail_out);     //data length
	/*
		E is end of a zip/rar file
		contains 0 size d_data, but still need it
		one zip/rar file will go this phase just one time
	*/

//1 /*EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE*/
	if (ss->flag & LC_DECOMPSERVER_FLG_FILE_END)
	{
		//3 /* all task for this session is finished */
		if (decomp_ml_on && ss_ext->exists == MULTI_LAYER_NONE)
		{
			if (ss->decomp_method == LC_GZIP)//gz's E  has data in it ...differ from zip/rar
			{
				if (dsti->flag & LC_DECOMP_FLG_FILE_NAME)
				{
					min_len = *((unsigned short *)(tx_buffer + 4)) + 6 + 8;
				}
				else
				{
					min_len = 8;
				}

				filename_offset = min_len - 8;//remove filename

				/*do here*/
				decomp_method = dcps_detect_comp_type(ss->decomp_method, (u8 *)(tx_buffer + filename_offset));
				if (decomp_method >= LC_INFLATE && decomp_method <= LC_RAR)
				{
					if (filename_offset && malloc_sess_extend(session_id, decomp_method))//DL start MALLOC
					{
						/*---->*/
						DEBUG_DECOMP(D_MULTI_LAYER, "    g1\n");
						//1 /*GGGGGGGGGGGGGGGGGGGGGG*/
						copy_sess_extend(session_id, decomp_method, 1, srci, dsti->data_len - filename_offset, filename_offset);
						ss_ext->exists = MULTI_LAYER_EXIST;
						*ioctl_send = 0;//do not send ioctl
						return LC_UNCOMP2_OK;
					}
				}
			}
		}
		else if (ss_ext->exists == MULTI_LAYER_REMAIN)
		{
			//1 /*GGGGGGGGGGGGGGGGGGGGGG*/
			if (ss->decomp_method == LC_GZIP  && ss_ext->sess->avail_in == 0)//bG
			{
				copy_sess_extend(session_id, ss_ext->sess->decomp_method, 0, srci, dsti->data_len, 0);
				ss_ext->exists = MULTI_LAYER_EXIST;
				*ioctl_send = 0;//do not send ioctl
				/*---->*/
				DEBUG_DECOMP(D_MULTI_LAYER, "	 g2\n");
				return LC_UNCOMP2_OK;
			}
			fprintf(stderr, "IMPOSSIBLE1\n");
			err = LC_DECOMP_ERR_DATA_ERROR;
			goto error_happened;
		}
		else if (ss_ext->exists == MULTI_LAYER_EXIST)
		{
			free_sess_extend(session_id);
			ss_ext->exists = MULTI_LAYER_NONE;
			/*
				this part code is important
			*/
			if (sess[session_id].flag & LC_DECOMPSERVER_FLG_FILE_END)
			{
				dsti->flag |= LC_DECOMP_FLG_FILE_END;
				dsti->flag |= LC_DECOMP_FLG_BLOCK_END;

				/*---->*/
				DEBUG_DECOMP(D_MULTI_LAYER, "	eE\n");
				return LC_UNCOMP2_OK;
			}

			if (dsti->decomp_method == LC_GZIP)//because ss_ext->sess had been free
			{
				/*---->*/
				DEBUG_DECOMP(D_MULTI_LAYER, "	e!\n");
				//send ioctl
				// because gz'E has data
				return LC_UNCOMP2_DO_AGAIN;
			}
			/*---->*/
			DEBUG_DECOMP(D_MULTI_LAYER, "	e\n");
			*ioctl_send = 0;//do not send ioctl
			return LC_UNCOMP2_DO_AGAIN;
		}

		dsti->flag |= LC_DECOMP_FLG_FILE_END;
		dsti->flag |= LC_DECOMP_FLG_BLOCK_END;

		/*the following code is to fix that if both NEXT_FILE and FILE_END FLAG are set,so the session will not be clean. Occured when previous tx is too small and copied to reserved, and reserved tx copied back at next state. We solve this by everytime we saw FILE_END flag we just clean the NEXT_FILE flag but the reserved tx will not be scanned*/
		//fix start
		dsti->flag &= ~LC_DECOMP_FLG_NEXT_FILE;
		//fix end
		/*---->*/
		DEBUG_DECOMP(D_MULTI_LAYER, "E\n");
		return LC_UNCOMP2_OK;
	}

	//1 	/* start of file*/
	#if 1
	if (dsti->flag & (LC_DECOMP_FLG_FILE_BEGIN | LC_DECOMP_FLG_NEXT_FILE))
	{
		if (dsti->flag & LC_DECOMP_FLG_FILE_NAME)
		{
			min_len = *((unsigned short *)(tx_buffer + pre_out_buf_reserved_len + 4)) + 6 + 8;
		}
		else
		{
			min_len = 8;
		}
		/*decompressed data is too small*/
	}
	#endif

	//1 TTTTTTTTTTTTTTTTTTTTTTTTT
	if (ss->flag & LC_DECOMPSERVER_FLG_TX_FULL)
	{
		/* need kernel side to poll result out */
		/*if reserved_happened==1*/
		if (decomp_ml_on && ss_ext->exists == MULTI_LAYER_NONE)
		{
			if (min_len != 0)
			{
				/* remove filename data */
				filename_offset = min_len - 8 + pre_out_buf_reserved_len;
			}

			decomp_method = dcps_detect_comp_type(ss->decomp_method, (u8 *)(tx_buffer + filename_offset));
			if (decomp_method >= LC_INFLATE && decomp_method <= LC_RAR)
			{
				/* DL start MALLOC */
				if (filename_offset && malloc_sess_extend(session_id, decomp_method))
				{
					/*---->*/
					DEBUG_DECOMP(D_MULTI_LAYER, "T1\n");
					copy_sess_extend(session_id, decomp_method, 1, srci, dsti->data_len - filename_offset, filename_offset);
					ss_ext->exists = MULTI_LAYER_EXIST;
					*ioctl_send = 0;//do not send ioctl
					return LC_UNCOMP2_OK;
				}
			}

		}
		else if (ss_ext->exists == MULTI_LAYER_REMAIN)
		{
			copy_sess_extend(session_id, ss_ext->sess->decomp_method, 0, srci, dsti->data_len, 0);
			ss_ext->exists = MULTI_LAYER_EXIST;
			*ioctl_send = 0;//do not send ioctl
			/*---->*/
			DEBUG_DECOMP(D_MULTI_LAYER, "T2\n");
			//T2->b->(T2)?->A
			return LC_UNCOMP2_OK;
		}

		return LC_UNCOMP2_DO_AGAIN;
	}

	/* We still have data */
	//1 XXXXXXXXXXXXXXXXXXXXXXXXXXx
	if (ss->avail_in != 0)
	{
		if (ss->flag & LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH)
		{
			/* hey, avail in still may have unused data since it's too small */
			/* copy it into in_buf */
			ss->in_buf_len = ss->avail_in;
			if (ss->in_buf_len > RX_BUFFER_LEN)
			{
				err = LC_DECOMP_ERR_DATA_ERROR;
				goto error_happened;
			}

			memcpy(ss->in_buf, ss->next_in, ss->in_buf_len);
			/* We need more input to proceed */
			/* This input block is processed */
			if (ss_ext->exists == MULTI_LAYER_REMAIN)
			{
				fprintf(stderr, "IMPOSSIBLE2\n");
				err = LC_DECOMP_ERR_DATA_ERROR;
				goto error_happened;
			}
			else if (ss_ext->exists == MULTI_LAYER_EXIST)
			{
				/*---->*/
				DEBUG_DECOMP(D_MULTI_LAYER, "    x\n");
				dsti->flag |= LC_DECOMP_FLG_BLOCK_END;

				ss_ext->exists = MULTI_LAYER_REMAIN;
				return LC_UNCOMP2_OK;
			}
			else
			{
				dsti->flag |= LC_DECOMP_FLG_BLOCK_END;
				/*---->*/
				DEBUG_DECOMP(D_MULTI_LAYER, "X\n");
			}
			return LC_UNCOMP2_OK;
		}
		//1 /*AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA*/
		else
		{
			/* We left some input data, maybe due to last end-of-file */
			/* just keep every thing untouched, do it again */
			if (decomp_ml_on && ss_ext->exists == MULTI_LAYER_NONE)
			{
				if (min_len != 0)
				{
					/* remove filename data */
					filename_offset = min_len - 8 + pre_out_buf_reserved_len;
				}

				decomp_method = dcps_detect_comp_type(ss->decomp_method, (u8 *)(tx_buffer + filename_offset));
				if (decomp_method >= LC_INFLATE && decomp_method <= LC_RAR)
				{
					/* DL start MALLOC */
					if (filename_offset && malloc_sess_extend(session_id, decomp_method))
					{
						/*---->*/
						DEBUG_DECOMP(D_MULTI_LAYER, "M1 %d\n", filename_offset);
						//dumpHex(tx_buffer+filename_offset,dsti->data_len-filename_offset);
						copy_sess_extend(session_id, decomp_method, 1, srci, dsti->data_len - filename_offset, filename_offset);
						ss_ext->exists = MULTI_LAYER_EXIST;
						*ioctl_send = 0;//do not send ioctl
						return LC_UNCOMP2_OK;
					}
				}
			}
			else if (ss_ext->exists == MULTI_LAYER_REMAIN)
			{
				copy_sess_extend(session_id, ss_ext->sess->decomp_method, 0, srci, dsti->data_len, 0);
				ss_ext->exists = MULTI_LAYER_EXIST;
				*ioctl_send = 0; //do not send ioctl
				/*---->*/
				DEBUG_DECOMP(D_MULTI_LAYER, "M2\n");
				return LC_UNCOMP2_OK;
			}
			/*
				check M malloc
			*/
			if (ss_ext->exists == MULTI_LAYER_EXIST)
			{
				/*---->*/
				DEBUG_DECOMP(D_MULTI_LAYER, "    a\n");
			}
			else
				/*---->*/DEBUG_DECOMP(D_MULTI_LAYER, "A pre=%d\n", pre_out_buf_reserved_len);

			return LC_UNCOMP2_DO_AGAIN;
		}
	}
	//1 /*BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB*/
	else
	{
		/* Happy, this block is ok! */
		if (ss_ext->exists == MULTI_LAYER_EXIST)
		{
			ss_ext->exists = MULTI_LAYER_REMAIN;
			if (sess[session_id].flag & LC_DECOMPSERVER_FLG_TX_FULL)///Tb!! special case
			{
				/*---->*/
				DEBUG_DECOMP(D_MULTI_LAYER, "    bt\n");
				return LC_UNCOMP2_DO_AGAIN;
			}
			dsti->flag |= LC_DECOMP_FLG_BLOCK_END;
			/*---->*/
			DEBUG_DECOMP(D_MULTI_LAYER, "    b\n");
			return LC_UNCOMP2_OK;
		}
		else if (ss_ext->exists == MULTI_LAYER_REMAIN)//bb or RbCa..
		{
			/*---->*/
			DEBUG_DECOMP(D_MULTI_LAYER, "N2\n");
			copy_sess_extend(session_id, ss_ext->srci->decomp_method, 0, srci, dsti->data_len, 0);
			ss_ext->exists = MULTI_LAYER_EXIST;
			*ioctl_send = 0;//do not send ioctl
			return LC_UNCOMP2_OK;
		}
		else if (decomp_ml_on && ss_ext->exists == MULTI_LAYER_NONE)
		{
			if (min_len != 0)
			{
				/* remove filename */
				filename_offset = min_len - 8 + pre_out_buf_reserved_len;
			}

			decomp_method = dcps_detect_comp_type(ss->decomp_method, (u8 *)(tx_buffer + filename_offset));
			if (decomp_method >= LC_INFLATE && decomp_method <= LC_RAR)
			{
				/* DL start MALLOC */
				if (filename_offset && malloc_sess_extend(session_id, decomp_method))
				{
					/*---->*/
					DEBUG_DECOMP(D_MULTI_LAYER, "N1\n");
					copy_sess_extend(session_id, decomp_method, 1, srci, dsti->data_len - filename_offset, filename_offset);
					ss_ext->exists = MULTI_LAYER_EXIST;
					*ioctl_send = 0;//do not send ioctl
					return LC_UNCOMP2_OK;
				}
			}
		}
		dsti->flag |= LC_DECOMP_FLG_BLOCK_END; /* This input block is processed */
		/*---->*/
		DEBUG_DECOMP(D_MULTI_LAYER, "B\n");

		return LC_UNCOMP2_OK;
	}

error_happened:

	dsti->err      = err;
	dsti->flag     = (LC_DECOMP_FLG_FILE_END |
	                  LC_DECOMP_FLG_BLOCK_END);
	dsti->data_len = 0;
	free_sess_extend(session_id);
	// fprintf(stderr, "! Error happened in uncomp2(), err = %x\n", err);
	#ifdef DETECT_DECOMP_BOMB_SUPPORT
	if (ss->flag & LC_DECOMPSERVER_FLG_DECOMP_BOMB)
	{
		dsti->err = LC_DECOMP_ERR_BOMB_HAPPEN;
		DEBUG_DECOMP(D_BOMB, "[1]LC_DECOMP_ERR_BOMB_HAPPEN\n");
	}
	#endif
	return LC_UNCOMP2_OK;
}
#else
int uncomp2 (int status)
{
	lc_decomp_info *srci;
	lc_decomp_info *dsti;
	decomp_session *ss = NULL;
	int err;

	keep_status = status;
	srci = (lc_decomp_info *) (rx_buffer_header);
	dsti = (lc_decomp_info *) (tx_buffer_header);

	#ifdef DUMP_DECOMP_SERVER_LOG
	fprintf(fpout, "uncomp2, src flag %x, len %d, status %d\n", srci->flag, srci->data_len, status);
	fflush(fpout);
	#endif

	memcpy(dsti, srci, sizeof(lc_decomp_info));

	session_id = srci->session_id;
	dsti->flag = LC_DECOMP_FLG_OK;
	dsti->data_len = 0;
	dsti->err  = 0;

	if (session_id >= session_max)
	{
		err = LC_DECOMP_ERR_INVALID_SID;
		goto error_happened;
	}

	ss = &(sess[session_id]);

	#ifdef DUMP_DECOMP_SERVER_LOG
	fprintf(fpout, "Decomp Method=%d\n", srci->decomp_method);
	fflush(fpout);
	#endif

	ss->next_out = (u8 *)tx_buffer; /* point to start of tx buffer */
	ss->avail_out = TX_BUFFER_LEN;

	if (status == LC_UNCOMP2_OK)
	{
		do_again_count = 0;
		ss->decomp_method = srci->decomp_method;

		/* New input arrived */
		if (srci->flag & LC_DECOMP_FLG_FILE_BEGIN || ss->in_buf_len == 0)
		{
			if (print_switch)
			{
				printf("get new data\n");
			}

			/*There no previous input left */
			ss->next_in  = (u8 *)rx_buffer + srci->skip_len;
			ss->avail_in = srci->data_len - srci->skip_len;
			ss->in_buf_len = 0;
		}
		else
		{
			if (print_switch)
			{
				printf("copy old data, in_buf_len %d\n", ss->in_buf_len);
			}

			/* We have to attach our last left input in front of this */
			/* Also move srci to new place */

			unsigned char *p;
			p = (u8 *)rx_buffer + srci->skip_len - ss->in_buf_len;
			memcpy(p, ss->in_buf, ss->in_buf_len);

			ss->next_in = p;
			ss->avail_in = ss->in_buf_len + srci->data_len - srci->skip_len;
			ss->in_buf_len = 0;
		}
	}
	else
	{
		if (print_switch)
		{
			printf("use old data\n");
		}

		do_again_count++; /* keep everything untouched */
	}

	if (print_switch)
	{
		printf("ss->avail_in = %d\n", ss->avail_in);
	}

	err = LC_DECOMPSERVER_OK;
	ss->flag = LC_DECOMPSERVER_FLG_NONE;
	status = LC_UNCOMP2_OK;

	if (srci->flag & LC_DECOMP_FLG_FILE_BEGIN)
	{
		srci->flag &= (~LC_DECOMP_FLG_FILE_BEGIN);
		ss->file_count = 0;
		ss->out_buf_reserved_len = 0;

		#ifdef DETECT_DECOMP_BOMB_SUPPORT
		// setup outer session
		if (srci->flag & LC_DECOMP_FLG_CHECK_BOMB)
		{
			ss->check_decomp_bomb = 1;
		}

		// inflate/gzip will make use of it. zip/rar no need it.
		ss->pack_size = 0;
		ss->unpack_size = 0;
		#endif

		switch (ss->decomp_method)
		{
		case LC_INFLATE:
			err = inflate_session_open(session_id);
			break;

		case LC_ZIP:
			err = zip_session_open(session_id);
			break;

		case LC_GZIP:
			err = gzip_session_open(session_id);
			break;

		#ifdef DECOMP_MODULE_RAR5
		case LC_RAR5:
			err = rar5_session_open(session_id);
			break;
		#endif

		case LC_RAR:
			rar_sess_status = *rar_sess_status_ptr;
			rar_session_update(rar_sess_status);
			err = rar_session_open(session_id);
			break;

		default: /* Unknown format error */
			err = LC_DECOMP_ERR_INVALID_METHOD;
			break;
		}

		if (err != LC_DECOMPSERVER_OK)
		{
			goto error_happened;
		}
	}


	switch (ss->decomp_method)
	{
	case LC_ZIP:
		err = zip_session_decomp(session_id);
		break;

	case LC_INFLATE:
		err = inflate_session_decomp(session_id);
		break;

	case LC_GZIP:
		err = gzip_session_decomp(session_id);
		break;

	#ifdef DECOMP_MODULE_RAR5
	case LC_RAR5:
		err = rar5_session_decomp(session_id);
		break;
	#endif

	case LC_RAR:
		err = rar_session_decomp(session_id);
		break;

	default: /* Unknown format error */
		err = LC_DECOMP_ERR_INVALID_METHOD;
	}

	if (print_switch)
	{
		printf("err = %d, ss->flag %x\n", err, ss->flag);
	}

	if (err != LC_DECOMPSERVER_OK)
	{
		goto error_happened;
	}

	/* check file begin */
	if (ss->flag & LC_DECOMPSERVER_FLG_FILE_BEGIN)
	{
		if (ss->file_count == 1)
		{
			/* first file */
			dsti->flag |= LC_DECOMP_FLG_FILE_BEGIN;
		}
		else
		{
			/* not first one, also imply previous file is finished */
			dsti->flag |= LC_DECOMP_FLG_NEXT_FILE;
		}
	}

	if (ss->flag & LC_DECOMPSERVER_FLG_HAS_FILENAME)
	{
		dsti->flag |= LC_DECOMP_FLG_FILE_NAME;
	}

	dsti->data_len = TX_BUFFER_LEN - (ss->avail_out); /* data length */

	if (ss->flag & LC_DECOMPSERVER_FLG_FILE_END)
	{
		/* all task for this session is finished */
		dsti->flag |= (LC_DECOMP_FLG_FILE_END | LC_DECOMP_FLG_BLOCK_END);

		/* the following code is to fix that if both NEXT_FILE and FILE_END FLAG are set, so the session will not be clean.
		 * Occured when previous tx is too small and copied to reserved, and reserved tx copied back at next state.
		 * We solve this by everytime
		 * we saw FILE_END flag
		 * we just clean the NEXT_FILE flag
		 * but the reserved tx will not be scanned
		 */

		dsti->flag &= ~LC_DECOMP_FLG_NEXT_FILE;
		return LC_UNCOMP2_OK;
	}

	if (ss->flag & LC_DECOMPSERVER_FLG_TX_FULL)
	{
		/* need kernel side to poll result out */
		return LC_UNCOMP2_DO_AGAIN;
	}

	/* We still have data */
	if (ss->avail_in != 0)
	{
		if (print_switch)
		{
			printf("avail_in left = %d, \n", ss->avail_in);
		}

		if (ss->flag & LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH)
		{
			/* hey, avail in still may have unused data since it's too small */
			/* copy it into in_buf */
			if (print_switch)
			{
				printf("copy left = %d, \n", ss->avail_in);
			}

			ss->in_buf_len = ss->avail_in;
			if (ss->in_buf_len > RX_BUFFER_LEN)
			{
				fprintf(stderr, "Too much left..\n");
				err = LC_DECOMP_ERR_DATA_ERROR;
				goto error_happened;
			}

			memcpy(ss->in_buf, ss->next_in, ss->in_buf_len);

			/* We need more input to proceed */
			/* This input block is processed */

			dsti->flag |= LC_DECOMP_FLG_BLOCK_END;
			return LC_UNCOMP2_OK;
		}
		else
		{
			/* We left some input data, maybe due to last end-of-file */
			/* just keep every thing untouched, do it again */

			return LC_UNCOMP2_DO_AGAIN;
		}
	}
	else
	{
		/* Happy, this block is ok! */
		/* This input block is processed */

		dsti->flag |= LC_DECOMP_FLG_BLOCK_END;
		return LC_UNCOMP2_OK;
	}

error_happened:
	dsti->err      = err;
	dsti->flag     = (LC_DECOMP_FLG_FILE_END | LC_DECOMP_FLG_BLOCK_END);
	dsti->data_len = 0;

	#ifdef DUMP_DECOMP_SERVER_LOG
	fprintf(fpout, "! Error happened in uncomp2(), err = %x\n", err);
	fflush(fpout);
	#endif

	#ifdef DETECT_DECOMP_BOMB_SUPPORT
	if (ss && ss->flag & LC_DECOMPSERVER_FLG_DECOMP_BOMB)
	{
		dsti->err = LC_DECOMP_ERR_BOMB_HAPPEN;
		DEBUG_DECOMP(D_BOMB, "[2]LC_DECOMP_ERR_BOMB_HAPPEN\n");
	}
	#endif

	return LC_UNCOMP2_OK;
}
#endif

int init_decomp_client(void)
{
	char dev_name[32];
	strcpy(dev_name, g_strNodeName);

	drv_fd = -1;
	mptr = NULL;

	/* connect to kernel space driver */
	drv_fd = open(dev_name, O_RDWR | O_SYNC);

	if (drv_fd == -1)
	{
		printf("Can't open it, %s!\n", dev_name);
		return -1;
	}

	fflush(stdout);

	mptr = (char*)mmap(0, DECOMP_BUFFER_LEN, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, drv_fd, 0);

	if (mptr == MAP_FAILED)
	{
		printf("mmap failed! %s\n", strerror(errno));
	}
	else
	{
		rar_sess_status_ptr = (unsigned int *)mptr;
		#ifdef DECOMP_MODULE_RAR5
		rar5_sess_status_ptr = (unsigned int *)mptr;
		#endif

		rx_buffer_header = mptr + DECOMP_RAR_SESSION_STATUS_LEN;
		rx_buffer = rx_buffer_header + sizeof(lc_decomp_info) + DECOMP_UNDECOMP_DATA_BUFFER_LEN;

		tx_buffer_header = rx_buffer + DECOMP_RX_BUFFER_LEN ;
		tx_buffer = tx_buffer_header + sizeof(lc_decomp_info);
	}

	return 0;
}

int init_decomp_session(lc_init_info *init_info)
{
	g_init_info = *init_info;

	if (init_info->version != 0x01)
	{
		return 1;
	}

	#ifdef DUMP_DECOMP_SERVER_LOG
	 #ifdef DECOMP_MODULE_RAR5
	fprintf(fpout, "init_decomp_session, ZIP %d, RAR %d, RAR5 %d\n", g_init_info.zip_session, g_init_info.rar_session, g_init_info.rar5_session);
	 #else
	fprintf(fpout, "init_decomp_session, ZIP %d, RAR %d\n", g_init_info.zip_session, g_init_info.rar_session);
	 #endif
	fflush(fpout);
	#endif

	#ifdef DECOMP_MODULE_RAR5
	session_max = g_init_info.zip_session + g_init_info.rar_session + g_init_info.rar5_session + 1;
	#else
	session_max = g_init_info.zip_session + g_init_info.rar_session + 1;
	#endif
	if (session_max < 1)
	{
		return 2;
	}

	free(sess);
	sess = (decomp_session *)malloc(session_max * sizeof (decomp_session));

	#ifdef AV_MULTI_LAYER_DECOMP
	sess_extend = (decomp_session_extend *)malloc(session_max * sizeof (decomp_session_extend));
	if (sess && sess_extend)
	#else
	if (sess)
	#endif
	{
		memset(sess, 0, session_max * sizeof (decomp_session));

		#ifdef AV_MULTI_LAYER_DECOMP
		memset(sess_extend, 0, session_max * sizeof (decomp_session_extend));
		#endif
	}
	else
	{
		fprintf(stderr, "Memory error\n");
	}

	zip_init(g_init_info.zip_session, 1);
	rar_init(g_init_info.rar_session, g_init_info.zip_session + 1, g_init_info.ppm_num);
	#ifdef DECOMP_MODULE_RAR5
	rar5_init(g_init_info.rar5_session, g_init_info.zip_session + g_init_info.rar_session + 1,
			g_init_info.rar5_in_buffer_size, g_init_info.rar5_out_buffer_size);
	#endif

	#ifdef AV_MULTI_LAYER_DECOMP
	DEBUG_DECOMP(D_MULTI_LAYER, "%d %d", rar_session_actvie_num, rar_session_actvie_max);

	/* set to default rar session num */
	rar_session_actvie_num = g_init_info.rar_session;
	rar_session_actvie_max = g_init_info.rar_session_active_max;
	#endif

	#ifdef DETECT_DECOMP_BOMB_SUPPORT
	/* set decompression-bomb ratio */
	g_decomp_bomb_ratio = g_init_info.decomp_bomb_ratio;
	#endif

	return 0;
}

int main(int argc, char *argv[])
{
	static int status = LC_UNCOMP2_OK;
	volatile lc_decomp_info *src_decomp_info;
	volatile lc_decomp_info *dst_decomp_info;
	lc_init_info *init_info;
	int srv_num = 1;
	int srv_id = 0;
	int i;
	int unused __attribute__ ((unused));

	#ifdef AV_MULTI_LAYER_DECOMP
	u8 ioctl_send = 1;
	#endif

	#ifndef NO_NICE
	unused = nice(-20); /* Change process priority */
	#endif

	initsignal();

	/* execute how many servers */
	if (argc >= 2)
	{
		srv_num = atoi(argv[1]);
	}

	/* set start server id */
	if (argc >= 3)
	{
		srv_id = atoi(argv[2]);
	}

	sprintf(g_strNodeName, "%s%02d", default_nodename, srv_id);

	sprintf(arg[0], "%s", argv[0]);
	sprintf(arg[1], "%d", srv_num);
	sprintf(arg[2], "%d", srv_id);

	/* execute other decompress server */
	for (i = 0; i < srv_num - 1; i++)
	{
		char cmd[64];
		sprintf(cmd, "%s 0 %d &", argv[0], srv_id + i + 1);
		printf("%s\n", cmd);
		unused = system(cmd);
	}

	/* Init mmap, rx&tx header and buffer */
	if (init_decomp_client() != 0)
	{
		printf("Initialize decomp. client fail\n");
		return 0;
	}

	#ifdef DUMP_DECOMP_SERVER_LOG
	fpout = fopen("decomp_server.log", "w+");
	if (!fpout)
	{
		printf("Can't open file for logging...\n");
	}
	else
	{
		printf("Open decomp_server.log for logging...\n");
	}
	#endif

	/* Notice decomp module(kernel) to init decomp misc dev file */
	ioctl(drv_fd, LC_IOCTL_DECOMP_INIT, rx_buffer_header);

	#ifdef DUMP_DECOMP_SERVER_LOG
	src_decomp_info = (lc_decomp_info*)(rx_buffer_header);
	fprintf(fpout, "Got a data, flag %x, len %d\n", src_decomp_info->flag, src_decomp_info->data_len);
	fflush(fpout);
	#endif

	while (1)
	{
		src_decomp_info = (lc_decomp_info*)(rx_buffer_header);

		#ifdef DUMP_DECOMP_SERVER_LOG
		fprintf(fpout, "In loop, flag %x, len %d\n", src_decomp_info->flag, src_decomp_info->data_len);
		fflush(fpout);
		#endif

		/* Force mmap and misc dev file to sync */
		msync(mptr, DECOMP_BUFFER_LEN, MS_SYNC | MS_INVALIDATE);

		/* This is a control signal */
		if (src_decomp_info->flag == LC_DECOMP_FLG_INIT && status == LC_UNCOMP2_OK)
		{
			init_info = (lc_init_info *)(rx_buffer);

			/* Init decomp methods */
			if (init_decomp_session(init_info) != 0 || src_decomp_info->data_id != 0x12345678)
			{
				printf("Error: Wrong initial data sent bye client!\n");
				break;
			}

			dst_decomp_info = (lc_decomp_info *)(tx_buffer_header);
			memset((char *)dst_decomp_info, 0, sizeof(lc_decomp_info));
			dst_decomp_info->flag = LC_DECOMP_FLG_INIT;
			dst_decomp_info->data_id = (u64)getpid();
			dst_decomp_info->data_len = 0;

			#ifdef DUMP_DECOMP_SERVER_LOG
			fprintf(fpout, "After init\n");
			fflush(fpout);
			#endif

			g_init_complete = 1;
		}
		else
		{
			if (!g_init_complete)
			{
				printf("Error: Failed to do init decomp_server!\n");
				break;
			}

			#ifdef AV_MULTI_LAYER_DECOMP
			status = uncomp2(status, &ioctl_send); /* real decompression handler */
			#else
			status = uncomp2(status); /* real decompression handler */
			#endif
		}

		/* Force mmap and misc dev file to sync */
		msync(mptr, DECOMP_BUFFER_LEN, MS_SYNC | MS_INVALIDATE);

		#ifdef AV_MULTI_LAYER_DECOMP
		if (!ioctl_send)
		{
			ioctl_send = 1;
		}
		else
		#endif
		{
			/* Notice decomp module(kernel) that decomp agent is decomping */
			ioctl(drv_fd, LC_IOCTL_DECOMP_HOOK, rx_buffer_header);
		}
	}

	#ifdef DUMP_DECOMP_SERVER_LOG
	fclose(fpout);
	#endif

	return 0;
}
