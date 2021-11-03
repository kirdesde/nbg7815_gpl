/*
 *  Extract RAR archives
 *
 *  Copyright (C) 2005-2006 trog@uncon.org
 *  Patches added by Sourcefire, Inc. Copyright (C) 2007-2013
 *
 *  This code is based on the work of Alexander L. Roshal (C)
 *
 *  The unRAR sources may be used in any software to handle RAR
 *  archives without limitations free of charge, but cannot be used
 *  to re-create the RAR compression algorithm, which is proprietary.
 *  Distribution of modified unRAR sources in separate form or as a
 *  part of other software is permitted, provided that it is clearly
 *  stated in the documentation and source comments that the code may
 *  not be used to develop a RAR (WinRAR) compatible archiver.
 *
 */

#ifndef UNRAR_H
#define UNRAR_H 1

#include <inttypes.h> //init64t

typedef struct unpack_data_tag unpack_data_t;
struct unpack_data_tag;
#include "unrardata.h"
#include "unrar20.h"
#include "unrarppm.h"
#include "unrarvm.h"
#include "unrarcmd.h"
#include "unrarfilter.h"


#define FALSE (0)
#define TRUE (1)
#ifndef MIN
#define MIN(a,b) ((a < b) ? a : b)
#endif

#define RAR_OK                              0x0
#define RAR_READ_BUFFER_OK                  0x0
#define RAR_READ_BUFFER_NOT_ENOUGH          0x01
#define RAR_READ_UNMATCHED_MAGIC_COOKIE     0x02
#define RAR_MALLOC_ERROR                    0x04
#define RAR_DATA_ERROR                      0x08
#define RAR_WRITE_BUFFER_NOT_ENOUGH         0x10
#define RAR_VERSION_ERROR                   0x20
#define RAR_REACH_MAX_PPM_MEM_ERROR         0x40
#define RAR_REACH_MAX_PPM_NUM_ERROR         0x80
#define RAR_SEE_DECOMP_BOMB				0x100


#define RAR_MAX_PPM_MEM                0x2800000 /* 40M */


#define UNPACK29_STATE_READ_TABLES    0x00
#define UNPACK29_STATE_UNPACK_DATA    0x01


#define SIZEOF_MARKHEAD 7
#define SIZEOF_NEWMHD 13
#define SIZEOF_NEWLHD 32
#define SIZEOF_SHORTBLOCKHEAD 7
#define SIZEOF_LONGBLOCKHEAD 11
#define SIZEOF_SUBBLOCKHEAD 14
#define SIZEOF_COMMHEAD 13
#define SIZEOF_PROTECTHEAD 26
#define SIZEOF_AVHEAD 14
#define SIZEOF_SIGNHEAD 15
#define SIZEOF_UOHEAD 18
#define SIZEOF_MACHEAD 22
#define SIZEOF_EAHEAD 24
#define SIZEOF_BEEAHEAD 24
#define SIZEOF_STREAMHEAD 26

#define MHD_VOLUME		0x0001
#define MHD_COMMENT		0x0002
#define MHD_LOCK		0x0004
#define MHD_SOLID		0x0008
#define MHD_PACK_COMMENT	0x0010
#define MHD_NEWNUMBERING	0x0010
#define MHD_AV			0x0020
#define MHD_PROTECT		0x0040
#define MHD_PASSWORD		0x0080
#define MHD_FIRSTVOLUME		0x0100
#define MHD_ENCRYPTVER		0x0200

#define LHD_SPLIT_BEFORE	0x0001
#define LHD_SPLIT_AFTER		0x0002
#define LHD_PASSWORD		0x0004
#define LHD_COMMENT		0x0008
#define LHD_SOLID		0x0010

#define LONG_BLOCK         0x8000

#define NC                 299  /* alphabet = {0, 1, 2, ..., NC - 1} */
#define DC                 60
#define RC		    28
#define LDC		    17
#define BC		    20
#define HUFF_TABLE_SIZE    (NC+DC+RC+LDC)

//#define MAX_BUF_SIZE        32768
#define MAX_BUF_SIZE        8192
#define MAX_OUT_BUF_SIZE    0x400000
#define MAXWINSIZE          0x400000
#define MAXWINMASK          (MAXWINSIZE-1)
#define LOW_DIST_REP_COUNT  16


struct Decode
{
	unsigned int MaxNum;
	unsigned int DecodeLen[16];
	unsigned int DecodePos[16];
	unsigned int DecodeNum[2];
};

struct LitDecode
{
	unsigned int MaxNum;
	unsigned int DecodeLen[16];
	unsigned int DecodePos[16];
	unsigned int DecodeNum[NC];
};

struct DistDecode
{
	unsigned int MaxNum;
	unsigned int DecodeLen[16];
	unsigned int DecodePos[16];
	unsigned int DecodeNum[DC];
};

struct LowDistDecode
{
	unsigned int MaxNum;
	unsigned int DecodeLen[16];
	unsigned int DecodePos[16];
	unsigned int DecodeNum[LDC];
};

struct RepDecode
{
	unsigned int MaxNum;
	unsigned int DecodeLen[16];
	unsigned int DecodePos[16];
	unsigned int DecodeNum[RC];
};

struct BitDecode
{
	unsigned int MaxNum;
	unsigned int DecodeLen[16];
	unsigned int DecodePos[16];
	unsigned int DecodeNum[BC];
};

struct UnpackFilter
{
	unsigned int block_start;
	unsigned int block_length;
	unsigned int exec_count;
	int next_window;
	struct rarvm_prepared_program prg;
};

/* RAR2 structures */
#define MC20 257
struct MultDecode
{
	unsigned int MaxNum;
	unsigned int DecodeLen[16];
	unsigned int DecodePos[16];
	unsigned int DecodeNum[MC20];
};

struct AudioVariables
{
	int K1, K2, K3, K4, K5;
	int D1, D2, D3, D4;
	int last_delta;
	unsigned int dif[11];
	unsigned int byte_count;
	int last_char;
};
/* *************** */

#define MAX_FILE_NAME (256)

typedef struct rar1_var_t
{
	/* RAR1 variables */
	unsigned int old_dist_ptr;
	unsigned int  flag_buf, avr_plc, avr_plcb, avr_ln1, avr_ln2, avr_ln3;
	int buf60, num_huf, st_mode, lcount, flags_cnt;
	unsigned int nhfb, nlzb, max_dist3;
	unsigned int chset[256], chseta[256], chsetb[256], chsetc[256];
	unsigned int place[256], placea[256], placeb[256], placec[256];
	unsigned int ntopl[256], ntoplb[256], ntoplc[256];
} rar1_var;


typedef struct rar2_var_t
{
	/* RAR2 variables */
	unsigned int old_dist_ptr;
	int unp_cur_channel, unp_channel_delta, unp_audio_block, unp_channels;
	unsigned char unp_old_table20[MC20 * 4];
	struct MultDecode MD[4];
	struct AudioVariables audv[4];
} rar2_var;
struct unpack_data_tag
{
	unsigned int opened;
	unsigned int state;
	unsigned int unpack_state;
	unsigned int avail_in, avail_out;
	unsigned char *next_in, *next_out;

	unsigned char mh_solid;
	unsigned char file_solid;
	unsigned char file_unpack_ver;
	unsigned char file_method;
	unsigned int file_pack_size;
	unsigned int file_unpack_size;
	unsigned short file_name_size;
	//char file_name[MAX_FILE_NAME];
	int decoding;
	unsigned int total_in;

	//unsigned char out_buf[MAX_OUT_BUF_SIZE];
	unsigned char *out_buf;
	unsigned int out_addr;
	unsigned int out_used;
	unsigned int rar_error;

	unsigned char in_buf[MAX_BUF_SIZE];
	u8_t *window;
	//u8_t window[MAXWINSIZE];
	int in_addr;
	int in_bit;
	int outbuf_full;
	unsigned int unp_ptr;
	unsigned int wr_ptr;
	int tables_read;
	int in_used;
	int read_border;
	int unp_block_type;
	int prev_low_dist;
	int low_dist_rep_count;
	unsigned char unp_old_table[HUFF_TABLE_SIZE];
	struct LitDecode LD;
	struct DistDecode DD;
	struct LowDistDecode LDD;
	struct RepDecode RD;
	struct BitDecode BD;
	unsigned int old_dist[4];
	unsigned int last_dist;
	unsigned int last_length;
	ppm_data_t ppm_data;
	int ppm_esc_char;
	int ppm_error;
	rar_filter_array_t Filters;
	rar_filter_array_t PrgStack;
	int *old_filter_lengths;
	int last_filter, old_filter_lengths_size;
	int64_t written_size;
	//int64_t dest_unp_size;
	int dest_unp_size;
	u32_t pack_size;
	rarvm_data_t rarvm_data;
//	unsigned int unp_crc;

	/* memory last secenario */
	int last_number;
	int is_last_exist;

	rar1_var *rar1_data;
	rar2_var *rar2_data;

	/*multi layer zip*/
#ifdef AV_MULTI_LAYER_DECOMP
	void *next_zs;
#endif
	unsigned char check_decomp_bomb;
	char reserved[3];

};

typedef enum
{
	ALL_HEAD = 0,
	MARK_HEAD = 0x72,
	MAIN_HEAD = 0x73,
	FILE_HEAD = 0x74,
	COMM_HEAD = 0x75,
	AV_HEAD = 0x76,
	SUB_HEAD = 0x77,
	PROTECT_HEAD = 0x78,
	SIGN_HEAD = 0x79,
	NEWSUB_HEAD = 0x7a,
	ENDARC_HEAD = 0x7b
} header_type;

enum BLOCK_TYPES
{
	BLOCK_LZ,
	BLOCK_PPM
};

//rar_metadata_t *cli_unrar(int fd, const char *dirname);
unsigned int rar_get_char(unpack_data_t *unpack_data);
void addbits(unpack_data_t *unpack_data, int bits);
unsigned int getbits(unpack_data_t *unpack_data);
int unp_read_buf(unpack_data_t *unpack_data, unsigned int size_limit);
void unpack_init_data(int solid, unpack_data_t *unpack_data);
void unpack_free_data(unpack_data_t *unpack_data);
void make_decode_tables(unsigned char *len_tab, struct Decode *decode, int size);
int unp_write_buf_old(unpack_data_t *unpack_data);
int decode_number(unpack_data_t *unpack_data, struct Decode *decode);

int is_rar_archive(unsigned char *buf);
int unp_write_out(unpack_data_t *unpack_data);
int rar_unpack29_state(/*int solid,*/ unpack_data_t *unpack_data);
int rar_unpack29(unpack_data_t *unpack_data);
int rar_store(unpack_data_t *unpack_data);
int rar_read_head(unpack_data_t *unpack_data, unsigned char *head_type);
int rar_set_ppm_max(int max);


#endif
