/*
** Streaming Decompression engine
*/

#ifndef _DPU_H
#define _DPU_H

#include "rar/unrar.h"
#include "zlib/zlib.h"


/********************************************************************************
 * Memory Assignment in Decompressing Buffer
 * RX_Header: sizeof(lc_decomp_info)
 * TX_Header: sizeof(lc_decomp_info)
 * DECOMP_BUFFER_LEN >= Needed memory space
 * ------------------------------------------------------------------------------
 *
 * DECOMP_RAR       RX_Header  DECOMP_UNDECOMP  DECOMP_RX   TX_Header  DECOMP_TX
 * _SESSION_STATUS             _DATA_BUFFER     _BUFFER_LEN            _BUFFER_LEN
 * _LEN                        _LEN
 *|----------------|----------|----------------|-----------|----------|-----------|
 *|----------------------- DECOMP_BUFFER_LEN >------------------------------------|
 *
***********************************************************************************/

/* Deferred memcpy() seems not stable! */
#undef DEFERRED_MEMCPY

#define	KB					1024
#define FILENAME_LEN_MAX			255

#define D_MULTI_LAYER				(1 << 1)
#define D_BOMB					(1 << 2)

#define LC_UNCOMP2_OK				0x0
#define LC_UNCOMP2_DO_AGAIN			0x1

/* Lower/Upper Memory Bound*/
#define LC_DPU_MEM_LOWER_BOUND			0x80000

/* error code is the same as lc_decomp_info err field */
#define LC_DECOMPSERVER_OK			0

/* For lc_decomp_info flag field */
#define LC_DECOMP_FLG_OK			0x00
#define LC_DECOMP_FLG_FILE_BEGIN		0x01
#define LC_DECOMP_FLG_BLOCK_END			0x02
#define LC_DECOMP_FLG_FILE_END			0x04
#define LC_DECOMP_FLG_NEXT_FILE			0x08
#define LC_DECOMP_FLG_FILE_NAME			0x10
#define LC_DECOMP_FLG_CHECK_BOMB		0x20
#define LC_DECOMP_FLG_MULTI_LAYER		0x40
#define LC_DECOMP_FLG_INIT			0x80
/* No any more space to add flag defines here(only u8 allocated for flag) */

/* For lc_decomp_server flag field */
#define LC_DECOMPSERVER_FLG_NONE		0
#define LC_DECOMPSERVER_FLG_FILE_BEGIN		0x1
#define LC_DECOMPSERVER_FLG_HAS_FILENAME	0x2
#define LC_DECOMPSERVER_FLG_FILE_END		0x4
#define LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH	0x8
#define LC_DECOMPSERVER_FLG_TX_FULL		0x10
#define LC_DECOMPSERVER_FLG_DECOMP_BOMB		0x20

/* For lc_decomp_info err field */
#define LC_DECOMP_ERR_MEM_ERROR			0x80
#define LC_DECOMP_ERR_DATA_ERROR		0x81
#define LC_DECOMP_ERR_INVALID_SID		0x82
#define LC_DECOMP_ERR_INVALID_METHOD		0x83
#define LC_DECOMP_ERR_PASSWORD			0x84
#define LC_DECOMP_ERR_NOT_SUPPORT		0x85
#define LC_DECOMP_ERR_PPM_TOO_LARGE		0x86
#define LC_DECOMP_ERR_PPM_FULL			0x87
#define LC_DECOMP_ERR_BOMB_HAPPEN		0x88

/* For lc_decomp_server err field */
#define LC_DECOMPSERVER_MEM_ERROR		LC_DECOMP_ERR_MEM_ERROR
#define LC_DECOMPSERVER_DATA_ERROR		LC_DECOMP_ERR_DATA_ERROR
#define LC_DECOMPSERVER_INVALID_SID		LC_DECOMP_ERR_INVALID_SID
#define LC_DECOMPSERVER_INVALID_METHOD		LC_DECOMP_ERR_INVALID_METHOD
#define LC_DECOMPSERVER_PASSWORD		LC_DECOMP_ERR_PASSWORD
#define LC_DECOMPSERVER_NOT_SUPPORT		LC_DECOMP_ERR_NOT_SUPPORT
#define LC_DECOMPSERVER_PPM_TOO_LARGE		LC_DECOMP_ERR_PPM_TOO_LARGE
#define LC_DECOMPSERVER_PPM_FULL		LC_DECOMP_ERR_PPM_FULL

#ifdef AV_SUPPORT_JUMBO_FRAME
 #define DECOMP_BUFFER_LEN			(56 * KB)
 #define DECOMP_RAR_SESSION_STATUS_LEN		4
 #define DECOMP_UNDECOMP_DATA_BUFFER_LEN	(16 * KB)
 #define DECOMP_RX_BUFFER_LEN			(16 * KB)
 #define DECOMP_TX_BUFFER_LEN			(16 * KB)
#else	/* AV_SUPPORT_JUMBO_FRAME */
 #define DECOMP_BUFFER_LEN			(16 * KB)
 #define DECOMP_RAR_SESSION_STATUS_LEN		4
 #define DECOMP_UNDECOMP_DATA_BUFFER_LEN	(2 * KB)
 #define DECOMP_RX_BUFFER_LEN			(2 * KB)
 #define DECOMP_TX_BUFFER_LEN			(8 * KB)
#endif	/* AV_SUPPORT_JUMBO_FRAME */

#define	RX_BUFFER_LEN				DECOMP_RX_BUFFER_LEN
#define	TX_BUFFER_LEN				DECOMP_TX_BUFFER_LEN

#define DEBUG_DECOMP(debug_id, fmt, args...)						\
	do {										\
		if (g_decomp_debug_mask & debug_id)					\
		{									\
			fprintf(stderr, "%s %d:" fmt, __FUNCTION__ , __LINE__, ## args);\
		}									\
	} while (0)

#define dumpHex(buf,len)								\
	do {										\
		unsigned long dm;							\
		fprintf(stderr,"{{{"#buf", dump address:0x%p, len:%d}}}\n",buf,len);	\
		for (dm = 0; dm < len; dm++)						\
		{									\
			fprintf(stderr,"0x%2x,", (u8)*(char*)(buf+dm));			\
			if((dm+1) % 16 == 0)						\
			{								\
				fprintf(stderr,"\n");					\
			}								\
		}									\
		fprintf(stderr,"\n{{{{{{{{{}}}}}}}}}\n");				\
	}while(0)


enum lc_decomp_type
{
	LC_AUTO,	/* NOT support yet. */
	LC_STORE,	/* Not compressed. Stored Only. */
	LC_INFLATE,
	LC_ZIP,		/* ZIP64 is supported, too. */
	LC_GZIP,
	LC_RAR,
	LC_BZIP2,
	LC_7ZIP
	#ifdef DECOMP_MODULE_RAR5
	,LC_RAR5
	#endif
};
#ifdef AV_MULTI_LAYER_DECOMP
/* muti-layer decompress */
enum decomp_sess_extend_status
{
	MULTI_LAYER_NONE = 0,	/* level 1 */
	MULTI_LAYER_EXIST,	/* level 2 */
	MULTI_LAYER_REMAIN	/* level 1 but level 2 session not done */
};
#endif

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

typedef struct _lc_decomp_info
{
	u16 data_len;
	u8  flag;
	u8  err;
	u16 session_id;
	u8  decomp_method;
	u8  skip_len;
	u64 data_id;
} lc_decomp_info;

/**
 * @struct _lc_init_info
 * @record the initial value of decompression.
 */
typedef struct _lc_init_info
{
	int version;			/* 0x00: lc_init_info version. This is 1 now. */
	int zip_session;		/* 0x04: Maximum zip/inflate sessions. */
	int rar_session;		/* 0x08: Maximum rar sessions. */
	int ppm_num;			/* 0x18: Maximum rar PPM sessions. */
	#ifdef AV_MULTI_LAYER_DECOMP
	int rar_session_active_max;	/* 0x10: Maximum active rar sessions. */
	#endif
	#ifdef DETECT_DECOMP_BOMB_SUPPORT
	int decomp_bomb_ratio;		/* 0x14: Maximum Decompression-Ratio to support */
	#endif
	#ifdef DECOMP_MODULE_RAR5
	int rar5_session;				/* 0x0C: Maximum rar sessions. */
	int rar5_session_active_max;	/* Maximum active rar sessions. */
	unsigned int rar5_in_buffer_size;
	unsigned int rar5_out_buffer_size;
	#endif
} lc_init_info;

typedef struct _decomp_session
{
	u16 decomp_method;
	u16 file_decomp_method;

	u16 avail_out;
	u16 avail_in;

	u16 flag;
	u16 file_flag;

	u8 *next_out;
	u8 *next_in;
	u32 pack_size;
	u32 unpack_size;
	int file_count;

	u16 file_state;
	u16 has_dd;

	u16 file_name_len;
	u16 extra_field_len;

	u16 comment_len;
	u16 in_buf_len;			/* In next file, store un-processed data here */

	u8 in_buf[RX_BUFFER_LEN];

	u16 out_buf_reserved_len;
	u8 check_decomp_bomb;
	u8 resv[1];			/* dummy for alignment */
} decomp_session;

#ifdef AV_MULTI_LAYER_DECOMP
typedef struct _decomp_session_extend
{
	u8 exists;
	decomp_session *sess;
	lc_decomp_info *srci;
	u16 out_buf_reserved_len;
	u8 *rx_buffer_pre;		/* max = 2KB */
	u8 *rx_buffer;			/* max = 8KB = TX */
} decomp_session_extend;
#endif

/* Extern Variables */
extern int session_max;
extern decomp_session *sess;
extern unsigned int g_decomp_debug_mask;

#ifdef AV_MULTI_LAYER_DECOMP
extern int zip_begin;
extern int zip_end;
extern int zip_session_num;
extern z_stream *zip_session;

extern int rar_begin;
extern int rar_end;
extern int rar_session_num;
extern unpack_data_t *rar_session;

extern int rar_session_actvie_num;
extern int rar_session_actvie_max;
extern decomp_session_extend *sess_extend;
#endif

#ifdef DETECT_DECOMP_BOMB_SUPPORT
extern unsigned int g_decomp_bomb_ratio;
#endif


/* Extern Functions */
void
get_u8 (u8 ** ptr, u8 * val);

void
get_u16 (u8 ** ptr, u16 * val);

void
get_u32 (u8 ** ptr, u32 * val);

int
store_session_open (int session_id);

int
store_session_decomp (int session_id);

int
zip_init (int session_num, int begin);

int
rar_session_update(int status_bitmap);

#ifdef DECOMP_MODULE_RAR5
int
rar5_session_update(int status_bitmap);

void
dump_RAR5_structure(int session_id);
#endif

void
dump_RAR_structure(int session_id);

void
dump_ZIP_structure(int session_id);

#ifdef AV_MULTI_LAYER_DECOMP
int
inflate_session_open (int session_id, u8 level);

int
inflate_session_decomp (int session_id, u8 level);

int
zip_session_open (int session_id, u8 level);

int
zip_session_decomp (int session_id, u8 level);

int
gzip_session_open (int session_id, u8 level);

int
gzip_session_decomp (int session_id, u8 level);

int
rar_init (int session_num, int begin, int ppm_max);

int
rar_session_open (int session_id, u8 level);

int
rar_session_decomp (int session_id, u8 level);

#ifdef DECOMP_MODULE_RAR5
int
rar5_init (int session_num, int begin, unsigned int in_buffer_size, unsigned int out_buffer_size);

int
rar5_session_open (int session_id);

int
rar5_session_decomp (int session_id);
#endif

#else

int
inflate_session_open (int session_id);

int
inflate_session_decomp (int session_id);

int
zip_session_open (int session_id);

int
zip_session_decomp (int session_id);

int
gzip_session_open (int session_id);

int
gzip_session_decomp (int session_id);

int
rar_init (int session_num, int begin, int ppm_max);

int
rar_session_open (int session_id);

int
rar_session_decomp (int session_id);

#ifdef DECOMP_MODULE_RAR5
int
rar5_init (int session_num, int begin, unsigned int in_buffer_size, unsigned int out_buffer_size);

int
rar5_session_open (int session_id);

int
rar5_session_decomp (int session_id);
#endif

#endif /* End of AV_MULTI_LAYER_DECOMP */

#endif
