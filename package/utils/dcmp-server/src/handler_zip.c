/*
** Handling Inflate/ZIP/GZIP format
*/

/* deflate format - RFC 1951 "DEFLATE Compressed Data Format Specification version 1.3"
   gzip format    - RFC 1952 "GZIP file format specification version 4.3"
   zlib format    - RFC 1950 "ZLIB Compressed Data Format Specification version 3.3"
   zip format     - InfoZIP APPNOTE.TXT
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dpu.h"
#include "endian.h"
#include "mymalloc.h"

#ifdef LOOP_DEBUG
extern int loop_idx;
#endif

//#define zip_dbgmsg printf
static void zip_dbgmsg() {};
#define zip_errmsg printf

/* ---------------------------------------------------------------- */
///////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
int     zip_begin, zip_end;
int 	zip_session_num;
z_stream *zip_session = NULL;
#else
static  int     zip_begin, zip_end;
static int zip_session_num;
static z_stream *zip_session = NULL;
#endif
//////////////////////
int check_zip_session_range(int session_id)
{
	if ((session_id >= zip_begin) && (session_id <= zip_end))
	{
		/* The session_id is in valid range */
		return 0;
	}
	/* The session_id is invalid. */
	return 1;
}

void dump_ZIP_structure(int session_id)
{
	z_stream *zs;

	/* check sid range */
	if (check_zip_session_range(session_id) != 0)
	{
		fprintf(stderr, "Invalid session_id for zip\n");
		return;
	}
	zs = &(zip_session[session_id-zip_begin]);
	fprintf(stderr, "ZIP next_in %p, next_out %p\n" \
	        "avail_in %d, avail_out %d \n" \
	        "inf_state mode %x, last %d, wrap %d, havedict %d\n" \
	        "flags %x dmax %u check %lu total %lu whave %u" \
	        "hold %lu bits %d length %d offset %u extra %d\n",
	        zs->next_in, zs->next_out,
	        zs->avail_in, zs->avail_out,
	        zs->inf_st.mode, zs->inf_st.last, zs->inf_st.wrap,
	        zs->inf_st.havedict, zs->inf_st.flags, zs->inf_st.dmax,
	        zs->inf_st.check, zs->inf_st.total,
	        zs->inf_st.whave, zs->inf_st.hold, zs->inf_st.bits,
	        zs->inf_st.length, zs->inf_st.offset, zs->inf_st.extra);
}

int zip_init (int session_num, int begin)
{
	zip_begin = begin;
	zip_end  = begin + session_num - 1;
	zip_session_num = session_num;

	if (zip_session)
	{
		free(zip_session);
	}
	zip_session =
	    (z_stream *) malloc (sizeof (z_stream) * zip_session_num);
	memset(zip_session, 0, sizeof (z_stream) * zip_session_num);

	return 0;
}

#define INFLATE_STATE_INIT_INFLATE 0x0
#define INFLATE_STATE_DECODE       (0x1<<0)
#define INFLATE_STATE_STORE        (0x1<<1)
#define INFLATE_STATE_END_INFLATE  (0x1<<2)


///////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
int inflate_session_open (int session_id, u8 level)
{
	decomp_session *ss;
	z_stream *zs;

	/* check sid range */
	if (check_zip_session_range(session_id) != 0
	        && sess[session_id].decomp_method >= LC_INFLATE
	        && sess[session_id].decomp_method <= LC_GZIP)
	{
		return LC_DECOMP_ERR_INVALID_SID;
	}

	/* double layer level 2 free */
	if (level == MULTI_LAYER_EXIST)
	{
		ss = sess_extend[session_id].sess;
		if (sess[session_id].decomp_method == LC_RAR)
		{
			if (rar_session[session_id-rar_begin].next_zs)
				return LC_DECOMPSERVER_INVALID_SID;
			rar_session[session_id-rar_begin].next_zs = (z_stream *) malloc (sizeof (z_stream));
			if (rar_session[session_id-rar_begin].next_zs == NULL)
				return LC_DECOMPSERVER_INVALID_SID;
			zs = rar_session[session_id-rar_begin].next_zs;

		}
		else
		{
			if (zip_session[session_id-zip_begin].next_zs)
				return LC_DECOMPSERVER_INVALID_SID;
			zip_session[session_id-zip_begin].next_zs = (z_stream *) malloc (sizeof (z_stream));
			if (zip_session[session_id-zip_begin].next_zs == NULL)
				return LC_DECOMPSERVER_INVALID_SID;
			zs = zip_session[session_id-zip_begin].next_zs;
		}
		memset(zs, 0, sizeof (z_stream));

	}
	else
	{
		ss = &(sess[session_id]);
		zs = &(zip_session[session_id-zip_begin]);
	}


	/* ss clean up */
	ss->has_dd = 0;
	ss->file_count = 0;
	ss->file_state = INFLATE_STATE_INIT_INFLATE;

	memset(zs, 0, sizeof (z_stream) - sizeof(zs->window));

	return LC_DECOMPSERVER_OK;
}
#else
int inflate_session_open (int session_id)
{
	decomp_session *ss;
	z_stream *zs;

	/* check sid range */
	if (check_zip_session_range(session_id) != 0)
	{
		return LC_DECOMPSERVER_INVALID_SID;
	}
	/* check magic cookie .. */

	ss = &(sess[session_id]);
	/* ss clean up */
	ss->has_dd = 0;
	ss->file_count = 0;
	ss->file_state = INFLATE_STATE_INIT_INFLATE;
	zs = &(zip_session[session_id-zip_begin]);
	memset(zs, 0, sizeof (z_stream) - sizeof(zs->window));

	return LC_DECOMPSERVER_OK;
}
#endif
/////////////////////////
////////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
int inflate_session_decomp (int session_id, u8 level)
#else
int inflate_session_decomp (int session_id)
#endif
////////////////////////
{
	int err = Z_OK;
	decomp_session *ss;
	z_stream *zs;

///////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
	if (level == MULTI_LAYER_EXIST)
	{
		ss = sess_extend[session_id].sess;
		if (sess[session_id].decomp_method == LC_RAR)
		{
			if (rar_session[session_id-rar_begin].next_zs)
				return LC_DECOMPSERVER_INVALID_SID;
			rar_session[session_id-zip_begin].next_zs = (z_stream *) malloc (sizeof (z_stream));
			if (rar_session[session_id-rar_begin].next_zs == NULL)
				return LC_DECOMPSERVER_INVALID_SID;
			zs = rar_session[session_id-rar_begin].next_zs;

		}
		else
		{
			if (zip_session[session_id-zip_begin].next_zs)
				return LC_DECOMPSERVER_INVALID_SID;
			zip_session[session_id-zip_begin].next_zs = (z_stream *) malloc (sizeof (z_stream));
			if (zip_session[session_id-zip_begin].next_zs == NULL)
				return LC_DECOMPSERVER_INVALID_SID;
			zs = zip_session[session_id-zip_begin].next_zs;
		}
		memset(zs, 0, sizeof (z_stream));

	}
	else
	{
		ss = &(sess[session_id]);
		zs = &(zip_session[session_id-zip_begin]);
	}
#else
	ss = &(sess[session_id]);
	zs = &(zip_session[session_id-zip_begin]);

#endif
////////////////////////

	zs->next_in = ss->next_in;
	zs->avail_in = ss->avail_in;
	zs->next_out = ss->next_out;
	zs->avail_out = ss->avail_out;

#ifdef LOOP_DEBUG
	loop_idx = 1;
#endif

	while (1)
	{
		if (ss->file_state == INFLATE_STATE_INIT_INFLATE)
		{
			/*Use (-MAX_WBITS) to skip zlib specific header */
			/*  zip & gzip do not use zlib header */
			err = inflateInit2 (zs, -MAX_WBITS);
			if (err != Z_OK)
			{
				return LC_DECOMPSERVER_DATA_ERROR;
			}
			/*
			if (ss->decomp_sub_method == LC_STORE)
			{
			    ss->file_state = INFLATE_STATE_STORE;
			}
			else
			*/
			{
				ss->file_state = INFLATE_STATE_DECODE;
			}
			ss->flag |= LC_DECOMPSERVER_FLG_FILE_BEGIN;
			ss->file_count++;
		}
		else if (ss->file_state == INFLATE_STATE_STORE)
		{
			int len;

			len = zs->avail_in;
			if ((ss->pack_size) < len)
			{
				len = ss->pack_size;
			}
			if (zs->avail_out < len)
			{
				len = zs->avail_out;
			}
			memcpy(zs->next_out, zs->next_in, len);
			zs->next_in += len;
			zs->avail_in -= len;
			zs->next_out += len;
			zs->avail_out -= len;

			ss->pack_size -= len;
			ss->unpack_size -= len;

			if ((ss->pack_size != 0) && (ss->avail_in == 0))
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
				break;
			}
			else
			{
				ss->file_state = INFLATE_STATE_END_INFLATE;
			}
		}
		else if (ss->file_state == INFLATE_STATE_DECODE)
		{
			if (zs->avail_in == 0)
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
				break;
			}

#ifdef DETECT_DECOMP_BOMB_SUPPORT
			ss->pack_size += zs->avail_in;//first, suppose avail_in all consumed
#endif

			// inflateSync(zs);
			err = inflate (zs, Z_SYNC_FLUSH);

			if ((err < 0) || (err == Z_NEED_DICT))
			{
#ifdef LOOP_DEBUG
				loop_idx = 2;
#endif
				return LC_DECOMPSERVER_DATA_ERROR;
			}


#ifdef DETECT_DECOMP_BOMB_SUPPORT
			ss->pack_size -= zs->avail_in;//second, minus avail_in not consumed to get EXACT consumed
			ss->unpack_size += TX_BUFFER_LEN - (zs->avail_out);

			DEBUG_DECOMP(D_BOMB, "[Inflate]CurrUnPackSize=%u,CurrPackSize=%u,CurrCompRatio=%u\n",
			             ss->unpack_size,
			             ss->pack_size,
			             ss->pack_size ? (ss->unpack_size / ss->pack_size) : 0
			            );

			if (ss->check_decomp_bomb &&
			        ss->pack_size &&
			        (ss->unpack_size / ss->pack_size) > g_decomp_bomb_ratio)
			{
				DEBUG_DECOMP(D_BOMB, "[Inflate]Over Bomb Ratio(%d), Bypass it!\n", g_decomp_bomb_ratio);
				ss->flag = LC_DECOMPSERVER_FLG_DECOMP_BOMB;
				err = -1;//give up this decomp session
				break;
			}
#endif

			if (err == Z_STREAM_END)
			{
				ss->file_state = INFLATE_STATE_END_INFLATE;
			}
			if (zs->avail_in == 0) /* All input is consumed */
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
			}
			if (zs->avail_out == 0)
			{
				ss->flag |= LC_DECOMPSERVER_FLG_TX_FULL;
				break;
			}
		}
		else if (ss->file_state == INFLATE_STATE_END_INFLATE)
		{
			zip_dbgmsg("We got z_stream_end\n");
			err = inflateEnd (zs);
			if (err != Z_OK)
				break;
			/* only first file ? */
			ss->flag |= LC_DECOMPSERVER_FLG_FILE_END;
///////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
			//1 /* double layer level 2 free */
			if (level == MULTI_LAYER_EXIST)
			{
				if (sess[session_id].decomp_method == LC_RAR)
				{
					if (rar_session[session_id-rar_begin].next_zs)
						free(rar_session[session_id-rar_begin].next_zs);
					rar_session[session_id-rar_begin].next_zs = NULL;
				}
				else
				{
					if (zip_session[session_id-zip_begin].next_zs)
						free(zip_session[session_id-zip_begin].next_zs);
					zip_session[session_id-zip_begin].next_zs = NULL;
				}
			}
#endif
////////////////////////
			break;
		}
		else
		{
			return LC_DECOMPSERVER_DATA_ERROR;
		}
	}
#ifdef LOOP_DEBUG
	loop_idx = 2;
#endif

	ss->next_in = zs->next_in;
	ss->avail_in = zs->avail_in;
	ss->next_out = zs->next_out;
	ss->avail_out = zs->avail_out;

	/* Error handling */
	if (err < 0)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}

	return LC_DECOMPSERVER_OK;
}

#define ZIP_STATE_READ_HEADER         0x0
#define ZIP_STATE_STORE               (0x1<<0)
#define ZIP_STATE_DECODE              (0x1<<1)
#define ZIP_STATE_END_INFLATE         (0x1<<2)
#define ZIP_STATE_READ_DATA_DESCRIPTOR (0x1<<3)
#define ZIP_STATE_READ_REDUNDANT_HEADER (0x1<<4)
#define ZIP_STATE_LOCAL_HEADER_DONE    (0x1<<5)
#define ZIP_STATE_READ_FILENAME        (0x1<<6)
#define ZIP_STATE_READ_EXTRA           (0x1<<7)

#define ZIP_LOCAL_FILE_HDR_LEN        (30)
#define ZIP_CDIR_HDR_LEN              (46)
#define ZIP_CDIR_END_HDR_LEN          (22)

char zip_local_file_sig[] = {0x50, 0x4b, 0x03, 0x04};
char zip_central_dir_sig[] = {0x50, 0x4b, 0x01, 0x02};
char zip_central_dir_end_sig[] = {0x50, 0x4b, 0x05, 0x06};

///////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
int zip_session_open (int session_id, u8 level)
{
	decomp_session *ss;
	z_stream *zs;

	if (check_zip_session_range(session_id) != 0
	        && sess[session_id].decomp_method >= LC_INFLATE
	        && sess[session_id].decomp_method <= LC_GZIP)
	{
		return LC_DECOMP_ERR_INVALID_SID;
	}

	/* double layer level 2 free */
	if (level == MULTI_LAYER_EXIST)
	{
		ss = sess_extend[session_id].sess;
		if (sess[session_id].decomp_method == LC_RAR)
		{
			if (rar_session[session_id-rar_begin].next_zs)
				return LC_DECOMPSERVER_INVALID_SID;
			rar_session[session_id-rar_begin].next_zs = (z_stream *) malloc (sizeof (z_stream));
			if (rar_session[session_id-rar_begin].next_zs == NULL)
				return LC_DECOMPSERVER_INVALID_SID;
			zs = rar_session[session_id-rar_begin].next_zs;

		}
		else
		{
			if (zip_session[session_id-zip_begin].next_zs)
				return LC_DECOMPSERVER_INVALID_SID;
			zip_session[session_id-zip_begin].next_zs = (z_stream *) malloc (sizeof (z_stream));
			if (zip_session[session_id-zip_begin].next_zs == NULL)
				return LC_DECOMPSERVER_INVALID_SID;
			zs = zip_session[session_id-zip_begin].next_zs;
		}
		memset(zs, 0, sizeof (z_stream));

	}
	else
	{
		ss = &(sess[session_id]);
		zs = &(zip_session[session_id-zip_begin]);
	}

	if (ss->avail_in < 4)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}
	/* check magic cookie .. */
	if (memcmp(ss->next_in, zip_local_file_sig, 4) != 0)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}

	/* We don't advance 4 bytes */
	ss->file_state = ZIP_STATE_READ_HEADER;
	ss->file_count = 0;
	ss->has_dd = 0;
	/* zs clean up */

	memset(zs, 0, sizeof (z_stream) - sizeof(zs->window));

	zip_dbgmsg("Open .zip ok\n");
	return LC_DECOMPSERVER_OK;
}
#else
int zip_session_open (int session_id)
{
	decomp_session *ss;
	z_stream *zs;

	if (check_zip_session_range(session_id) != 0)
	{
		return LC_DECOMPSERVER_INVALID_SID;
	}

	ss = &(sess[session_id]);

	if (ss->avail_in < 4)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}
	/* check magic cookie .. */
	if (memcmp(ss->next_in, zip_local_file_sig, 4) != 0)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}

	/* We don't advance 4 bytes */
	ss->file_state = ZIP_STATE_READ_HEADER;
	ss->file_count = 0;
	ss->has_dd = 0;
	/* zs clean up */
	zs = &(zip_session[session_id-zip_begin]);
	memset(zs, 0, sizeof (z_stream) - sizeof(zs->window));

	zip_dbgmsg("Open .zip ok\n");
	return LC_DECOMPSERVER_OK;
}
#endif
////////////////////////
///////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
int zip_session_decomp (int session_id, u8 level)
#else
int zip_session_decomp (int session_id)
#endif
///////////////////////
{
	decomp_session *ss;
	z_stream *zs;
	int err = Z_OK;
	int read_len;
	u16 flag;
///////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
	if (level == MULTI_LAYER_EXIST)
	{
		ss = sess_extend[session_id].sess;
		if (sess[session_id].decomp_method == LC_RAR)
			zs = rar_session[session_id-rar_begin].next_zs;
		else
			zs = zip_session[session_id-zip_begin].next_zs;
	}
	else
	{
		ss = &(sess[session_id]);
		zs = &(zip_session[session_id-zip_begin]);
	}
#else
	ss = &(sess[session_id]);
	zs = &(zip_session[session_id-zip_begin]);
#endif
//////////////////////
	zs->next_in = ss->next_in;
	zs->avail_in = ss->avail_in;
	zs->next_out = ss->next_out;
	zs->avail_out = ss->avail_out;

#ifdef LOOP_DEBUG
	loop_idx = 3;
#endif
	while (1)
	{
		zip_dbgmsg("ss->file_state = %x, avail_in %d avail_out %d\n",
		           ss->file_state, zs->avail_in, zs->avail_out);

		if (ss->file_state == ZIP_STATE_READ_EXTRA)
		{
			read_len = MIN(zs->avail_in,ss->extra_field_len);
			zip_dbgmsg("read len %d, extra_field_len %d\n", read_len, ss->extra_field_len);
			zs->next_in += read_len;
			zs->avail_in -= read_len;
			ss->extra_field_len -= read_len;
			read_len = 0;
			if(!ss->extra_field_len)
			{
				ss->file_state = ZIP_STATE_LOCAL_HEADER_DONE;
			}
			else
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
				break;
			}
		}
		else if (ss->file_state == ZIP_STATE_READ_FILENAME)
		{
			if ((zs->avail_in) < ss->file_name_len)
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
				break;
			}
			//In has_dd case: the unpack_size is unknown and is 0 now, but, still need to decompress it
			//In Android APK format, the has_dd is always 1
			if (ss->unpack_size != 0 || ss->has_dd)
			{   /* skip directory & empty file */
#ifdef DETECT_DECOMP_BOMB_SUPPORT
				unsigned char save_byte = zs->next_in[ss->file_name_len];
				zs->next_in[ss->file_name_len] = 0;
				DEBUG_DECOMP(D_BOMB, "[ZIP]Filename=%s,UnPackSize=%u,PackSize=%u,CompRatio=%u\n",
				             zs->next_in,
				             ss->unpack_size,
				             ss->pack_size,
				             ss->pack_size ? (ss->unpack_size / ss->pack_size) : 0
				            );
				zs->next_in[ss->file_name_len] = save_byte;

				if (ss->check_decomp_bomb &&
				        ss->pack_size &&
				        (ss->unpack_size / ss->pack_size) > g_decomp_bomb_ratio)
				{
					DEBUG_DECOMP(D_BOMB, "[ZIP]Over Bomb Ratio(%d), Bypass it!\n", g_decomp_bomb_ratio);
					zs->next_in  += ss->file_name_len;
					zs->avail_in -= ss->file_name_len;
					ss->file_name_len = 0;
					ss->extra_field_len = 0;
					ss->comment_len = 0;
					ss->file_state = ZIP_STATE_READ_HEADER;
					ss->flag  = LC_DECOMPSERVER_FLG_DECOMP_BOMB;
					err = -1;//give up this decomp session
					break;
				}
				else
#endif
				{//Do not remove this bracket
					// fprintf(stderr, "pack_size %u file_name_len %d", ss->pack_size, ss->file_name_len);

					ss->flag |= LC_DECOMPSERVER_FLG_FILE_BEGIN;
					ss->file_count++;

					if(ss->pack_size)
						*((unsigned int *)(zs->next_out)) = ss->pack_size;
					else
						*((unsigned int *)(zs->next_out)) = 0;

					zs->next_out += 4;
					zs->avail_out -= 4;
					*((unsigned short *)(zs->next_out)) = ss->file_name_len;
					zs->next_out += 2;
					zs->avail_out -= 2;
					memcpy(zs->next_out,
					       (char *)zs->next_in, ss->file_name_len);

					zs->next_out  += ss->file_name_len;
					zs->avail_out -= ss->file_name_len;
					zs->next_in   += ss->file_name_len;
					zs->avail_in  -= ss->file_name_len;

					ss->flag  |= LC_DECOMPSERVER_FLG_HAS_FILENAME;
					ss->file_name_len = 0;
				}//Do not remove this bracket
			}
			else
			{
				zs->next_in  += ss->file_name_len;
				zs->avail_in -= ss->file_name_len;
				ss->file_name_len = 0;
			}
			if (ss->extra_field_len)
			{
				ss->file_state = ZIP_STATE_READ_EXTRA;
			}
			else
			{
				ss->file_state = ZIP_STATE_LOCAL_HEADER_DONE;
			}
		}
		else if (ss->file_state == ZIP_STATE_LOCAL_HEADER_DONE)
		{
			if ((ss->unpack_size == 0) || (ss->pack_size == 0))
			{
				//Anyone of them is 0 will lead us to empty file.
				zip_dbgmsg("Skip 0-size file\n");
				ss->file_state = ZIP_STATE_READ_HEADER;
				continue;
			}
			err = inflateInit2 (zs, -MAX_WBITS);
			if (err != Z_OK)
			{
				return LC_DECOMPSERVER_DATA_ERROR;
			}

			if (ss->file_decomp_method == LC_STORE)
			{
				ss->file_state = ZIP_STATE_STORE;
			}
			else
			{
				ss->file_state = ZIP_STATE_DECODE;
			}
		}
		else if (ss->file_state == ZIP_STATE_READ_REDUNDANT_HEADER)
		{
			if (ss->file_name_len > zs->avail_in)
			{
				ss->file_name_len -= zs->avail_in;
				zs->next_in += zs->avail_in;
				zs->avail_in = 0;
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
				break;
			}
			else
			{
				zs->avail_in -= ss->file_name_len;
				zs->next_in += ss->file_name_len;
				ss->file_name_len = 0;
			}
			if (ss->extra_field_len > zs->avail_in)
			{
				ss->extra_field_len -= zs->avail_in;
				zs->next_in += zs->avail_in;
				zs->avail_in = 0;
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
				break;
			}
			else
			{
				zs->avail_in -= ss->extra_field_len;
				zs->next_in += ss->extra_field_len;
				ss->extra_field_len = 0;
			}
			if (ss->comment_len > zs->avail_in)
			{
				ss->comment_len -= zs->avail_in;
				zs->next_in += zs->avail_in;
				zs->avail_in = 0;
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
				break;
			}
			else
			{
				zs->avail_in -= ss->comment_len;
				zs->next_in += ss->comment_len;
				ss->comment_len = 0;
			}
			if (ss->comment_len == 0)
			{
				ss->file_state = ZIP_STATE_READ_HEADER;
			}
		}
		else if (ss->file_state == ZIP_STATE_READ_HEADER)
		{
			if ((zs->avail_in) < 4)
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
				break;
			}

			if (memcmp(zs->next_in, zip_central_dir_end_sig, 4) == 0)
			{   /* Central directory end, also means file end */
				zip_dbgmsg("end of central directory \n");
				zip_dbgmsg("avail-in %d, CDIR END %d\n",
				           zs->avail_in, ZIP_CDIR_END_HDR_LEN);
				if ((zs->avail_in) < ZIP_CDIR_END_HDR_LEN)
				{
					ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
					break;
				}
				ss->comment_len = zs->next_in[20] + ((unsigned int)(zs->next_in[21]) << 8);
				read_len = ZIP_CDIR_END_HDR_LEN + ss->comment_len;
				zip_dbgmsg("read len %d, comment_len %d\n",
				           read_len, ss->comment_len);
				if ((zs->avail_in) < read_len)
				{
					ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
					break;
				}
				zip_dbgmsg("ZIP archive end\n");
				zs->next_in += read_len;
				zs->avail_in -= read_len;
				/* We reach the end of file */
				ss->flag |= LC_DECOMPSERVER_FLG_FILE_END;
///////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
				//1 /* double layer level 2 free */
				if (level == MULTI_LAYER_EXIST)
				{

					if (sess[session_id].decomp_method == LC_RAR)
					{
						if (rar_session[session_id-rar_begin].next_zs)
							free(rar_session[session_id-rar_begin].next_zs);
						rar_session[session_id-rar_begin].next_zs = NULL;
					}
					else
					{
						if (zip_session[session_id-zip_begin].next_zs)
							free(zip_session[session_id-zip_begin].next_zs);
						zip_session[session_id-zip_begin].next_zs = NULL;
					}
				}
#else
#endif
				break;
			}
			else if (memcmp(zs->next_in, zip_central_dir_sig, 4) == 0)
			{   /* Central directory dir, skip them all */
				zip_dbgmsg("central directory \n");
				if ((zs->avail_in) < ZIP_CDIR_HDR_LEN)
				{
					ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
					break;
				}
				ss->file_name_len = zs->next_in[28] + ((unsigned int)(zs->next_in[29]) << 8);
				ss->extra_field_len     = zs->next_in[30] + ((unsigned int)(zs->next_in[31]) << 8);
				ss->comment_len = zs->next_in[32] + ((unsigned int)(zs->next_in[33]) << 8);
				zs->next_in += ZIP_CDIR_HDR_LEN;
				zs->avail_in -= ZIP_CDIR_HDR_LEN;
				ss->file_state = ZIP_STATE_READ_REDUNDANT_HEADER;
			}
			else if (memcmp(zs->next_in, zip_local_file_sig, 4) == 0)
			{
				zip_dbgmsg("local file hdr\n");
				if ((zs->avail_in) < ZIP_LOCAL_FILE_HDR_LEN)
				{
					ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
					break;
				}
				ss->file_decomp_method  = zs->next_in[8] + ((unsigned int)(zs->next_in[9]) << 8);
				if (ss->file_decomp_method == 8)
				{
					ss->file_decomp_method = LC_INFLATE;
				}
				else if (ss->file_decomp_method == 0)
				{
					ss->file_decomp_method = LC_STORE;
				}
				else
				{   /* Other method is not supported */
					zip_dbgmsg("unknown type\n");
#ifdef LOOP_DEBUG
					loop_idx = 1004;
#endif
					return LC_DECOMPSERVER_NOT_SUPPORT;
				}
				ss->pack_size    = zs->next_in[18] +
				                   ((unsigned int)zs->next_in[19] << 8) +
				                   ((unsigned int)zs->next_in[20] << 16) +
				                   ((unsigned int)zs->next_in[21] << 24);
				ss->unpack_size    = zs->next_in[22] +
				                     ((unsigned int)zs->next_in[23] << 8) +
				                     ((unsigned int)zs->next_in[24] << 16) +
				                     ((unsigned int)zs->next_in[25] << 24);

				ss->file_name_len    = zs->next_in[26] + ((unsigned int)(zs->next_in[27]) << 8);
				ss->extra_field_len  = zs->next_in[28] + ((unsigned int)(zs->next_in[29]) << 8);
				ss->comment_len = 0;
				flag = zs->next_in[6] + ((unsigned int)(zs->next_in[7]) << 8);

				if (flag & 0x01) /* password protected */
				{
					zip_dbgmsg("password protected\n");
#ifdef LOOP_DEBUG
					loop_idx = 2004;
#endif

					return LC_DECOMPSERVER_DATA_ERROR;
				}
				if (flag & (0x01 << 3)) /* has data descriptor */
				{
					ss->has_dd = 1;
				}
				else
				{
					ss->has_dd = 0;
				}
				zs->next_in += ZIP_LOCAL_FILE_HDR_LEN;
				zs->avail_in -= ZIP_LOCAL_FILE_HDR_LEN;
				if (ss->file_name_len)
				{
					ss->file_state = ZIP_STATE_READ_FILENAME;
				}
				else
				{
					ss->file_state = ZIP_STATE_READ_EXTRA;
				}


			}
			else
			{
				/* Unknown header signature */
#ifdef LOOP_DEBUG
				loop_idx = 3004;
#endif
				zip_dbgmsg("Unknown data segment\n");
				--(zs->avail_in);
				++(zs->next_in);
			}
		}
		else if (ss->file_state == ZIP_STATE_STORE)
		{
			int len;

			len = zs->avail_in;
			if ((ss->pack_size) < len)
			{
				len = ss->pack_size;
			}
			if (zs->avail_out < len)
			{
				len = zs->avail_out;
			}
			memcpy(zs->next_out, zs->next_in, len);
			zs->next_in += len;
			zs->avail_in -= len;
			zs->next_out += len;
			zs->avail_out -= len;

			ss->pack_size -= len;
			ss->unpack_size -= len;

			if ((ss->pack_size != 0) && (zs->avail_in == 0))
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
				break;
			}
			else
			{
				ss->file_state = ZIP_STATE_END_INFLATE;
			}
		}
		else if (ss->file_state == ZIP_STATE_DECODE)
		{
			if (zs->avail_in == 0)
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
				break;
			}

			// inflateSync(zs);
			err = inflate (zs, Z_SYNC_FLUSH);

			zip_dbgmsg("Err %d after inflate.\n", err);
			if ((err < 0) || (err == Z_NEED_DICT))
			{
#ifdef LOOP_DEBUG
				loop_idx = 4004;
#endif
				return LC_DECOMPSERVER_DATA_ERROR;
			}
			if (err == Z_STREAM_END)
			{
				ss->file_state = ZIP_STATE_END_INFLATE;
			}
			if (zs->avail_in == 0) /* All input is consumed */
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
			}
			if (zs->avail_out == 0)
			{
				ss->flag |= LC_DECOMPSERVER_FLG_TX_FULL;
				break;
			}
		}
		else if (ss->file_state == ZIP_STATE_END_INFLATE)
		{
			zip_dbgmsg("We got z_stream_end\n");
			err = inflateEnd (zs);
			if (err != Z_OK)
				break;
			if (ss->has_dd)
			{
			
				#if 1
				//Work around for Android Application(.apk)
				//Root Cause: 
				//It always flags on the bit 3 of general-purpose flag field of "ZIP local file header"
				//But, the decompressed data length is always less shifting 4 bytes.
				//Wiki: 
				//If bit 3 (0x08) of the general-purpose flags field is set, then the CRC-32 and file sizes are not known when the header is written. 
				//The fields in the local header are filled with zero, and the CRC-32 and size are appended in a 12-byte structure immediately after the compressed data.
				if (zs->avail_in >= 4)
				{
					zs->avail_in -= 4;
					zs->next_in += 4;
				}
				#endif
				ss->file_state = ZIP_STATE_READ_DATA_DESCRIPTOR;
				ss->has_dd = 0;
			}
			else
			{
				ss->file_state = ZIP_STATE_READ_HEADER;
				break; /* force out */
			}
		}
		else if (ss->file_state == ZIP_STATE_READ_DATA_DESCRIPTOR)
		{
			if (zs->avail_in < 12)
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
				break;
			}
			zs->avail_in -= 12;
			zs->next_in += 12;
			ss->file_state = ZIP_STATE_READ_HEADER;
			break; /* force out */

		}
		else
		{
			return LC_DECOMPSERVER_DATA_ERROR;
		}

	}
#ifdef LOOP_DEBUG
	loop_idx = 5004;
#endif

	ss->next_in = zs->next_in;
	ss->avail_in = zs->avail_in;
	ss->next_out = zs->next_out;
	ss->avail_out = zs->avail_out;

	/* Error handling */
	if (err < 0)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}
	return LC_DECOMPSERVER_OK;
}


#define GZIP_STATE_READ_HEADER         0x0
#define GZIP_STATE_READ_EXTRA          (0x1<<0)
#define GZIP_STATE_READ_FNAME          (0x1<<1)
#define GZIP_STATE_READ_COMMENT        (0x1<<2)
#define GZIP_STATE_READ_FHCRC          (0x1<<3)
#define GZIP_STATE_DECODE              (0x1<<4)
#define GZIP_STATE_END_INFLATE         (0x1<<5)
#define GZIP_STATE_READ_TAILER         (0x1<<6)

#define GZIP_HDR_ID_SIZE (2)
char gzip_member_hdr_id[GZIP_HDR_ID_SIZE] = {0x1f, 0x8b};
#define GZIP_HDR_MIN_SIZE (10)

/* gzip flag byte */
#define GZIP_HDR_ASCII        (0x01<<0)       /* bit 0 set: file probably ascii text */
#define GZIP_HDR_HEAD_CRC     (0x01<<1)       /* bit 1 set: header CRC present */
#define GZIP_HDR_EXTRA_FIELD  (0x01<<2)       /* bit 2 set: extra field present */
#define GZIP_HDR_ORIG_NAME    (0x01<<3)       /* bit 3 set: original file name present */
#define GZIP_HDR_COMMENT      (0x01<<4)       /* bit 4 set: file comment present */
#define GZIP_HDR_RESERVED     0xE0            /* bits 5..7: reserved */

///////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
int gzip_session_open (int session_id, u8 level)
{
	decomp_session *ss;
	z_stream *zs;

	if (check_zip_session_range(session_id) != 0
	        && sess[session_id].decomp_method >= LC_INFLATE
	        && sess[session_id].decomp_method <= LC_GZIP)
	{
		return LC_DECOMP_ERR_INVALID_SID;
	}

	/* double layer level 2 free */
	if (level == MULTI_LAYER_EXIST)
	{
		ss = sess_extend[session_id].sess;
		if (sess[session_id].decomp_method == LC_RAR)
		{
			if (rar_session[session_id-rar_begin].next_zs)
				return LC_DECOMPSERVER_INVALID_SID;
			rar_session[session_id-rar_begin].next_zs = (z_stream *) malloc (sizeof (z_stream));
			if (rar_session[session_id-rar_begin].next_zs == NULL)
				return LC_DECOMPSERVER_INVALID_SID;
			zs = rar_session[session_id-rar_begin].next_zs;

		}
		else
		{
			if (zip_session[session_id-zip_begin].next_zs)
				return LC_DECOMPSERVER_INVALID_SID;
			zip_session[session_id-zip_begin].next_zs = (z_stream *) malloc (sizeof (z_stream));
			if (zip_session[session_id-zip_begin].next_zs == NULL)
				return LC_DECOMPSERVER_INVALID_SID;
			zs = zip_session[session_id-zip_begin].next_zs;
		}
		memset(zs, 0, sizeof (z_stream));

	}
	else
	{
		ss = &(sess[session_id]);
		zs = &(zip_session[session_id-zip_begin]);
	}

	if (ss->avail_in < GZIP_HDR_ID_SIZE)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}
	/* check magic cookie .. */
	if (memcmp(ss->next_in, gzip_member_hdr_id, GZIP_HDR_ID_SIZE) != 0)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}
	/* We don't advance 4 bytes */
	ss->file_state = GZIP_STATE_READ_HEADER;
	ss->file_count = 0;
	ss->file_flag = 0;
	ss->has_dd = 0;
	/* zs clean up */

	memset(zs, 0, sizeof (z_stream) - sizeof(zs->window));
	zip_dbgmsg("successfully open gzip..\n");
	return LC_DECOMPSERVER_OK;
}
#else
int gzip_session_open (int session_id)
{
	decomp_session *ss;
	z_stream *zs;

	if (check_zip_session_range(session_id) != 0)
	{
		return LC_DECOMPSERVER_INVALID_SID;
	}

	ss = &(sess[session_id]);

	if (ss->avail_in < GZIP_HDR_ID_SIZE)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}
	/* check magic cookie .. */
	if (memcmp(ss->next_in, gzip_member_hdr_id, GZIP_HDR_ID_SIZE) != 0)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}
	/* We don't advance 4 bytes */
	ss->file_state = GZIP_STATE_READ_HEADER;
	ss->file_count = 0;
	ss->file_flag = 0;
	ss->has_dd = 0;
	/* zs clean up */
	zs = &(zip_session[session_id-zip_begin]);
	memset(zs, 0, sizeof (z_stream) - sizeof(zs->window));
	zip_dbgmsg("successfully open gzip..\n");
	return LC_DECOMPSERVER_OK;
}
#endif
/////////////////////
/////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
int gzip_session_decomp (int session_id, u8 level)
#else
int gzip_session_decomp (int session_id)
#endif
/////////////////////
{
	decomp_session *ss;
	z_stream *zs;
	int err = Z_OK;
	int read_len;
	int i;
/////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
	if (level == MULTI_LAYER_EXIST)
	{
		ss = sess_extend[session_id].sess;
		if (sess[session_id].decomp_method == LC_RAR)
			zs = rar_session[session_id-rar_begin].next_zs;
		else
			zs = zip_session[session_id-zip_begin].next_zs;
	}
	else
	{
		ss = &(sess[session_id]);
		zs = &(zip_session[session_id-zip_begin]);
	}
#else
	ss = &(sess[session_id]);
	zs = &(zip_session[session_id-zip_begin]);
#endif
	zs->next_in = ss->next_in;
	zs->avail_in = ss->avail_in;
	zs->next_out = ss->next_out;
	zs->avail_out = ss->avail_out;

#ifdef LOOP_DEBUG
	loop_idx = 5;
#endif
	while (1)
	{
		zip_dbgmsg("ss->file_state = %x, avail_in %d\n",
		           ss->file_state, zs->avail_in);
		if (ss->file_state == GZIP_STATE_READ_HEADER)
		{

			if ((zs->avail_in) < GZIP_HDR_MIN_SIZE)
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
#ifdef LOOP_DEBUG
				loop_idx = 1006;
#endif
				break;
			}

			if (memcmp(zs->next_in, gzip_member_hdr_id, GZIP_HDR_ID_SIZE) != 0)
			{
				/* Unknown member type */
#ifdef LOOP_DEBUG
				loop_idx = 2006;
#endif
				return LC_DECOMPSERVER_DATA_ERROR;
			}
			ss->file_decomp_method  = *((u8 *)(zs->next_in + 2));
			if (ss->file_decomp_method == 8)
			{
				ss->file_decomp_method = LC_INFLATE;
			}
			else
			{   /* Other method is not supported */
#ifdef LOOP_DEBUG
				loop_idx = 3006;
#endif
				return LC_DECOMPSERVER_NOT_SUPPORT;
			}
			ss->file_flag = *((u8 *)(zs->next_in + 3));
			zs->filename_len = 0;
			zs->next_in += GZIP_HDR_MIN_SIZE;
			zs->avail_in -= GZIP_HDR_MIN_SIZE;
			ss->file_state = GZIP_STATE_READ_EXTRA;
			ss->file_count++;
			ss->flag |= LC_DECOMPSERVER_FLG_FILE_BEGIN;
		}
		else if (ss->file_state == GZIP_STATE_READ_EXTRA)
		{

			if (ss->file_flag & GZIP_HDR_EXTRA_FIELD) /* Have FEXTRA */
			{
				if (zs->avail_in < 2)
				{
					ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
#ifdef LOOP_DEBUG
					loop_idx = 4006;
#endif

					break;
				}
				read_len = zs->next_in[0] + ((unsigned int)(zs->next_in[1]) << 8);
				read_len += 2;
				if (read_len > RX_BUFFER_LEN)
				{
#ifdef LOOP_DEBUG
					loop_idx = 21006;
#endif
					return LC_DECOMPSERVER_DATA_ERROR;
				}
				if (zs->avail_in < read_len)
				{
					ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
#ifdef LOOP_DEBUG
					loop_idx = 5006;
#endif
					break;
				}
				zs->next_in += read_len;
				zs->avail_in -= read_len;

			}
			else
			{
				zip_dbgmsg("No extra\n");
			}
			ss->file_state = GZIP_STATE_READ_FNAME;
		}
		else if (ss->file_state == GZIP_STATE_READ_FNAME)
		{
			if (ss->file_flag & GZIP_HDR_ORIG_NAME) /* Have FNAME */
			{
				/* We look ahead util zero */
				/* Well, we skip filename for GZIP */
#ifdef LOOP_DEBUG
				loop_idx = 7;
#endif
				for (i = 0; zs->avail_in != 0; i++)
				{
					if (zs->next_in[0] == '\0')
					{
						zip_dbgmsg("filename len %d\n", i + 1);
						zs->next_in++;
						zs->avail_in--;
#if 1
						*((unsigned int *)(zs->next_out)) = 0;
						zs->next_out += 4;
						zs->avail_out -= 4;
						*((unsigned short *)(zs->next_out)) = zs->filename_len;
						//printf("filename len %d\n", zs->filename_len);
						zs->next_out += 2;
						zs->avail_out -= 2;
						memcpy(zs->next_out, zs->filename,  zs->filename_len);

#ifdef DETECT_DECOMP_BOMB_SUPPORT
						zs->filename[zs->filename_len] = 0;
						DEBUG_DECOMP(D_BOMB, "[GZ]Filename=%s\n", zs->filename);
#endif

						zs->next_out  += zs->filename_len;
						zs->avail_out -= zs->filename_len;
						ss->flag  |= LC_DECOMPSERVER_FLG_HAS_FILENAME;
#endif
						ss->file_state = GZIP_STATE_READ_COMMENT;
						break;
					}
					else
					{
#if 1
						if (zs->filename_len >= 127)
						{
							memmove(zs->filename, zs->filename + 64, 64);
							zs->filename_len -= 64;
						}
						zs->filename[zs->filename_len] = zs->next_in[0];
						zs->filename_len++;
#endif
						zs->next_in++;
						zs->avail_in--;
					}
				}
#ifdef LOOP_DEBUG
				loop_idx = 8;
#endif
				if (ss->file_state != GZIP_STATE_READ_COMMENT)
				{
					ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
#ifdef LOOP_DEBUG
					loop_idx = 6006;
#endif
					break;
				}
			}
			else
			{
				zip_dbgmsg("no filename\n");
				ss->file_state = GZIP_STATE_READ_COMMENT;
			}
		}
		else if (ss->file_state == GZIP_STATE_READ_COMMENT)
		{
			if (ss->file_flag & GZIP_HDR_COMMENT) /* Have COMMENT */
			{
				/* Well, we skip comment for GZIP */
#ifdef LOOP_DEBUG
				loop_idx = 9;
#endif
				for (i = 0; zs->avail_in != 0; i++)
				{
					if (zs->next_in[0] == '\0')
					{
						ss->file_state = GZIP_STATE_READ_FHCRC;
						zs->next_in++;
						zs->avail_in--;
						break;
					}
					else
					{
						zs->next_in++;
						zs->avail_in--;
					}
				}
#ifdef LOOP_DEBUG
				loop_idx = 10;
#endif
				if (ss->file_state != GZIP_STATE_READ_FHCRC)
				{
					ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
#ifdef LOOP_DEBUG
					loop_idx = 7006;
#endif
					break;
				}
			}
			else
			{
				zip_dbgmsg("no comment\n");
				ss->file_state = GZIP_STATE_READ_FHCRC;
			}
		}
		else if (ss->file_state == GZIP_STATE_READ_FHCRC)
		{
			if (ss->file_flag & GZIP_HDR_HEAD_CRC) /* Have FHCRC */
			{
				if (zs->avail_in < 2)
				{
					ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
#ifdef LOOP_DEBUG
					loop_idx = 8006;
#endif
					break;
				}
				zs->next_in += 2;
				zs->avail_in -= 2;
			}
			else
			{
				zip_dbgmsg("No FHCRC\n");
			}
			err = inflateInit2 (zs, -MAX_WBITS);
			if (err != Z_OK)
			{
#ifdef LOOP_DEBUG
				loop_idx = 9006;
#endif
				return LC_DECOMPSERVER_DATA_ERROR;
			}
			ss->file_state = GZIP_STATE_DECODE;
		}
		else if (ss->file_state == GZIP_STATE_DECODE)
		{

			if (zs->avail_in == 0)
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
#ifdef LOOP_DEBUG
				loop_idx = 10006;
#endif
				break;
			}

#ifdef DETECT_DECOMP_BOMB_SUPPORT
			ss->pack_size += zs->avail_in;//first, suppose avail_in all consumed
#endif
			err = inflate (zs, Z_SYNC_FLUSH);
			zip_dbgmsg("Err %d after inflate.\n", err);
			if ((err < 0) || (err == Z_NEED_DICT))
			{
#ifdef LOOP_DEBUG
				loop_idx = 11006;
#endif
				return LC_DECOMPSERVER_DATA_ERROR;
			}

#ifdef DETECT_DECOMP_BOMB_SUPPORT
			ss->pack_size -= zs->avail_in;//second, minus avail_in not consumed to get EXACT consumed
			ss->unpack_size += TX_BUFFER_LEN - (zs->avail_out);

			DEBUG_DECOMP(D_BOMB, "[GZ]CurrUnPackSize=%u,CurrPackSize=%u,CurrCompRatio=%u\n",
			             ss->unpack_size,
			             ss->pack_size,
			             ss->pack_size ? (ss->unpack_size / ss->pack_size) : 0
			            );

			if (ss->check_decomp_bomb &&
			        ss->pack_size &&
			        (ss->unpack_size / ss->pack_size) > g_decomp_bomb_ratio)
			{
				DEBUG_DECOMP(D_BOMB, "[GZ]Over Bomb Ratio(%d), Bypass it!\n", g_decomp_bomb_ratio);
				ss->file_state = GZIP_STATE_READ_HEADER;
				ss->flag = LC_DECOMPSERVER_FLG_DECOMP_BOMB;
				err = -1; //give up the decomp session
				break;
			}
#endif

			if (err == Z_STREAM_END)
			{
				ss->file_state = GZIP_STATE_END_INFLATE;
			}
			if (zs->avail_in == 0) /* All input is consumed */
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
			}
			if (zs->avail_out == 0)
			{
				ss->flag |= LC_DECOMPSERVER_FLG_TX_FULL;
#ifdef LOOP_DEBUG
				loop_idx = 12006;
#endif
				break;
			}
		}
		else if (ss->file_state == GZIP_STATE_END_INFLATE)
		{
			ss->next_in = zs->next_in;
			ss->avail_in = zs->avail_in;
			ss->next_out = zs->next_out;
			ss->avail_out = zs->avail_out;

			zip_dbgmsg("We got z_stream_end\n");
			err = inflateEnd (zs);
			if (err != Z_OK)
			{
#ifdef LOOP_DEBUG
				loop_idx = 13006;
#endif
				break;
			}
			ss->file_state = GZIP_STATE_READ_TAILER;
		}
		else if (ss->file_state == GZIP_STATE_READ_TAILER)
		{
			if (zs->avail_in < 8)
			{
				ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
#ifdef LOOP_DEBUG
				loop_idx = 14006;
#endif
				break;
			}
			zs->next_in += 8;
			zs->avail_in -= 8;
			ss->file_state = GZIP_STATE_READ_HEADER;
			ss->flag |= LC_DECOMPSERVER_FLG_FILE_END;
			/* force out */
#ifdef LOOP_DEBUG
			loop_idx = 15006;
#endif
/////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
			//1 /* double layer level 2 free */
			if (level == MULTI_LAYER_EXIST)
			{

				if (sess[session_id].decomp_method == LC_RAR)
				{
					if (rar_session[session_id-rar_begin].next_zs)
						free(rar_session[session_id-rar_begin].next_zs);
					rar_session[session_id-rar_begin].next_zs = NULL;
				}
				else
				{
					if (zip_session[session_id-zip_begin].next_zs)
						free(zip_session[session_id-zip_begin].next_zs);
					zip_session[session_id-zip_begin].next_zs = NULL;
				}
			}
#endif
			break;
		}
		else
		{
			return LC_DECOMPSERVER_DATA_ERROR;
		}
	}

	ss->next_in = zs->next_in;
	ss->avail_in = zs->avail_in;
	ss->next_out = zs->next_out;
	ss->avail_out = zs->avail_out;

	/* Error handling */
	if (err < 0)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}
	return LC_DECOMPSERVER_OK;
}

