/*
** Handling RAR format
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dpu.h"

/////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
//#include "rar/unrar.h"    //move to dpu.h
#else
#include "rar/unrar.h"
#endif
////////////////////
#include "mymalloc.h"

#ifdef LOOP_DEBUG
extern int loop_idx;
#endif

#define UNRAR_STATE_READ_HEAD               0x00
#define UNRAR_STATE_WAIT_FLUSH_OUT          0x01
#define UNRAR_STATE_UNPACK_FILE_PRECHECK    0x02
#define UNRAR_STATE_UNPACK_FILE_STORE       0x04
#define UNRAR_STATE_UNPACK_FILE_UNPACK29    0x08
#define UNRAR_STATE_UNPACK_FILE_UNPACK20    0x10
#define UNRAR_STATE_UNPACK_FILE_UNPACK15    0x20


//////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
int     rar_begin, rar_end;
int     rar_session_num;
unpack_data_t *rar_session = NULL;
int rar_session_actvie_num = 0;//will be set default in init_decomp_session(lc_init_info *init_info)
int rar_session_actvie_max = 0;//will be set default in init_decomp_session(lc_init_info *init_info)
#else
static  int     rar_begin, rar_end;
static  int     rar_session_num;
static  unpack_data_t *rar_session = NULL;
#endif
/////////////////////
unsigned int rar_opened_bitmap = 0;
extern int print_switch;


static int check_rar_session_range(int session_id)
{
	if ((session_id >= rar_begin) && (session_id <= rar_end))
	{
		// The session_id is in valid range
		return 0;
	}

	// The session_id is invalid.
	return 1;
}

void dump_RAR_structure(int session_id)
{
	unpack_data_t *Unp;

	/* check sid range */
	if (check_rar_session_range(session_id) != 0)
	{
		fprintf(stderr, "Invalid session_id for RAR\n");
		return;
	}
	Unp = &(rar_session[session_id-rar_begin]);
	fprintf(stderr, "RAR opened %d, state %x, unpack_state %x\n",
	        Unp->opened, Unp->state, Unp->unpack_state);
	fprintf(stderr, "avail_in %d, avail_out %d \n" \
	        "file_unp_ver %d, file_method %d, pack %d, unpack %d\n",
	        Unp->avail_in, Unp->avail_out, Unp->file_unpack_ver,
	        Unp->file_method, Unp->file_pack_size, Unp->file_unpack_size);
	fprintf(stderr, "decoding %d, total in %d\n"\
	        "out_addr %d, out_used %d, in_addr %d, in_bit %d\n",
	        Unp->decoding, Unp->total_in, Unp->out_addr,
	        Unp->out_used, Unp->in_addr, Unp->in_bit);
	fprintf(stderr, "out_full %d, unp_ptr %d, wr_ptr %d\n" \
	        "tables read %d, in_used %d, block_type %d\n",
	        Unp->outbuf_full, Unp->unp_ptr, Unp->wr_ptr,
	        Unp->tables_read, Unp->in_used, Unp->unp_block_type);
	fprintf(stderr, "ppm_error %x, written_size %llu, des_unp_size %d, pack_size %d\n",
	        Unp->ppm_error, (long long unsigned int)(Unp->written_size), Unp->dest_unp_size,
	        (Unp->pack_size));
}

int rar_init (int session_num, int begin, int ppm_max)
{
	rar_begin = begin;
	rar_end  = begin + session_num - 1;
	rar_session_num = session_num;
	if (rar_session)
	{
		free(rar_session);
	}
	rar_session = (unpack_data_t *) malloc (sizeof (unpack_data_t) * rar_session_num);

	if (rar_session == NULL)
	{
		rar_errmsg("RAR %d failed 1\n", rar_session_num);
	}
	/* initialize all to zero */
	memset(rar_session, '\0', sizeof (unpack_data_t) * rar_session_num);
	rar_set_ppm_max(ppm_max);
	return 0;
}


int rar_session_update(int status_bitmap)
{
	int i;

	status_bitmap &= rar_opened_bitmap;

	for (i = 0; i < rar_session_num; i++)
	{
		if (!(status_bitmap & (1 << i)))
		{
			unpack_free_data(&rar_session[i]);
			rar_opened_bitmap &= ~(1 << i);
		}
	}

	return 0;
}

//////////////////////
#ifdef AV_MULTI_LAYER_DECOMP
int rar_session_open (int session_id, u8 level)
{
	/* only check magic cookie */
	decomp_session *ss;
	unpack_data_t *Unp = NULL;
	int ret;

	if (check_rar_session_range(session_id)
	        && sess[session_id].decomp_method == LC_RAR)
	{
		return LC_DECOMP_ERR_INVALID_SID;
	}
	//1 /* Multi LAYER	*/
	if (level == MULTI_LAYER_EXIST)
	{
		int sid;
		ss = sess_extend[session_id].sess;
		if (sess[session_id].decomp_method == LC_RAR)
		{
			sid = session_id - rar_begin;
			if (rar_session[sid].next_zs)
			{
				unpack_free_data(rar_session[sid].next_zs);
				free(rar_session[sid].next_zs);
				rar_session[sid].next_zs = NULL;
			}
			rar_session[sid].next_zs = (unpack_data_t *) malloc (sizeof (unpack_data_t));
			if (rar_session[sid].next_zs == NULL)
			{
				return LC_DECOMPSERVER_MEM_ERROR;
			}
			Unp = rar_session[session_id-rar_begin].next_zs;
		}
		else if (sess[session_id].decomp_method >= LC_INFLATE
		         && sess[session_id].decomp_method <= LC_GZIP)
		{
			sid = session_id - zip_begin;
			if (zip_session[sid].next_zs)
			{
				unpack_free_data(zip_session[sid].next_zs);
				free(zip_session[sid].next_zs);
				zip_session[sid].next_zs = NULL;
			}
			zip_session[sid].next_zs = (unpack_data_t *) malloc (sizeof (unpack_data_t));
			if (zip_session[sid].next_zs == NULL)
			{
				return LC_DECOMPSERVER_MEM_ERROR;
			}
			Unp = zip_session[session_id-zip_begin].next_zs;
		}
		rar_session_actvie_num++;
		memset(Unp, 0, sizeof (unpack_data_t));
	}
	else //1 /*ONE LAYER*/
	{
		ss = &(sess[session_id]);
		Unp = &(rar_session[session_id-rar_begin]);
		rar_opened_bitmap |= (1 << (session_id - rar_begin));
	}


	/* for open, make sure we have magic cookie len */
	if (ss->avail_in < SIZEOF_MARKHEAD)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}
	/* Make sure we have right magic cookie */
	ret = is_rar_archive(ss->next_in);

	if (ret == RAR_READ_UNMATCHED_MAGIC_COOKIE)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}
	ss->next_in += SIZEOF_MARKHEAD;
	ss->avail_in -= SIZEOF_MARKHEAD;
	ss->file_state = UNRAR_STATE_READ_HEAD;

	unpack_init_data(FALSE, Unp);

	Unp->opened = 1;

#ifdef DETECT_DECOMP_BOMB_SUPPORT
	Unp->check_decomp_bomb = ss->check_decomp_bomb;
#endif

	return LC_DECOMPSERVER_OK;
}
#else
int rar_session_open (int session_id)
{
	/* only check magic cookie */
	decomp_session *ss;
	unpack_data_t *Unp;
	int ret;

	if (check_rar_session_range(session_id))
	{
		return LC_DECOMP_ERR_INVALID_SID;
	}

	ss = &(sess[session_id]);

	/* for open, make sure we have magic cookie len */
	if (ss->avail_in < SIZEOF_MARKHEAD)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}

	/* Make sure we have right magic cookie */
	ret = is_rar_archive(ss->next_in);

	if (ret == RAR_READ_UNMATCHED_MAGIC_COOKIE)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}

	ss->next_in += SIZEOF_MARKHEAD;
	ss->avail_in -= SIZEOF_MARKHEAD;
	ss->file_state = UNRAR_STATE_READ_HEAD;
	Unp = &(rar_session[session_id-rar_begin]);
	unpack_init_data(FALSE, Unp);
	rar_opened_bitmap |= (1 << (session_id - rar_begin));
	Unp->opened = 1;

	#ifdef DETECT_DECOMP_BOMB_SUPPORT
	Unp->check_decomp_bomb = ss->check_decomp_bomb;
	#endif

	return LC_DECOMPSERVER_OK;
}
#endif

#ifdef AV_MULTI_LAYER_DECOMP
int rar_session_decomp (int session_id, u8 level)
#else
int rar_session_decomp (int session_id)
#endif
{
	decomp_session *ss;
	unpack_data_t *Unp;
	int ret = RAR_OK;
	unsigned char head_type;


	#ifdef AV_MULTI_LAYER_DECOMP
	if (level == MULTI_LAYER_EXIST)
	{
		ss = sess_extend[session_id].sess;
		if (sess[session_id].decomp_method == LC_RAR)
			Unp = rar_session[session_id-rar_begin].next_zs;
		else
			Unp = zip_session[session_id-zip_begin].next_zs;
	}
	else
	{
		ss = &(sess[session_id]);
		Unp = &(rar_session[session_id-rar_begin]);
	}
	#else
	if (check_rar_session_range(session_id))
	{
		return LC_DECOMPSERVER_INVALID_SID;
	}

	ss = &(sess[session_id]);
	Unp = &(rar_session[session_id-rar_begin]);
	#endif

	if (Unp->opened == 0)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}

	Unp->next_in = ss->next_in;
	Unp->next_out = ss->next_out;
	Unp->avail_in = ss->avail_in;
	Unp->avail_out = ss->avail_out;

	rar_dbgmsg("rar_session_decomp: Unp->avail_in %d, Unp->avail_out %d\n", Unp->avail_in, Unp->avail_out);
	if (print_switch)
	{
		printf("rar_session_decomp: Unp->avail_in %d, Unp->avail_out %d\n", Unp->avail_in, Unp->avail_out);
	}

	#ifdef LOOP_DEBUG
	loop_idx = 603;
	#endif

	while (1)
	{
		if (print_switch)
		{
			printf("rar_session_decomp: File State %x\n", ss->file_state);
			printf("rar_session_decomp: left packsize %d, left unpacksize %d\n", Unp->pack_size, Unp->dest_unp_size);
		}

		rar_dbgmsg("rar_session_decomp: File State %x\n", ss->file_state);
		rar_dbgmsg("rar_session_decomp: left packsize %d, left unpacksize %d\n", Unp->pack_size, Unp->dest_unp_size);

		if (ss->file_state == UNRAR_STATE_UNPACK_FILE_UNPACK29)
		{
			#ifdef LOOP_DEBUG
			loop_idx = 601;
			#endif

			do
			{
				ret = rar_unpack29_state(/*((Unp->main_header.flags&MHD_SOLID)!=0),*/ Unp);
			}
			while ((ret == RAR_OK) && (Unp->dest_unp_size != 0));

			#ifdef LOOP_DEBUG
			loop_idx = 602;
			#endif

			if ((Unp->dest_unp_size == 0) && (Unp->pack_size != 0))
			{
				ret = RAR_DATA_ERROR;
				break;
			}

			unp_write_out(Unp);

			if (Unp->dest_unp_size == 0)
			{
				Unp->decoding = 0;
				if (Unp->out_used)
				{
					ss->file_state = UNRAR_STATE_WAIT_FLUSH_OUT;
				}
				else
				{
					Unp->written_size = 0;
					ss->file_state = UNRAR_STATE_READ_HEAD;
				}
				rar_dbgmsg("rar_session_decomp: UNPACK29, Get a new file at file position %x %x, free %d\n",
				           7 + Unp->total_in + Unp->in_addr,
				           Unp->in_buf[Unp->in_addr],
				           Unp->in_used);
				if (Unp->in_used) /* maybe padding for some bogus winrar */
				{
					Unp->in_addr += Unp->in_used;
					Unp->in_used = 0;
				}
				ss->avail_in = Unp->avail_in;
				ss->avail_out = Unp->avail_out;
				ss->next_in = Unp->next_in;
				ss->next_out = Unp->next_out;

				/* Force out */
				#ifdef LOOP_DEBUG
				loop_idx = 10604;
				#endif

				return LC_DECOMPSERVER_OK;
			}

			if (ret != RAR_OK)
			{
				/* handle errors */
				break;
			}
		}
		else if (ss->file_state == UNRAR_STATE_UNPACK_FILE_UNPACK20)
		{
			#ifdef LOOP_DEBUG
			loop_idx = 605;
			#endif

			do
			{
				ret = rar_unpack20_state(/*((Unp->main_header.flags&MHD_SOLID)!=0),*/ Unp);
				rar_dbgmsg("ret %x, Unp->dest_unp_size %d\n", ret, Unp->dest_unp_size);

			}
			while ((ret == RAR_OK) && (Unp->dest_unp_size != 0));

			#ifdef LOOP_DEBUG
			loop_idx = 606;
			#endif

			unp_write_out(Unp);

			if (Unp->dest_unp_size == 0 && Unp->pack_size != 0)
			{
				ret = RAR_DATA_ERROR;
				break;
			}

			if (Unp->dest_unp_size == 0)
			{
				Unp->decoding = 0;
				if (Unp->out_used)
				{
					ss->file_state = UNRAR_STATE_WAIT_FLUSH_OUT;
				}
				else
				{
					Unp->written_size = 0;
					ss->file_state = UNRAR_STATE_READ_HEAD;
				}

				rar_dbgmsg("rar_session_decomp: UNPACK20, Get a new file at file position %x %x, free %d\n",
					7 + Unp->total_in + Unp->in_addr,
					Unp->in_buf[Unp->in_addr],
					Unp->in_used);

				if (Unp->in_used)
				{
					/* maybe padding for some bogus winrar */
					Unp->in_addr += Unp->in_used;
					Unp->in_used = 0;
				}

				ss->avail_in = Unp->avail_in;
				ss->avail_out = Unp->avail_out;
				ss->next_in = Unp->next_in;
				ss->next_out = Unp->next_out; /* Force out */

				#ifdef LOOP_DEBUG
				loop_idx = 20604;
				#endif

				return LC_DECOMPSERVER_OK;
			}

			if (ret != RAR_OK)
			{
				/* handle errors */
				break;
			}
		}
		else if (ss->file_state == UNRAR_STATE_UNPACK_FILE_STORE)
		{
			ret = rar_store(Unp);

			if (Unp->dest_unp_size == 0 && Unp->pack_size != 0)
			{
				ret = RAR_DATA_ERROR;
				break;
			}

			unp_write_out(Unp);

			if (ret == RAR_OK)
			{
				if (Unp->dest_unp_size == 0)
				{
					if (print_switch)
					{
						printf("step1\n");
					}
					Unp->decoding = 0;
					/*flush */
					if (Unp->out_used)
					{
						ss->file_state = UNRAR_STATE_WAIT_FLUSH_OUT;
					}
					else
					{
						Unp->written_size = 0;
						ss->file_state = UNRAR_STATE_READ_HEAD;
					}
					rar_dbgmsg("rar_session_decomp: STORE, Get a new file at file position %x, free %d\n",
						7 + Unp->total_in + Unp->in_addr, Unp->in_used);

				}
				else if (Unp->avail_in == 0)
				{
					ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
				}

				ss->avail_in = Unp->avail_in;
				ss->avail_out = Unp->avail_out;
				ss->next_in = Unp->next_in;
				ss->next_out = Unp->next_out; /* Force out */

				#ifdef LOOP_DEBUG
				loop_idx = 30604;
				#endif
				return LC_DECOMPSERVER_OK;
			}
			else
			{
				/* handle errors */
				if (print_switch)
				{
					printf("step2 ret = %x\n", ret);
				}

				break;
			}
		}
		else if (ss->file_state == UNRAR_STATE_READ_HEAD)
		{
			ret = rar_read_head(Unp, &head_type);
			unp_write_out(Unp);
			rar_dbgmsg("rar_session_decomp: READ_HEAD, after rar_read_head() ret = %d\n", ret);

			if (ret == RAR_OK)
			{
				if ((head_type == FILE_HEAD) && (Unp->file_unpack_size > 0)) /* skip empty file or directory */
				{
					ss->flag |= LC_DECOMPSERVER_FLG_FILE_BEGIN;
					ss->file_count++;
					if (Unp->file_name_size)
					{
						ss->flag |= LC_DECOMPSERVER_FLG_HAS_FILENAME;
					}
					ss->file_state = UNRAR_STATE_UNPACK_FILE_PRECHECK;
				}
				else if (head_type == ENDARC_HEAD) /* End of archive */
				{
					rar_dbgmsg("rar_session_decomp: ENDARC_HEAD\n");
					ss->file_state = UNRAR_STATE_READ_HEAD;
					//ss->avail_in = Unp->avail_in;
					ss->avail_in = 0;
					ss->avail_out = Unp->avail_out;
					ss->next_in = Unp->next_in;
					ss->next_out = Unp->next_out;
					/* Force out */
					ss->flag |= LC_DECOMPSERVER_FLG_FILE_END;
					unpack_free_data(Unp);

					#ifdef AV_MULTI_LAYER_DECOMP
					//1 /* multi layer level 2 free */
					if (level == MULTI_LAYER_EXIST)
					{

						if (sess[session_id].decomp_method == LC_RAR)
						{
							if (rar_session[session_id-rar_begin].next_zs)
								free(rar_session[session_id-rar_begin].next_zs);
							rar_session[session_id-rar_begin].next_zs = NULL;
							rar_session_actvie_num--;
						}
						else if (sess[session_id].decomp_method >= LC_INFLATE
						         && sess[session_id].decomp_method <= LC_GZIP)
						{
							if (zip_session[session_id-zip_begin].next_zs)
								free(zip_session[session_id-zip_begin].next_zs);
							zip_session[session_id-zip_begin].next_zs = NULL;
						}
						if (rar_session_actvie_num > 0) rar_session_actvie_num--;
					}
					#endif

					#ifdef LOOP_DEBUG
					loop_idx = 40604;
					#endif

					return 0; /*LC_DECOMPSERVER_OK*/
				}
				/* else still stay in this state and wait effective header type */
				else
				{
					if (print_switch)
					{
						printf("step4 head_type = %x\n", head_type);
					}
				}
			}
			else
			{
				/* error handling */
				if (print_switch)
				{
					printf("step3 ret = %x\n", ret);
				}

				break;
			}
		}
		else if (ss->file_state == UNRAR_STATE_UNPACK_FILE_PRECHECK)
		{
			Unp->decoding = 1;
			Unp->pack_size = Unp->file_pack_size;
			Unp->dest_unp_size = Unp->file_unpack_size;
			Unp->unpack_state = 0;
			Unp->in_bit = 0;

			/* adjust packsize, no need now*/
			rar_dbgmsg("rar_session_decomp: FILE_PRECHECK, unpack size is %d, in_used is %d, in addr is %d\n",
				Unp->pack_size, Unp->in_used, Unp->in_addr);
			if (Unp->file_method == 0x30)
			{
				/* store */
				ss->file_state = UNRAR_STATE_UNPACK_FILE_STORE;
			}
			else
			{
				if (Unp->file_unpack_ver == 29)
				{
					ss->file_state = UNRAR_STATE_UNPACK_FILE_UNPACK29;
				}
				else if (Unp->file_unpack_ver == 20)
				{
					unpack_init_data20(FALSE, Unp);
					ss->file_state = UNRAR_STATE_UNPACK_FILE_UNPACK20;
				}
				else
				{
					ret = RAR_DATA_ERROR;
					break;
				}
			}
		}
		else if (ss->file_state == UNRAR_STATE_WAIT_FLUSH_OUT)
		{
			unp_write_out(Unp);
			if (Unp->out_used == 0)
			{
				Unp->decoding = 0;
				Unp->written_size = 0;
				ss->file_state = UNRAR_STATE_READ_HEAD;
				/* Force out */
				ss->avail_in = Unp->avail_in;
				ss->avail_out = Unp->avail_out;
				ss->next_in = Unp->next_in;
				ss->next_out = Unp->next_out;

				#ifdef LOOP_DEBUG
				loop_idx = 50604;
				#endif

				return  LC_DECOMPSERVER_OK;
			}

			ret = RAR_WRITE_BUFFER_NOT_ENOUGH;
			break;
		}
		else
		{
			ret = RAR_DATA_ERROR;
			break;
		}
	} /* End of while(1) */

	#ifdef LOOP_DEBUG
	loop_idx = 60604;
	#endif

	ss->avail_in = Unp->avail_in;
	ss->avail_out = Unp->avail_out;
	ss->next_in = Unp->next_in;
	ss->next_out = Unp->next_out;

	/* Error handling */
	if (ret == RAR_WRITE_BUFFER_NOT_ENOUGH)
	{
		ss->flag |= LC_DECOMPSERVER_FLG_TX_FULL;
	}

	if (ret == RAR_READ_BUFFER_NOT_ENOUGH)
	{
		ss->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;
		return LC_DECOMPSERVER_OK;
	}
	else if (ret == RAR_DATA_ERROR || ret == RAR_MALLOC_ERROR)
	{
		unpack_free_data(Unp);
		return LC_DECOMPSERVER_DATA_ERROR;
	}
	else if (ret == RAR_REACH_MAX_PPM_MEM_ERROR)
	{
		unpack_free_data(Unp);
		return LC_DECOMPSERVER_PPM_TOO_LARGE;
	}
	else if (ret == RAR_REACH_MAX_PPM_NUM_ERROR)
	{
		unpack_free_data(Unp);
		return LC_DECOMPSERVER_PPM_FULL;
	}
	else if (ret == RAR_VERSION_ERROR)
	{
		unpack_free_data(Unp);
		return LC_DECOMPSERVER_NOT_SUPPORT;
	}
	else if (ret == RAR_SEE_DECOMP_BOMB)
	{
		ss->flag = LC_DECOMPSERVER_FLG_DECOMP_BOMB;
		unpack_free_data(Unp);
		return LC_DECOMPSERVER_DATA_ERROR;
	}

	return LC_DECOMPSERVER_OK;
}
