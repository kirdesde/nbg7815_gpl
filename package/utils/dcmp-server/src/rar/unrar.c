/*
 *  Extract RAR archives
 *
 *  Copyright (C) 2005-2006 trog@uncon.org
 *
 *  This code is based on the work of Alexander L. Roshal
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */


#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "unrar.h"
#include "unrarppm.h"
#include "unrarvm.h"
#include "unrarfilter.h"
//#include "unrar20.h"
//#include "unrar15.h"
#include "cltypes.h"
#include "../dpu.h"
#include "../endian.h"
#include "../mymalloc.h"

#ifdef LOOP_DEBUG
extern int loop_idx;
#endif

#define int64to32(x) ((unsigned int)(x))
//#define rar_endian_convert_16(v)	le16_to_cpu(v)
//#define rar_endian_convert_32(v)	le32_to_cpu(v)

/* rar session control variables */

int ppm_num = 0;
int ppm_max = 0;

int rar_set_ppm_max(int max)
{
	ppm_max = max;
	return 0;
}

int rar_read_head(unpack_data_t *unpack_data, unsigned char *head_type)
{
	unsigned char htype;
	unsigned short hlen;
	unsigned short flags;
	unsigned char *head_start;
	unsigned int i;

	rar_dbgmsg("rar_read_head: before unp_read_buf, in_used=%d, in_addr=%d\n",
	           unpack_data->in_used, unpack_data->in_addr);
	unp_read_buf(unpack_data, 7);
	rar_dbgmsg("rar_read_head: after unp_read_buf, in_used=%d, in_addr=%d\n",
	           unpack_data->in_used, unpack_data->in_addr);
	head_start = (unpack_data->in_buf + unpack_data->in_addr);

	if (unpack_data->in_used < 7) /* 7 is common length for all headers */
	{
		return RAR_READ_BUFFER_NOT_ENOUGH;
	}
	htype = *((unsigned char *)(head_start + 2));
	flags = head_start[3] + ((unsigned int)(head_start[4]) << 8);
	hlen = head_start[5] + ((unsigned int)(head_start[6]) << 8);

	rar_dbgmsg("htype %x, hlen %d\n", htype, hlen);

	/* detect buggy input if the header length is unusually long */
	switch (htype)
	{
	case MAIN_HEAD:
		if (hlen < SIZEOF_NEWMHD)
		{
			rar_dbgmsg("too short main header len\n");
			return RAR_DATA_ERROR;
		}
		if ((hlen > SIZEOF_NEWMHD + 1) && !(flags & MHD_COMMENT))
		{
			rar_dbgmsg("extra long main header hlen\n");
			return RAR_DATA_ERROR;
		}
		if (flags & MHD_VOLUME)
		{
			/* Part of a RAR VOLUME - Skip it */
			rar_dbgmsg("RAR MUTIPART VOLUME - Skippng.\n");
			return RAR_DATA_ERROR;
		}
		if (flags & MHD_PASSWORD)
		{
			/* Password protected */
			rar_dbgmsg("RAR PASSWORD PROTECTED VOLUME - Skippng.\n");
			return RAR_DATA_ERROR;
		}
		break;
	case NEWSUB_HEAD:
		if (hlen < SIZEOF_NEWLHD)
		{
			rar_dbgmsg("too new sub header len\n");
			return RAR_DATA_ERROR;
		}
		break;
	case FILE_HEAD:
		if (hlen < SIZEOF_NEWLHD)
		{
			rar_dbgmsg("too short file header len\n");
			return RAR_DATA_ERROR;
		}
		if (flags & LHD_PASSWORD)
		{
			/* password protected */
			rar_dbgmsg("Password protected file\n");
			return RAR_DATA_ERROR;
		}
		if (flags & LHD_SPLIT_BEFORE)
		{
			/* not first volumne */
			rar_dbgmsg("Not first volumne\n");
			return RAR_DATA_ERROR;
		}

		break;
	case COMM_HEAD:
		if (hlen < SIZEOF_COMMHEAD)
		{
			return RAR_DATA_ERROR;
		}
		break;
	default:
		if ((htype < 0x70) || (htype >= 0x80))
		{
			return RAR_DATA_ERROR;
		}
		break;
	}

	if (hlen > 4*1024)
		return RAR_DATA_ERROR;

	unp_read_buf(unpack_data, hlen);
	head_start = (unpack_data->in_buf + unpack_data->in_addr);
	rar_dbgmsg("rar_read_head: after unp_read_buf, in_used=%d\n", unpack_data->in_used);

	/* proceed when full header is read */
	if (unpack_data->in_used < hlen)
	{
		return RAR_READ_BUFFER_NOT_ENOUGH;
	}

	switch (htype)
	{
	case MAIN_HEAD:

		if (flags & MHD_SOLID)
		{
			unpack_data->mh_solid = 1;
		}
		else
		{
			unpack_data->mh_solid = 0;
		}

		break;
	case FILE_HEAD:
	case NEWSUB_HEAD:
		unpack_data->file_pack_size = head_start[7] + ((unsigned int)(head_start[8]) << 8)
		                              + ((unsigned int)(head_start[9]) << 16) + ((unsigned int)(head_start[10]) << 24);
		unpack_data->file_unpack_size =  head_start[11] + ((unsigned int)(head_start[12]) << 8)
		                                 + ((unsigned int)(head_start[13]) << 16) + ((unsigned int)(head_start[14]) << 24);
		unpack_data->file_unpack_ver = *((unsigned char *)(head_start + 24));
		unpack_data->file_method = *((unsigned char *)(head_start + 25));
		unpack_data->file_name_size =  head_start[26] + ((unsigned int)(head_start[27]) << 8);

		if ((unpack_data->file_name_size + SIZEOF_NEWLHD) > hlen)
		{
			/* Corrupt header, file_name_size > header len */
			rar_dbgmsg("Corrupt header, file_name_size > header len\n");
			return RAR_DATA_ERROR;
		}

		if ((htype == FILE_HEAD) && (flags & LHD_SOLID))
		{
			unpack_data->file_solid = 1;
			rar_dbgmsg("FILE SOLID\n");
		}

		if (unpack_data->file_unpack_size && (unpack_data->file_name_size)) /* copy filename and embedded in output stream */
		{
			/* Here check if there is null character inside the name
			field since maybe some bogus winrar did this */
			if ((unpack_data->file_unpack_ver != 29)
			        /*&& (unpack_data->file_unpack_ver != 15)*/
			        && (unpack_data->file_unpack_ver != 20)
			        && (unpack_data->file_unpack_ver != 26))
			{
				/* Unsupported version */
				rar_dbgmsg("Rar unpack ver %d is not supported\n", unpack_data->file_unpack_ver);
				return RAR_VERSION_ERROR;
			}

			if (unpack_data->file_unpack_ver == 26)
			{
				unpack_data->file_unpack_ver = 20;
			}
#ifdef LOOP_DEBUG
			loop_idx = 1201;
#endif

			for (i = 0; i < unpack_data->file_name_size; i++)
			{
				if (*(head_start + SIZEOF_NEWLHD + i) == '\0')
				{
					unpack_data->file_name_size = i;
					break;
				}
			}
#ifdef LOOP_DEBUG
			loop_idx = 1202;
#endif


#ifdef DETECT_DECOMP_BOMB_SUPPORT
			{
				//Do not remove this bracket
				unsigned char* fname = head_start + SIZEOF_NEWLHD;
				unsigned char save_byte = fname[unpack_data->file_name_size];
				unpack_data->next_out[unpack_data->file_name_size] = 0;
				DEBUG_DECOMP(D_BOMB, "[RAR]Filename=%s,UnPackSize=%u,PackSize=%u,CompRatio=%d\n",
				             fname,
				             unpack_data->file_unpack_size,
				             unpack_data->file_pack_size,
				             unpack_data->file_pack_size ? (unpack_data->file_unpack_size / unpack_data->file_pack_size) : 0
				            );
				fname[unpack_data->file_name_size] = save_byte;
			}//Do not remove this bracket

			if (unpack_data->check_decomp_bomb &&
			        unpack_data->file_pack_size &&
			        (unpack_data->file_unpack_size / unpack_data->file_pack_size) > g_decomp_bomb_ratio)
			{
				DEBUG_DECOMP(D_BOMB, "[RAR]Over Bomb Ratio(%d), Bypass it!\n", g_decomp_bomb_ratio);
				unpack_data->mh_solid = 0;
				htype = ALL_HEAD;
				return RAR_SEE_DECOMP_BOMB;
			}
			else
#endif
			{//Do not remove this bracket
				*((unsigned int *)(unpack_data->next_out))   = unpack_data->file_pack_size;
				unpack_data->next_out += 4;
				unpack_data->avail_out -= 4;
				*((unsigned short *)(unpack_data->next_out)) = unpack_data->file_name_size;
				unpack_data->next_out += 2;
				unpack_data->avail_out -= 2;
				memcpy(unpack_data->next_out, head_start + SIZEOF_NEWLHD, unpack_data->file_name_size);
				unpack_data->next_out  += unpack_data->file_name_size;
				unpack_data->avail_out -= unpack_data->file_name_size;
			}//Do not remove this bracket


		}
		else
		{   /* might be directory */
			unpack_data->file_name_size = 0;
		}
		rar_dbgmsg("rar_read_head: File head size %d, pack %d, unpack %d, ver %d, \nmethod %x, name_size %d\n",
		           hlen, unpack_data->file_pack_size, unpack_data->file_unpack_size,
		           unpack_data->file_unpack_ver, unpack_data->file_method,
		           unpack_data->file_name_size);
		/* Just consider it as normal file */
		if (htype == NEWSUB_HEAD)
		{
			htype = FILE_HEAD;
		}
		break;
	case COMM_HEAD:
		if (hlen < SIZEOF_COMMHEAD)
		{
			return RAR_DATA_ERROR;
		}
		break;
	default:
		if (hlen < 7)
		{
			return RAR_DATA_ERROR;
		}
		break;
	}

	unpack_data->in_addr += hlen;
	unpack_data->in_used -= hlen;
	*head_type = htype;
	return RAR_OK;
}






#if 0
static void dump_tables(unpack_data_t *unpack_data)
{
	int i;

	/* Dump LD table */
	rar_dbgmsg("LD Table MaxNum=%d\n", unpack_data->LD.MaxNum);
	rar_dbgmsg("\tDecodeLen:");
	for (i = 0 ; i < 16; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->LD.DecodeLen[i]);
	}
	rar_dbgmsg("\n\tDecodePos:");
	for (i = 0 ; i < 16; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->LD.DecodePos[i]);
	}
	rar_dbgmsg("\n\tDecodeNum:");
	for (i = 0 ; i < NC; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->LD.DecodeNum[i]);
	}


	rar_dbgmsg("\nDD Table MaxNum=%d\n", unpack_data->DD.MaxNum);
	rar_dbgmsg("\tDecodeLen:");
	for (i = 0 ; i < 16; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->DD.DecodeLen[i]);
	}
	rar_dbgmsg("\n\tDecodePos:");
	for (i = 0 ; i < 16; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->DD.DecodePos[i]);
	}
	rar_dbgmsg("\n\tDecodeNum:");
	for (i = 0 ; i < DC; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->DD.DecodeNum[i]);
	}

	rar_dbgmsg("\nLDD Table MaxNum=%d\n", unpack_data->LDD.MaxNum);
	rar_dbgmsg("\tDecodeLen:");
	for (i = 0 ; i < 16; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->LDD.DecodeLen[i]);
	}
	rar_dbgmsg("\n\tDecodePos:");
	for (i = 0 ; i < 16; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->LDD.DecodePos[i]);
	}
	rar_dbgmsg("\n\tDecodeNum:");
	for (i = 0 ; i < LDC; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->LDD.DecodeNum[i]);
	}

	rar_dbgmsg("\nRD Table MaxNum=%d\n", unpack_data->RD.MaxNum);
	rar_dbgmsg("\tDecodeLen:");
	for (i = 0 ; i < 16; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->RD.DecodeLen[i]);
	}
	rar_dbgmsg("\n\tDecodePos:");
	for (i = 0 ; i < 16; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->RD.DecodePos[i]);
	}
	rar_dbgmsg("\n\tDecodeNum:");
	for (i = 0 ; i < RC; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->RD.DecodeNum[i]);
	}

	rar_dbgmsg("\nBD Table MaxNum=%d\n", unpack_data->BD.MaxNum);
	rar_dbgmsg("\tDecodeLen:");
	for (i = 0 ; i < 16; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->BD.DecodeLen[i]);
	}
	rar_dbgmsg("\n\tDecodePos:");
	for (i = 0 ; i < 16; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->BD.DecodePos[i]);
	}
	rar_dbgmsg("\n\tDecodeNum:");
	for (i = 0 ; i < BC; i++)
	{
		rar_dbgmsg(" %.8d", unpack_data->BD.DecodeNum[i]);
	}
	rar_dbgmsg("\n");
}


static u32_t copy_file_data(int ifd, int ofd, u32_t len)
{
	unsigned char data[8192];
	u32_t count, rem;
	unsigned int todo;

	rem = len;

	while (rem > 0)
	{
		todo = MIN(8192, rem);
		count = cli_readn(ifd, data, todo);
		if (count != todo)
		{
			return len -rem;
		}
		if (cli_writen(ofd, data, count) != count)
		{
			return len -rem - count;
		}
		rem -= count;
	}
	return len;
}
#endif

int is_rar_archive(unsigned char *buf)
{
	const unsigned char rar_hdr_0[] = {0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00};
	const unsigned char rar_hdr_1[] = {'U', 'n', 'i', 'q', 'u', 'E', '!'};

	if (memcmp(buf, rar_hdr_0, SIZEOF_MARKHEAD) == 0)
	{
		return TRUE;
	}
	if (memcmp(buf, rar_hdr_1, SIZEOF_MARKHEAD) == 0)
	{
		return TRUE;
	}

	rar_dbgmsg("Not a rar archive\n");
	return FALSE;
}


static void insert_old_dist(unpack_data_t *unpack_data, unsigned int distance)
{
	unpack_data->old_dist[3] = unpack_data->old_dist[2];
	unpack_data->old_dist[2] = unpack_data->old_dist[1];
	unpack_data->old_dist[1] = unpack_data->old_dist[0];
	unpack_data->old_dist[0] = distance;
}

static void insert_last_match(unpack_data_t *unpack_data, unsigned int length, unsigned int distance)
{
	unpack_data->last_dist = distance;
	unpack_data->last_length = length;
}

static void copy_string(unpack_data_t *unpack_data, unsigned int length, unsigned int distance)
{
	unsigned int dest_ptr;

	dest_ptr = unpack_data->unp_ptr - distance;
	if (dest_ptr < MAXWINSIZE - 260 && unpack_data->unp_ptr < MAXWINSIZE - 260)
	{
		unpack_data->window[unpack_data->unp_ptr] =
		    unpack_data->window[dest_ptr++];
		unpack_data->unp_ptr = (unpack_data->unp_ptr + 1) & MAXWINMASK;
#ifdef LOOP_DEBUG
		loop_idx = 65;
#endif

		while (--length > 0)
		{
			unpack_data->window[unpack_data->unp_ptr] = unpack_data->window[dest_ptr++];
			unpack_data->unp_ptr = (unpack_data->unp_ptr + 1) & MAXWINMASK;
		}
#ifdef LOOP_DEBUG
		loop_idx = 66;
#endif

	}
	else
	{
#ifdef LOOP_DEBUG
		loop_idx = 63;
#endif

		while (length--)
		{
			unpack_data->window[unpack_data->unp_ptr] =
			    unpack_data->window[dest_ptr++ & MAXWINMASK];
			unpack_data->unp_ptr = (unpack_data->unp_ptr + 1) & MAXWINMASK;
		}
#ifdef LOOP_DEBUG
		loop_idx = 64;
#endif

	}
}


void addbits(unpack_data_t *unpack_data, int bits)
{

	//rar_dbgmsg("addbits: in_addr=%d in_bit=%d\n", unpack_data->in_addr, unpack_data->in_bit);
	bits += unpack_data->in_bit;
	unpack_data->in_addr += (bits >> 3);
	unpack_data->in_used -= (bits >> 3);
	unpack_data->in_bit = (bits & 7);
}

unsigned int getbits(unpack_data_t *unpack_data)
{
	unsigned int bit_field;

	//rar_dbgmsg("getbits: in_addr=%d in_bit=%d\n", unpack_data->in_addr, unpack_data->in_bit);
	bit_field = (unsigned int) unpack_data->in_buf[unpack_data->in_addr] << 16;
	bit_field |= (unsigned int) unpack_data->in_buf[unpack_data->in_addr+1] << 8;
	bit_field |= (unsigned int) unpack_data->in_buf[unpack_data->in_addr+2];
	bit_field >>= (8 - unpack_data->in_bit);
	/*rar_dbgmsg("getbits return(%d)\n", BitField & 0xffff);*/
	return(bit_field & 0xffff);
}

int unp_read_buf(unpack_data_t *unpack_data, unsigned int size_limit)
{
	/* if size_limit is set (>0), then just let in_used equal to limit,
	   otherwise, fetch data is not more than left pack_size */
	unsigned int data_size;

	rar_dbgmsg("unp_read_buf: enter with in_used=%d, in_addr=%d size_limit %d\n",
	           unpack_data->in_used, unpack_data->in_addr, size_limit);

	if (size_limit > 0)
	{   /* size_limt is set */
		if (unpack_data->in_used >= size_limit)
		{   /* we have sufficient data */
			return 0;
		}
		else
		{  /* only fetch unsufficient portion */
			size_limit -= unpack_data->in_used;
		}
	}

	/* Is buffer read pos more than half way? */
	if (unpack_data->in_addr > MAX_BUF_SIZE / 2)
	{
		if (unpack_data->in_used > 0)
		{
			memmove(unpack_data->in_buf, unpack_data->in_buf + unpack_data->in_addr,
			        unpack_data->in_used);
		}
		unpack_data->total_in += unpack_data->in_addr;
		unpack_data->in_addr = 0;
		if (unpack_data->in_used > 70)
		{
			unpack_data->read_border = unpack_data->in_addr + unpack_data->in_used - 70;
		}
		else
		{
			unpack_data->read_border = unpack_data->in_addr;
		}
	}
	data_size = unpack_data->in_addr + unpack_data->in_used;

	if (size_limit == 0)
	{
		/* RAR2 depends on us only reading upto the end of the current compressed file */
		size_limit = unpack_data->pack_size;
	}
	rar_dbgmsg("data size is %d, left pack size %d\n", data_size, unpack_data->pack_size);

	if ((MAX_BUF_SIZE - data_size) < size_limit)
	{
		size_limit = (MAX_BUF_SIZE - data_size);
	}

	rar_dbgmsg("size_limit %d, avail_in %d\n", size_limit, unpack_data->avail_in);
	if ((unpack_data->avail_in == 0) && (size_limit != 0))
	{
		/* No avail_in */
		rar_dbgmsg("No avail in..border %d\n", unpack_data->read_border);
		return -1;
	}

	if (size_limit > unpack_data->avail_in)
	{
		size_limit = unpack_data->avail_in;
	}

	if (size_limit > 0)
	{
		rar_dbgmsg("data_size = %d\n", data_size);
		memcpy(unpack_data->in_buf + data_size, unpack_data->next_in, size_limit);
		unpack_data->next_in += size_limit;
		unpack_data->avail_in -= size_limit;
		unpack_data->in_used += size_limit;

		if (unpack_data->decoding)
		{
			rar_dbgmsg("packsize %d, size_limit %d\n",  unpack_data->pack_size, size_limit);
			unpack_data->pack_size -= size_limit;
		}
		if (unpack_data->in_used > 70)
		{
			unpack_data->read_border = unpack_data->in_addr + unpack_data->in_used - 70;
		}
		else
		{
			unpack_data->read_border = unpack_data->in_addr;
		}
	}

	rar_dbgmsg("after unp_read_buf packsize %d readsize %d in_used %d, in_addr %d\n", unpack_data->pack_size, size_limit, unpack_data->in_used, unpack_data->in_addr);
	return 0;
}

unsigned int rar_get_char(unpack_data_t *unpack_data)
{
	unsigned int ch;
	if (unpack_data->in_addr > MAX_BUF_SIZE - 30)
	{
		if (unp_read_buf(unpack_data, 0))
		{
			rar_errmsg("rar_get_char: unp_read_buf FAILED\n");
			return -1;
		}
	}
	rar_dbgmsg("rar_get_char = %u\n", unpack_data->in_buf[unpack_data->in_addr]);
	ch = unpack_data->in_buf[unpack_data->in_addr];
	unpack_data->in_addr++;
	unpack_data->in_used--;
	return ch;
}


int
unp_write_out(unpack_data_t *unpack_data)
{
	unsigned int max_write_len, frag_len;


	max_write_len = unpack_data->out_used;
	if (unpack_data->avail_out < max_write_len)
	{
		unpack_data->outbuf_full = 1;
		max_write_len = unpack_data->avail_out;
		rar_dbgmsg("OUT buffer full..\n");
	}
	else
	{
		unpack_data->outbuf_full = 0;
	}
	if (max_write_len == 0)
	{
		return 0;
	}
	rar_dbgmsg("UNP WRITE OUT %d\n", max_write_len);

	if ((MAXWINSIZE - unpack_data->out_addr) >= max_write_len)
	{
		memcpy(unpack_data->next_out,
		       unpack_data->out_buf + unpack_data->out_addr,
		       max_write_len);
		unpack_data->out_addr += max_write_len;
	}
	else
	{
		frag_len = max_write_len - (MAXWINSIZE - unpack_data->out_addr);
		memcpy(unpack_data->next_out,
		       unpack_data->out_buf + unpack_data->out_addr,
		       (MAXWINSIZE - unpack_data->out_addr));
		memcpy(unpack_data->next_out + (MAXWINSIZE - unpack_data->out_addr),
		       unpack_data->out_buf, frag_len);
		unpack_data->out_addr = frag_len;
	}
	unpack_data->next_out += max_write_len;
	unpack_data->out_used -= max_write_len;
	unpack_data->avail_out -= max_write_len;
	rar_dbgmsg("avail out %d, write len %d\n",
	           unpack_data->avail_out, max_write_len);
	return 0;
}


int unp_write_data(unpack_data_t *unpack_data, u8_t *data, unsigned int size)
{
	unsigned int frag_len, curr_top;

	if (size == 0)  return 0;

	unp_write_out(unpack_data);

	if ((MAX_OUT_BUF_SIZE - unpack_data->out_used) <= size)
	{
		printf("NO SPACE unpack_data->out_used %d, out_add %d, ERROR1\n", unpack_data->out_used, unpack_data->out_addr);
		/* No space */
		return -1;
	}

	curr_top = (unpack_data->out_addr + unpack_data->out_used) & MAXWINMASK;

	if ((MAX_OUT_BUF_SIZE - curr_top) >= size)
	{
		memcpy(unpack_data->out_buf + curr_top, data, size);
	}
	else
	{
		frag_len = size - (MAX_OUT_BUF_SIZE - curr_top);
		memcpy(unpack_data->out_buf + curr_top, data,
		       (MAX_OUT_BUF_SIZE - curr_top));
		memcpy(unpack_data->out_buf,
		       data + (MAX_OUT_BUF_SIZE - curr_top), frag_len);
	}

	unpack_data->out_used += size;
	unpack_data->written_size += size;
	unpack_data->dest_unp_size -= size;
	rar_dbgmsg(" des %d, write_len %d\n", unpack_data->dest_unp_size,
	           size);

	//unpack_data->unp_crc = rar_crc(unpack_data->unp_crc, data, max_write_len);
	unp_write_out(unpack_data);
	return 0;
}


int unp_write_area(unpack_data_t *unpack_data, unsigned int start_ptr, unsigned int end_ptr)
{
	unsigned int write_len, room_len;
	if (end_ptr == start_ptr)
	{
		rar_dbgmsg("NODATA\n");
		return 0;
	}
	if (end_ptr < start_ptr)
	{
		write_len = (MAXWINSIZE - start_ptr) + end_ptr;
	}
	else
	{
		write_len = end_ptr - start_ptr;
	}
	room_len = MAX_OUT_BUF_SIZE - unpack_data->out_used;
	if (room_len <= write_len)
		return -1;

	if (end_ptr < start_ptr)
	{
		unp_write_data(unpack_data, &unpack_data->window[start_ptr], MAXWINSIZE - start_ptr);
		if (end_ptr != 0)
			unp_write_data(unpack_data, unpack_data->window, end_ptr);
	}
	else
	{
		unp_write_data(unpack_data, &unpack_data->window[start_ptr], end_ptr - start_ptr);
	}
	return 0;
}

int unp_write_buf_old(unpack_data_t *unpack_data)
{
	rar_dbgmsg("%s: Enter\n", __FUNCTION__);
	if (unpack_data->unp_ptr == unpack_data->wr_ptr)
	{
		return 0;
	}
	if (unpack_data->unp_ptr < unpack_data->wr_ptr)
	{
		if (unp_write_data(unpack_data, &unpack_data->window[unpack_data->wr_ptr],
		                   -unpack_data->wr_ptr & MAXWINMASK) != 0)
		{
			rar_dbgmsg("%s: unp_write_data failed 0 \n", __FUNCTION__);
			return -1;
		}
		unpack_data->wr_ptr += (-unpack_data->wr_ptr & MAXWINMASK);
		if (unp_write_data(unpack_data, unpack_data->window, unpack_data->unp_ptr) != 0)
		{
			rar_dbgmsg("%s: unp_write_data failed 1\n", __FUNCTION__);
			return -1;
		}
		unpack_data->wr_ptr = unpack_data->unp_ptr;
	}
	else
	{
		if (unp_write_data(unpack_data, &unpack_data->window[unpack_data->wr_ptr],
		                   unpack_data->unp_ptr - unpack_data->wr_ptr) != 0)
		{
			rar_dbgmsg("%s: unp_write_data failed 2\n", __FUNCTION__);
			return -1;
		}
		unpack_data->wr_ptr = unpack_data->unp_ptr;
	}
	return 0;
}

static void execute_code(unpack_data_t *unpack_data, struct rarvm_prepared_program *prg)
{
	rar_dbgmsg("in execute_code\n");
	rar_dbgmsg("global_size: %ld\n", prg->global_size);
	if (prg->global_size > 0)
	{
		prg->init_r[6] = int64to32(unpack_data->written_size);
		rarvm_set_value(FALSE, (unsigned int *)&prg->global_data[0x24],
		                int64to32(unpack_data->written_size));
		rarvm_set_value(FALSE, (unsigned int *)&prg->global_data[0x28],
		                int64to32(unpack_data->written_size >> 32));
		rarvm_execute(&unpack_data->rarvm_data, prg);
	}
}


static int unp_write_buf(unpack_data_t *unpack_data)
{
	unsigned int written_border, part_length, filtered_size;
	unsigned int write_size, block_start, block_length, block_end;
	struct UnpackFilter *flt, *next_filter;
	struct rarvm_prepared_program *prg, *next_prg;
	u8_t *filtered_data;
	int i, j;

	rar_dbgmsg("in unp_write_buf, wr_ptr %x, unptr %x, prgstack %d\n",
	           unpack_data->wr_ptr , unpack_data->unp_ptr,
	           unpack_data->unp_ptr - unpack_data->wr_ptr);
	written_border = unpack_data->wr_ptr;
	write_size = (unpack_data->unp_ptr - written_border) & MAXWINMASK;
	rar_dbgmsg("filter count %d\n", unpack_data->PrgStack.num_items);
#ifdef LOOP_DEBUG
	loop_idx = 1203;
#endif

	for (i = 0 ; i < unpack_data->PrgStack.num_items ; i++)
	{
		flt = unpack_data->PrgStack.array[i];
		if (flt == NULL)
		{
			continue;
		}
		if (flt->next_window)
		{
			flt->next_window = FALSE;
			continue;
		}
		block_start = flt->block_start;
		block_length = flt->block_length;
		if (((block_start - written_border)&MAXWINMASK) < write_size)
		{
			rar_dbgmsg("blcok start %d len %d\n", block_start, block_length);
			if (written_border != block_start)
			{
				rar_dbgmsg("We can write %d bystes before VM\n", block_start - written_border);
				if (unp_write_area(unpack_data, written_border, block_start))
				{
#ifdef LOOP_DEBUG
					loop_idx = 1204;
#endif
					return -1;
				}
				written_border = block_start;
				write_size = (unpack_data->unp_ptr - written_border) & MAXWINMASK;
			}
			write_size = (unpack_data->unp_ptr - written_border) & MAXWINMASK;
			if (block_length <= write_size)
			{
				block_end = (block_start + block_length) & MAXWINMASK;
				if (block_start < block_end || block_end == 0)
				{
					rarvm_set_memory(&unpack_data->rarvm_data, 0,
					                 unpack_data->window + block_start, block_length);
				}
				else
				{
					part_length = MAXWINMASK - block_start;
					rarvm_set_memory(&unpack_data->rarvm_data, 0,
					                 unpack_data->window + block_start, part_length);
					rarvm_set_memory(&unpack_data->rarvm_data, part_length,
					                 unpack_data->window, block_end);
				}
				prg = &flt->prg;
				execute_code(unpack_data, prg);

				filtered_data = prg->filtered_data;
				filtered_size = prg->filtered_data_size;

				rar_filter_delete(unpack_data->PrgStack.array[i]);
				unpack_data->PrgStack.array[i] = NULL;
#ifdef LOOP_DEBUG
				loop_idx = 61;
#endif

				while (i + 1 < unpack_data->PrgStack.num_items)
				{
					next_filter = unpack_data->PrgStack.array[i+1];
					if (next_filter == NULL ||
					        next_filter->block_start != block_start ||
					        next_filter->block_length != filtered_size ||
					        next_filter->next_window)
					{
						break;
					}
					rarvm_set_memory(&unpack_data->rarvm_data, 0,
					                 filtered_data, filtered_size);
					next_prg = &unpack_data->PrgStack.array[i+1]->prg;
					execute_code(unpack_data, next_prg);
					filtered_data = next_prg->filtered_data;
					filtered_size = next_prg->filtered_data_size;
					i++;
					rar_filter_delete(unpack_data->PrgStack.array[i]);
					unpack_data->PrgStack.array[i] = NULL;
				}
#ifdef LOOP_DEBUG
				loop_idx = 62;
#endif
				unp_write_data(unpack_data, filtered_data, filtered_size);
				written_border = block_end;
				write_size = (unpack_data->unp_ptr - written_border) & MAXWINMASK;
			}
			else
			{
#ifdef LOOP_DEBUG
				loop_idx = 59;
#endif
				for (j = i ; j < unpack_data->PrgStack.num_items ; j++)
				{
					flt = unpack_data->PrgStack.array[j];
					if (flt != NULL && flt->next_window)
					{
						flt->next_window = FALSE;
					}
				}
#ifdef LOOP_DEBUG
				loop_idx = 60;
#endif
				unpack_data->wr_ptr = written_border;
				rar_dbgmsg("unsufficient write buffer for filter\n");
				return 0;

			}
		}
	}
#ifdef LOOP_DEBUG
	loop_idx = 1204;
#endif

	rar_dbgmsg("We can write %d bystes after VM, %d - %d\n", written_border - unpack_data->unp_ptr, written_border, unpack_data->unp_ptr);
	unpack_data->wr_ptr = written_border;

	if (unpack_data->unp_ptr != written_border)
		if (unp_write_area(unpack_data, written_border, unpack_data->unp_ptr))
			return -1;
	unpack_data->wr_ptr = unpack_data->unp_ptr;
	return 0;
}

void make_decode_tables(unsigned char *len_tab, struct Decode *decode, int size)
{
	int len_count[16], tmp_pos[16], i;
	long m, n;

	memset(len_count, 0, sizeof(len_count));
	memset(decode->DecodeNum, 0, size*sizeof(*decode->DecodeNum));
#ifdef LOOP_DEBUG
	loop_idx = 1205;
#endif
	for (i = 0 ; i < size ; i++)
	{
		len_count[len_tab[i] & 0x0f]++;
	}
#ifdef LOOP_DEBUG
	loop_idx = 1207;
#endif

	len_count[0] = 0;
	for (tmp_pos[0] = decode->DecodePos[0] = decode->DecodeLen[0] = 0, n = 0, i = 1;i < 16;i++)
	{
		n = 2 * (n + len_count[i]);
		m = n << (15 - i);
		if (m > 0xFFFF)
		{
			m = 0xFFFF;
		}
		decode->DecodeLen[i] = (unsigned int)m;
		tmp_pos[i] = decode->DecodePos[i] = decode->DecodePos[i-1] + len_count[i-1];
	}
#ifdef LOOP_DEBUG
	loop_idx = 1209;
#endif

	for (i = 0;i < size;i++)
	{
		if (len_tab[i] != 0)
		{
			decode->DecodeNum[tmp_pos[len_tab[i] & 0x0f]++] = i;
		}
	}
#ifdef LOOP_DEBUG
	loop_idx = 1210;
#endif

	decode->MaxNum = size;
}

int decode_number(unpack_data_t *unpack_data, struct Decode *decode)
{
	unsigned int bits, bit_field, n;

	bit_field = getbits(unpack_data) & 0xfffe;
	rar_dbgmsg("decode_number BitField=%u\n", bit_field);
	if (bit_field < decode->DecodeLen[8])
		if (bit_field < decode->DecodeLen[4])
			if (bit_field < decode->DecodeLen[2])
				if (bit_field < decode->DecodeLen[1])
					bits = 1;
				else
					bits = 2;
			else
				if (bit_field < decode->DecodeLen[3])
					bits = 3;
				else
					bits = 4;
		else
			if (bit_field < decode->DecodeLen[6])
				if (bit_field < decode->DecodeLen[5])
					bits = 5;
				else
					bits = 6;
			else
				if (bit_field < decode->DecodeLen[7])
					bits = 7;
				else
					bits = 8;
	else
		if (bit_field < decode->DecodeLen[12])
			if (bit_field < decode->DecodeLen[10])
				if (bit_field < decode->DecodeLen[9])
					bits = 9;
				else
					bits = 10;
			else
				if (bit_field < decode->DecodeLen[11])
					bits = 11;
				else
					bits = 12;
		else
			if (bit_field < decode->DecodeLen[14])
				if (bit_field < decode->DecodeLen[13])
					bits = 13;
				else
					bits = 14;
			else
				bits = 15;

	//rar_dbgmsg("decode_number: bits=%d\n", bits);

	addbits(unpack_data, bits);
	n = decode->DecodePos[bits] + ((bit_field - decode->DecodeLen[bits-1]) >> (16 - bits));
	if (n >= decode->MaxNum)
	{
		n = 0;
	}
	/*rar_dbgmsg("decode_number return(%d)\n", decode->DecodeNum[n]);*/

	return(decode->DecodeNum[n]);
}

static int read_tables(unpack_data_t *unpack_data)
{
	u8_t bit_length[BC];
	unsigned char table[HUFF_TABLE_SIZE];
	unsigned int bit_field;
	int i, length, zero_count, number, n;
	const int table_size = HUFF_TABLE_SIZE;

	rar_dbgmsg("in read_tables in_addr=%d in_used=%d\n",
	           unpack_data->in_addr, unpack_data->in_used);
	rar_dbgmsg("FILE ADDR %x\n", unpack_data->in_addr + unpack_data->total_in + 7);
	unp_read_buf(unpack_data, 0);
	if ((unpack_data->in_used < 100) && (unpack_data->pack_size > 0))
	{
		return FALSE;
	}

	addbits(unpack_data, (8 - unpack_data->in_bit) & 7);
	bit_field = getbits(unpack_data);
	rar_dbgmsg("BitField = 0x%x\n", bit_field);
	if (bit_field & 0x8000)
	{
		/* Here we check the total PPM number */
		rar_dbgmsg("ppm_num=%d, ppm_max=%d\n", ppm_num, ppm_max);
		if (ppm_num + 1 > ppm_max)
		{
			/* we have to kick this session off */
			unpack_data->rar_error = RAR_REACH_MAX_PPM_NUM_ERROR;
			return FALSE;
		}
		rar_dbgmsg("PPM num is %d\n", ppm_num);
		unpack_data->unp_block_type = BLOCK_PPM;
		rar_dbgmsg("Calling ppm_decode_init\n");
		if (!ppm_decode_init(&unpack_data->ppm_data, unpack_data, &unpack_data->ppm_esc_char))
		{
			rar_dbgmsg("ERROR: read_tables: ppm_decode_init failed\n");
			return FALSE;
		}
		rar_dbgmsg("PPM read table done\n");
		unpack_data->tables_read = TRUE;
		rar_dbgmsg("FILE ADDR %x\n", unpack_data->in_addr + unpack_data->total_in + 7);
		return(TRUE);
	}
	rar_dbgmsg("LZ\n");
	/* Here we check the total PPM number meets the max,
	therefore, even LZSS have to be kicked-off */
	if (ppm_num >= ppm_max)
	{
		unpack_data->rar_error = RAR_REACH_MAX_PPM_NUM_ERROR;
		return FALSE;
	}
	unpack_data->unp_block_type = BLOCK_LZ;
	unpack_data->prev_low_dist = 0;
	unpack_data->low_dist_rep_count = 0;

	if (!(bit_field & 0x4000))
	{
		memset(unpack_data->unp_old_table, 0, sizeof(unpack_data->unp_old_table));
	}
	addbits(unpack_data, 2);

	for (i = 0 ; i < BC ; i++)
	{
		length = (u8_t)(getbits(unpack_data) >> 12);
		addbits(unpack_data, 4);
		if (length == 15)
		{
			zero_count = (u8_t)(getbits(unpack_data) >> 12);
			addbits(unpack_data, 4);
			if (zero_count == 0)
			{
				bit_length[i] = 15;
			}
			else
			{
				zero_count += 2;
#ifdef LOOP_DEBUG
				loop_idx = 57;
#endif

				while (zero_count-- > 0 &&
				        i < sizeof(bit_length) / sizeof(bit_length[0]))
				{
					bit_length[i++] = 0;
				}
#ifdef LOOP_DEBUG
				loop_idx = 58;
#endif

				i--;
			}
		}
		else
		{
			bit_length[i] = length;
		}
	}
	make_decode_tables(bit_length, (struct Decode *)&unpack_data->BD, BC);
#ifdef LOOP_DEBUG
	loop_idx = 1211;
#endif

	for (i = 0;i < table_size;)
	{
		if (unpack_data->in_used < 5)
		{
			if (unp_read_buf(unpack_data, 0))
			{
				rar_dbgmsg("ERROR: read_tables unp_read_buf failed 2\n");
#ifdef LOOP_DEBUG
				loop_idx = 1212;
#endif
				return FALSE;
			}
		}
		number = decode_number(unpack_data, (struct Decode *) & unpack_data->BD);
		if (number < 16)
		{
			table[i] = (number + unpack_data->unp_old_table[i]) & 0xf;
			i++;
		}
		else if (number < 18)
		{
			if (number == 16)
			{
				n = (getbits(unpack_data) >> 13) + 3;
				addbits(unpack_data, 3);
			}
			else
			{
				n = (getbits(unpack_data) >> 9) + 11;
				addbits(unpack_data, 7);
			}
#ifdef LOOP_DEBUG
			loop_idx = 55;
#endif

			while (n-- > 0 && i < table_size)
			{
				table[i] = table[i-1];
				i++;
			}
#ifdef LOOP_DEBUG
			loop_idx = 56;
#endif

		}
		else
		{
			if (number == 18)
			{
				n = (getbits(unpack_data) >> 13) + 3;
				addbits(unpack_data, 3);
			}
			else
			{
				n = (getbits(unpack_data) >> 9) + 11;
				addbits(unpack_data, 7);
			}
#ifdef LOOP_DEBUG
			loop_idx = 53;
#endif

			while (n-- > 0 && i < table_size)
			{
				table[i++] = 0;
			}
#ifdef LOOP_DEBUG
			loop_idx = 54;
#endif

		}
	}
#ifdef LOOP_DEBUG
	loop_idx = 1212;
#endif

	unpack_data->tables_read = TRUE;
	if (unpack_data->in_used == 0)
	{
		rar_dbgmsg("ERROR: read_tables check failed\n");
		return FALSE;
	}
	make_decode_tables(&table[0], (struct Decode *)&unpack_data->LD, NC);
	make_decode_tables(&table[NC], (struct Decode *)&unpack_data->DD, DC);
	make_decode_tables(&table[NC+DC], (struct Decode *)&unpack_data->LDD, LDC);
	make_decode_tables(&table[NC+DC+LDC], (struct Decode *)&unpack_data->RD, RC);
	memcpy(unpack_data->unp_old_table, table, sizeof(unpack_data->unp_old_table));


	/*dump_tables(unpack_data);*/
	rar_dbgmsg("ReadTables finished\n");
	return TRUE;
}



static void init_filters(unpack_data_t *unpack_data)
{
	if (unpack_data->old_filter_lengths)
	{
		free(unpack_data->old_filter_lengths);
		unpack_data->old_filter_lengths = NULL;
	}
	unpack_data->old_filter_lengths_size = 0;
	unpack_data->last_filter = 0;

	rar_filter_array_reset(&unpack_data->Filters);
	rar_filter_array_reset(&unpack_data->PrgStack);
}

static int add_vm_code(unpack_data_t *unpack_data, unsigned int first_byte,
                       unsigned char *vmcode, int code_size)
{
	rarvm_input_t rarvm_input;
	unsigned int filter_pos, new_filter, block_start, init_mask, cur_size;
	struct UnpackFilter *filter, *stack_filter;
	int i, empty_count, stack_pos, vm_codesize, static_size, data_size;
	unsigned char *vm_code, *global_data;

	rar_dbgmsg("in add_vm_code first_byte=0x%x code_size=%d\n", first_byte, code_size);
	rarvm_input.in_buf = vmcode;
	rarvm_input.buf_size = code_size;
	rarvm_input.in_addr = 0;
	rarvm_input.in_bit = 0;

	if (first_byte & 0x80)
	{
		filter_pos = rarvm_read_data(&rarvm_input);
		if (filter_pos == 0)
		{
			init_filters(unpack_data);
		}
		else
		{
			filter_pos--;
		}
	}
	else
	{
		filter_pos = unpack_data->last_filter;
	}
	rar_dbgmsg("filter_pos = %u\n", filter_pos);
	if (filter_pos > unpack_data->Filters.num_items ||
	        filter_pos > unpack_data->old_filter_lengths_size)
	{
		rar_errmsg("filter_pos check failed\n");
		return FALSE;
	}
	unpack_data->last_filter = filter_pos;
	new_filter = (filter_pos == unpack_data->Filters.num_items);
	rar_dbgmsg("Filters.num_items=%d\n", unpack_data->Filters.num_items);
	rar_dbgmsg("new_filter=%d\n", new_filter);
	if (new_filter)
	{
		if (!rar_filter_array_add(&unpack_data->Filters, 1))
		{
			rar_errmsg("rar_filter_array_add failed\n");
			return FALSE;
		}
		unpack_data->Filters.array[unpack_data->Filters.num_items-1] =
		    filter = rar_filter_new();
		if (!unpack_data->Filters.array[unpack_data->Filters.num_items-1])
		{
			rar_errmsg("rar_filter_new failed\n");
			return FALSE;
		}
		unpack_data->old_filter_lengths_size++;
		unpack_data->old_filter_lengths = (int *) realloc(unpack_data->old_filter_lengths,
		                                  sizeof(int) * unpack_data->old_filter_lengths_size);
		if (!unpack_data->old_filter_lengths)
		{
			rar_errmsg("unrar: add_vm_code: cli_realloc failed for unpack_data->old_filter_lengths\n");
			return FALSE;
		}
		unpack_data->old_filter_lengths[unpack_data->old_filter_lengths_size-1] = 0;
		filter->exec_count = 0;
	}
	else
	{
		filter = unpack_data->Filters.array[filter_pos];
		filter->exec_count++;
	}

	stack_filter = rar_filter_new();

	empty_count = 0;
#ifdef LOOP_DEBUG
	loop_idx = 1213;
#endif

	for (i = 0 ; i < unpack_data->PrgStack.num_items; i++)
	{
		unpack_data->PrgStack.array[i-empty_count] = unpack_data->PrgStack.array[i];
		if (unpack_data->PrgStack.array[i] == NULL)
		{
			empty_count++;
		}
		if (empty_count > 0)
		{
			unpack_data->PrgStack.array[i] = NULL;
		}
	}
#ifdef LOOP_DEBUG
	loop_idx = 1214;
#endif

	if (empty_count == 0)
	{
		rar_filter_array_add(&unpack_data->PrgStack, 1);
		empty_count = 1;
	}
	stack_pos = unpack_data->PrgStack.num_items - empty_count;
	unpack_data->PrgStack.array[stack_pos] = stack_filter;
	stack_filter->exec_count = filter->exec_count;

	block_start = rarvm_read_data(&rarvm_input);
	rar_dbgmsg("block_start=%u\n", block_start);
	if (first_byte & 0x40)
	{
		block_start += 258;
	}
	stack_filter->block_start = (block_start + unpack_data->unp_ptr) & MAXWINMASK;
	if (first_byte & 0x20)
	{
		stack_filter->block_length = rarvm_read_data(&rarvm_input);
	}
	else
	{
		stack_filter->block_length = filter_pos < unpack_data->old_filter_lengths_size ?
		                             unpack_data->old_filter_lengths[filter_pos] : 0;
	}
	rar_dbgmsg("block_length=%u\n", stack_filter->block_length);
	/* check for bogus file */
	if (stack_filter->block_length > 0x4000000) /* 64M */
	{
		rar_errmsg("Block length > 0x4000000!\n");
		return FALSE;
	}
	stack_filter->next_window = unpack_data->wr_ptr != unpack_data->unp_ptr &&
	                            ((unpack_data->wr_ptr - unpack_data->unp_ptr) & MAXWINMASK) <= block_start;

	unpack_data->old_filter_lengths[filter_pos] = stack_filter->block_length;

	memset(stack_filter->prg.init_r, 0, sizeof(stack_filter->prg.init_r));
	stack_filter->prg.init_r[3] = VM_GLOBALMEMADDR;
	stack_filter->prg.init_r[4] = stack_filter->block_length;
	stack_filter->prg.init_r[5] = stack_filter->exec_count;
	if (first_byte & 0x10)
	{
		init_mask = rarvm_getbits(&rarvm_input) >> 9;
		rarvm_addbits(&rarvm_input, 7);
		for (i = 0 ; i < 7 ; i++)
		{
			if (init_mask & (1 << i))
			{
				stack_filter->prg.init_r[i] =
				    rarvm_read_data(&rarvm_input);
				rar_dbgmsg("prg.init_r[%d] = %u\n", i, stack_filter->prg.init_r[i]);
			}
		}
	}
	if (new_filter)
	{
		vm_codesize = rarvm_read_data(&rarvm_input);
		if (vm_codesize >= 0x1000 || vm_codesize == 0)
		{
			rar_errmsg("ERROR: vm_codesize=0x%x\n", vm_codesize);
			return FALSE;
		}
		vm_code = (unsigned char *) malloc(vm_codesize);
		if (!vm_code)
		{
			rar_errmsg("unrar: add_vm_code: cli_malloc failed for vm_code\n");
			return FALSE;
		}
#ifdef LOOP_DEBUG
		loop_idx = 1215;
#endif

		for (i = 0 ; i < vm_codesize ; i++)
		{
			vm_code[i] = rarvm_getbits(&rarvm_input) >> 8;
			rarvm_addbits(&rarvm_input, 8);
		}
#ifdef LOOP_DEBUG
		loop_idx = 1216;
#endif
		if (!rarvm_prepare(&unpack_data->rarvm_data, &rarvm_input, &vm_code[0], vm_codesize, &filter->prg))
		{
			rar_errmsg("unrar: add_vm_code: rarvm_prepare failed\n");
			free(vm_code);
			return FALSE;
		}
		free(vm_code);
	}
	stack_filter->prg.alt_cmd = &filter->prg.cmd.array[0];
	stack_filter->prg.cmd_count = filter->prg.cmd_count;

	static_size = filter->prg.static_size;
	if (static_size > 0 && static_size < VM_GLOBALMEMSIZE)
	{
		stack_filter->prg.static_data = malloc(static_size);
		if (!stack_filter->prg.static_data)
		{
			rar_errmsg("unrar: add_vm_code: cli_malloc failed for stack_filter->prg.static_data\n");
			return FALSE;
		}
		memcpy(stack_filter->prg.static_data, filter->prg.static_data, static_size);
	}

	if (stack_filter->prg.global_size < VM_FIXEDGLOBALSIZE)
	{
		free(stack_filter->prg.global_data);
		stack_filter->prg.global_data = malloc(VM_FIXEDGLOBALSIZE);
		if (!stack_filter->prg.global_data)
		{
			rar_errmsg("unrar: add_vm_code: cli_malloc failed for stack_filter->prg.global_data\n");
			return FALSE;
		}
		memset(stack_filter->prg.global_data, 0, VM_FIXEDGLOBALSIZE);
		stack_filter->prg.global_size = VM_FIXEDGLOBALSIZE;
	}
	global_data = &stack_filter->prg.global_data[0];
	for (i = 0 ; i < 7 ; i++)
	{
		rar_dbgmsg("init_r[%d]=%u\n", i, stack_filter->prg.init_r[i]);
		rarvm_set_value(FALSE, (unsigned int *)&global_data[i*4],
		                stack_filter->prg.init_r[i]);
	}
	rarvm_set_value(FALSE, (unsigned int *)&global_data[0x1c], stack_filter->block_length);
	rarvm_set_value(FALSE, (unsigned int *)&global_data[0x20], 0);
	rarvm_set_value(FALSE, (unsigned int *)&global_data[0x2c], stack_filter->exec_count);
	memset(&global_data[0x30], 0, 16);
	for (i = 0 ; i < 30 ; i++)
	{
		rar_dbgmsg("global_data[%d] = %d\n", i, global_data[i]);
	}
	if (first_byte & 8)
	{
		data_size = rarvm_read_data(&rarvm_input);
		rar_dbgmsg("data size is %d\n", data_size);
		if (data_size >= 0x10000)
		{
			rar_dbgmsg("Error, too large\n");
			return FALSE;
		}
		cur_size = stack_filter->prg.global_size;
		rar_dbgmsg("step 1\n");
		if (cur_size < data_size + VM_FIXEDGLOBALSIZE)
		{
			stack_filter->prg.global_size += data_size + VM_FIXEDGLOBALSIZE - cur_size;
			stack_filter->prg.global_data = realloc(stack_filter->prg.global_data,
			                                        stack_filter->prg.global_size);
			rar_dbgmsg("step 2\n");
			if (!stack_filter->prg.global_data)
			{
				rar_errmsg("unrar: add_vm_code: cli_realloc failed for stack_filter->prg.global_data\n");
				return FALSE;
			}
		}
		global_data = &stack_filter->prg.global_data[VM_FIXEDGLOBALSIZE];
		rar_dbgmsg("step 4, FIXED %d, datasize %d, stack %ld\n", VM_FIXEDGLOBALSIZE, data_size, stack_filter->prg.global_size);
#ifdef LOOP_DEBUG
		loop_idx = 1217;
#endif

		for (i = 0 ; i < data_size ; i++)
		{
			/* check for bogus file */
			if (rarvm_input.in_addr + 3 >= rarvm_input.buf_size)
			{
				rar_errmsg("rarvm_input.in_addr + 3 >= rar_input.buf_size\n");
#ifdef LOOP_DEBUG
				loop_idx = 1218;
#endif
				return FALSE;
			}
			global_data[i] = rarvm_getbits(&rarvm_input) >> 8;
			rarvm_addbits(&rarvm_input, 8);
			rar_dbgmsg("global_data[%d] = %d\n", i, global_data[i]);
		}
#ifdef LOOP_DEBUG
		loop_idx = 1218;
#endif

	}
	return TRUE;
}

/* return 0 ok, 1 for data not enough, -1 for error */
static int read_vm_code(unpack_data_t *unpack_data)
{
	unsigned int first_byte;
	int length, i, retval;
	unsigned char *vmcode = NULL;
	int in_addr_bk = unpack_data->in_addr;
	int in_used_bk = unpack_data->in_used;
	int in_bit_bk = unpack_data->in_bit;

	if ((unpack_data->in_used <= 3) && (unpack_data->pack_size != 0))
	{
		return 1; /* Buffer is not enough */
	}

	first_byte = getbits(unpack_data) >> 8;
	addbits(unpack_data, 8);
	length = (first_byte & 7) + 1;
	if (length == 7)
	{
		length = (getbits(unpack_data) >> 8) + 7;
		addbits(unpack_data, 8);
	}
	else if (length == 8)
	{
		length = getbits(unpack_data);
		addbits(unpack_data, 16);
	}
	if (length > 4*1024)
		return -1;
	vmcode = (unsigned char *) malloc(length + 2);
	rar_dbgmsg("VM code length: %d\n", length);
	if (!vmcode)
	{
		rar_errmsg("Unable to allocated %d\n", length + 2);
		return -1;
	}
	if ((unpack_data->in_used <= length) && (unpack_data->pack_size != 0))
	{
		goto rollback;
	}
#ifdef LOOP_DEBUG
	loop_idx = 1219;
#endif

	for (i = 0 ; i < length ; i++)
	{
		if (unpack_data->in_used <= 0)
		{
#ifdef LOOP_DEBUG
			loop_idx = 1220;
#endif
			goto rollback;
		}
		vmcode[i] = getbits(unpack_data) >> 8;
		addbits(unpack_data, 8);
	}
#ifdef LOOP_DEBUG
	loop_idx = 1220;
#endif

	retval = add_vm_code(unpack_data, first_byte, vmcode, length);
	free(vmcode);
	if (retval == FALSE)
	{
		rar_errmsg("add vm code error\n");
		return -1;
	}
	return 0;
rollback:
	if (vmcode)
	{
		free(vmcode);
	}
	unpack_data->in_addr = in_addr_bk;
	unpack_data->in_used = in_used_bk;
	unpack_data->in_bit = in_bit_bk;
	return 1;
}

static int read_vm_code_PPM(unpack_data_t *unpack_data)
{
	unsigned int first_byte;
	int length, i, ch, retval, b1, b2;
	unsigned char *vmcode;

	first_byte = ppm_decode_char(&unpack_data->ppm_data, unpack_data);
	if ((int)first_byte == -1)
	{
		return FALSE;
	}
	length = (first_byte & 7) + 1;
	if (length == 7)
	{
		b1 = ppm_decode_char(&unpack_data->ppm_data, unpack_data);
		if (b1 == -1)
		{
			return FALSE;
		}
		length = b1 + 7;
	}
	else if (length == 8)
	{
		b1 = ppm_decode_char(&unpack_data->ppm_data, unpack_data);
		if (b1 == -1)
		{
			return FALSE;
		}
		b2 = ppm_decode_char(&unpack_data->ppm_data, unpack_data);
		if (b2 == -1)
		{
			return FALSE;
		}
		length = b1 * 256 + b2;
	}
	vmcode = (unsigned char *) malloc(length + 2);
	rar_dbgmsg("VM PPM code length: %d\n", length);
	if (!vmcode)
	{
		return FALSE;
	}
#ifdef LOOP_DEBUG
	loop_idx = 1221;
#endif

	for (i = 0 ; i < length ; i++)
	{
		ch = ppm_decode_char(&unpack_data->ppm_data, unpack_data);
		if (ch == -1)
		{
			free(vmcode);
#ifdef LOOP_DEBUG
			loop_idx = 1222;
#endif

			return FALSE;
		}
		vmcode[i] = ch;
	}
#ifdef LOOP_DEBUG
	loop_idx = 1222;
#endif

	retval = add_vm_code(unpack_data, first_byte, vmcode, length);
	free(vmcode);
	return retval;
}

void unpack_init_data(int solid, unpack_data_t *unpack_data)
{

	/* init & cleanup old copy */
	unpack_free_data(unpack_data);
	unpack_data->window = malloc(MAXWINSIZE);
	if (unpack_data->window == NULL)
	{
		rar_errmsg("ERROR: Unable to allocate RAR window buffer\n");
		return;
	}
	unpack_data->out_buf = malloc(MAX_OUT_BUF_SIZE);
	if (unpack_data->out_buf == NULL)
	{
		rar_errmsg("ERROR: Unable to allocate RAR output buffer\n");
		return;
	}
	unpack_data->rarvm_data.mem = NULL;
	unpack_data->old_filter_lengths = NULL;
	//unpack_data->unp_crc = 0xffffffff;
	unpack_data->rar_error = 0;

	if (!solid)
	{
		unpack_data->tables_read = FALSE;
		memset(unpack_data->old_dist, 0, sizeof(unpack_data->old_dist));
		//unpack_data->old_dist_ptr= 0;
		memset(unpack_data->unp_old_table, 0, sizeof(unpack_data->unp_old_table));
		unpack_data->last_dist = 0;
		unpack_data->last_length = 0;
		unpack_data->ppm_esc_char = 2;
		unpack_data->unp_ptr = 0;
		unpack_data->wr_ptr = 0;
		unpack_data->out_addr = 0;
		unpack_data->out_used = 0;
		unpack_data->outbuf_full = 0;

		init_filters(unpack_data);
	}
	unpack_data->total_in = 0;
	unpack_data->decoding = 0;

	unpack_data->unpack_state = 0;

	unpack_data->in_bit = 0;
	unpack_data->in_addr = 0;
	unpack_data->in_used = 0;
	unpack_data->ppm_error = FALSE;
	unpack_data->unp_block_type = BLOCK_LZ;

	unpack_data->written_size = 0;
	rarvm_init(&unpack_data->rarvm_data);
	//unpack_data->unp_crc = 0xffffffff;

	//unpack_init_data20(solid, unpack_data);
	/* Just clear vars, no malloc happened */
	ppm_constructor(&(unpack_data->ppm_data));

}

void unpack_free_data(unpack_data_t *unpack_data)
{
	if (!unpack_data)
	{
		return;
	}
	free(unpack_data->window);
	unpack_data->window = NULL;
	free(unpack_data->out_buf);
	unpack_data->out_buf = NULL;

	ppm_destructor(&(unpack_data->ppm_data));
	rar_filter_array_reset(&unpack_data->Filters);
	rar_filter_array_reset(&unpack_data->PrgStack);
	if (unpack_data->old_filter_lengths)
	{
		free(unpack_data->old_filter_lengths);
		unpack_data->old_filter_lengths = NULL;
	}

	rarvm_free(&(unpack_data->rarvm_data));
	unpack_data->opened = 0;

	if (unpack_data->rar1_data)
	{
		free(unpack_data->rar1_data);
	}
	unpack_data->rar1_data = NULL;

	if (unpack_data->rar2_data)
	{
		free(unpack_data->rar2_data);
	}
	unpack_data->rar2_data = NULL;

}


int rar_unpack29_state(unpack_data_t *unpack_data)
{
	int ret;

	rar_dbgmsg("unpack29 state %x, %x\n", unpack_data->unpack_state,
	           unpack_data->in_buf[unpack_data->in_addr]);
	if (unpack_data->unpack_state == UNPACK29_STATE_READ_TABLES)
	{
		if (!unpack_data->tables_read)
		{
			if ((unpack_data->in_used < 1024) && (unpack_data->in_used < unpack_data->pack_size))
			{
				unp_read_buf(unpack_data, 0);
			}
			rar_dbgmsg("in used %d, pack size %d\n", unpack_data->in_used, unpack_data->pack_size);
			if ((unpack_data->in_used < 1024) && (unpack_data->decoding && (unpack_data->in_used < unpack_data->pack_size)))
			{
				return RAR_READ_BUFFER_NOT_ENOUGH;
			}
			rar_dbgmsg("Read tables\n");
			if (!read_tables(unpack_data))
			{
				if (unpack_data->rar_error)
				{
					return unpack_data->rar_error;
				}
				else
				{
					return RAR_READ_BUFFER_NOT_ENOUGH;
				}
			}
			rar_dbgmsg("Read ok!\n");
		}
		unpack_data->unpack_state = UNPACK29_STATE_UNPACK_DATA;
	}
	else
	{
		ret = rar_unpack29(unpack_data);
		if (!unpack_data->tables_read)
		{
			rar_dbgmsg("des unpack size %d\n", unpack_data->dest_unp_size);
			if (unpack_data->dest_unp_size == 0)
			{
				return -1;
			}
			else
			{
				rar_dbgmsg("JUMP to\n");
				unpack_data->unpack_state = UNPACK29_STATE_READ_TABLES;
			}
		}
		return ret;
	}

	return RAR_OK;
}

static int rar_ppm(unpack_data_t *unpack_data, int *retval)
{
	int i, ch, next_ch;
	unsigned int length = 0;
	unsigned int distance;


	rar_dbgmsg("PPM ADDR %x, value %x\n", unpack_data->in_addr + unpack_data->total_in + 7, unpack_data->in_buf[unpack_data->in_addr]);
	*retval = RAR_OK;
	ch = ppm_decode_char(&unpack_data->ppm_data, unpack_data);
	rar_dbgmsg("PPM char: %d\n", ch);
	if (ch == -1)
	{
		unpack_data->ppm_error = TRUE;
		*retval = RAR_DATA_ERROR;
		rar_dbgmsg("PPM DATA ERROR1\n");
		return 1;
	}
	if (ch == unpack_data->ppm_esc_char)
	{
		next_ch = ppm_decode_char(&unpack_data->ppm_data, unpack_data);
		rar_dbgmsg("PPM next char: %d\n", next_ch);
		if (next_ch == -1)
		{
			unpack_data->ppm_error = TRUE;
			*retval = RAR_DATA_ERROR;
			rar_dbgmsg("PPM DATA ERROR2\n");
			return 1;
		}
		else if (next_ch == 0)
		{
			unpack_data->tables_read = FALSE;
			unpack_data->in_bit = 0;
			rar_dbgmsg("NEW TABLE\n");
			/* quick clear here */
			ppm_destructor(&(unpack_data->ppm_data));

			/*
			if (!read_tables(unpack_data)) {
			    rar_dbgmsg("PPM read tables ERROR\n");
				*retval = FALSE;
			    return 1;
			}
			return 0;
			*/
			return 1;
		}
		else if (next_ch == 2 || next_ch == -1)
		{
			/* just break */
			unp_write_buf(unpack_data);
			if (unpack_data->dest_unp_size == 0)
			{
				rar_dbgmsg("rar_ppm: File end with in used=%d, in_addr=%d\n",
				           unpack_data->in_used, unpack_data->in_addr);
				unpack_data->tables_read = 0;
				//unpack_data->in_bit = 0;
				/* quick clear here */
				ppm_destructor(&(unpack_data->ppm_data));
				if (unpack_data->in_used > 0)
				{
					rar_dbgmsg("rar_ppm: File end after adjustment in used=%d, in_addr=%d\n",
					           unpack_data->in_used, unpack_data->in_addr );
					unpack_data->in_addr += unpack_data->in_used;
					unpack_data->in_used = 0;
				}

			}
			return 1;
		}
		else if (next_ch == 3)
		{
			if (!read_vm_code_PPM(unpack_data))
			{
				*retval = RAR_READ_BUFFER_NOT_ENOUGH;
				rar_dbgmsg("PPM read VM tables ERROR\n");
				return 1;
			}
			return 0;
		}
		else if (next_ch == 4)
		{
			distance = 0;
			for (i = 0 ; i < 4; i++)
			{
				ch = ppm_decode_char(&unpack_data->ppm_data,
				                     unpack_data);
				if (ch == -1)
				{
					*retval = RAR_DATA_ERROR;
					rar_dbgmsg("PPM ERROR\n");
					return 1;
				}
				else
				{
					if (i == 3)
					{
						length = (u8_t)ch;
					}
					else
					{
						distance = (distance << 8) +
						           (u8_t)ch;
					}
				}
			}
			copy_string(unpack_data, length + 32, distance + 2);
			return 0;
		}
		else if (next_ch == 5)
		{
			length = ppm_decode_char(&unpack_data->ppm_data,
			                         unpack_data);
			rar_dbgmsg("PPM length: %d\n", length);
			if (length == -1)
			{
				rar_dbgmsg("PPM ERROR4\n");
				*retval = RAR_DATA_ERROR;
				return 1;
			}
			copy_string(unpack_data, length + 4, 1);
			return 0;
		}
	}
	unpack_data->window[unpack_data->unp_ptr] = ch;
	unpack_data->unp_ptr = (unpack_data->unp_ptr + 1) & MAXWINMASK;
	return 0;
}


static int rar_lz(unpack_data_t *unpack_data, int *retval)
{
	unsigned int bits, distance;
	int  i, number, length, dist_number, low_dist;
	int length_number;
	int val;


	*retval = RAR_OK;

	rar_dbgmsg("ADDR %x, value %x\n", unpack_data->in_addr + unpack_data->total_in + 7, unpack_data->in_buf[unpack_data->in_addr]);

	if ((unpack_data->in_used < 16) && (unpack_data->pack_size != 0))
	{
		*retval = RAR_READ_BUFFER_NOT_ENOUGH;
		return 1;
	}

	if (unpack_data->is_last_exist)
	{
		number = unpack_data->last_number;
		unpack_data->is_last_exist = 0;
	}
	else
	{

		number = decode_number(unpack_data, (struct Decode *) & unpack_data->LD);
		unpack_data->last_number = number;
	}

	if (unpack_data->in_used < 0)
	{
		rar_errmsg("ERROR: decode_number leads to in_used < 0, %d\n", __LINE__);
		*retval = RAR_DATA_ERROR;
		return 1;
	}

	rar_dbgmsg("number = %d\n", number);
	if (number < 256)
	{
		unpack_data->window[unpack_data->unp_ptr] = (u8_t) number;
		unpack_data->unp_ptr = (unpack_data->unp_ptr + 1) & MAXWINMASK;
		return 0;
	}
	else if (number >= 271)
	{
		length = ldecode[number-=271] + 3;
		if ((bits = lbits[number]) > 0)
		{
			length += getbits(unpack_data) >> (16 - bits);
			addbits(unpack_data, bits);
		}
		dist_number = decode_number(unpack_data,
		                            (struct Decode *) & unpack_data->DD);
		if (unpack_data->in_used < 0)
		{
			rar_errmsg("ERROR: decode_number leads to in_used < 0, %d\n", __LINE__);
			*retval = RAR_DATA_ERROR;
			return 1;
		}
		distance = ddecode[dist_number] + 1;
		if ((bits = dbits[dist_number]) > 0)
		{
			if (dist_number > 9)
			{
				if (bits > 4)
				{
					distance += ((getbits(unpack_data) >>
					              (20 - bits)) << 4);
					addbits(unpack_data, bits - 4);
				}
				if (unpack_data->low_dist_rep_count > 0)
				{
					unpack_data->low_dist_rep_count--;
					distance += unpack_data->prev_low_dist;
				}
				else
				{
					low_dist = decode_number(unpack_data,
					                         (struct Decode *) & unpack_data->LDD);
					if (unpack_data->in_used < 0)
					{
						rar_errmsg("ERROR: decode_number leads to in_used < 0, %d\n", __LINE__);
						*retval = RAR_DATA_ERROR;
						return 1;
					}
					if (low_dist == 16)
					{
						unpack_data->low_dist_rep_count =
						    LOW_DIST_REP_COUNT - 1;
						distance += unpack_data->prev_low_dist;
					}
					else
					{
						distance += low_dist;
						unpack_data->prev_low_dist = low_dist;
					}
				}
			}
			else
			{
				distance += getbits(unpack_data) >> (16 - bits);
				addbits(unpack_data, bits);
			}
		}

		if (distance >= 0x2000)
		{
			length++;
			if (distance >= 0x40000L)
			{
				length++;
			}
		}
		rar_dbgmsg("in_addr %d, in_used %d\n", unpack_data->in_addr, unpack_data->in_used);

		insert_old_dist(unpack_data, distance);
		insert_last_match(unpack_data, length, distance);
		copy_string(unpack_data, length, distance);
		return 0;
	}
	else if (number == 256)
	{
		unsigned int bit_field;
		int new_table, new_file = FALSE;


		rar_dbgmsg("read end of block\n");
		bit_field = getbits(unpack_data);
		if (bit_field & 0x8000)
		{
			new_table = TRUE;
			addbits(unpack_data, 1);
		}
		else
		{
			new_file = TRUE;
			new_table = (bit_field & 0x4000);
			addbits(unpack_data, 2);
		}
		unpack_data->tables_read = !new_table;
		rar_dbgmsg("NewFile=%d NewTable=%d TablesRead=%d\n", new_file,
		           new_table, unpack_data->tables_read);
		if (new_file)
		{
			unpack_data->in_bit = 0;
			rar_dbgmsg("in_addr %x, in_used %x, pack left %x\n",
			           unpack_data->in_addr, unpack_data->in_used, unpack_data->pack_size);

			if (unpack_data->in_used > 0)
			{
				rar_dbgmsg("rar_lz: File end after adjustment, in_used=%d, in_addr=%d\n",
				           unpack_data->in_used, unpack_data->in_addr);
				unpack_data->in_addr += unpack_data->in_used;
				unpack_data->in_used = 0;
			}
			rar_dbgmsg("curr position %x\n", unpack_data->total_in + unpack_data->in_addr + 7);
			rar_dbgmsg("%x %x\n", unpack_data->in_buf[unpack_data->in_addr-2], unpack_data->in_buf[unpack_data->in_addr-1]);
			return 1;
		}
		else
		{
			if (new_table)
			{
				//unpack_data->in_bit = 0;
				return 1;
			}
			else
				return 0;
		}

		return 0;
	}
	else if (number == 257)
	{
		rar_dbgmsg("read VM\n");

		unp_read_buf(unpack_data, 0);
		val = read_vm_code(unpack_data);
		if (val == 1)
		{
			rar_dbgmsg("read VM failed\n");
			*retval = RAR_READ_BUFFER_NOT_ENOUGH;
			unpack_data->is_last_exist = 1;
			return 1;
		}
		else if (val == -1)
		{
			rar_errmsg("ERROR: read VM data error\n");
			*retval = RAR_DATA_ERROR;
			return 1;
		}

		return 0;
	}
	else if (number == 258)
	{
		if (unpack_data->last_length != 0)
		{
			copy_string(unpack_data, unpack_data->last_length,
			            unpack_data->last_dist);
		}
		return 0;
	}
	else if (number < 263)
	{
		dist_number = number - 259;
		distance = unpack_data->old_dist[dist_number];
#ifdef LOOP_DEBUG
		loop_idx = 1223;
#endif

		for (i = dist_number ; i > 0 ; i--)
		{
			unpack_data->old_dist[i] = unpack_data->old_dist[i-1];
		}
#ifdef LOOP_DEBUG
		loop_idx = 1224;
#endif

		unpack_data->old_dist[0] = distance;

		length_number = decode_number(unpack_data,
		                              (struct Decode *) & unpack_data->RD);
		if (unpack_data->in_used < 0)
		{
			rar_errmsg("ERROR: decode_number leads to in_used < 0, %d\n", __LINE__);
			*retval = RAR_DATA_ERROR;
			return 1;
		}
		length = ldecode[length_number] + 2;
		if ((bits = lbits[length_number]) > 0)
		{
			length += getbits(unpack_data) >> (16 - bits);
			addbits(unpack_data, bits);
		}
		insert_last_match(unpack_data, length, distance);
		copy_string(unpack_data, length, distance);
		return 0;
	}
	else if (number < 272)
	{
		distance = sddecode[number-=263] + 1;
		if ((bits = sdbits[number]) > 0)
		{
			distance += getbits(unpack_data) >> (16 - bits);
			addbits(unpack_data, bits);
		}
		insert_old_dist(unpack_data, distance);
		insert_last_match(unpack_data, 2, distance);
		copy_string(unpack_data, 2, distance);
		return 0;
	}
	return 0;
}

int rar_unpack29(unpack_data_t *unpack_data)
{
	int retval = RAR_OK;


	//rar_dbgmsg("Offset: %ld\n", lseek(fd, 0, SEEK_CUR));

	rar_dbgmsg("unpack29\n");
	if (!unpack_data->tables_read)
	{
		rar_dbgmsg("JUMP0\n");
	}
	if (((unpack_data->unp_ptr - unpack_data->wr_ptr) &  MAXWINMASK) > 1024)
	{
		if (unp_write_buf(unpack_data))
		{
			return RAR_WRITE_BUFFER_NOT_ENOUGH;
		}
	}

#ifdef LOOP_DEBUG
	loop_idx = 51;
#endif
	while (1)
	{
#if 0
		if (((unpack_data->unp_ptr - unpack_data->wr_ptr) &  MAXWINMASK) > 1024)
		{
			unp_write_buf(unpack_data);
		}
#endif
		//rar_dbgmsg("UnpPtr = %d\n", unpack_data->unp_ptr);
		rar_dbgmsg("in_addr %d, read_border %d, in_used%d, avail_in %d\n",
		           unpack_data->in_addr, unpack_data->read_border,
		           unpack_data->in_used, unpack_data->avail_in);
		if ((unpack_data->in_addr >= unpack_data->read_border))
		{
			unp_read_buf(unpack_data, 0);

			if (unpack_data->pack_size && (unpack_data->in_addr >= unpack_data->read_border))
			{
				rar_dbgmsg("insufficient data..\n");
				retval = RAR_READ_BUFFER_NOT_ENOUGH;
				break;
			}
		}

		if (((unpack_data->wr_ptr - unpack_data->unp_ptr) & MAXWINMASK) < 260 &&
		        unpack_data->wr_ptr != unpack_data->unp_ptr)
		{
			if (unp_write_buf(unpack_data))
			{
				retval = RAR_WRITE_BUFFER_NOT_ENOUGH;
				break;
			}
		}
		if (unpack_data->unp_block_type == BLOCK_PPM)
		{
			if (rar_ppm(unpack_data, &retval))
				break;
		}
		else
		{
			if (rar_lz(unpack_data, &retval))
				break;
		}
	}
#ifdef LOOP_DEBUG
	loop_idx = 52;
#endif

#if 0
	if (!unpack_data->tables_read)
	{
		rar_dbgmsg("retval %d\n", retval);
		unp_write_buf(unpack_data);
		rar_dbgmsg("UNP avail_out %d\n", unpack_data->avail_out);
	}
#endif

	rar_dbgmsg("retval %d\n", retval);
	if (retval != RAR_WRITE_BUFFER_NOT_ENOUGH)
	{
		if (unp_write_buf(unpack_data))
			retval = RAR_WRITE_BUFFER_NOT_ENOUGH;
	}

	if (unpack_data->avail_out == 0)
	{
		retval = RAR_WRITE_BUFFER_NOT_ENOUGH;
	}

	rar_dbgmsg("Finished length: %ld\n", unpack_data->written_size);

	return retval;
}

int rar_store(unpack_data_t *unpack_data)
{
	unsigned int read_len;

	unp_read_buf(unpack_data, 0);
	rar_dbgmsg("current in_used %d\n", unpack_data->in_used);
	read_len = unpack_data->dest_unp_size;

	if (read_len > unpack_data->in_used)
	{
		read_len = unpack_data->in_used;
	}

	if (unp_write_data(unpack_data, unpack_data->in_buf + unpack_data->in_addr, read_len) != -1)
	{
		unpack_data->in_used -= read_len;
		unpack_data->in_addr += read_len;
		rar_dbgmsg("left pack %d unpack %d\n", unpack_data->pack_size, unpack_data->dest_unp_size);
		return RAR_OK;
	}
	else
	{
		rar_dbgmsg("FAILED left pack %d unpack %d\n", unpack_data->pack_size, unpack_data->dest_unp_size);
		return RAR_WRITE_BUFFER_NOT_ENOUGH;
	}
}

