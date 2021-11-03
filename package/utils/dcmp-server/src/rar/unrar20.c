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

#include <string.h>

#include "unrar.h"
#include "unrar20.h"
#include "../mymalloc.h"

void unpack_init_data20(int solid, unpack_data_t *unpack_data)
{
	rar2_var *rar2_data;

	if (!unpack_data->rar2_data)
	{
		unpack_data->rar2_data = malloc(sizeof(rar2_var));
	}

	rar2_data = unpack_data->rar2_data;

	if (!solid)
	{
		rar2_data->old_dist_ptr = 0;
		rar2_data->unp_channel_delta = 0;
		rar2_data->unp_cur_channel = 0;
		rar2_data->unp_channels = 1;
		memset(rar2_data->audv, 0, sizeof(rar2_data->audv));
		memset(rar2_data->unp_old_table20, 0, sizeof(rar2_data->unp_old_table20));
	}
}

static void copy_string20(unpack_data_t *unpack_data, unsigned int length, unsigned int distance)
{
	unsigned int dest_ptr;

	unpack_data->last_dist = unpack_data->old_dist[unpack_data->rar2_data->old_dist_ptr++ & 3] = distance;
	unpack_data->last_length = length;
	//unpack_data->dest_unp_size -= length;

	if (unpack_data->unp_ptr < distance)
	{
		rar_dbgmsg("......\n");
	}
	dest_ptr = unpack_data->unp_ptr - distance;
	if (dest_ptr < MAXWINSIZE - 300 && unpack_data->unp_ptr < MAXWINSIZE - 300)
	{
		unpack_data->window[unpack_data->unp_ptr++] = unpack_data->window[dest_ptr++];
		unpack_data->window[unpack_data->unp_ptr++] = unpack_data->window[dest_ptr++];
		while (length > 2)
		{
			length--;
			unpack_data->window[unpack_data->unp_ptr++] = unpack_data->window[dest_ptr++];
		}
	}
	else while (length--)
		{
			unpack_data->window[unpack_data->unp_ptr] = unpack_data->window[dest_ptr++ & MAXWINMASK];
			unpack_data->unp_ptr = (unpack_data->unp_ptr + 1) & MAXWINMASK;
		}
}

static int read_tables20(unpack_data_t *unpack_data)
{
	unsigned char bit_length[BC20];
	unsigned char table[MC20 * 4];
	int table_size, n, i, number;
	unsigned int bit_field;
	rar2_var *rar2_data = unpack_data->rar2_data;

	rar_dbgmsg("%s: enter.\n", __FUNCTION__);

	//unp_read_buf(unpack_data, unpack_data->pack_size);
	unp_read_buf(unpack_data, 0);
	if ((unpack_data->in_used < 500) && (unpack_data->pack_size > 0))
	{
		rar_dbgmsg("%s: No enough buffer for readtable20, in-used %d\n", __FUNCTION__, unpack_data->in_used);
		return FALSE;
	}

	bit_field = getbits(unpack_data);
	rar2_data->unp_audio_block = (bit_field & 0x8000);

	if (!(bit_field & 0x4000))
	{
		memset(rar2_data->unp_old_table20, 0, sizeof(rar2_data->unp_old_table20));
	}
	addbits(unpack_data, 2);

	if (rar2_data->unp_audio_block)
	{
		rar2_data->unp_channels = ((bit_field >> 12) & 3) + 1;
		if (rar2_data->unp_cur_channel >= rar2_data->unp_channels)
		{
			rar2_data->unp_cur_channel = 0;
		}
		addbits(unpack_data, 2);
		table_size = MC20 * rar2_data->unp_channels;
	}
	else
	{
		table_size = NC20 + DC20 + RC20;
	}
	rar_dbgmsg("%s: table size is %d\n", __FUNCTION__, table_size);

	for (i = 0 ; i < BC20 ; i++)
	{
		bit_length[i] = (unsigned char) (getbits(unpack_data) >> 12);
		addbits(unpack_data, 4);
	}
	make_decode_tables(bit_length, (struct Decode *)&unpack_data->BD, BC20);
	i = 0;
	while (i < table_size)
	{
		if (unpack_data->in_used < 5)
		{
			//if (!unp_read_buf(unpack_data, unpack_data->pack_size)) {
			if (!unp_read_buf(unpack_data, 0))
			{
				rar_dbgmsg("No enough buffer for readtable20 Step2\n");
				return FALSE;
			}
		}
		number = decode_number(unpack_data, (struct Decode *) & unpack_data->BD);
		if (number < 16)
		{
			table[i] = (number + rar2_data->unp_old_table20[i]) & 0xf;
			i++;
		}
		else if (number == 16)
		{
			n = (getbits(unpack_data) >> 14) + 3;
			addbits(unpack_data, 2);
			while ((n-- > 0) && (i < table_size))
			{
				table[i] = table[i-1];
				i++;
			}
		}
		else
		{
			if (number == 17)
			{
				n = (getbits(unpack_data) >> 13) + 3;
				addbits(unpack_data, 3);
			}
			else
			{
				n = (getbits(unpack_data) >> 9) + 11;
				addbits(unpack_data, 7);
			}
			while ((n-- > 0) && (i < table_size))
			{
				table[i++] = 0;
			}
		}
	}
	if (unpack_data->in_used == 0)
	{
//		return TRUE;
		rar_dbgmsg("ERROR: read_tables check failed\n");
		return FALSE;

	}
	if (rar2_data->unp_audio_block)
	{
		for (i = 0 ; i < rar2_data->unp_channels ; i++)
		{
			make_decode_tables(&table[i*MC20], (struct Decode *)&rar2_data->MD[i], MC20);
		}
	}
	else
	{
		make_decode_tables(&table[0], (struct Decode *)&unpack_data->LD, NC20);
		make_decode_tables(&table[NC20], (struct Decode *)&unpack_data->DD, DC20);
		make_decode_tables(&table[NC20+DC20], (struct Decode *)&unpack_data->RD, RC20);
	}
	memcpy(rar2_data->unp_old_table20, table, sizeof(rar2_data->unp_old_table20));
	rar_dbgmsg("read_table20 OK\n");

	return TRUE;
}


static unsigned char decode_audio(unpack_data_t *unpack_data, int delta)
{
	rar2_var *rar2_data = unpack_data->rar2_data;
	struct AudioVariables *v;
	int pch, d, i;
	unsigned int ch, mindif, num_min_dif;

	v = &rar2_data->audv[rar2_data->unp_cur_channel];
	v->byte_count++;
	v->D4 = v->D3;
	v->D3 = v->D2;
	v->D2 = v->last_delta - v->D1;
	v->D1 = v->last_delta;

	pch = 8 * v->last_char + v->K1 * v->D1 + v->K2 * v->D2 + v->K3 *
	      v->D3 + v->K4 * v->D4 + v->K5 * rar2_data->unp_channel_delta;
	pch = (pch >> 3) & 0xff;

	ch = pch - delta;

	d = ((signed char) delta) << 3;

	v->dif[0] += abs(d);
	v->dif[1] += abs(d - v->D1);
	v->dif[2] += abs(d + v->D1);
	v->dif[3] += abs(d - v->D2);
	v->dif[4] += abs(d + v->D2);
	v->dif[5] += abs(d - v->D3);
	v->dif[6] += abs(d + v->D3);
	v->dif[7] += abs(d - v->D4);
	v->dif[8] += abs(d + v->D4);
	v->dif[9] += abs(d - rar2_data->unp_channel_delta);
	v->dif[10] += abs(d + rar2_data->unp_channel_delta);

	rar2_data->unp_channel_delta = v->last_delta = (signed char) (ch - v->last_char);
	v->last_char = ch;

	if ((v->byte_count & 0x1f) == 0)
	{
		mindif = v->dif[0];
		num_min_dif = 0;
		v->dif[0] = 0;
		for (i = 1 ; i < 11 ; i++)
		{
			if (v->dif[i] < mindif)
			{
				mindif = v->dif[i];
				num_min_dif = i;
			}
			v->dif[i] = 0; /* ?????? looks wrong to me */
		}
		switch (num_min_dif)
		{
		case 1:
			if (v->K1 >= -16)
			{
				v->K1--;
			}
			break;
		case 2:
			if (v->K1 < 16)
			{
				v->K1++;
			}
			break;
		case 3:
			if (v->K2 >= -16)
			{
				v->K2--;
			}
			break;
		case 4:
			if (v->K2 < 16)
			{
				v->K2++;
			}
			break;
		case 5:
			if (v->K3 >= -16)
			{
				v->K3--;
			}
			break;
		case 6:
			if (v->K3 < 16)
			{
				v->K3++;
			}
			break;
		case 7:
			if (v->K4 >= -16)
			{
				v->K4--;
			}
			break;
		case 8:
			if (v->K4 < 16)
			{
				v->K4++;
			}
			break;
		case 9:
			if (v->K5 >= -16)
			{
				v->K5--;
			}
			break;
		case 10:
			if (v->K5 < 16)
			{
				v->K5++;
			}
			break;
		}
	}
	return ((unsigned char) ch);
}


int rar_unpack20_state(unpack_data_t *unpack_data)
{
	int ret = RAR_OK;

	rar_dbgmsg("%s: unpack_state %d\n", __FUNCTION__, unpack_data->unpack_state);
	if (unpack_data->unpack_state == UNPACK20_STATE_READ_FIRST_TABLE)
	{

		if (!read_tables20(unpack_data))
		{
			if (unpack_data->rar_error)
			{
				rar_dbgmsg("unpack_data->rar_error %x\n",
				           unpack_data->rar_error);
				return unpack_data->rar_error;
			}
			else
			{
				rar_dbgmsg("read buffer not enough\n");
				return RAR_READ_BUFFER_NOT_ENOUGH;
			}
		}
		unpack_data->tables_read = TRUE;
		unpack_data->unpack_state = UNPACK20_STATE_DECODE;
		//--unpack_data->dest_unp_size;

	}
	else if (unpack_data->unpack_state == UNPACK20_STATE_READ_TABLE)
	{

		if (!read_tables20(unpack_data))
		{
			if (unpack_data->rar_error)
			{
				rar_dbgmsg("1, unpack_data->rar_error %x\n",
				           unpack_data->rar_error);
				return unpack_data->rar_error;
			}
			else
			{
				rar_dbgmsg("1, read buffer not enough\n");
				return RAR_READ_BUFFER_NOT_ENOUGH;
			}
		}
		unpack_data->tables_read = TRUE;
		unpack_data->unpack_state = UNPACK20_STATE_DECODE;
	}
	else
	{
		ret = rar_unpack20(unpack_data);
//        unp_write_buf_old(unpack_data);

		if (unpack_data->dest_unp_size == 0)
		{
			unpack_data->unpack_state = UNPACK20_STATE_READ_LAST_TABLE;

		}
		else if (!unpack_data->tables_read)
		{
			unpack_data->unpack_state = UNPACK20_STATE_READ_TABLE;
		}
	}
	return ret;
}

int rar_unpack20(unpack_data_t *unpack_data)
{
	int ret = RAR_OK;
	unsigned int bits, distance;
	int audio_number, number, length, dist_number, length_number;
	rar2_var *rar2_data = unpack_data->rar2_data;


	rar_dbgmsg("in rar_unpack20 in_used = %d, avail_in = %d, left_pack %d\n",
	           unpack_data->in_used, unpack_data->avail_in,
	           unpack_data->pack_size);


	while (unpack_data->dest_unp_size >= 0)
	{

		rar_dbgmsg("dest_unp_size = %ld\n", unpack_data->dest_unp_size);
		unpack_data->unp_ptr &= MAXWINMASK;


		if (unpack_data->in_used < 30)
		{
			rar_dbgmsg("::in used %d, file packet size %d\n", unpack_data->in_used , unpack_data->pack_size);
			//unp_read_buf(unpack_data, unpack_data->pack_size);
			unp_read_buf(unpack_data, 0);

			if ((unpack_data->in_used < 30) && (unpack_data->pack_size > 0))
			{
				rar_dbgmsg("unp_read_buf 2 failed\n");
				ret = RAR_READ_BUFFER_NOT_ENOUGH;
				return ret;
			}
		}

		rar_dbgmsg("OO:unpack_data->wr_ptr=%d unpack_data->unp_ptr=%d\n", unpack_data->wr_ptr, unpack_data->unp_ptr);
		if (((unpack_data->unp_ptr - unpack_data->wr_ptr) & MAXWINMASK) == unpack_data->dest_unp_size)
		{
			if (unp_write_buf_old(unpack_data) == -1)
			{
				rar_dbgmsg("Write buffer not enough\n");
				return RAR_WRITE_BUFFER_NOT_ENOUGH;
			}
			break;
		}
		if (((unpack_data->unp_ptr - unpack_data->wr_ptr) & MAXWINMASK) > 270 &&
		        (unpack_data->wr_ptr != unpack_data->unp_ptr))
		{
			if (unp_write_buf_old(unpack_data) == -1)
			{
				rar_dbgmsg("Write buffer not enough\n");
				return RAR_WRITE_BUFFER_NOT_ENOUGH;
			}
			if (unpack_data->outbuf_full)
			{
				rar_dbgmsg("OUT BUFFER exit\n");
				return RAR_WRITE_BUFFER_NOT_ENOUGH;
			}
		}


		if (rar2_data->unp_audio_block)
		{
			rar_dbgmsg("AUDIO block..\n");
			audio_number = decode_number(unpack_data,
			                             (struct Decode *) & rar2_data->MD[rar2_data->unp_cur_channel]);
			if (audio_number == 256)
			{
				unpack_data->tables_read = FALSE;
				break;
			}
			unpack_data->window[unpack_data->unp_ptr++] =
			    decode_audio(unpack_data, audio_number);
			if (++rar2_data->unp_cur_channel == rar2_data->unp_channels)
			{
				rar2_data->unp_cur_channel = 0;
			}
			//--unpack_data->dest_unp_size;
			continue;
		}

		number = decode_number(unpack_data, (struct Decode *) & unpack_data->LD);
		rar_dbgmsg("%s: decode = %d\n", __FUNCTION__, number);
		if (number < 256)
		{
			unpack_data->window[unpack_data->unp_ptr++] = (unsigned char) number;
			//--unpack_data->dest_unp_size;
			continue;
		}
		if (number > 269)
		{
			length = ldecode[number-=270] + 3;
			if ((bits = lbits[number]) > 0)
			{
				length += getbits(unpack_data) >> (16 - bits);
				addbits(unpack_data, bits);
			}

			dist_number = decode_number(unpack_data, (struct Decode *) & unpack_data->DD);
			distance = ddecode[dist_number] + 1;
			if ((bits = dbits[dist_number]) > 0)
			{
				distance += getbits(unpack_data) >> (16 - bits);
				addbits(unpack_data, bits);
			}

			if (distance >= 0x2000)
			{
				length++;
				if (distance >= 0x40000L)
				{
					length++;
				}
			}

			copy_string20(unpack_data, length, distance);
			continue;
		}
		if (number == 269)
		{
			rar_dbgmsg("Read new table\n");
			unpack_data->tables_read = FALSE;
			break;
		}
		if (number == 256)
		{
			copy_string20(unpack_data, unpack_data->last_length, unpack_data->last_dist);
			continue;
		}
		if (number < 261)
		{
			distance = unpack_data->old_dist[(rar2_data->old_dist_ptr-(number-256)) & 3];
			length_number = decode_number(unpack_data, (struct Decode *) & unpack_data->RD);
			length = ldecode[length_number] + 2;
			if ((bits = lbits[length_number]) > 0)
			{
				length += getbits(unpack_data) >> (16 - bits);
				addbits(unpack_data, bits);
			}
			if (distance >= 0x101)
			{
				length++;
				if (distance >= 0x2000)
				{
					length++;
					if (distance >= 0x40000)
					{
						length++;
					}
				}
			}
			copy_string20(unpack_data, length, distance);
			continue;
		}
		if (number < 270)
		{
			distance = sddecode[number-=261] + 1;
			if ((bits = sdbits[number]) > 0)
			{
				distance += getbits(unpack_data) >> (16 - bits);
				addbits(unpack_data, bits);
			}
			copy_string20(unpack_data, 2, distance);
			continue;
		}
	}
	if (unpack_data->dest_unp_size == 0)
	{
		rar_dbgmsg("DEST_UNP_SIZE = %d pack lefti = %d\n",
		           unpack_data->dest_unp_size,
		           unpack_data->pack_size);
		unp_read_buf(unpack_data, 0);
		if (unpack_data->in_used >= 5)
		{
			if (rar2_data->unp_audio_block)
			{
				if (decode_number(unpack_data,
				                  (struct Decode *)&rar2_data->MD[rar2_data->unp_cur_channel]) == 256)
				{
					unpack_data->tables_read = FALSE;
				}
			}
			else if (decode_number(unpack_data, (struct Decode *)&unpack_data->LD) == 269)
			{
				unpack_data->tables_read = FALSE;
			}
		}
	}
	return ret;
}
