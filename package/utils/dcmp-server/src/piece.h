/*
** piece.h
**
*/

#ifndef _PIECE_H_
#define _PIECE_H_

#define PL_ALLOC 					(1 << 0)
#define PL_ALLOC_DMA 				(1 << 1)
#define PL_MEMCPY_FROM_USER		(1 << 2)

typedef struct _piece_load_cb_s piece_load_cb_t;
struct _piece_load_cb_s
{
	int state;
	int piece_data_pos;
	unsigned char* piece_data;
	int piece_data_size;
	int target_pos;
	unsigned char* target;
	int target_size;
	unsigned short target_items;
	unsigned char piece_flag;
	unsigned char target_flag;
	void* priv_use;
	void (*free_priv_use)(piece_load_cb_t*);
};

static inline void
piece_load_pos_inc(piece_load_cb_t* pl, int offset)
{
	if (!pl) return;

	pl->piece_data_pos += offset;
	pl->target_pos += offset;
	return;
}

static inline int
piece_load_is_target_full(piece_load_cb_t* pl)
{
	if (!pl) return 1;

	return (pl->target_pos >= pl->target_size);
}

static inline int
piece_load_is_data_drained(piece_load_cb_t* pl)
{
	if (!pl) return 1;

	return (pl->piece_data_pos >= pl->piece_data_size);
}

static inline void
piece_load_data_reset(piece_load_cb_t* pl)
{
	if (!pl) return;

	if ((pl->piece_flag & PL_ALLOC) && pl->piece_data)
	{
		if (pl->piece_flag & PL_ALLOC_DMA)
			free_dma(pl->piece_data);
		else
			free(pl->piece_data);
	}

	pl->piece_data = NULL;
	pl->piece_data_size = 0;
	pl->piece_data_pos = 0;
	pl->piece_flag = 0;

	return ;
}

static inline int
piece_load_data_link(piece_load_cb_t* pl, unsigned char* data, int data_size)
{
	if (!pl || !data || !data_size) return -1;

	piece_load_data_reset(pl);

	pl->piece_data = data;
	pl->piece_data_size = data_size;
	pl->piece_data_pos = 0;
	return 0;
}

static inline int
piece_load_data_alloc(piece_load_cb_t* pl, const char __user * src, int src_size, int flag)
{
	unsigned char* p;
	int len = 0;

	if (!pl || !src || !src_size) return -1;

	piece_load_data_reset(pl);

	if (flag & PL_ALLOC_DMA)
		p = (unsigned char*)malloc_dma(src_size);
	else
		p = (unsigned char*)malloc(src_size);
	if (!p) return -1;

	if (flag & PL_MEMCPY_FROM_USER)
		len = _copy_from_user_(p, src, src_size);
	else
		MEMCPY(p, src, src_size);

	pl->piece_data = p;
	pl->piece_data_size = src_size;
	pl->piece_data_pos = 0;
	pl->piece_flag = (flag | PL_ALLOC);

	return 0;
}

static inline void
piece_load_target_reset(piece_load_cb_t* pl)
{
	if (!pl) return;

	if ((pl->target_flag & PL_ALLOC) && pl->target)
	{
		if (pl->target_flag & PL_ALLOC_DMA)
			free_dma(pl->target);
		else
			free(pl->target);
	}

	pl->target = NULL;
	pl->target_items = 0;
	pl->target_size = 0;
	pl->target_pos = 0;
	pl->target_flag = 0;

	return;
}

static inline int
piece_load_target_link(piece_load_cb_t* pl, unsigned char* target, int target_size)
{
	if (!pl || !target || !target_size) return -1;

	piece_load_target_reset(pl);

	pl->target = target;
	pl->target_items = 1;
	pl->target_size = target_size;
	pl->target_pos = 0;

	return 0;
}

static inline int
piece_load_target_alloc(piece_load_cb_t* pl, int target_items, int target_item_size, int flag)
{
	unsigned char* p;
	int size;
	if (!pl) return -1;

	size = target_items * target_item_size;
	if (flag & PL_ALLOC_DMA)
		p = (unsigned char*)malloc_dma(size);
	else
		p = (unsigned char*)malloc(size);

	if (!p) return -1;

	pl->target = p;
	pl->target_items = target_items;
	pl->target_size = size;
	pl->target_pos = 0;
	pl->target_flag = (flag | PL_ALLOC);

	return 0;
}

static inline int
piece_load_data_skip(piece_load_cb_t* pl, int skip_len)
{
	int piece_remain_len;
	if (!pl) return -1;

	piece_remain_len = pl->piece_data_size - pl->piece_data_pos;
	skip_len = (skip_len >= piece_remain_len) ? piece_remain_len : skip_len;
	pl->piece_data_pos += skip_len;

	return 0;
}

static inline int
piece_load_to_target(piece_load_cb_t* pl)
{
	int piece_remain_len;
	int target_remain_len;
	int fill_len;

	if (!pl || !pl->piece_data || !pl->piece_data_size ||
	        !pl->target || !pl->target_size ) return -1;

	piece_remain_len = pl->piece_data_size - pl->piece_data_pos;
	target_remain_len = pl->target_size - pl->target_pos;
	fill_len = (piece_remain_len <= target_remain_len) ? piece_remain_len : target_remain_len;
	MEMCPY(&pl->target[pl->target_pos], &pl->piece_data[pl->piece_data_pos], fill_len);
	piece_load_pos_inc(pl, fill_len);

	return 0;
}

static inline void
piece_load_exit(piece_load_cb_t* pl)
{
	if (pl && pl->free_priv_use)
	{
		(*pl->free_priv_use)(pl);
	}
	piece_load_target_reset(pl);
	piece_load_data_reset(pl);
	pl->state = 0;
}

static inline void
piece_load_init(piece_load_cb_t* pl)
{
	piece_load_exit(pl);
}

#endif /* _PIECE_H_ */

/* vi:set ts=4 sw=4: */
