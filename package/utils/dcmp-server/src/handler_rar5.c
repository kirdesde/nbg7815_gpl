/*
** Handling RAR format
*/

#ifdef DECOMP_MODULE_RAR5

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>

#include "dpu.h"
#include "rar5/unrar5.h"
#include "mymalloc.h"

#define UNRAR5_STATE_READ_HEAD               0x00
#define UNRAR5_STATE_WAIT_FLUSH_OUT          0x01
#define UNRAR5_STATE_UNPACK_FILE_PRECHECK    0x02
#define UNRAR5_STATE_UNPACK_FILE_STORE       0x04
#define UNRAR5_STATE_UNPACK_FILE_UNPACK29    0x08
#define UNRAR5_STATE_UNPACK_FILE_UNPACK20    0x10
#define UNRAR5_STATE_UNPACK_FILE_UNPACK15    0x20

extern int print_switch;

static int rar5_begin;
static int rar5_end;
static int rar5_session_num;
static unsigned int rar5_in_buffer_size;
static unsigned int rar5_out_buffer_size;

unsigned int rar5_opened_bitmap = 0;

struct rar5_data  *rar5_session = NULL;
struct rar5_thread rar5_threads = {0};

static int check_rar5_session_range(int session_id)
{
	if ((session_id >= rar5_begin) && (session_id <= rar5_end))
	{
		/* The session_id is in valid range */
		return 0;
	}

	/* The session_id is invalid */
	return 1;
}

void dump_RAR5_structure(int session_id)
{
	struct rar5_data *rar5_sess;

	/* check sid range */
	if (check_rar5_session_range(session_id) != 0)
	{
		fprintf(stderr, "Invalid session_id for RAR\n");
		return;
	}

	rar5_sess = &(rar5_session[session_id - rar5_begin]);
	fprintf(stderr, "avail_in %d, avail_out %d \n", rar5_sess->in_buffer_len, rar5_sess->out_buffer_len);
}

int rar5_session_update(int status_bitmap)
{
	int i;

	status_bitmap &= rar5_opened_bitmap;
	for (i = 0; i < rar5_session_num; i++)
	{
		if (!(status_bitmap & (1 << i)))
		{
			if (rar5_session[i].in_buffer)
			{
				free(rar5_session[i].in_buffer);
			}

			rar5_session[i].flag = 0;
			rar5_session[i].in_buffer_len = 0;
			rar5_session[i].out_buffer_len = 0;
			rar5_opened_bitmap &= ~(1 << i);
		}
	}

	return 0;
}

static int is_rar5_archive(unsigned char *buf)
{
	const unsigned char rar5_signature[] = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00};

	if (memcmp(buf, rar5_signature, RAR5_SIZEOF_MARKHEAD) == 0)
	{
		return TRUE;
	}

	rar_dbgmsg("Not a rar5 archive\n");
	return FALSE;
}

void *urar5_thread(void *arg)
{
	int session_id = *(int*)arg;
	int thread_id = session_id - rar5_begin;

	uint64_t size = 0;
	uint64_t len;

	char initial = 1;

	dmc_unrar_archive a, *archive;
	struct rar5_data *rar5_sess = &(rar5_session[thread_id]);

	unsigned char uncompressed[32];
	uint64_t uncompressed_size;

	unsigned char *mem = NULL;
	unsigned char *tmp = NULL;

	pthread_t pid = pthread_self();
	pthread_detach(pid);

	dmc_unrar_archive_init(&a);
	archive = &a;

	/* loop thread */
	while (1)
	{
		/* Wait permission to exec thread */
		pthread_mutex_lock(&rar5_threads.wlock[thread_id]);
		while (!rar5_threads.wcount[thread_id])
		{
			pthread_cond_wait(&rar5_threads.wcv[thread_id], &rar5_threads.wlock[thread_id]);
		}
		rar5_threads.wcount[thread_id] = 0;
		pthread_mutex_unlock(&rar5_threads.wlock[thread_id]);

		if (rar5_sess->used == 0)
		{
			goto EXT;
		}

		if ((size + rar5_sess->in_buffer_len) > rar5_in_buffer_size)
		{
			//fprintf(stdout, "over buffer limit\n");
			//fflush(stdout);
			rar5_sess->flag |= LC_DECOMPSERVER_DATA_ERROR;
			goto ERR;
		}

		tmp = realloc(mem, size + rar5_sess->in_buffer_len);
		if (tmp == NULL)
		{
			rar5_sess->flag |= LC_DECOMPSERVER_DATA_ERROR;
			goto ERR;
		}

		mem = tmp;
		len = rar5_sess->in_buffer_len;
		memcpy(mem + size, rar5_sess->in_buffer, len);
		size += len;

		/* Step 1: INITIAL */
		if (initial)
		{
			int generation;
			dmc_unrar_return alloc_check;

			/* Initialize allocators */
			alloc_check = dmc_unrar_archive_check_alloc(&archive->alloc);
			if (alloc_check != DMC_UNRAR_OK)
			{
				rar5_sess->flag |= LC_DECOMPSERVER_DATA_ERROR;
				goto ERR;
			}

			/* Allocate and initialize a simple memory reader. */
			dmc_unrar_mem_reader *mem_reader = (dmc_unrar_mem_reader *) dmc_unrar_malloc(&archive->alloc, 1, sizeof(dmc_unrar_mem_reader));
			if (mem_reader == NULL)
			{
				rar5_sess->flag |= LC_DECOMPSERVER_DATA_ERROR;
				goto ERR;
			}

			/* dmc_unrar_archive_open() */
			dmc_unrar_io_init_mem_reader(&archive->io, mem_reader, mem, 19589);
			archive->io.offset = 0;
			archive->io.size = 19589;

			/* Get archive file state */
			archive->internal_state = (dmc_unrar_internal_state *) dmc_unrar_malloc(&archive->alloc, 1, sizeof(dmc_unrar_internal_state));
			if (archive->internal_state == NULL)
			{
				rar5_sess->flag |= LC_DECOMPSERVER_DATA_ERROR;
				goto ERR;
			}

			/* Allocate rar context */
			DMC_UNRAR_CLEAR_OBJ(*archive->internal_state);
			archive->internal_state->unpack_context = dmc_unrar_rar_context_alloc(&archive->alloc);
			if (!archive->internal_state->unpack_context)
			{
				rar5_sess->flag |= LC_DECOMPSERVER_DATA_ERROR;
				goto ERR;
			}

			/* Identify the RAR generation (RAR4? RAR5?) */
			generation = dmc_unrar_identify_generation(&archive->io);
			if (generation < 0)
			{
				rar5_sess->flag |= LC_DECOMPSERVER_DATA_ERROR;
				goto ERR;
			}

			/* Not a RAR file? */
			archive->internal_state->generation = (dmc_unrar_generation)generation;
			if (archive->internal_state->generation == DMC_UNRAR_GENERATION_INVALID)
			{
				rar5_sess->flag |= LC_DECOMPSERVER_INVALID_METHOD;
				goto ERR;
			}

			/* Ancient RAR 1.3. We don't support it */
			if (archive->internal_state->generation == DMC_UNRAR_GENERATION_ANCIENT)
			{
				rar5_sess->flag |= LC_DECOMPSERVER_NOT_SUPPORT;
				goto ERR;
			}

			if (!(archive->internal_state->generation == DMC_UNRAR_GENERATION_RAR5))
			{
				rar5_sess->flag |= LC_DECOMPSERVER_NOT_SUPPORT;
				goto ERR;
			}

			/* Initialize the block and file arrays */
			if (!dmc_unrar_init_internal_blocks(archive))
			{
				rar5_sess->flag |= LC_DECOMPSERVER_DATA_ERROR;
				goto ERR;
			}
			if (!dmc_unrar_init_internal_files(archive))
			{
				rar5_sess->flag |= LC_DECOMPSERVER_DATA_ERROR;
				goto ERR;
			}

			/* Initial done */
			initial = 0;
		}

		/* Step 2 : UNRAR5
		 *  (Run through the archive to collect all blocks and files)
		 */
		if (archive->internal_state->generation == DMC_UNRAR_GENERATION_RAR4)
		{
			/* SKIP!!!! */
			/*dmc_unrar_rar4_collect_blocks */
			continue;
		}

		/* dmc_unrar_rar5_collect_blocks */
		uint64_t offset;

		/* loop file */
		while (archive->io.offset < size)
		{
			dmc_unrar_mem_reader *mem_reader = (dmc_unrar_mem_reader *)archive->io.opaque;

			dmc_unrar_block_header block = {0};
			dmc_unrar_file_block file = {0};

			dmc_unrar_return read_block, read_file;

			offset = archive->io.offset;
			size -= offset;

			memmove(mem, mem + offset, size);
			mem_reader->buffer = mem;
			mem_reader->size = size;
			mem_reader->offset = 0;

			offset = 0;
			archive->io.offset = 0;
			archive->io.size = size;

			/* Read the block. */
			if (rar5_sess->wait == 0)
			{
				read_block = dmc_unrar_rar5_read_block_header(archive, &block);
				if (read_block != DMC_UNRAR_OK)
				{
					break;
				}

				/* It's an ending marker, so we're done. */
				if (block.type == DMC_UNRAR_BLOCK5_TYPE_END)
				{
					goto EXT;
				}

				/* Check if we have all block data */
				if ((block.start_pos + block.header_size) > size)
				{
					break;
				}

				if (rar5_sess->head &&
					(block.start_pos + block.header_size + block.data_size) > size)
				{
					break;
				}

				rar5_sess->wait = (block.start_pos + block.header_size + block.data_size);
				rar5_sess->head = 1;

				/* It's a file. */
				if (block.type == DMC_UNRAR_BLOCK5_TYPE_FILE)
				{
					/* Read the rest of the file header. */
					read_file = dmc_unrar_rar5_read_file_header(archive, &block, &file);
					if (read_file != DMC_UNRAR_OK)
					{
						rar5_sess->flag |= LC_DECOMPSERVER_DATA_ERROR;
						goto ERR;
					}

					if (file.is_encrypted == 0 && file.is_solid == 0 && file.is_split == 0 &&
						(file.file.compressed_size != 0) &&
						(file.file.uncompressed_size != 0) &&
						(file.file.uncompressed_size < rar5_out_buffer_size) &&
						(file.file.uncompressed_size / file.file.compressed_size < 1024))
					{
						//fprintf(stdout, "skip due to file size\n");
						//fflush(stdout);
						rar5_sess->wait = 0;
					}
				}
			}

			if (rar5_sess->wait)
			{
				//printf("file wait\n");

				if (rar5_sess->wait > size)
				{
					rar5_sess->wait -= size;

					offset = 0;
					size = 0;

					archive->io.offset = 0;
					archive->io.size = 0;

					break;
				}

				archive->io.offset = rar5_sess->wait;

				rar5_sess->wait = 0;
				rar5_sess->head = 0;

				continue;
			}

			if ((block.start_pos + block.header_size + block.data_size) > size)
			{
				break;
			}

			/* extract file */
			{
				uint32_t crc = 0;

				file.my_sess = rar5_sess;
				file.my_id   = thread_id;

				rar5_sess->filename = mem + file.name_offset;
				rar5_sess->filename_len = file.name_size;

				switch (file.method)
				{
				case DMC_UNRAR_METHOD_STORE:
					read_file = dmc_unrar_file_unstore(archive, &file, uncompressed, rar5_out_buffer_size,
							(size_t *)&uncompressed_size, &crc, NULL, &dmc_unrar_extract_callback_mem);
					break;

				case DMC_UNRAR_METHOD_FASTEST:
				case DMC_UNRAR_METHOD_FAST:
				case DMC_UNRAR_METHOD_NORMAL:
				case DMC_UNRAR_METHOD_GOOD:
				case DMC_UNRAR_METHOD_BEST:
					read_file = dmc_unrar_file_unpack(archive, &file, uncompressed, rar5_out_buffer_size,
							(size_t *)&uncompressed_size, &crc, NULL, &dmc_unrar_extract_callback_mem);
					break;

				default:
					rar5_sess->flag |= LC_DECOMPSERVER_DATA_ERROR;
					goto ERR;
				}

				if (read_file != DMC_UNRAR_OK)
				{
					rar5_sess->flag |= LC_DECOMPSERVER_DATA_ERROR;
					goto ERR;
				}
			}

			if (rar5_sess->used == 0)
			{
				goto ERR;
			}

			/* Seek past this block, so we can read the next one. */
			dmc_unrar_archive_seek(&archive->io, block.start_pos + block.header_size + block.data_size);
			rar5_sess->head = 0;
		}

		// data not_enough
		{
			rar5_sess->flag |= LC_DECOMPSERVER_FLG_RX_NOT_ENOUGH;

			pthread_mutex_lock(&rar5_threads.rlock[thread_id]);
			rar5_threads.rcount[thread_id] = 1;
			pthread_cond_signal(&rar5_threads.rcv[thread_id]);
			pthread_mutex_unlock(&rar5_threads.rlock[thread_id]);

			dmc_unrar_archive_seek(&archive->io, offset);
		}
	}

EXT:
	rar5_sess->flag |= LC_DECOMPSERVER_FLG_FILE_END;
ERR:
	/* memory collection */
	if (mem)
	{
		free(mem);
		mem = NULL;
	}

	rar5_sess->used = 0;

	pthread_mutex_lock(&rar5_threads.rlock[thread_id]);
	rar5_threads.rcount[thread_id] = 1;
	pthread_cond_signal(&rar5_threads.rcv[thread_id]);
	pthread_mutex_unlock(&rar5_threads.rlock[thread_id]);

	dmc_unrar_archive_close(&a);

	pthread_exit(NULL);
	return NULL;
}

void rar5_session_collocation(int thread_id, struct rar5_data *rar5_sess)
{
	if (rar5_sess->used == 1)
	{
		/* send signal to kill thread */
		rar5_sess->used = 0;

		pthread_mutex_lock(&rar5_threads.wlock[thread_id]);
		rar5_threads.wcount[thread_id] = 1;
		pthread_cond_signal(&rar5_threads.wcv[thread_id]);
		pthread_mutex_unlock(&rar5_threads.wlock[thread_id]);

		/* check wait */
		pthread_mutex_lock(&rar5_threads.rlock[thread_id]);
		while (!rar5_threads.rcount[thread_id])
		{
			pthread_cond_wait(&rar5_threads.rcv[thread_id], &rar5_threads.rlock[thread_id]);
		}
		rar5_threads.rcount[thread_id] = 0;
		pthread_mutex_unlock(&rar5_threads.rlock[thread_id]);
	}
}

int rar5_session_open(int session_id)
{
	decomp_session *ss;
	struct rar5_data *rar5_sess;

	int ret, thread_id;
	int r;

	if (!rar5_session)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}

	if (check_rar5_session_range(session_id))
	{
		return LC_DECOMP_ERR_INVALID_SID;
	}

	/* for open, make sure we have magic cookie len */
	ss = &(sess[session_id]);
	if (ss->avail_in < RAR5_SIZEOF_MARKHEAD)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}

	/* Make sure we have right magic cookie */
	ret = is_rar5_archive(ss->next_in);
	if (ret == RAR5_READ_UNMATCHED_MAGIC_COOKIE)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}

	/* global session */
	ss->file_state = UNRAR5_STATE_READ_HEAD;

	/* rar5 session */
	thread_id = session_id - rar5_begin;
	rar5_sess = &(rar5_session[thread_id]);

	rar5_session_collocation(thread_id, rar5_sess);

	memset(rar5_sess, 0, sizeof(struct rar5_data));

	/* create thread */
	rar5_threads.session_id[thread_id] = session_id;
	if((r = pthread_create(&rar5_threads.thread[thread_id], NULL, &urar5_thread, &rar5_threads.session_id[thread_id])) != 0)
	{
		return LC_DECOMPSERVER_DATA_ERROR;
	}

	rar5_sess->used = 1;
	return LC_DECOMPSERVER_OK;
}

int rar5_session_decomp(int session_id)
{
	int thread_id;
	int ret = LC_DECOMPSERVER_OK;

	decomp_session *ss;
	struct rar5_data *rar5_sess;

	if (check_rar5_session_range(session_id))
	{
		ret = LC_DECOMPSERVER_INVALID_SID;
		return ret;
	}

	ss = &(sess[session_id]);
	ss->flag = 0;

	thread_id = session_id - rar5_begin;
	rar5_sess = &(rar5_session[thread_id]);

	if (rar5_sess->used != 1)
	{
		goto ERR;
	}

	rar5_threads.wcount[thread_id] = 0;
	rar5_threads.rcount[thread_id] = 0;

	/* Start to decomp */
	rar5_sess->in_buffer = ss->next_in;
	rar5_sess->in_buffer_len = ss->avail_in;

	rar5_sess->out_buffer = NULL;
	rar5_sess->out_buffer_len = 0;

	rar5_sess->filename = NULL;
	rar5_sess->filename_len = 0;

	rar5_sess->used = 1;
	rar5_sess->flag = 0;

	/* send signal to triger rar5 decomp */
	pthread_mutex_lock(&rar5_threads.wlock[thread_id]);
	rar5_threads.wcount[thread_id] = 1;
	pthread_cond_signal(&rar5_threads.wcv[thread_id]);
	pthread_mutex_unlock(&rar5_threads.wlock[thread_id]);

	/* check wait */
	pthread_mutex_lock(&rar5_threads.rlock[thread_id]);
	while (!rar5_threads.rcount[thread_id])
	{
		pthread_cond_wait(&rar5_threads.rcv[thread_id], &rar5_threads.rlock[thread_id]);
	}
	rar5_threads.rcount[thread_id] = 0;
	pthread_mutex_unlock(&rar5_threads.rlock[thread_id]);

	/* copy output buffer */
	ss->avail_in = 0;		// input buffer is consumed to zero
	ss->file_count = rar5_sess->file_count;
	ss->flag = rar5_sess->flag;
	ss->avail_out = TX_BUFFER_LEN;

	if (rar5_sess->out_buffer_len)
	{
		unsigned int shift_len = 0;

		if (rar5_sess->flag & LC_DECOMPSERVER_FLG_FILE_BEGIN && rar5_sess->filename_len)
		{
			unsigned int zero = 0;
			u16 filename_len;

			if (rar5_sess->filename_len > 256)
			{
				filename_len = 256;
				memcpy(ss->next_out + 0, &zero, 4);
				memcpy(ss->next_out + 4, &filename_len, 4);
				memcpy(ss->next_out + 6, rar5_sess->filename + rar5_sess->filename_len - 256, 256);
			}
			else
			{
				filename_len = rar5_sess->filename_len;
				memcpy(ss->next_out + 0, &zero, 4);
				memcpy(ss->next_out + 4, &filename_len, 4);
				memcpy(ss->next_out + 6, rar5_sess->filename, rar5_sess->filename_len);
			}

			ss->flag |= LC_DECOMPSERVER_FLG_HAS_FILENAME;

			shift_len = filename_len + 6;
		}

		memcpy(ss->next_out + shift_len, rar5_sess->out_buffer, rar5_sess->out_buffer_len);
		ss->avail_out = TX_BUFFER_LEN - (shift_len + rar5_sess->out_buffer_len);
	}

	return LC_DECOMPSERVER_OK;


ERR:
	ss->avail_in = 0;
	ss->avail_out = TX_BUFFER_LEN;
	ss->flag = LC_DECOMPSERVER_FLG_FILE_END;
	return ret;
}

void rar5_exit()
{
	if (rar5_threads.thread)
		free(rar5_threads.thread);
	if (rar5_threads.rlock)
		free(rar5_threads.rlock);
	if (rar5_threads.wlock)
		free(rar5_threads.wlock);
	if (rar5_threads.rcv)
		free(rar5_threads.rcv);
	if (rar5_threads.wcv)
		free(rar5_threads.wcv);
	if (rar5_threads.rcount)
		free(rar5_threads.rcount);
	if (rar5_threads.wcount)
		free(rar5_threads.wcount);
	if (rar5_threads.session_id)
		free(rar5_threads.session_id);
	if (rar5_session)
		free(rar5_session);

	rar5_session = NULL;
	memset(&rar5_threads, 0, sizeof(struct rar5_thread));
}

int rar5_init (int session_num, int begin, unsigned int in_buffer_size, unsigned int out_buffer_size)
{
	int i;

	if (rar5_session)
	{
		return 0;
	}

	/* init session */
	rar5_begin = begin;
	rar5_end  = begin + session_num - 1;
	rar5_session_num = session_num;
	rar5_in_buffer_size = in_buffer_size;
	rar5_out_buffer_size = out_buffer_size;


	memset(&rar5_threads, 0, sizeof(struct rar5_thread));

	rar5_session = (struct rar5_data *)malloc(sizeof(struct rar5_data) * rar5_session_num);
	if (rar5_session == NULL)
	{
		return -1;
	}
	memset(rar5_session, 0, sizeof (struct rar5_data) * rar5_session_num);

	/* init thread */
	rar5_threads.num = rar5_session_num;
	rar5_threads.thread = malloc(sizeof(pthread_t) * rar5_session_num);
	if (rar5_threads.thread == NULL)
	{
		goto ERR;
	}

	rar5_threads.rlock = malloc(sizeof(pthread_mutex_t) * rar5_session_num);
	if (rar5_threads.rlock == NULL)
	{
		goto ERR;
	}
	rar5_threads.wlock = malloc(sizeof(pthread_mutex_t) * rar5_session_num);
	if (rar5_threads.wlock == NULL)
	{
		goto ERR;
	}
	rar5_threads.rcv = malloc(sizeof(pthread_cond_t) * rar5_session_num);
	if (rar5_threads.rcv == NULL)
	{
		goto ERR;
	}
	rar5_threads.wcv = malloc(sizeof(pthread_cond_t) * rar5_session_num);
	if (rar5_threads.wcv == NULL)
	{
		goto ERR;
	}
	rar5_threads.rcount = malloc(sizeof(int) * rar5_session_num);
	if (rar5_threads.rcount == NULL)
	{
		goto ERR;
	}
	rar5_threads.wcount = malloc(sizeof(int) * rar5_session_num);
	if (rar5_threads.wcount == NULL)
	{
		goto ERR;
	}
	rar5_threads.session_id = malloc(sizeof(int) * rar5_session_num);
	if (rar5_threads.session_id == NULL)
	{
		goto ERR;
	}

	memset(rar5_threads.thread, 0, sizeof(pthread_t)       * rar5_session_num);
	memset(rar5_threads.rlock,  0, sizeof(pthread_mutex_t) * rar5_session_num);
	memset(rar5_threads.wlock,  0, sizeof(pthread_mutex_t) * rar5_session_num);
	memset(rar5_threads.rcv,    0, sizeof(pthread_cond_t)  * rar5_session_num);
	memset(rar5_threads.wcv,    0, sizeof(pthread_cond_t)  * rar5_session_num);

	memset(rar5_threads.rcount, 0, sizeof(int) * rar5_session_num);
	memset(rar5_threads.wcount, 0, sizeof(int) * rar5_session_num);
	memset(rar5_threads.session_id, 0, sizeof(int) * rar5_session_num);

	for (i = 0; i < rar5_session_num; i++)
	{
		pthread_mutex_init(&rar5_threads.rlock[i], NULL);
		pthread_mutex_init(&rar5_threads.wlock[i], NULL);

		pthread_cond_init(&rar5_threads.rcv[i], NULL);
		pthread_cond_init(&rar5_threads.wcv[i], NULL);
	}

	return 0;

ERR:
	if (rar5_threads.thread)
		free(rar5_threads.thread);
	if (rar5_threads.rlock)
		free(rar5_threads.rlock);
	if (rar5_threads.wlock)
		free(rar5_threads.wlock);
	if (rar5_threads.rcv)
		free(rar5_threads.rcv);
	if (rar5_threads.wcv)
		free(rar5_threads.wcv);
	if (rar5_threads.rcount)
		free(rar5_threads.rcount);
	if (rar5_threads.wcount)
		free(rar5_threads.wcount);
	if (rar5_threads.session_id)
		free(rar5_threads.session_id);
	if (rar5_session)
		free(rar5_session);

	rar5_session = NULL;
	memset(&rar5_threads, 0, sizeof(struct rar5_thread));

	return -1;
}
#endif
