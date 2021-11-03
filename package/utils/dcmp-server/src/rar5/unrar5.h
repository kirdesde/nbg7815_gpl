/* The unrar code in this file is based heavily on three (L)GPL projects:
 *
 * - The Unarchiver (<http://unarchiver.c3.cx/unarchiver>) by Dag Ågren,
 *   licensed under the terms of the GNU Lesser General Public License version
 *   2.1 or later.
 *
 *   The original copyright note in The Unarchiver reads as follows:
 *
 *   This program, "The Unarchiver", its accompanying libraries, "XADMaster"
 *   and "UniversalDetector", and the various smaller utility programs, such
 *   as "unar" and "lsar", are distributed under the GNU Lesser General
 *   Public License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   "UniversalDetector" is also available under other licenses, such as the
 *   Mozilla Public License. Please refer to the files in its subdirectory
 *   for further information.
 *
 *   The GNU Lesser General Public License might be too restrictive for some
 *   users of this code. Parts of the code are derived from earlier
 *   LGPL-licensed code and will as such always be bound by the LGPL, but
 *   some parts of the code are developed from scratch by the author of The
 *   Unarchiver, Dag Ågren, and can thus be made available under a more
 *   permissive license. For simplicity, everything is currently licensed
 *   under the LGPL, but if you are interested in using any code from this
 *   project under another license, please contact the author for further
 *   information.
 *
 *       - Dag Ågren, <paracelsus@gmail.com>
 *
 * - unrarlib, the UniquE RAR File Libary (<http://unrarlib.org/>) by
 *   Christian Scheurer. unrarlib is dual-licensed, available under
 *   the terms of the UniquE RAR File Library license and the GNU
 *   General Public License Version 2 or later.
 *
 *   The original copyright note in unrarlib reads as follows:
 *
 *   Copyright (C) 2000-2002 by Christian Scheurer (www.ChristianScheurer.ch)
 *   UNIX port copyright (c) 2000-2002 by Johannes Winkelmann (jw@tks6.net)
 *
 *   The contents of this file are subject to the UniquE RAR File Library
 *   License (the "unrarlib-license.txt"). You may not use this file except
 *   in compliance with the License. You may obtain a copy of the License
 *   at http://www.unrarlib.org/license.html.
 *   Software distributed under the License is distributed on an "AS IS"
 *   basis, WITHOUT WARRANTY OF ANY KIND, either express or implied warranty.
 *
 *   Alternatively, the contents of this file may be used under the terms
 *   of the GNU General Public License Version 2 or later (the "GPL"), in
 *   which case the provisions of the GPL are applicable instead of those
 *   above. If you wish to allow use of your version of this file only
 *   under the terms of the GPL and not to allow others to use your version
 *   of this file under the terms of the UniquE RAR File Library License,
 *   indicate your decision by deleting the provisions above and replace
 *   them with the notice and other provisions required by the GPL. If you
 *   do not delete the provisions above, a recipient may use your version
 *   of this file under the terms of the GPL or the UniquE RAR File Library
 *   License.
 *
 * - unrar-free (<https://gna.org/projects/unrar/>), by Jeroen Dekkers and
 *   Ben Asselstine, which itself is based on unrarlib. unrar-free is licensed
 *   under the terms of the GNU General Public License Version 2 or later.
 *
 *   The original copyright note in unrar-free reads as follows:
 *
 *   Copyright (C) 2004  Jeroen Dekkers <jeroen@dekkers.cx>
 *   Copyright (C) 2004  Ben Asselstine <benasselstine@canada.com>
 *   Copyright (C) 2000-2002  Christian Scheurer (www.ChristianScheurer.ch)
 *   Copyright (C) 2000-2002  Johannes Winkelmann (jw@tks6.net)
 *   RAR decompression code:
 *   Copyright (c) 1993-2002  Eugene Roshal
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation; either version 2
 *   of the License, or (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *
 * The bitstream code is heavily based on the bitstream interface found in the
 * single-file FLAC decoding library dr_flac by David Reid
 * (<https://mackron.github.io/dr_flac.html>), licensed under the terms of the
 * unlicense.
 *
 * Additionally, dmc_unrar takes some inspiration from miniz.c, the public
 * domain single-file deflate/inflate, zlib-subset, ZIP reading/writing library
 * (<https://github.com/richgel999/miniz>) by Rich Geldreich. miniz.c is
 * licensed under the terms of the unlicense.
 */

#ifdef DECOMP_MODULE_RAR5

#include <pthread.h>

#ifndef DMC_UNRAR_HEADER
#define DMC_UNRAR_HEADER

#define RAR5_SIZEOF_MARKHEAD 8
#define RAR5_READ_UNMATCHED_MAGIC_COOKIE     0x02

#define DMC_UNRAR_ASSERT_R(x)	if(!(x)) return
#define DMC_UNRAR_ASSERT_0(x)	if(!(x)) return 0
#define DMC_UNRAR_ASSERT_N(x)	if(!(x)) return NULL
#define DMC_UNRAR_ASSERT_F(x)	if(!(x)) return false
#define DMC_UNRAR_ASSERT_E(x)	if(!(x)) return DMC_UNRAR_FILE_IS_INVALID

#define DMC_UNRAR_CLEAR_OBJ(obj)     memset(&(obj), 0, sizeof(obj))
#define DMC_UNRAR_CLEAR_OBJS(obj, n) memset((obj), 0, (n) * sizeof((obj)[0]))

/** The return code of a dmc_unrar operation. See dmc_unrar_strerror(). */
typedef enum {
	DMC_UNRAR_OK = 0,

	DMC_UNRAR_NO_ALLOC,
	DMC_UNRAR_ALLOC_FAIL,

	DMC_UNRAR_OPEN_FAIL,
	DMC_UNRAR_READ_FAIL,
	DMC_UNRAR_WRITE_FAIL,
	DMC_UNRAR_SEEK_FAIL,

	DMC_UNRAR_INVALID_DATA,

	DMC_UNRAR_ARCHIVE_EMPTY,

	DMC_UNRAR_ARCHIVE_IS_NULL,
	DMC_UNRAR_ARCHIVE_NOT_CLEARED,
	DMC_UNRAR_ARCHIVE_MISSING_FIELDS,

	DMC_UNRAR_ARCHIVE_NOT_RAR,
	DMC_UNRAR_ARCHIVE_UNSUPPORTED_ANCIENT,

	DMC_UNRAR_ARCHIVE_UNSUPPORTED_VOLUMES,
	DMC_UNRAR_ARCHIVE_UNSUPPORTED_ENCRYPTED,

	DMC_UNRAR_FILE_IS_INVALID,
	DMC_UNRAR_FILE_IS_DIRECTORY,

	DMC_UNRAR_FILE_SOLID_BROKEN,
	DMC_UNRAR_FILE_CRC32_FAIL,

	DMC_UNRAR_FILE_UNSUPPORTED_VERSION,
	DMC_UNRAR_FILE_UNSUPPORTED_METHOD,
	DMC_UNRAR_FILE_UNSUPPORTED_ENCRYPTED,
	DMC_UNRAR_FILE_UNSUPPORTED_SPLIT,
	DMC_UNRAR_FILE_UNSUPPORTED_LINK,
	DMC_UNRAR_FILE_UNSUPPORTED_LARGE,

	DMC_UNRAR_HUFF_RESERVED_SYMBOL,
	DMC_UNRAR_HUFF_PREFIX_PRESENT,
	DMC_UNRAR_HUFF_INVALID_CODE,

	DMC_UNRAR_PPMD_INVALID_MAXORDER,

	DMC_UNRAR_FILTERS_UNKNOWN,
	DMC_UNRAR_FILTERS_INVALID_FILTER_INDEX,
	DMC_UNRAR_FILTERS_REUSE_LENGTH_NEW_FILTER,
	DMC_UNRAR_FILTERS_INVALID_LENGTH,
	DMC_UNRAR_FILTERS_INVALID_FILE_POSITION,
	DMC_UNRAR_FILTERS_XOR_SUM_NO_MATCH,
	DMC_UNRAR_FILTERS_UNSUPPORED_ITANIUM,

	DMC_UNRAR_15_INVALID_FLAG_INDEX,
	DMC_UNRAR_15_INVALID_LONG_MATCH_OFFSET_INDEX,

	DMC_UNRAR_20_INVALID_LENGTH_TABLE_DATA,

	DMC_UNRAR_30_DISABLED_FEATURE_PPMD,
	DMC_UNRAR_30_DISABLED_FEATURE_FILTERS,

	DMC_UNRAR_30_INVALID_LENGTH_TABLE_DATA,

	DMC_UNRAR_50_DISABLED_FEATURE_FILTERS,

	DMC_UNRAR_50_INVALID_LENGTH_TABLE_DATA,
	DMC_UNRAR_50_BLOCK_CHECKSUM_NO_MATCH

} dmc_unrar_return;

/* Heap allocation functions. */
typedef void *(*dmc_unrar_alloc_func)  (void *opaque, size_t items, size_t size);
typedef void *(*dmc_unrar_realloc_func)(void *opaque, void *address, size_t items, size_t size);
typedef void  (*dmc_unrar_free_func)   (void *opaque, void *address);

typedef size_t (*dmc_unrar_read_func)(void *opaque, void *buffer, size_t n);
typedef int    (*dmc_unrar_seek_func)(void *opaque, uint64_t offset);

/* --- Public unrar API --- */

/** The operating system a file was packed into a RAR. */
typedef enum {
	DMC_UNRAR_HOSTOS_DOS   = 0, /**< DOS, MS-DOS. */
	DMC_UNRAR_HOSTOS_OS2   = 1, /**< OS/2. */
	DMC_UNRAR_HOSTOS_WIN32 = 2, /**< Windows. */
	DMC_UNRAR_HOSTOS_UNIX  = 3, /**< Unix. */
	DMC_UNRAR_HOSTOS_MACOS = 4, /**< Mac OS. */
	DMC_UNRAR_HOSTOS_BEOS  = 5  /**< BeOS. */
} dmc_unrar_host_os;

/** DOS/Windows file attributes. */
typedef enum {
	DMC_UNRAR_ATTRIB_DOS_READONLY    = 0x00001,
	DMC_UNRAR_ATTRIB_DOS_HIDDEN      = 0x00002,
	DMC_UNRAR_ATTRIB_DOS_SYSTEM      = 0x00004,
	DMC_UNRAR_ATTRIB_DOS_VOLUMELABEL = 0x00008,
	DMC_UNRAR_ATTRIB_DOS_DIRECTORY   = 0x00010,
	DMC_UNRAR_ATTRIB_DOS_ARCHIVE     = 0x00020,
	DMC_UNRAR_ATTRIB_DOS_DEVICE      = 0x00040,
	DMC_UNRAR_ATTRIB_DOS_NORMAL      = 0x00080,
	DMC_UNRAR_ATTRIB_DOS_TEMPORARY   = 0x00100,
	DMC_UNRAR_ATTRIB_DOS_SPARSE      = 0x00200,
	DMC_UNRAR_ATTRIB_DOS_SYMLINK     = 0x00400,
	DMC_UNRAR_ATTRIB_DOS_COMPRESSED  = 0x00800,
	DMC_UNRAR_ATTRIB_DOS_OFFLINE     = 0x01000,
	DMC_UNRAR_ATTRIB_DOS_NOTINDEXED  = 0x02000,
	DMC_UNRAR_ATTRIB_DOS_ENCRYPTED   = 0x04000,
	DMC_UNRAR_ATTRIB_DOS_INTEGRITY   = 0x08000,
	DMC_UNRAR_ATTRIB_DOS_VIRTUAL     = 0x10000,
	DMC_UNRAR_ATTRIB_DOS_NOSCRUB     = 0x20000
} dmc_unrar_windows_attribute;

/** Unix file attributes. */
typedef enum {
	/* Mask to check for the types of a file. */
	DMC_UNRAR_ATTRIB_UNIX_FILETYPE_MASK       = 0170000,
	/* Mask to check for the permissions of a file. */
	DMC_UNRAR_ATTRIB_UNIX_PERMISSIONS_MASK    = 0007777,

	/* .--- File types. Mutually exclusive. */
	DMC_UNRAR_ATTRIB_UNIX_IS_SYMBOLIC_LINK    = 0120000,
	DMC_UNRAR_ATTRIB_UNIX_IS_SOCKET           = 0140000,

	DMC_UNRAR_ATTRIB_UNIX_IS_REGULAR_FILE     = 0100000,

	DMC_UNRAR_ATTRIB_UNIX_IS_BLOCK_DEVICE     = 0060000,
	DMC_UNRAR_ATTRIB_UNIX_IS_DIRECTORY        = 0040000,
	DMC_UNRAR_ATTRIB_UNIX_IS_CHARACTER_DEVICE = 0020000,
	DMC_UNRAR_ATTRIB_UNIX_IS_FIFO             = 0010000,
	/* '--- */

	/* .--- File permissions. OR-able. */
	DMC_UNRAR_ATTRIB_UNIX_SET_USER_ID         = 0004000,
	DMC_UNRAR_ATTRIB_UNIX_SET_GROUP_ID        = 0002000,
	DMC_UNRAR_ATTRIB_UNIX_STICKY              = 0001000,

	DMC_UNRAR_ATTRIB_UNIX_USER_READ           = 0000400,
	DMC_UNRAR_ATTRIB_UNIX_USER_WRITE          = 0000200,
	DMC_UNRAR_ATTRIB_UNIX_USER_EXECUTE        = 0000100,
	DMC_UNRAR_ATTRIB_UNIX_GROUP_READ          = 0000040,
	DMC_UNRAR_ATTRIB_UNIX_GROUP_WRITE         = 0000020,
	DMC_UNRAR_ATTRIB_UNIX_GROUP_EXECUTE       = 0000010,
	DMC_UNRAR_ATTRIB_UNIX_OTHER_READ          = 0000004,
	DMC_UNRAR_ATTRIB_UNIX_OTHER_WRITE         = 0000002,
	DMC_UNRAR_ATTRIB_UNIX_OTHER_EXECUTE       = 0000001
	/* '--- */
} dmc_unrar_unix_attribute;

/** Exact type of a RAR5 block. */
enum {
	DMC_UNRAR_BLOCK5_TYPE_ARCHIVEHEADER = 0x01, /**< Information header describing the archive. */
	DMC_UNRAR_BLOCK5_TYPE_FILE          = 0x02, /**< A file within the archive. */
	DMC_UNRAR_BLOCK5_TYPE_SERVICE       = 0x03, /**< Service header. */
	DMC_UNRAR_BLOCK5_TYPE_ENCRYPTION    = 0x04, /**< Archive encryption header. */
	DMC_UNRAR_BLOCK5_TYPE_END           = 0x05  /**< Archive end marker. */
};

/** The general compression method (from worst to best). */
enum {
	DMC_UNRAR_METHOD_STORE   = 0x30, /**< Uncompressed. */
	DMC_UNRAR_METHOD_FASTEST = 0x31,
	DMC_UNRAR_METHOD_FAST    = 0x32,
	DMC_UNRAR_METHOD_NORMAL  = 0x33,
	DMC_UNRAR_METHOD_GOOD    = 0x34,
	DMC_UNRAR_METHOD_BEST    = 0x35
};

typedef enum {
	DMC_UNRAR_GENERATION_INVALID = 0,

	DMC_UNRAR_GENERATION_ANCIENT,
	DMC_UNRAR_GENERATION_RAR4,
	DMC_UNRAR_GENERATION_RAR5
} dmc_unrar_generation;


struct dmc_unrar_file_block_tag;
typedef struct dmc_unrar_file_block_tag dmc_unrar_file_block;

struct dmc_unrar_rar_context_tag;
typedef struct dmc_unrar_rar_context_tag dmc_unrar_rar_context;

/** A file entry within a RAR archive. */
typedef struct dmc_unrar_file_tag {
	uint64_t compressed_size;   /**< Size of the compressed file data, in bytes. */
	uint64_t uncompressed_size; /**< Size of the uncompressed file data, in bytes. */

	/** The operating system on which the file was packed into the RAR. */
	dmc_unrar_host_os host_os;

	bool has_crc; /**< Does this file entry have a checksum? */

	uint32_t crc;       /**< Checksum (CRC-32, 0xEDB88320 polynomial). */
	uint64_t unix_time; /**< File modification timestamp, POSIX epoch format. */

	/** File attributes, operating-system-specific.
	 *
	 *  The meaning depends on the host_os value:
	 *  - DMC_UNRAR_HOSTOS_DOS:   see dmc_unrar_windows_attribute
	 *  - DMC_UNRAR_HOSTOS_OS2:   ???
	 *  - DMC_UNRAR_HOSTOS_WIN32: see dmc_unrar_windows_attribute
	 *  - DMC_UNRAR_HOSTOS_UNIX:  see dmc_unrar_unix_attribute
	 *  - DMC_UNRAR_HOSTOS_MACOS: ???
	 *  - DMC_UNRAR_HOSTOS_BEOS:  ???
	 */
	uint64_t attrs;

} dmc_unrar_file;


struct rar5_thread
{
	int num;
	pthread_t *thread;

	pthread_mutex_t *rlock;
	pthread_mutex_t *wlock;

	pthread_cond_t *rcv;
	pthread_cond_t *wcv;

	int *wcount;
	int *rcount;
	int *session_id;
};

struct rar5_data
{
	unsigned char used;		// from unrar5()
	unsigned char head;		// from unrar5()
	unsigned char resv[2];

	unsigned int wait;		// from unrar5()
	unsigned int flag;		// from unrar5()

	unsigned char *in_buffer;	// uncomp2
	unsigned int in_buffer_len;	// uncomp2
	unsigned char *out_buffer;	// from unrar5()
	unsigned int out_buffer_len;	// from unrar5()

	unsigned char *filename;	// from unrar5()
	unsigned int filename_len;	// from unrar5()

	unsigned int file_count;	// from unrar5()
};

struct dmc_unrar_file_block_tag {
	size_t index; /** The index of this file within the files array. */

	uint64_t start_pos; /**< The offset within the file *after* the whole file block header. */

	uint64_t flags; /**< flags describing the file. */

	uint16_t version; /**< RAR compression version for this file. */
	uint8_t  method;  /**< RAR compression method for this file. */

	uint64_t name_offset; /**< Offset to the name field. */
	uint64_t name_size;   /**< Size of the name field. */

	bool is_split;     /**< This file is a split file. */
	bool is_solid;     /**< This is a solid file. */
	bool is_link;      /**< This file is hard or symbolic link. */
	bool is_encrypted; /**< This file is encrypted. */

	uint64_t dict_size; /**< Dictionary size in bytes. */

	struct rar5_data *my_sess;  /**/
	int my_id;

	dmc_unrar_file_block *solid_start; /**< The first file entry in a solid block. */
	dmc_unrar_file_block *solid_prev;  /**< The previous file entry in a solid block. */
	dmc_unrar_file_block *solid_next;  /**< The next file entry in a solid block. */

	dmc_unrar_file file; /**< Public file structure. */
};

typedef struct dmc_unrar_block_header_tag {
	uint64_t start_pos; /**< The offset within the file the block start at. */
	uint64_t extra_pos; /**< The offset within the file the extra header data starts. */

	uint64_t type; /**< The type of the block. */

	uint32_t crc;   /**< Checksum. */
	uint64_t flags; /**< flags describing this block. */

	uint64_t header_size; /**< Size of the full block header in bytes. */
	uint64_t data_size;   /**< Size of the extra block data in bytes. */

	uint64_t extra_size; /** Size of extra file properties in RAR5, in bytes. */

} dmc_unrar_block_header;

struct dmc_unrar_internal_state_tag;
typedef struct dmc_unrar_internal_state_tag dmc_unrar_internal_state;

typedef struct dmc_unrar_alloc_tag {
	dmc_unrar_alloc_func func_alloc;     /**< Memory allocation function, or NULL to use malloc(). */
	dmc_unrar_realloc_func func_realloc; /**< Memory allocation function, or NULL to use realloc(). */
	dmc_unrar_free_func func_free;       /**< Memory deallocation function, or NULL to use free(). */
	void *opaque;                        /**< Private data passed to func_alloc, func_realloc and func_free. */

} dmc_unrar_alloc;

typedef struct dmc_unrar_io_tag {
	dmc_unrar_read_func func_read; /**< RAR file reading function. Must not be NULL. */
	dmc_unrar_seek_func func_seek; /**< RAR file seeking function. Must not be NULL. */
	void *opaque;                  /**< Private data passed to func_read and func_seek. */

	uint64_t offset; /**< Current offset within the IO stream. */
	uint64_t size;   /**< Size of the IO stream. */

} dmc_unrar_io;

/** A RAR archive. */
typedef struct dmc_unrar_archive_tag {
	dmc_unrar_alloc alloc;
	dmc_unrar_io io;

	/** Private internal state. */
	dmc_unrar_internal_state *internal_state;

} dmc_unrar_archive;

/* .--- Memory IO functions */
typedef struct dmc_unrar_mem_reader_tag {
        const uint8_t *buffer;
        uint64_t size;
        uint64_t offset;
} dmc_unrar_mem_reader;

struct dmc_unrar_internal_state_tag {
        /** RAR generation. RAR4 (1.5 - 3.6) vs RAR5 (5.0). */
        dmc_unrar_generation generation;

        uint16_t archive_flags; /**< Global archive flags. */

        dmc_unrar_block_header *comment; /**< Archive comments block. */

        size_t block_count;             /**< Number of blocks in this RAR archive. */
        dmc_unrar_block_header *blocks; /**< All blocks in this RAR archive. */
        size_t block_capacity;          /**< Memory capacity of the blocks array. */

        size_t file_count;           /**< Number of files (and directories) in this RAR archive. */
        dmc_unrar_file_block *files; /**< All files (and directories) in this RAR archive. */
        size_t file_capacity;        /**< Memory capacity of the files array. */

        /** Saved unpack context, for sequential solid block unpacking. */
        dmc_unrar_rar_context *unpack_context;
};

typedef struct dmc_unrar_file_reader_tag {
	FILE *file;
	uint64_t size;

	bool need_close;
} dmc_unrar_file_reader;

/** Return a human-readable description of a return code. */
const char *dmc_unrar_strerror(dmc_unrar_return code);

bool dmc_unrar_archive_seek(dmc_unrar_io *io, uint64_t offset);

/** Detect whether an IO structure contains a RAR archive. */
bool dmc_unrar_is_rar(dmc_unrar_io *io);

/** Detect whether the memory region contains a RAR archive. */
bool dmc_unrar_is_rar_mem(const void *mem, size_t size);

/* Detect whether this FILE contains a RAR archive. */
bool dmc_unrar_is_rar_file(FILE *file);

/* Detect whether the file at this path contains a RAR archive. */
bool dmc_unrar_is_rar_path(const char *path);

void *dmc_unrar_malloc(dmc_unrar_alloc *alloc, size_t items, size_t size);

bool dmc_unrar_extract_callback_mem(void *opaque, void **buffer,
	size_t *buffer_size, size_t uncompressed_size, dmc_unrar_return *err);

/** Initialize/clear this archive struct.
 *
 *  @param  archive A valid pointer to an archive structure to initialize.
 *  @return DMC_UNRAR_OK on success. Any other value is an error condition.
 */
dmc_unrar_return dmc_unrar_archive_init(dmc_unrar_archive *archive);

/** Open this RAR archive, reading its block and file headers.
 *  The func_read, func_read and opaque_io fields have to be set.
 *  The func_alloc, func_realloc, func_free and opaque_mem fields may be set.
 *  All other fields must have been cleared.
 *
 *  @param  archive Pointer to the archive structure to use. Needs to be a valid
 *                  pointer, with the fields properly initialized and set.
 *  @param  size Size of the RAR file described by the archive fields.
 *  @return DMC_UNRAR_OK if the archive was successfully opened. Any other value
 *          describes an error condition.
 */
dmc_unrar_return dmc_unrar_archive_open(dmc_unrar_archive *archive, uint64_t size);

/** Open this RAR archive from a memory block, reading its block and file headers.
 *  The func_alloc, func_realloc, func_free and opaque_mem fields may be set.
 *  All other fields must have been cleared.
 *
 *  @param  archive Pointer to the archive structure to use. Needs to be a valid
 *                  pointer, with the fields properly initialized and set.
 *  @param  mem Pointer to a block of memory to read the RAR file out of.
 *  @param  size Size of the RAR memory region.
 *  @return DMC_UNRAR_OK if the archive was successfully opened. Any other value
 *          describes an error condition.
 */
dmc_unrar_return dmc_unrar_archive_open_mem(dmc_unrar_archive *archive,
	const void *mem, size_t size);

/** Open this RAR archive from a stdio FILE, reading its block and file headers.
 *  The func_alloc, func_realloc, func_free and opaque_mem fields may be set.
 *  All other fields must have been cleared.
 *
 *  @param  archive Pointer to the archive structure to use. Needs to be a valid
 *                  pointer, with the fields properly initialized and set.
 *  @param  file The stdio FILE structure to read out of.
 *  @return DMC_UNRAR_OK if the archive was successfully opened. Any other value
 *          describes an error condition.
 */
dmc_unrar_return dmc_unrar_archive_open_file(dmc_unrar_archive *archive, FILE *file);

/** Open this RAR archive from a path, opening the file with fopen(), and reading
 *  its block and file headers. The func_alloc, func_realloc, func_free and
 *   opaque_mem fields may be set. All other fields must have been cleared.
 *
 *  @param  archive Pointer to the archive structure to use. Needs to be a valid
 *                  pointer, with the fields properly initialized and set.
 *  @param  path The path of the file to fopen() and read out of.
 *  @return DMC_UNRAR_OK if the archive was successfully opened. Any other value
 *          describes an error condition.
 */
dmc_unrar_return dmc_unrar_archive_open_path(dmc_unrar_archive *archive, const char *path);

/** Close this RAR archive again.
 *
 *  All allocated memory will be freed. */
void dmc_unrar_archive_close(dmc_unrar_archive *archive);

/** Get the global archive comment of a RAR archive.
 *
 *  Note: we don't necessarily know the encoding of this data, nor is
 *  the data always \0-terminated or even a human-readable string!
 *
 *  - RAR 5.0 always stores UTF-8 data.
 *  - RAR 2.9/3.6 stores either ASCII or UTF-16LE data.
 *    We don't know which is which.
 *  - RAR 2.0/2.6 stores *anything*.
 *  - RAR 1.5 doesn't support archive comments.
 *
 *  Use dmc_unrar_unicode_detect_encoding() to roughly detect the
 *  encoding of a comment.
 *
 *  Use dmc_unrar_unicode_convert_utf16le_to_utf8() to convert a
 *  UTF-16LE comment into UTF-8.
 *
 *  Returns the number of bytes written to comment. If comment is NULL, this function
 *  returns the number of bytes needed to fully store the comment.
 */
size_t dmc_unrar_get_archive_comment(dmc_unrar_archive *archive, void *comment, size_t comment_size);

/** Return the number of file entries in this RAR archive. */
size_t dmc_unrar_get_file_count(dmc_unrar_archive *archive);

/** Return the detailed information about a file entry, or NULL on error.
 *  Does not need to be free'd. */
const dmc_unrar_file *dmc_unrar_get_file_stat(dmc_unrar_archive *archive, size_t index);

/** Get the filename of a RAR file entry, UTF-8 encoded and \0-terminated.
 *
 *  Note: the filename is *not* checked to make sure it contains fully
 *  valid UTF-8 data. Use dmc_unrar_unicode_is_valid_utf8() and/or
 *  dmc_unrar_unicode_make_valid_utf8() for that.
 *
 *  Returns the number of bytes written to filename. If filename is NULL, this function
 *  returns the number of bytes needed to fully store the filename.
 */
size_t dmc_unrar_get_filename(dmc_unrar_archive *archive, size_t index,
	char *filename, size_t filename_size);

/** Is this file entry a directory? */
bool dmc_unrar_file_is_directory(dmc_unrar_archive *archive, size_t index);

/** Does this file entry have a comment attached? */
bool dmc_unrar_file_has_comment(dmc_unrar_archive *archive, size_t index);

/** Check if we support extracted this file entry.
 *
 *  If we do support extracting this file entry, DMC_UNRAR_OK is returned.
 *  Otherwise, the return code gives an idea why we don't have support. */
dmc_unrar_return dmc_unrar_file_is_supported(dmc_unrar_archive *archive, size_t index);

/** Get the comment of a file entry.
 *
 *  Note: we don't necessarily know the encoding of this data, nor is
 *  the data always \0-terminated or even a human-readable string!
 *
 *  Only RAR 2.0/2.6 supports file comments.
 *
 *  Use dmc_unrar_unicode_detect_encoding() to roughly detect the
 *  encoding of a comment.
 *
 *  Use dmc_unrar_unicode_convert_utf16le_to_utf8() to convert a
 *  UTF-16LE comment into UTF-8.
 *
 *  Returns the number of bytes written to comment. If comment is NULL, this function
 *  returns the number of bytes needed to fully store the comment.
 */
size_t dmc_unrar_get_file_comment(dmc_unrar_archive *archive, size_t index,
	void *comment, size_t comment_size);

/** Extract a file entry into a pre-allocated memory buffer.
 *
 *  @param  archive The archive to extract from.
 *  @param  index The index of the file entry to extract.
 *  @param  buffer The pre-allocated memory buffer to extract into.
 *  @param  buffer_size The size of the pre-allocated memory buffer.
 *  @param  uncompressed_size If != NULL, the number of bytes written
 *          to the buffer will be stored here.
 *  @param  validate_crc If true, validate the uncompressed data against
 *          the CRC-32 stored within the archive. If the validation fails,
 *          this counts as an error (DMC_UNRAR_FILE_CRC32_FAIL).
 *  @return An error condition, or DMC_UNRAR_OK if extraction succeeded.
 */
dmc_unrar_return dmc_unrar_extract_file_to_mem(dmc_unrar_archive *archive, size_t index,
	void *buffer, size_t buffer_size, size_t *uncompressed_size, bool validate_crc);

/** Extract a file entry into a dynamically allocated heap buffer.
 *
 *  @param  archive The archive to extract from.
 *  @param  index The index of the file entry to extract.
 *  @param  buffer The heap-allocated memory buffer will be stored here.
 *  @param  uncompressed_size The size of the heap-allocated memory buffer
 *          will be stored here. Must not be NULL.
 *  @param  validate_crc If true, validate the uncompressed data against
 *          the CRC-32 stored within the archive. If the validation fails,
 *          this counts as an error (DMC_UNRAR_FILE_CRC32_FAIL).
 *  @return An error condition, or DMC_UNRAR_OK if extraction succeeded.
 */
dmc_unrar_return dmc_unrar_extract_file_to_heap(dmc_unrar_archive *archive, size_t index,
	void **buffer, size_t *uncompressed_size, bool validate_crc);

/** The callback function for dmc_unrar_extract_file_with_callback().
 *
 *  Note that even with small buffer slices, decompressing a buffer
 *  full might take an unexpected long time, if the requested file
 *  is part of a solid block and/or uses the PPMd decoder.
 *
 *  @param  opaque Opaque memory pointer for personal use.
 *  @param  buffer Pointer to the buffer where the current part of the
 *          extracted file resides. Can be changed, to use a different
 *          buffer for further extraction. Can be set to NULL to let
 *          dmc_unrar_extract_file_with_callback() allocate its own
 *          internal buffer.
 *  @param  buffer_size Size of the buffer. Can be modified, to use
 *          a different buffer size for further extraction.
 *  @param  uncompressed_size Number of bytes of extracted file waiting
 *          in the buffer.
 *  @param  err In combination with returning false, the callback can
 *          set this parameter to something other than DMC_UNRAR_OK to
 *          signal an error. dmc_unrar_extract_file_with_callback() will
 *          return with that error condition.
 *  @return true if extraction should continue, false otherwise.
 */
typedef bool (*dmc_unrar_extract_callback_func)(void *opaque, void **buffer,
	size_t *buffer_size, size_t uncompressed_size, dmc_unrar_return *err);

/** Extract a file entry using a callback function.
 *
 *  Extract into the buffer of buffer_size, calling callback every time the
 *  buffer has been filled (or all the input has been processed).
 *
 *  @param  archive The archive to extract from.
 *  @param  index The index of the file entry to extract.
 *  @param  buffer The pre-allocated memory buffer to extract into. Can be
 *          NULL to mean that a buffer of buffer_size should be allocated.
 *  @param  buffer_size The size of the output buffer.
 *  @param  uncompressed_size If != NULL, the total number of bytes written
 *          to the buffer will be stored here.
 *  @param  validate_crc If true, validate the uncompressed data against
 *          the CRC-32 stored within the archive. If the validation fails,
 *          this counts as an error (DMC_UNRAR_FILE_CRC32_FAIL).
 *  @param  opaque Opaque memory pointer to pass to the callback.
 *  @param  callback The callback to call.
 *  @return An error condition, or DMC_UNRAR_OK if extraction succeeded.
 */
dmc_unrar_return dmc_unrar_extract_file_with_callback(dmc_unrar_archive *archive, size_t index,
	void *buffer, size_t buffer_size, size_t *uncompressed_size, bool validate_crc,
	void *opaque, dmc_unrar_extract_callback_func callback);

/** Extract a file entry into a file.
 *
 *  @param  archive The archive to extract from.
 *  @param  index The index of the file entry to extract.
 *  @param  file The file to write into.
 *  @param  uncompressed_size If not NULL, the number of bytes written
 *          to the file will be stored here.
 *  @param  validate_crc If true, validate the uncompressed data against
 *          the CRC-32 stored within the archive. If the validation fails,
 *          this counts as an error (DMC_UNRAR_FILE_CRC32_FAIL).
 *  @return An error condition, or DMC_UNRAR_OK if extraction succeeded.
 */
dmc_unrar_return dmc_unrar_extract_file_to_file(dmc_unrar_archive *archive, size_t index,
	FILE *file, size_t *uncompressed_size, bool validate_crc);

/** Open a file and extract a RAR file entry into it.
 *
 *  @param  archive The archive to extract from.
 *  @param  index The index of the file entry to extract.
 *  @param  path The file to open and write into.
 *  @param  uncompressed_size If not NULL, the number of bytes written
 *          to the file will be stored here.
 *  @param  validate_crc If true, validate the uncompressed data against
 *          the CRC-32 stored within the archive. If the validation fails,
 *          this counts as an error (DMC_UNRAR_FILE_CRC32_FAIL).
 *  @return An error condition, or DMC_UNRAR_OK if extraction succeeded.
 */
dmc_unrar_return dmc_unrar_extract_file_to_path(dmc_unrar_archive *archive, size_t index,
	const char *path, size_t *uncompressed_size, bool validate_crc);

/** Return true if the given \0-terminated string contains valid UTF-8 data. */
bool dmc_unrar_unicode_is_valid_utf8(const char *str);

/** Cut off the given \0-terminated string at the first invalid UTF-8 sequence.
 *
 *  @param str The string to check and potentially modify.
 *  @return True if the string was modified, false otherwise.
 */
bool dmc_unrar_unicode_make_valid_utf8(char *str);

typedef enum {
	DMC_UNRAR_UNICODE_ENCODING_UTF8,
	DMC_UNRAR_UNICODE_ENCODING_UTF16LE,

	DMC_UNRAR_UNICODE_ENCODING_UNKNOWN

} dmc_unrar_unicode_encoding;

/** Try to detect the encoding of a memory region containing human-readable text.
 *
 *  This is of course far from 100% reliable. The detection is rather simplistic
 *  and just meant to roughly detect the encoding of archive comments.
 *
 *  This function does not check for \0-termination.
 */
dmc_unrar_unicode_encoding dmc_unrar_unicode_detect_encoding(const void *data, size_t data_size);


dmc_unrar_return dmc_unrar_archive_check_alloc(dmc_unrar_alloc *alloc);

/** Convert UTF-16LE data into UTF-8.
 *
 *  Conversion will stop at the first invalid UTF-16 sequence. The result will
 *  always be fully valid, \0-terminated UTF-8 string, but possibly cut off.
 *
 *  A leading UTF-16LE BOM will be removed.
 *
 *  @param utf16le_size Size of utf16le_data in bytes.
 *  @param utf8_size Size of utf8_data in bytes.
 *
 *  Returns the number of bytes written to utf8_data. If utf8_data is NULL, this
 *  function returns the number of bytes needed to fully store the UTF-8 string.
 */
size_t dmc_unrar_unicode_convert_utf16le_to_utf8(const void *utf16le_data, size_t utf16le_size,
	char *utf8_data, size_t utf8_size);

/** Calculate a CRC-32 (0xEDB88320 polynomial) checksum from this memory region. */
uint32_t dmc_unrar_crc32_calculate_from_mem(const void *mem, size_t size);

/** Append the CRC-32 (0xEDB88320 polynomial) checksum calculate from this memory region
  * to the CRC-32 of a previous memory region. The result is the CRC-32 of the two
  * memory regions pasted together.
  *
  * I.e. these two functions will result in the same value:
  *
  * uint32_t crc32_1(const uint8_t *mem, size_t size) {
  *   assert(size >= 10);
  *   return dmc_unrar_crc32_calculate_from_mem(mem, size);
  * }
  *
  * uint32_t crc32_2(const uint8_t *mem, size_t size) {
  *   assert(size >= 10);
  *   uint32_t crc = dmc_unrar_crc32_calculate_from_mem(mem, 10);
  *   dmc_unrar_crc32_continue_from_mem(crc, mem + 10, size - 10);
  *   return crc;
  * }
  */
uint32_t dmc_unrar_crc32_continue_from_mem(uint32_t hash, const void *mem, size_t size);

dmc_unrar_rar_context*
dmc_unrar_rar_context_alloc(dmc_unrar_alloc *alloc);

dmc_unrar_return
dmc_unrar_rar5_read_block_header(dmc_unrar_archive *archive,dmc_unrar_block_header *block);

dmc_unrar_return
dmc_unrar_file_unpack(dmc_unrar_archive *archive, dmc_unrar_file_block *file,
	void *buffer, size_t buffer_size, size_t *uncompressed_size, uint32_t *crc,
	void *opaque, dmc_unrar_extract_callback_func callback);

dmc_unrar_return
dmc_unrar_rar5_read_file_header(dmc_unrar_archive *archive,
	dmc_unrar_block_header *block, dmc_unrar_file_block *file);
void
dmc_unrar_io_init_mem_reader(dmc_unrar_io *io, dmc_unrar_mem_reader *mem_reader, const void *mem, size_t size);

int
dmc_unrar_identify_generation(dmc_unrar_io *io);


bool
dmc_unrar_init_internal_blocks(dmc_unrar_archive *archive);

bool
dmc_unrar_init_internal_files(dmc_unrar_archive *archive);

dmc_unrar_return
dmc_unrar_file_unstore(dmc_unrar_archive *archive, dmc_unrar_file_block *file,
	void *buffer, size_t buffer_size, size_t *uncompressed_size, uint32_t *crc,
	void *opaque, dmc_unrar_extract_callback_func callback);

extern struct rar5_data  *rar5_session;
extern struct rar5_thread rar5_threads;

#endif /* DMC_UNRAR_HEADER */
#endif