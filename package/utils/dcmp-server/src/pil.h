/*
** pil.h
**
*/

#ifndef _PIL_H_
#define _PIL_H_

#define MEM_GARBAGE_COLLECT
#define KERNEL_MODE
#define MULTIPLE_INSTANCE
#define GIDS

enum
{
	MEM_TYPE_VMALLOC = 0,
	MEM_TYPE_KMALLOC,
	MEM_TYPE_KMALLOC_DMA
};

#define MEM_MAGIC_TAG		0xbeefdead
#define FREE_MEM_MAGIC_TAG	0xdeadbeef

typedef struct _memlink memlink;
struct _memlink
{
#ifdef MEM_GARBAGE_COLLECT
	memlink *fore;
	memlink *next;
#endif	/* MEM_GARBAGE_COLLECT */

	unsigned int size;
	char *codeFile;
	int codeLine;
	unsigned int magicWord;
	unsigned char memType;
	unsigned char res[3];
};

extern unsigned int g_pkt_seq;
#define DEBUG_PKT_SEQ_RANGE (g_pkt_seq >= 0) /*(g_pkt_seq >= 3987789318u && g_pkt_seq < 3988075545u)*/

#ifndef KERNEL_MODE

#include <pthread.h>
#include <semaphore.h>

/* Wrap for thread */
#define THREAD_T pthread_t
#define THREAD_CREATE(thread_t, thread_attr, thread_func, thread_argv) \
         pthread_create(thread_t, thread_attr, thread_func, thread_argv)
#define THREAD_RUN(thread_t, thread_flag) {}
#define THREAD_EXIT(ret) thread_exit(ret)
#define THREAD_DETACH() pthread_detach(pthread_self())
#define THREAD_JOIN(thread_t, ret) pthread_join(thread_t, ret)


/* Wrap for thread mutex */
#define MUTEX_TYPE							pthread_mutex_t
#define MUTEX_INIT(x)						pthread_mutex_init((x), NULL)
#define MUTEX_CLEANUP(x)					pthread_mutex_destroy((x))
#define MUTEX_LOCK(x)						pthread_mutex_lock((x))
#define MUTEX_UNLOCK(x)						pthread_mutex_unlock((x))
#define MUTEX_TRYLOCK(x)					pthread_mutex_tryunlock((x))

/*Wrap for semaphore */
#define SEMAPHORE_T sem_t
#define SEMAPHORE_INIT(sem_ptr, init_val) sem_init(sem_ptr, 0, init_val)
#define SEMAPHORE_WAIT(sem_ptr) sem_wait(sem_ptr)
#define SEMAPHORE_POST(sem_ptr) sem_post(sem_ptr)
#define SEMAPHOTE_TRYWAIT(sem_ptr) sem_trywait(sem_ptr)

extern MUTEX_TYPE atomic_mutex;

#define ATOMIC_INC(var) \
	do {                    \
		(*var)++;           \
	} while (0)

#define ATOMIC_DEC(var) 	\
	do {                    \
		(*var)--;           \
	} while (0)


#if 0
#define ATOMIC_INC(var)               \
    do {                              \
        MUTEX_LOCK(&atomic_mutex);   \
        (*(var))++;                   \
        MUTEX_UNLOCK(&atomic_mutex); \
    } while(0)

#define ATOMIC_DEC(var)               \
    do {                              \
        MUTEX_LOCK(&atomic_mutex);   \
        (*(var))--;                   \
        MUTEX_UNLOCK(&atomic_mutex); \
    } while(0)

#endif

#else /* KERNEL_MODE */

#include "../porting.h"

#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/dst.h>

#include <stdarg.h>

#define calloc(size, num) 		my_calloc(size, num, 0, __FILE__, __LINE__)
#define malloc(size)      		my_malloc(size, 0, __FILE__, __LINE__)
#define realloc(ptr, size)      my_realloc(ptr, size, 0, __FILE__, __LINE__)
#define free(ptr)        		my_free(ptr, 0, __FILE__, __LINE__)
#define malloc_dma(size)		my_malloc(size, 1, __FILE__, __LINE__)
#define realloc_dma(ptr, size)	my_realloc(ptr, size, 1, __FILE__, __LINE__)
#define free_dma(ptr)			my_free(ptr, 1, __FILE__, __LINE__)

#ifdef DEBUG_MEM_OVERWRITE
#define MEMCPY(to, from, size) my_memcpy((to),(from),(size), __FILE__, __LINE__)
#define STRLCPY(to, from, to_size) my_strlcpy((to),(from),(to_size), __FILE__, __LINE__)
#else
#define MEMCPY(to, from, size) _memcpy_((to),(from),(size))
#define STRLCPY(to, from, to_size) lc_strlcpy((to),(from),(to_size))
#endif

#define dumpAscii(buf,len) do{\
        u32 dm;\
        _printk_(">>>"#buf", dump address:%p.<<<\n", buf );\
        for (dm=0;dm<len;dm++){\
                _printk_("%c", *(char*)(buf+dm));\
        }\
        _printk_("\n^^^^^^^^^^^^^^\n");\
}while(0)

#define dumpHex(buf,len) do{\
        unsigned long dm;\
        _printk_("{{{"#buf", dump address:0x%p, len:%d}}}\n",buf,len);\
        for (dm=0;dm<len;dm++){\
                _printk_("0x%2x,", (u8)*(char*)(buf+dm));\
                if((dm+1) % 16 == 0)\
                        _printk_("\n");\
        }\
        _printk_("\n{{{{{{{{{}}}}}}}}}\n");\
}while(0)

#define LC_IPV4_FMT "%u.%u.%u.%u"

#define LC_IPV6_FMT "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"

#define LC_IPV4(addr) \
		((u8 *)&addr)[0], ((u8 *)&addr)[1], ((u8 *)&addr)[2], ((u8 *)&addr)[3]

#define LC_IPV6(addr6) \
		((u8 *)addr6)[0],  ((u8 *)addr6)[1],  ((u8 *)addr6)[2],  ((u8 *)addr6)[3],  \
		((u8 *)addr6)[4],  ((u8 *)addr6)[5],  ((u8 *)addr6)[6],  ((u8 *)addr6)[7],  \
		((u8 *)addr6)[8],  ((u8 *)addr6)[9],  ((u8 *)addr6)[10], ((u8 *)addr6)[11], \
		((u8 *)addr6)[12], ((u8 *)addr6)[13], ((u8 *)addr6)[14], ((u8 *)addr6)[15]


/* Wrap for thread */
typedef struct task_struct *thread_ptr;

#define THREAD_T 										thread_ptr
#define THREAD_CREATE(thread_func, thread_argv, ...)	kthread_create(thread_func, thread_argv, ...)
#define THREAD_EXIT(ret) 								do_exit(ret)
#define THREAD_DETACH(a) 								{}
#define THREAD_JOIN(thread_t, ret) 						{}

/* Wrap for thread mutex */
#define MUTEX_TYPE							struct semaphore
#define MUTEX_INIT(x)						init_Mutex((x))
#define MUTEX_CLEANUP(x)
#define MUTEX_LOCK(x)						down((x))
#define MUTEX_UNLOCK(x)						up((x))
#define MUTEX_TRYLOCK(x)					down_trylock((x))

/*Wrap for semaphore */
#define SEMAPHORE_T							struct semaphore
#define SEMAPHORE_INIT(sem_ptr, init_val)	sema_init(sem_ptr, init_val)
#define SEMAPHORE_WAIT(sem_ptr)				down(sem_ptr)
#define SEMAPHORE_POST(sem_ptr)				up(sem_ptr)
#define SEMAPHOTE_TRYWAIT(sem_ptr)			down_trylock(sem_ptr)
#define ATOMIC_INC(var)						{}
#define ATOMIC_DEC(var)						{}

#ifndef NULL
#define NULL ((void *)0)
#endif

#define fprintf(file, fmt, ...)		{}
#define bzero(d, n)					memset((d), 0, (n))
#define bcopy(src, dest, n)			MEMCPY((dest), (const char *)(src), (n))
#define getpid						(unsigned int)get_current
#ifndef strncasecmp
#define strncasecmp					strnicmp
#endif
#ifndef strcasecmp
#define strcasecmp(a,b)				strnicmp(a, b, (~0U)>>1)
#endif

#define exit(exit_val)
#define srand(val)

#define FALSE	0

/* Extract a short from a int */
#define hiword(x)		((u16)((x) >> 16))
#define loword(x)		((u16)(x))

/* Extract a byte from a short */
#define hibyte(x)		((u8)((x) >> 8))
#define lobyte(x)		((u8)(x))

/* Prepare for IOCTR string */
#define TO_IOCTL_STR(buf, fmt, args...) 	\
do{\
	_sprintf_(buf,fmt,##args);\
	add_to_ioctl_str(buf);\
}while(0)
extern unsigned char lc_printk_level;
extern unsigned char g_ioctl_str[];
extern unsigned int g_ioctl_str_len;
extern int add_to_ioctl_str(unsigned char* buf);


/* ---------------------------------------------------------------- */
static inline unsigned char lc_toupper(unsigned char c)
{
	return (c >= 'a' && c <= 'z') ? (c - 0x20) : (c);
}

static inline unsigned char lc_tolower(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') ? (c + 0x20) : (c);
}
static inline int lc_strncasecmp(const u8* dst, const u8* src, int count)
{
	u8 d, s;

	if (count)
	{
		do
		{
			d = *dst++;
			s = *src++;
			d = lc_toupper(d);
			s = lc_toupper(s);

		}
		while ((--count) && (d == s));
		return (d -s);
	}

	return 0;
}
/* ---------------------------------------------------------------- */
int lc_hex2bin(unsigned char* hex_str, unsigned char** bin_pp, unsigned int* bin_cnt_p);
char *inet_ntoa(struct in_addr);
int inet_pton(int af, const char *src, void *dst);
char *inet_ntop(int af, const void *src, char *dst, size_t size);
#define strdup lc_strdup
char *lc_strdup(char *);
#define strndup lc_strndup
char * lc_strndup(char *strold, size_t size);
unsigned long int strtoul(const char *string, char **endPtr, int base);
long int strtol(const char *string, char **endPtr, int base);
long int atol(char *p);
int atoi(char *p);
void itoa(int n, char *p, int sz);
char *strtok(char *, const char *);
char *strtok_r(char *, const char *, char **);
int rand(void);
void *my_realloc(void *ptr, int size, int flag, char *cfile, int cline);
void *my_calloc(int size, int num, int flag, char *cfile, int cline);
void *my_malloc(int size, int flag, char *cfile, int cline);
int my_free(void *ptr, int flag, char *cfile, int cline);
void dumpmem(void);
extern unsigned int total_mem;
void initMem(void);
void cleanupMem(void);
unsigned int usedMem(void);
char *nstrstr(unsigned char *ptr, unsigned char *str, int times);
char *lc_strnstr(unsigned char *s1, unsigned char *s2, int len1, int len2);
char *revstrnstr(unsigned char *s1, unsigned char *s2, int len1, int len2);
char *strncasestr(unsigned char *s1, unsigned char *s2, int len1, int len2);
char *substrnstr(unsigned char *s1, unsigned char *s2, int len1, int len2,
                 unsigned short *str_offset, int is_case);
char *strcasestr(unsigned char *s1, unsigned char *s2);
int checkMemStatus(char *p_mem, char *cfun, int cline);

void * my_memcpy(void *to , const void *from, int size, char *cfile, int cline);
size_t lc_strlcpy(char *dest, const char *src, size_t size);
size_t my_strlcpy(char *to , const char *from, int to_size, char *cfile, int cline);

#endif /* KERNEL_MODE */

#ifdef LC_DEBUG_ASSERT
#ifdef KERNEL_MODE
#define LC_ASSERT(expr)                        \
    {                                          \
        if (!(expr)) {                         \
        	_printk_("ASSERT[%s,%d] %s\n", __FILE__, __LINE__, #expr);                    \
			BUG();                             \
        }                                      \
    }
#else
#define LC_ASSERT(expr)                        \
    {                                          \
        if (!(expr)) {                         \
        	printf("ASSERT[%s,%d] %s\n", __FILE__, __LINE__, #expr);                    \
			exit(1);                             \
        }                                      \
    }
#endif
#else /* LC_DEBUG */

#define LC_ASSERT(expr)

#endif /* LC_DEBUG */

#endif /* _PIL_H_ */

/* vi:set ts=4 sw=4: */
