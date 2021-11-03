

#ifndef __MYMALLOC_H__
#define __MYMALLOC_H__

#ifdef APPLY_MYMALLOC
#define calloc(size, num) my_calloc(size, num, __FILE__, __LINE__)

#define malloc(size)      my_malloc(size, __FILE__, __LINE__)

#define realloc(ptr, size)      my_realloc(ptr, size, __FILE__, __LINE__)

#define free(ptr)        my_free(ptr, __FILE__, __LINE__)

void usedMem(void);
void listMem(void);
void cleanupMem(void);
int my_free(void *ptr, char *cfile, int cline);
void * my_realloc(void *ptr, int size, char *cfile, int cline);
void * my_calloc(int size, int num, char *cfile, int cline);
void * my_malloc(int size, char *cfile, int cline);

#else /* APPLY_MYMALLOC */
#define usedMem()
#define listMem()
#define cleanupMem()
#endif /* APPLY_MYMALLOC */

#endif /* __MYMALLOC_H__ */


