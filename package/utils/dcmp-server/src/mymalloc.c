#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEM_GARBAGE_COLLECT
typedef struct _memlink memlink;

#define MEM_MAGIC_TAG 0xbeefdead
#define FREE_MEM_MAGIC_TAG 0xdeadbeef

struct _memlink
{
#ifdef MEM_GARBAGE_COLLECT
	memlink *fore;
	memlink *next;
#endif /* MEM_GARBAGE_COLLECT */
	unsigned int size;
	char * codeFile;
	int codeLine;
	unsigned int magicWord;
};


unsigned int total_mem = 0;
#ifdef MEM_GARBAGE_COLLECT
memlink *mem_in_use_list = NULL;
#endif /* MEM_GARBAGE_COLLECT */

int my_free(void *ptr, char *cfile, int cline);
void * my_realloc(void *ptr, int size, char *cfile, int cline);
void * my_calloc(int size, int num, char *cfile, int cline);
void * my_malloc(int size, char *cfile, int cline);

void
listMem(void)
{
	memlink *ptr;
	fprintf(stderr, "total mem is %d\n", total_mem);
	ptr = mem_in_use_list;
	while (ptr != NULL)
	{
		fprintf(stderr, "mem used, size %d, allocated in %s:%d\n",
		        ptr->size, ptr->codeFile, ptr->codeLine);
		ptr = ptr->next;
	}
}

void
cleanupMem(void)
{
#ifdef MEM_GARBAGE_COLLECT
	memlink *ptr;
	fprintf(stderr, "total mem is %d\n", total_mem);
	ptr = mem_in_use_list;
	while (ptr != NULL)
	{
		fprintf(stderr, "mem unfreed, size %d, allocated in %s:%d\n",
		        ptr->size, ptr->codeFile, ptr->codeLine);
		my_free((void *)((char *)ptr + sizeof(memlink)),  __FILE__, __LINE__);
		ptr = mem_in_use_list;
	}
	fprintf(stderr, "total mem is %d\n", total_mem);
#endif
}

void usedMem(void)
{
	fprintf(stderr, "total mem is %d\n", total_mem);
}

void *
my_calloc(int size, int num, char *cfile, int cline)
{
	void *ptr;
	unsigned int total_size;
	memlink *link;

	total_size = (size * num) + sizeof(memlink);
	link = malloc(total_size);
	if (!link)
	{
		printf("unable to malloc, %d\n", total_mem);
		return NULL;
	}
	total_mem += total_size;

	link->size = total_size;
	link->codeFile = cfile;
	link->codeLine = cline;
	link->magicWord = MEM_MAGIC_TAG;

#ifdef MEM_GARBAGE_COLLECT
	if (mem_in_use_list != NULL)
	{
		mem_in_use_list->fore = link;
	}
	link->fore = NULL;
	link->next = mem_in_use_list;
	mem_in_use_list = link;
#endif

	ptr = (unsigned char *)link + sizeof(memlink);
	memset(ptr, 0, num*size);
	return ptr;
}

void *
my_realloc(void *ptr, int size, char *cfile, int cline)
{
	void *ptr_new;
	memlink *link;
	int old_size;

	ptr_new = my_malloc(size, cfile, cline);
	if (ptr_new == NULL)
		return NULL;
	/* Here we want to know old size from memlink */
	link = (memlink *)((unsigned char *)ptr - sizeof(memlink));
	if (ptr != NULL)
	{
		old_size = link->size - sizeof(memlink);
		memcpy(ptr_new, ptr, old_size);
		my_free(ptr, cfile, cline);
	}
	return ptr_new;
}

void *
my_malloc(int size, char *cfile, int cline)
{
	void *ptr;
	unsigned int total_size;
	memlink *link;

	total_size = size + sizeof(memlink);
	link = malloc(total_size);
	if (!link)
	{
		printf("unable to malloc, %d\n", total_mem);
		return NULL;
	}

	total_mem += total_size;
	link->size = total_size;
	link->codeFile = cfile;
	link->codeLine = cline;
	link->magicWord = MEM_MAGIC_TAG;

#ifdef MEM_GARBAGE_COLLECT
	if (mem_in_use_list != NULL)
	{
		mem_in_use_list->fore = link;
	}
	link->fore = NULL;
	link->next = mem_in_use_list;
	mem_in_use_list = link;
#endif

	ptr = (unsigned char *)link + sizeof(memlink);
	return ptr;
}

int
my_free(void *ptr, char *cfile, int cline)
{
	unsigned int total_size;
	memlink *link;

	if (!ptr) return 1;

	link = (memlink *)((unsigned char *)ptr - sizeof(memlink));
	if ( link->magicWord != MEM_MAGIC_TAG )
	{
		printf("magicWord=%x\n", link->magicWord);
		printf("User %s: Fix me! Free an invalid address=%p\n", __FUNCTION__, ptr);
		printf("FILE%s: LINE=%d\n", cfile, cline);
		return 1;
	}

	total_size = link->size;
	total_mem -= total_size;

#ifdef MEM_GARBAGE_COLLECT
	if (link->next != NULL)
	{
		link->next->fore = link->fore;
	}
	if (link->fore != NULL)
	{
		link->fore->next = link->next;
	}
	else
	{
		mem_in_use_list = link->next;
	}
#endif

	link->magicWord = FREE_MEM_MAGIC_TAG;

	free(link);
	return 0;
}


