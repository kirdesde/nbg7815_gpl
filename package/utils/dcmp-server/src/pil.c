/*
** pil.c
**
*/

#include "pil.h"
#include "../osi4/osi4.h"

unsigned int total_mem = 0;
LC_DEFINE_SPINLOCK(mem_in_use_list_lock);

#ifdef MEM_GARBAGE_COLLECT
memlink *mem_in_use_list = NULL;
#endif /* MEM_GARBAGE_COLLECT */



void
initMem(void)
{
#ifdef MEM_GARBAGE_COLLECT
	spin_lock_init(&mem_in_use_list_lock);
	mem_in_use_list = NULL;
#endif
}

void
cleanupMem(void)
{
#ifdef MEM_GARBAGE_COLLECT
	memlink *ptr;

	LC_LOG_INFO(LOG_MEM, "total mem is %u\n", total_mem);
	ptr = mem_in_use_list;
	while (ptr != NULL)
	{
		//_printk_("%s: Line %d, Size %d.\n", ptr->codeFile, ptr->codeLine, ptr->size);
		my_free((void *) ((char *) ptr + sizeof(memlink)), 0, __FILE__, __LINE__);
		ptr = mem_in_use_list;
	}
	LC_LOG_INFO(LOG_MEM, "total mem is %u\n", total_mem);
#endif
}

void
dumpmem(void)
{
#ifdef MEM_GARBAGE_COLLECT
	memlink *ptr;
	unsigned long lock_flag;
	unsigned int in_use_mem = 0;

	typedef struct _mem_chunk_s mem_chunk_t;
	struct _mem_chunk_s
	{
		char* cFile;
		int cLine;
		int cSize;
		int cCnt;
		int tSize;
		mem_chunk_t* next;
	};
	mem_chunk_t* mc_head = NULL;
	mem_chunk_t* mc_p = NULL;
	mem_chunk_t* mc_prev_p = NULL;

	_spin_lock_irqsave_(&mem_in_use_list_lock, lock_flag);
	ptr = mem_in_use_list;
	while (ptr != NULL)
	{
		if (ptr->magicWord != MEM_MAGIC_TAG)
		{
			LC_LOG_WARN(LOG_MEM, "magicWord=%x\n", ptr->magicWord);
			LC_LOG_WARN(LOG_MEM, "%s: Line %d, Size %d.\n", ptr->codeFile, ptr->codeLine, ptr->size);
		}
		else
		{
			if (mc_head == NULL)
			{
				if ((mc_head = _kmalloc_(sizeof(mem_chunk_t), GFP_ATOMIC)) == NULL)
				{
					LC_LOG_ERROR(LOG_MEM, "[1]kmalloc(sizeof(mem_chunk_t)) failed!\n");
					_spin_unlock_irqrestore_(&mem_in_use_list_lock, lock_flag);
					return;
				}
				mc_head->cFile = ptr->codeFile;
				mc_head->cLine = ptr->codeLine;
				mc_head->cSize = ptr->size;
				mc_head->tSize = ptr->size;
				mc_head->cCnt = 1;
				mc_head->next = NULL;
			}
			else
			{
				mc_prev_p = NULL;
				mc_p = mc_head;
				while (mc_p)
				{
					if ((mc_p->cFile == ptr->codeFile) &&
					        (mc_p->cLine == ptr->codeLine) &&
					        (mc_p->cSize == ptr->size))
					{
						mc_p->tSize += ptr->size;
						mc_p->cCnt++;
						break;
					}
					mc_prev_p = mc_p;
					mc_p = mc_p->next;
				}
				if (mc_prev_p && !mc_p)
				{
					if ((mc_p = _kmalloc_(sizeof(mem_chunk_t), GFP_ATOMIC)) == NULL)
					{
						LC_LOG_ERROR(LOG_MEM, "[2]kmalloc(sizeof(mem_chunk_t)) failed!\n");
						_spin_unlock_irqrestore_(&mem_in_use_list_lock, lock_flag);
						return;
					}
					mc_p->cFile = ptr->codeFile;
					mc_p->cLine = ptr->codeLine;
					mc_p->cSize = ptr->size;
					mc_p->tSize = ptr->size;
					mc_p->cCnt = 1;
					mc_p->next = NULL;
					mc_prev_p->next = mc_p;
				}
			}
		}
		in_use_mem += ptr->size;
		ptr = ptr->next;
	}
	LC_LOG_INFO(LOG_MEM, "total_mem=%u, in_use_mem=%u\n", total_mem, in_use_mem);
	_spin_unlock_irqrestore_(&mem_in_use_list_lock, lock_flag);

	while (mc_head)
	{
		LC_LOG_INFO(LOG_MEM, "(%s:%d)cSize=%d,cCnt=%d,tSize=%d.\n",
		         strrchr(mc_head->cFile, '/'),
		         mc_head->cLine,
		         mc_head->cSize,
		         mc_head->cCnt,
		         mc_head->tSize);
		mc_p = mc_head;
		mc_head = mc_head->next;
		_kfree_(mc_p);
	}
#endif
}

unsigned int
usedMem(void)
{
	return total_mem;
}

static char cvtIn[] =
{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,   /* '0' - '9' */
	100, 100, 100, 100, 100, 100, 100,  /* punctuation */
	10, 11, 12, 13, 14, 15, 16, 17, 18, 19, /* 'A' - 'Z' */
	20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
	30, 31, 32, 33, 34, 35,
	100, 100, 100, 100, 100, 100,   /* punctuation */
	10, 11, 12, 13, 14, 15, 16, 17, 18, 19, /* 'a' - 'z' */
	20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
	30, 31, 32, 33, 34, 35
};


int lc_hex2bin(unsigned char* hex_str, unsigned char** bin_pp, unsigned int* bin_cnt_p)
{
	int i;
	int hex_str_len = strlen((const char*)hex_str);
	unsigned char* tmp_buf = NULL;
	int tmp_cnt = 0;
	char in_use = 0;
	unsigned char h_hex = 0;
	unsigned char c;

	if(hex_str_len <= 0) return -1;

	tmp_buf = malloc(hex_str_len);
	if(tmp_buf == NULL) return -1;

	for(i=0; i < hex_str_len; i++)
	{
		c = hex_str[i];
		if( c >= '0' && c <= '9')
		{
			if(in_use == 0)
			{
				h_hex = c - '0';
			}
			else
			{
				tmp_buf[tmp_cnt++] = (h_hex << 4) | (c-'0');
			}
			in_use = !in_use;
		}
		else if( c >= 'a' && c <= 'f')
		{
			if(in_use == 0)
			{
				h_hex = c - 'a' + 10;
			}
			else
			{
				tmp_buf[tmp_cnt++] = (h_hex << 4) | (c-'a'+10);
			}
			in_use = !in_use;
		}
		else if( c >= 'A' && c <= 'F')
		{
			if(in_use == 0)
			{
				h_hex = c - 'A' + 10;
			}
			else
			{
				tmp_buf[tmp_cnt++] = (h_hex << 4) | (c-'A'+10);
			}
			in_use = !in_use;
		}
	}

	if(in_use)
	{
		LC_LOG_ERROR(LOG_MEM, "should not in used here!\n");
		free(tmp_buf);
		return -1;
	}

	tmp_buf[tmp_cnt] = '\0';
	(*bin_pp) = tmp_buf;
	(*bin_cnt_p) = tmp_cnt;

	return 0;
}

/*
 *----------------------------------------------------------------------
 *
 * strtoul --
 *
 *	Convert an ASCII string into an integer.
 *
 * Results:
 *	The return value is the integer equivalent of string.  If endPtr
 *	is non-NULL, then *endPtr is filled in with the character
 *	after the last one that was part of the integer.  If string
 *	doesn't contain a valid integer value, then zero is returned
 *	and *endPtr is set to string.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

unsigned long int
strtoul(const char *string,
        char **endPtr,
        int base)
{
	register const char *p;
	register unsigned long int result = 0;
	register unsigned digit;
	int anyDigits = 0;
	int negative = 0;
	int overflow = 0;

	/*
	 * Skip any leading blanks.
	 */
	p = string;
	while (_isspace_((unsigned char) (*p)))
	{
		p += 1;
	}
	if (*p == '-')
	{
		negative = 1;
		p += 1;
	}
	else
	{
		if (*p == '+')
		{
			p += 1;
		}
	}

	/*
	 * If no base was provided, pick one from the leading characters
	 * of the string.
	 */
	if (base == 0)
	{
		if (*p == '0')
		{
			p += 1;
			if ((*p == 'x') || (*p == 'X'))
			{
				p += 1;
				base = 16;
			}
			else
			{

				/*
				 * Must set anyDigits here, otherwise "0" produces a
				 * "no digits" error.
				 */

				anyDigits = 1;
				base = 8;
			}
		}
		else
			base = 10;
	}
	else if (base == 16)
	{

		/*
		 * Skip a leading "0x" from hex numbers.
		 */

		if ((p[0] == '0') && ((p[1] == 'x') || (p[1] == 'X')))
		{
			p += 2;
		}
	}

	/*
	 * Sorry this code is so messy, but speed seems important.  Do
	 * different things for base 8, 10, 16, and other.
	 */
	if (base == 8)
	{
		unsigned long maxres = ULONG_MAX >> 3;

		for (;; p += 1)
		{
			digit = *p - '0';
			if (digit > 7)
			{
				break;
			}
			if (result > maxres)
			{
				overflow = 1;
			}
			result = (result << 3);
			if (digit > (ULONG_MAX - result))
			{
				overflow = 1;
			}
			result += digit;
			anyDigits = 1;
		}
	}
	else if (base == 10)
	{
		unsigned long maxres = ULONG_MAX / 10;

		for (;; p += 1)
		{
			digit = *p - '0';
			if (digit > 9)
			{
				break;
			}
			if (result > maxres)
			{
				overflow = 1;
			}
			result *= 10;
			if (digit > (ULONG_MAX - result))
			{
				overflow = 1;
			}
			result += digit;
			anyDigits = 1;
		}
	}
	else if (base == 16)
	{
		unsigned long maxres = ULONG_MAX >> 4;

		for (;; p += 1)
		{
			digit = *p - '0';
			if (digit > ('z' - '0'))
			{
				break;
			}
			digit = cvtIn[digit];
			if (digit > 15)
			{
				break;
			}
			if (result > maxres)
			{
				overflow = 1;
			}
			result = (result << 4);
			if (digit > (ULONG_MAX - result))
			{
				overflow = 1;
			}
			result += digit;
			anyDigits = 1;
		}
	}
	else if (base >= 2 && base <= 36)
	{
		unsigned long maxres = ULONG_MAX / base;

		for (;; p += 1)
		{
			digit = *p - '0';
			if (digit > ('z' - '0'))
			{
				break;
			}
			digit = cvtIn[digit];
			if (digit >= ((unsigned) base))
			{
				break;
			}
			if (result > maxres)
			{
				overflow = 1;
			}
			result *= base;
			if (digit > (ULONG_MAX - result))
			{
				overflow = 1;
			}
			result += digit;
			anyDigits = 1;
		}
	}

	/*
	 * See if there were any digits at all.
	 */
	if (!anyDigits)
	{
		p = string;
	}

	if (endPtr != 0)
	{
		/* unsafe, but required by the strtoul prototype */
		*endPtr = (char *) p;
	}

	if (overflow)
	{
#ifndef KERNEL_MODE
		errno = ERANGE;
#endif

		return ULONG_MAX;
	}
	if (negative)
	{
		return -result;
	}
	return result;
}

/*
    CONST char *string;          String of ASCII digits, possibly
                                 preceded by white space.  For bases
                                 greater than 10, either lower- or
                                 upper-case digits may be used.

    char **endPtr;               Where to store address of terminating
                                  character, or NULL.
    int base;                    Base for conversion.  Must be less
                                 than 37.  If 0, then the base is chosen
                                 from the leading characters of string:
                                 "0x" means hex, "0" means octal, anything
                                 else means decimal.
*/

long int
strtol(const char *string,
       char **endPtr,
       int base)
{
	register char *p;
	long result;

	/*
	 * Skip any leading blanks.
	 */

	p = (char *) string;
	while (_isspace_((unsigned char) (*p)))
	{
		p += 1;
	}

	/*
	 * Check for a sign.
	 */

	if (*p == '-')
	{
		p += 1;
		result = -(strtoul(p, endPtr, base));
	}
	else
	{
		if (*p == '+')
		{
			p += 1;
		}
		result = strtoul(p, endPtr, base);
	}
	if ((result == 0) && (endPtr != 0) && (*endPtr == p))
	{
		*endPtr = (char *) string;
	}
	return result;
}

char *
lc_strdup(char *strold)
{
	char *strnew;
	int len;

	if (!strold)
	{
		return NULL;
	}
	len = _strlen_(strold);
	if (len <= 0)
	{
		return NULL;
	}
	strnew = (char *) malloc(len + 1);
	if (!strnew)
	{
		return NULL;
	}
	STRLCPY(strnew, strold, len + 1);
	return strnew;
}

char *
lc_strndup(char *strold, size_t size)
{
	char *strnew;
	int len;

	if (!strold)
	{
		return NULL;
	}
	len = _strlen_(strold);
	if (len <= 0)
	{
		return NULL;
	}
	if(len > size)
	{
		len = size;
	}
	strnew = (char *) malloc(len + 1);
	if (!strnew)
	{
		return NULL;
	}
	STRLCPY(strnew, strold, len + 1);
	return strnew;
}

char *
inet_ntoa(struct in_addr ina)
{
	static char buf[4 * sizeof "123"];
	unsigned char *ucp = (unsigned char *) & ina;

	_sprintf_(buf, LC_IPV4_FMT,
	          ucp[0] & 0xff, ucp[1] & 0xff, ucp[2] & 0xff, ucp[3] & 0xff);
	return buf;
}

/*
time_t
timewrap(time_t *timeptr)
{
        time_t now_time;
        now_time = (time_t) get_seconds();
	if (timeptr)
        {
   	    *timeptr = now_time;
        }
	return now_time;
}
*/

long int
atol(char *p)
{
	return strtol(p, (char **) NULL, 10);
}

int
atoi(char *p)
{
	register int n;
	register int f;

	n = 0;
	f = 0;
	for (;; p++)
	{
		switch (*p)
		{
		case ' ':
		case '\t':
			continue;
		case '-':
			f++;
		case '+':
			p++;
		}
		break;
	}
	while (*p >= '0' && *p <= '9')
		n = n * 10 + *p++ - '0';
	return (f ? -n : n);
}

void
itoa(int n, char *p, int sz)
{
	int mod;
	int i = 0;
	char *ph, *pt;
	char tmp;

	if (!p || !sz)
		return;

	memset(p, 0, sz);
	if (!n)
	{
		*p = '0';
		return;
	}

	while (i < sz - 1 && n > 0)
	{
		mod = n % 10;
		n /= 10;

		*(p + i++) = mod + '0';
	}

	ph = p;
	pt = p + _strlen_(p) - 1;
	while (ph < pt)
	{
		tmp = *ph;
		*ph = *pt;
		*pt = tmp;

		ph++;
		pt--;
	}
}

/* Borrow from glibc */

size_t
strspn(const char *s,
       const char *accept)
{
	const char *p;
	const char *a;
	size_t count = 0;

	//_printk_("strspn s %s, accept %s\n", s, accept);

	for (p = s; (*p) != '\0'; ++p)
	{
		for (a = accept; (*a) != '\0'; ++a)
		{
			if ((*p) == (*a))
				break;
		}
		if ((*a) == '\0')
			return count;
		else
			++count;
	}

	return count;
}

char *
strpbrk(const char *s,
        const char *accept)
{
	while (*s != '\0')
	{
		const char *a = accept;

		while (*a != '\0')
			if (*a++ == *s)
				return (char *) s;
		++s;
	}

	return NULL;
}

static char *olds;

char *
strtok(char *s,
       const char *delim)
{
	char *token;

	if (s == NULL)
	{
		//_printk_("olds is %s\n", olds);
		s = olds;
	}

	if ((s == NULL) || (*s == '\0'))
	{
		//_printk_("s and olds are empty..\n");
		return NULL;
	}


	/* Scan leading delimiters.  */
	//_printk_("strtok %s %s\n", s, delim);
	s += strspn(s, delim);
	//_printk_("after strspn\n");
	if ((*s) == '\0')
	{
		//_printk_("last pattern\n");
		olds = s;
		return NULL;
	}

	/* Find the end of the token.  */
	token = s;
	s = strpbrk(token, delim);
	if (s == NULL)
		/* This token finishes the string.  */
		olds = _memchr_(token, '\0', strlen(token));
	else
	{
		/* Terminate the token and make OLDS point past it.  */
		*s = '\0';
		olds = s + 1;
	}
	return token;
}

char *strtok_r(char *s,
               const char *delim,
               char **save_ptr)
{
	char *token;

	if (s == NULL)
		s = *save_ptr;

	/* Scan leading delimiters.  */
	s += strspn(s, delim);
	if (*s == '\0')
	{
		//*save_ptr = s;
		return NULL;
	}

	/* Find the end of the token.  */
	token = s;
	s = strpbrk(token, delim);
	if (s == NULL)
		/* This token finishes the string.  */
		*save_ptr = _strchr_(token, '\0');
		//*save_ptr = _memchr_(token, '\0', strlen(token));
	else
	{
		/* Terminate the token and make *SAVE_PTR point past it.  */
		*s = '\0';
		*save_ptr = s + 1;
	}
	return token;
}

char *
nstrstr(unsigned char *ptr,
        unsigned char *str,
        int times)
{
	unsigned char *result = ptr;
	int i;

	for (i = 0; i < times; i++)
	{
		if (i > 0)
			result++;
		result = _strstr_(result, str);
	}

	return result;
}

char *
revstrnstr(unsigned char *s1,
           unsigned char *s2,
           int len1,
           int len2)
{
	int len, i;

	// Check if the substring is longer than the string being searched.
	if (len2 > len1)
		return 0;

	// Go upto <len>
	len = len1 - len2;

	for (i = len; i >= 0; i--)
	{
		if (_memcmp_(s1 + i, s2, len2) == 0)
			// Found a match!  Return the index.
			return s1 + i;
	}

	return 0;
}

char *
lc_strnstr(unsigned char *s1,
        unsigned char *s2,
        int len1,
        int len2)
{
#if 0
	int len, i;

	// Check if the substring is longer than the string being searched.
	if (len2 > len1)
		return 0;

	// Go upto <len>
	len = len1 - len2;

	for (i = 0; i <= len; i++)
	{
		if (memcmp(s1 + i, s2, len2) == 0)
			// Found a match!  Return the index.
			return s1 + i;
	}

	return 0;
#else //enhance performance by avoiding already compared cells

	int i, j, lastStart;

	if (len2 > len1)
		return 0;

	lastStart = len1 - len2;
	i = 0;
	while (i <= lastStart)
	{
		j = 0;
		for (; j < len2 && s2[j] == s1[i + j]; j++)
			;

		if (j == len2)          //completely matched
			return (s1 + i);
		else if (j == 0)        //1st char mismatched
			i++;
		else                    //skip already matched(j length)
			i += j;
	}

	return 0;
	/*Test case: just for unit test
	   s2             s1        result
	   a strnstr abcabce:abcabce
	   abc strnstr abcabce:abcabce
	   abce strnstr abcabce:abce
	   e strnstr abcabce:e
	   "" strnstr abcabce:abcabce
	   X strnstr abcabce:(null)
	 */
#endif
}

char *
strncasestr(unsigned char *s1,
            unsigned char *s2,
            int len1,
            int len2)
{
	int len, i;

	// Check if the substring is longer than the string being searched.
	if (len2 > len1)
		return 0;

	// Go upto <len>
	len = len1 - len2;

	for (i = 0; i <= len; i++)
	{
		if (_strncasecmp_(s1 + i, s2, len2) == 0)
			// Found a match!  Return the index.
			return s1 + i;
	}

	return 0;
}

char *
strcasestr(unsigned char *s1,
           unsigned char *s2)
{
	int len, len1, len2, i;

	len1 = _strlen_(s1);
	len2 = _strlen_(s2);
	// Check if the substring is longer than the string being searched.
	if (len2 > len1)
		return 0;

	// Go upto <len>
	len = len1 - len2;

	for (i = 0; i <= len; i++)
	{
		if (_strncasecmp_(s1 + i, s2, len2) == 0)
			// Found a match!  Return the index.
			return s1 + i;
	}

	return 0;
}

//if return != 0
//(1)str_offset==0:shorter is substring of longer
//(2)str_offset!=0:prefix-of-shorter is substring of longer
//if return 0: len?< 0 or nothing matched at all
char *
substrnstr(unsigned char *s1,
           unsigned char *s2,
           int len1,
           int len2,
           unsigned short *str_offset,
           int is_case)
{
	int len = 0, i = 0, scope = 0;
	int cmp_len = 0;


	if (!s1 || !s2 || !str_offset)
	{
		LC_LOG_ERROR(LOG_MEM, "!! Error s1=%p s2=%p str_offset=%p\n", s1, s2, str_offset);
		return NULL;
	}
	if (len2 <= 0 || len1 <= 0)
	{
		return 0;
	}

	//s1:len1:|+++++++++|
	//           (scope)
	//s2:len2:|+++++|(len)|
	//           |(len)|+++++|
	if (len1 - len2 > 0)
	{
		scope = len1;
		len = len1 - len2;
	}
	//s1:len1:|+++++|
	//s2:len2:|+++++++++|
	//               (scope)
	else                        //len1 <= len2
	{
		scope = len2;
	}

	/*i.e.
	   s1:abcde
	   s2:xyz
	         xyz
	           xyz
	   (1)look if s2 itself is s1's substring
	   (2)if (1) failed, look if "prefix-of-s2" is s1's substring with prefix-len recoreded in str_offset
	*/
	for (i = 0; i < scope /*longer str */ ; i++)
	{
		if (len1 - len2 > 0)    //s2 shorter
		{
			if (i > len)
			{
				cmp_len = len2 - (i - len); //decrease len2 by 1 as compare length, want compare "prefix-of-s2"
			}
			else
			{
				cmp_len = len2;
			}
		}
		else                    //s1 shorter:len1 <= len2
		{
			if (i >= len1)
				break;
			//i<len1
			cmp_len = len1 - i; //decrease len1 by 1 as compare length
		}
		if (is_case)
		{
			if (_strncasecmp_(s1 + i, s2, cmp_len) == 0)
			{
				if (cmp_len != len2)    //cmp_len has been decreased by 1
				{
					*str_offset = cmp_len;
				}
				return s1 + i;
			}
		}
		else
		{
			if (_memcmp_(s1 + i, s2, cmp_len) == 0)
			{
				if (cmp_len != len2)
				{
					*str_offset = cmp_len;
				}
				return s1 + i;
			}
		}
	}                           //for

	return 0;
}

char* strrch(char* str, int c)
{
	char* p = str;
	while (str && *str)
	{
		if (*str == c) p = str;
		str++;
	}
	return p;
}

int
rand(void)
{
	int val;
	_get_random_bytes_((char *) &val, sizeof(int));
	return val;
}

#define MAX_DMA_SIZE 65535
#define MAX_ATOMIC_SIZE 131056

void *
my_calloc(int size,
          int num,
          int flag,
          char *cfile,
          int cline)
{
	void *ptr;
	unsigned int total_size;
	memlink *link;
	unsigned long lock_flag;
	u8 mem_type;

	total_size = (size * num) + sizeof(memlink);
	if (flag)
	{
		if (total_size > MAX_DMA_SIZE)
		{
			LC_LOG_ERROR(LOG_MEM, "%s:%d, Too large for DMA! (%d)\n", cfile, cline, total_size);
			return NULL;
		}
		link = kmalloc(total_size, GFP_ATOMIC | GFP_DMA);

		mem_type = MEM_TYPE_KMALLOC_DMA;
	}
	else
	{
		if (total_size > MAX_ATOMIC_SIZE)
		{
			link = _vmalloc_(total_size);
			mem_type = MEM_TYPE_VMALLOC;
		}
		else
		{
			link = kmalloc(total_size, GFP_ATOMIC);
			mem_type = MEM_TYPE_KMALLOC;
		}
	}

	if (!link)
	{
		LC_LOG_ERROR(LOG_MEM, "%s:%d, unable to kernel malloc, %u\n", cfile, cline, total_mem);
		return NULL;
	}

	link->size = total_size;
	link->codeFile = cfile;
	link->codeLine = cline;
	link->memType = mem_type;

	_spin_lock_irqsave_(&mem_in_use_list_lock, lock_flag);
	total_mem += total_size;
#ifdef MEM_GARBAGE_COLLECT
	link->magicWord = MEM_MAGIC_TAG;
	if (mem_in_use_list != NULL)
	{
		mem_in_use_list->fore = link;
	}
	link->fore = NULL;
	link->next = mem_in_use_list;
	mem_in_use_list = link;
#endif
	_spin_unlock_irqrestore_(&mem_in_use_list_lock, lock_flag);


	ptr = (unsigned char *) link + sizeof(memlink);
	bzero(ptr, num * size);
	return ptr;
}

void *
my_realloc(void *ptr,
           int size,
           int flag,
           char *cfile,
           int cline)
{
	void *ptr_new;
	memlink *link;
	int old_size;

	ptr_new = my_malloc(size, flag, cfile, cline);
	if (ptr_new == NULL)
		return NULL;

	if (ptr == NULL)
	{
		return ptr_new;
	}
	/* Here we want to know old size from memlink */
	link = (memlink *) ((unsigned char *) ptr - sizeof(memlink));
	old_size = link->size - sizeof(memlink);

	/* Prevent buffer overflow */
	if (old_size > size)
	{
		memcpy(ptr_new, ptr, size);
	}
	else
	{
		memcpy(ptr_new, ptr, old_size);
	}
	my_free(ptr, flag, cfile, cline);
	return ptr_new;
}

void *
my_malloc(int size,
          int flag,
          char *cfile,
          int cline)
{
	void *ptr;
	unsigned int total_size;
	memlink *link;
	unsigned long lock_flag;
	u8 mem_type;

	total_size = size + sizeof(memlink);
	if (flag)
	{
		if (total_size > MAX_DMA_SIZE)
		{
			LC_LOG_ERROR(LOG_MEM, "%s:%d, Too large for DMA! (%d)\n", cfile, cline, total_size);
			return NULL;
		}

		link = kmalloc(total_size, GFP_ATOMIC | GFP_DMA);

		mem_type = MEM_TYPE_KMALLOC_DMA;
	}
	else
	{
		if (total_size > MAX_ATOMIC_SIZE)
		{
			link = _vmalloc_(total_size);
			mem_type = MEM_TYPE_VMALLOC;
		}
		else
		{
			link = _kmalloc_(total_size, GFP_ATOMIC);
			mem_type = MEM_TYPE_KMALLOC;
		}
	}

	if (!link)
	{
		LC_LOG_ERROR(LOG_MEM, "%s:%d, unable to kernel malloc, %u\n", cfile, cline, total_size);
		return NULL;
	}

	link->size = total_size;
	link->codeFile = cfile;
	link->codeLine = cline;
	link->memType = mem_type;

	_spin_lock_irqsave_(&mem_in_use_list_lock, lock_flag);
	total_mem += total_size;
#ifdef MEM_GARBAGE_COLLECT
	link->magicWord = MEM_MAGIC_TAG;
	if (mem_in_use_list != NULL)
	{
		mem_in_use_list->fore = link;
	}
	link->fore = NULL;
	link->next = mem_in_use_list;
	mem_in_use_list = link;
#endif
	_spin_unlock_irqrestore_(&mem_in_use_list_lock, lock_flag);

	ptr = (unsigned char *) link + sizeof(memlink);
	//_printk_("my_malloc() size=%d ptr=%p\n",size,ptr);
	return ptr;
}

int
my_free(void *ptr,
        int flag,
        char *cfile,
        int cline)
{
	unsigned int total_size;
	memlink *link;
	unsigned long lock_flag;

	if (!ptr)
		return 1;

	link = (memlink *) ((unsigned char *) ptr - sizeof(memlink));

	if (link->magicWord != MEM_MAGIC_TAG)
	{
		LC_LOG_ERROR(LOG_MEM, "magicWord=%x\n", link->magicWord);
		LC_LOG_ERROR(LOG_MEM, "%s: Fix me! Free an invalid address=%p from %s, %d.\n",
		         __FUNCTION__, ptr, cfile, cline );
		return 1;
	}

	total_size = link->size;

	_spin_lock_irqsave_(&mem_in_use_list_lock, lock_flag);
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
	link->magicWord = FREE_MEM_MAGIC_TAG;
#endif
	_spin_unlock_irqrestore_(&mem_in_use_list_lock, lock_flag);

	if (flag)
	{
		if (link->memType == MEM_TYPE_KMALLOC || link->memType == MEM_TYPE_KMALLOC_DMA)
		{
			_kfree_(link);
		}
		else
		{
			LC_LOG_ERROR(LOG_MEM, "%s: Fix me! address=%p is MEM_TYPE_VMALLOC, but free it with kfree() from %s, %d.\n", __FUNCTION__, ptr, cfile, cline );
			_vfree_(link);
		}
	}
	else
	{
		if (total_size > MAX_ATOMIC_SIZE)
		{
			if (link->memType == MEM_TYPE_VMALLOC)
			{
				_vfree_(link);
			}
			else
			{
				LC_LOG_ERROR(LOG_MEM, "%s: Fix me! address=%p is MEM_TYPE_KMALLOC, but free it with vfree() from %s, %d.\n", __FUNCTION__, ptr, cfile, cline );
				_kfree_(link);
			}
		}
		else
		{
			if (link->memType == MEM_TYPE_KMALLOC || link->memType == MEM_TYPE_KMALLOC_DMA)
			{
				_kfree_(link);
			}
			else
			{
				LC_LOG_ERROR(LOG_MEM, "%s: Fix me! address=%p is MEM_TYPE_VMALLOC, but free it with kfree() from %s, %d.\n", __FUNCTION__, ptr, cfile, cline );
				_vfree_(link);
			}
		}
	}

	return 0;
}

int
checkMemStatus(char *p_mem,
               char *cfun,
               int cline)
{
	memlink *p_memlink = NULL;

	if (!p_mem)
	{
		//_printk_("!! Error %s %d: NULL p_mem\n", cfun, cline);
		return 1;
	}
	p_memlink = (memlink *) (p_mem - sizeof(memlink));
	if (p_memlink->magicWord != MEM_MAGIC_TAG)
	{
		//_printk_("!! Error %s %d: memory space have been freed or invalid. magicWord=%x\n",cfun, cline, p_memlink->magicWord);
		return 1;
	}
	return 0;
}

void * my_memcpy(void *to , const void *from, int size, char *cfile, int cline)
{
	// 1. check if size abnormal
	if (size <= 0)
	{
		LC_LOG_WARN(LOG_MEM, "FILE:%s, LINE:%d, size <= 0 in MEMCPY[size=%d].\n", cfile, cline, size);
	}

	// 2. check pointer is NULL
	if (to == NULL)
	{
		LC_LOG_ERROR(LOG_MEM, "FILE:%s, LINE:%d, \"to\" is NULL in MEMCPY!\n", cfile, cline);
		return NULL;
	}
	if (from == NULL)
	{
		LC_LOG_ERROR(LOG_MEM, "FILE:%s, LINE:%d, \"from\" is NULL in MEMCPY!\n", cfile, cline);
		return NULL;
	}

	// 3. check if from/to overlapping
	if ((to >= from) && (to <= from + size))//from--to--(from+size)
	{
		LC_LOG_WARN(LOG_MEM, "File:%s, LINE:%d, from-to-size overlapping in MEMCPY[from:0x%p,to:0x%p,size:%d].\n", cfile, cline, from, to, size);
	}


	return _memcpy_(to, from, (__kernel_size_t)size);

}

/* Borrow from linux kernel lib. strlcpy impl.
 *  Why not use strlcpy() directly? bcuz. this function is not available on all linux kernels
 */
size_t lc_strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size)
	{
		size_t len = (ret >= size) ? size - 1 : ret;
		_memcpy_(dest, src, len);
		dest[len] = '\0';
	}
	return ret;
}

size_t my_strlcpy(char *to , const char *from, int to_size, char *cfile, int cline)
{
	int from_len = _strlen_(from);

	// 1. check if size abnormal
	if (to_size <= 0)
	{
		LC_LOG_WARN(LOG_MEM, "FILE:%s, LINE:%d, to_size <= 0 in STRLCPY[to_size=%d].\n", cfile, cline, to_size);
	}

	if (to_size < from_len)
	{
		LC_LOG_WARN(LOG_MEM, "FILE:%s, LINE:%d,to_size < from_len in STRLCPY[to_size=%d,from_len=%d].\n", cfile, cline, to_size, from_len);
	}

	// 2. check pointer NULL
	if (to == NULL)
	{
		LC_LOG_ERROR(LOG_MEM, "FILE:%s, LINE:%d, \"to\" is NULL in STRLCPY!\n", cfile, cline);
		return 0;
	}

	if (from == NULL)
	{
		LC_LOG_ERROR(LOG_MEM, "FILE:%s, LINE:%d, \"from\" parameter is NULL in STRLCPY!\n", cfile, cline);
		return 0;

	}

	// 3. check from/to overlapping
	if ( (from <= to) && (to <= from + from_len))
	{
		LC_LOG_WARN(LOG_MEM, "File:%s, LINE:%d, from-to-from_len overlapping in STRLCPY[from:0x%p,to:0x%p,from_len:%d].\n", cfile, cline, from, to, from_len);
	}

	return lc_strlcpy(to, from, (size_t)to_size);

}


static int
inet_pton4(const char *src, unsigned char *dst)
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
#define NS_INADDRSZ     4
	unsigned char tmp[NS_INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr(digits, ch)) != NULL) {
			unsigned int new = *tp * 10 + (pch - digits);

			if (saw_digit && *tp == 0)
				return (0);
			if (new > 255)
				return (0);
			*tp = new;
			if (!saw_digit) {
				if (++octets > 4)
					return (0);
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
		} else
			return (0);
	}
	if (octets < 4)
		return (0);
	memcpy(dst, tmp, NS_INADDRSZ);
	return (1);
}

static int
inet_pton6(const char *src, unsigned char *dst)
{
	static const char xdigits_l[] = "0123456789abcdef",
			   xdigits_u[] = "0123456789ABCDEF";
#define NS_IN6ADDRSZ    16
#define NS_INT16SZ      2
	unsigned char tmp[NS_IN6ADDRSZ], *tp, *endp, *colonp;
	const char *xdigits, *curtok;
	int ch, seen_xdigits;
	unsigned int val;

	memset((tp = tmp), '\0', NS_IN6ADDRSZ);
	endp = tp + NS_IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	seen_xdigits = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (++seen_xdigits > 4)
				return (0);
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!seen_xdigits) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			} else if (*src == '\0') {
				return (0);
			}
			if (tp + NS_INT16SZ > endp)
				return (0);
			*tp++ = (unsigned char) (val >> 8) & 0xff;
			*tp++ = (unsigned char) val & 0xff;
			seen_xdigits = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) &&
				inet_pton4(curtok, tp) > 0) {
			tp += NS_INADDRSZ;
			seen_xdigits = 0;
			break;  /*%< '\\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (seen_xdigits) {
		if (tp + NS_INT16SZ > endp)
			return (0);
		*tp++ = (unsigned char) (val >> 8) & 0xff;
		*tp++ = (unsigned char) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		if (tp == endp)
			return (0);
		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	memcpy(dst, tmp, NS_IN6ADDRSZ);
	return (1);
}

int inet_pton(int af, const char *src, void *dst)
{
	switch (af)
	{
	case AF_INET:
		return inet_pton4(src, dst);
	case AF_INET6:
		return inet_pton6(src, dst);
	default:
		return (-1);
    }
	/* NOTREACHED */
}

static char *
inet_ntop4(const unsigned char *src, char *dst, size_t size)
{
	static const char fmt[] = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];
	int l;

	l = snprintf(tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]);
	if (l <= 0 || (size_t) l >= size) {
		return (NULL);
	}
	strlcpy(dst, tmp, size);
	return (dst);
}

static char *
inet_ntop6(const unsigned char *src, char *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
	struct { int base, len; } best, cur;
#define NS_IN6ADDRSZ    16
#define NS_INT16SZ      2
	unsigned int words[NS_IN6ADDRSZ / NS_INT16SZ];
	int i;

	/*
	 * Preprocess:
	 *      Copy the input (bytewise) array into a wordwise array.
	 *      Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < NS_IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	best.len = 0;
	cur.base = -1;
	cur.len = 0;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
				i < (best.base + best.len)) {
			if (i == best.base)
				*tp++ = ':';
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			*tp++ = ':';
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 && (best.len == 6 ||
					(best.len == 7 && words[7] != 0x0001) ||
					(best.len == 5 && words[5] == 0xffff))) {
			if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
				return (NULL);
			tp += strlen(tp);
			break;
		}
		tp += sprintf(tp, "%x", words[i]);
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) ==
			(NS_IN6ADDRSZ / NS_INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((size_t)(tp - tmp) > size) {
		return (NULL);
	}
	strcpy(dst, tmp);
	return (dst);
}

char *
inet_ntop(int af, const void *src, char *dst, size_t size)
{
	switch (af) {
		case AF_INET:
			return (inet_ntop4(src, dst, size));
		case AF_INET6:
			return (inet_ntop6(src, dst, size));
		default:
			return (NULL);
	}
	/* NOTREACHED */
}

/* vi:set ts=4 sw=4: */
