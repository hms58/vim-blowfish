
#include "vim.h"

void mch_memmove(void *src_arg, void *dst_arg, size_t  len) {
    char *dst = dst_arg, *src = src_arg;
    if (dst > src && dst < src + len)
    {
	src += len;
	dst += len;
	while (len-- > 0)
	    *--dst = *--src;
    }
    else				/* copy forwards */
	while (len-- > 0)
	    *dst++ = *src++;
}

void * vim_memset(void *ptr, int c, size_t  size)
{
    char *p = ptr;

    while (size-- > 0)
	*p++ = c;
    return ptr;
}


/*
 * Allocate memory and set all bytes to zero.
 */
    char_u *
alloc_clear(size)
    unsigned	    size;
{
    char_u *p;
    p = (char_u *)malloc((size_t)size);
    if (p != NULL)
	(void)vim_memset(p, 0, (size_t)size);
    return p;
}

