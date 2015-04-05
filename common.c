
#include <stdlib.h>

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
