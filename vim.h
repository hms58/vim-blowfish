#ifndef VIM_H_
#define VIM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FEAT_CRYPT
#define HAVE_CONFIG_H
#define _(x) x
#define EMSG(x) printf(x)

#define BF_BLOCK    8
#define BF_BLOCK_MASK 7
#define BF_MAX_CFB_LEN  (8 * BF_BLOCK)

# define CRYPT_M_ZIP	0
# define CRYPT_M_BF	1
# define CRYPT_M_BF2	2
# define CRYPT_M_COUNT	3 /* number of crypt methods */

#define __ARGS(x) x
#define UINT32_T unsigned int
typedef unsigned char char_u;
typedef struct {
    int	    method_nr;
    void    *method_state;  /* method-specific state information */
} cryptstate_T;  

typedef struct {
  UINT32_T total[2];
  UINT32_T state[8];
  char_u   buffer[64];
} context_sha256_T;

#define BUFSIZE 512		/* long enough to hold a file name path */
#define NUL 0

#define FAIL 0
#define OK 1

#ifndef FALSE
# define FALSE 0
#endif
#ifndef TRUE
# define TRUE 1
#endif

#define STRLEN(s)	    strlen((char *)(s))
#define STRCPY(d, s)	    strcpy((char *)(d), (char *)(s))
#define STRNCPY(d, s, n)    strncpy((char *)(d), (char *)(s), (size_t)(n))
#define STRCMP(d, s)	    strcmp((char *)(d), (char *)(s))


extern unsigned char* sha256_key(unsigned char *buf, unsigned char *salt, int salt_len);
extern void mch_memmove(void *src_arg, void *dst_arg, size_t  len);
extern void * vim_memset(void *ptr, int c, size_t  size);

extern int sha256_self_test();
extern int blowfish_self_test();
extern void crypt_blowfish_encode (cryptstate_T *state, unsigned char *from, size_t len, unsigned char *to);
extern void crypt_blowfish_decode (cryptstate_T *state, unsigned char *from, size_t len, unsigned char *to);
extern void crypt_blowfish_init (cryptstate_T *state, unsigned char *key, unsigned char *salt, int salt_len, unsigned char *seed, int seed_len);

extern char_u * alloc_clear(unsigned	    size);
#endif
