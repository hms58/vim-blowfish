#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int bf_self_test();

#define STRCMP(d, s)           strcmp((char *)(d), (char *)(s))
#define STRLEN(s)      strlen((char *)(s))

/* values for method_nr */
#define CRYPT_M_ZIP 0
#define CRYPT_M_BF  1
#define CRYPT_M_BF2 2
#define CRYPT_M_COUNT   3 /* number of crypt methods */

typedef struct {
    int     method_nr;
    void    *method_state;  /* method-specific state information */
} cryptstate_T;

typedef struct {
    char    *name;  /* encryption name as used in 'cryptmethod' */
    char    *magic; /* magic bytes stored in file header */
    int     salt_len;   /* length of salt, or 0 when not using salt */
    int     seed_len;   /* length of seed, or 0 when not using salt */
    int  (* self_test_fn)();
    void (* init_fn)(cryptstate_T *state, unsigned char *key, unsigned char *salt, int salt_len, unsigned char *seed, int seed_len);
    void (*encode_fn)(cryptstate_T *state, unsigned char *from, size_t len, unsigned char *to);
    void (*decode_fn)(cryptstate_T *state, unsigned char *from, size_t len, unsigned char *to);
} cryptmethod_T;    

void crypt_blowfish_encode (cryptstate_T *state, unsigned char *from, size_t len, unsigned char *to);
void crypt_blowfish_decode (cryptstate_T *state, unsigned char *from, size_t len, unsigned char *to);
void crypt_blowfish_init (cryptstate_T *state, unsigned char *key, unsigned char *salt, int salt_len, unsigned char *seed, int seed_len);
int blowfish_self_test (void);

void mch_memmove(void *src_arg, void *dst_arg, size_t  len);

/* index is method_nr of cryptstate_T, CRYPT_M_* */
static cryptmethod_T cryptmethods[CRYPT_M_COUNT] = {
    /* Blowfish/CFB + SHA-256 custom key derivation; implementation issues. */
    {
    "blowfish",
    "VimCrypt~02!",
    8,
    8,
    blowfish_self_test,
    crypt_blowfish_init,
    crypt_blowfish_encode, crypt_blowfish_decode,
    },

    /* Blowfish/CFB + SHA-256 custom key derivation; fixed. */
    {
    "blowfish2",
    "VimCrypt~03!",
    8,
    8,
    blowfish_self_test,
    crypt_blowfish_init,
    crypt_blowfish_encode, crypt_blowfish_decode,
    },
};

char    crypt_magic_head[] = "VimCrypt~";  
#define CRYPT_MAGIC_LEN 12  /* cannot change */




/*
 * Allocate a crypt state and initialize it.
 */
cryptstate_T* crypt_create(int method_nr, unsigned char *key, unsigned char *salt, int salt_len, unsigned char *seed, int seed_len) {
    cryptstate_T *state = (cryptstate_T *)malloc((int)sizeof(cryptstate_T));
    state->method_nr = method_nr;
    cryptmethods[method_nr].init_fn(state, key, salt, salt_len, seed, seed_len);
    return state;
}  

/*
 * Allocate a crypt state from a file header and initialize it.
 * Assumes that header contains at least the number of bytes that
 * crypt_get_header_len() returns for "method_nr".
 */
cryptstate_T* crypt_create_from_header(int method_nr, unsigned char *key, unsigned char *header) {
    unsigned char *salt = NULL;
    unsigned char *seed = NULL;
    int salt_len = cryptmethods[method_nr].salt_len;
    int seed_len = cryptmethods[method_nr].seed_len;

    if (salt_len > 0)
        salt = header + CRYPT_MAGIC_LEN;
    if (seed_len > 0)
        seed = header + CRYPT_MAGIC_LEN + salt_len;

    return crypt_create(method_nr, key, salt, salt_len, seed, seed_len);
}

/*
 * Get crypt method specifc length of the file header in bytes.
 */
int crypt_get_header_len(int method_nr) {
    return CRYPT_MAGIC_LEN
	+ cryptmethods[method_nr].salt_len
	+ cryptmethods[method_nr].seed_len;
}

/*
 * Return int value for crypt method name.
 * 0 for "zip", the old method.  Also for any non-valid value.
 * 1 for "blowfish".
 * 2 for "blowfish2".
 */
int crypt_method_nr_from_name(unsigned char  *name)
{
    int i;
    for (i = 0; i < CRYPT_M_COUNT; ++i)
    if (STRCMP(name, cryptmethods[i].name) == 0)
        return i;
    return 0;
}

/*
 * Get the crypt method used for a file from "ptr[len]", the magic text at the
 * start of the file.
 * Returns -1 when no encryption used.
 */
int crypt_method_nr_from_magic(char *ptr, int len)
{
    int i;

    if (len < CRYPT_MAGIC_LEN)
	return -1;

    for (i = 0; i < CRYPT_M_COUNT; i++)
	if (memcmp(ptr, cryptmethods[i].magic, CRYPT_MAGIC_LEN) == 0)
	    return i;

    i = (int)STRLEN(crypt_magic_head);
    if (len >= i && memcmp(ptr, crypt_magic_head, i) == 0)
	    printf("E821: File is encrypted with unknown method");

    return -1;
}   

/*
 * Read the crypt method specific header data from "fp".
 * Return an allocated cryptstate_T or NULL on error.
 */
cryptstate_T* crypt_create_from_file(FILE *fp, unsigned char *key)
{
    int     method_nr;
    int     header_len;
    char    magic_buffer[CRYPT_MAGIC_LEN];
    unsigned char  *buffer;
    cryptstate_T *state;

    if (fread(magic_buffer, CRYPT_MAGIC_LEN, 1, fp) != 1)
        return NULL;

    method_nr = crypt_method_nr_from_magic(magic_buffer, CRYPT_MAGIC_LEN);
    if (method_nr < 0)
        return NULL;

    header_len = crypt_get_header_len(method_nr);
    if ((buffer = malloc(header_len)) == NULL)
        return NULL;

    mch_memmove(buffer, magic_buffer, CRYPT_MAGIC_LEN);
    if (header_len > CRYPT_MAGIC_LEN
        && fread(buffer + CRYPT_MAGIC_LEN,
                    header_len - CRYPT_MAGIC_LEN, 1, fp) != 1)
    {
        free(buffer);
        return NULL;
    }

    state = crypt_create_from_header(method_nr, key, buffer);
    free(buffer);
    return state;
}


int main() {
    FILE *fp; 
    cryptstate_T *state; 

    fp = fopen("file", "r");
    state = crypt_create_from_file(fp, "test");

    printf("Method found: %d\n", (*state).method_nr);


    //printf("bf_self_test() returned %d\n", blowfish_self_test());
    return 0;
}

