#include <stdio.h>

static int bf_self_test();


/* values for method_nr */
#define CRYPT_M_ZIP	0
#define CRYPT_M_BF	1
#define CRYPT_M_BF2	2
#define CRYPT_M_COUNT	3 /* number of crypt methods */

typedef struct {
    int	    method_nr;
    void    *method_state;  /* method-specific state information */
} cryptstate_T;

typedef struct {
    char    *name;	/* encryption name as used in 'cryptmethod' */
    char    *magic;	/* magic bytes stored in file header */
    int	    salt_len;	/* length of salt, or 0 when not using salt */
    int	    seed_len;	/* length of seed, or 0 when not using salt */
    int  (* self_test_fn)();
    void (* init_fn)(cryptstate_T *state, unsigned char *key, unsigned char *salt, int salt_len, unsigned char *seed, int seed_len);
    void (*encode_fn)(cryptstate_T *state, unsigned char *from, size_t len, unsigned char *to);
    void (*decode_fn)(cryptstate_T *state, unsigned char *from, size_t len, unsigned char *to);
} cryptmethod_T;    

void crypt_blowfish_encode (cryptstate_T *state, unsigned char *from, size_t len, unsigned char *to);
void crypt_blowfish_decode (cryptstate_T *state, unsigned char *from, size_t len, unsigned char *to);
void crypt_blowfish_init (cryptstate_T *state, unsigned char *key, unsigned char *salt, int salt_len, unsigned char *seed, int seed_len);
int blowfish_self_test (void);


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

#define CRYPT_MAGIC_LEN	12	/* cannot change */
static char	crypt_magic_head[] = "VimCrypt~";  

int main() {
    printf("bf_self_test() returned %d\n", blowfish_self_test());
    return 0;
}

