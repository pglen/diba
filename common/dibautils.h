
/* =====[ dibautils.h ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.10  Jun.25.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <string.h>
#include "gcrypt.h"

#define NUMSIG 3        // Three signatures (change code to accomodate)

typedef struct _build_next_struct
{
    char *next_calc;
    char *next_hash;
    char *next_pad;
    char *next_id;
    char *next_file;
    char *next_workhash;

} build_next_struct;

#define INIT_NEXT_STRUCT(st)                     \
        (st)->next_calc = (char*)nonestr;        \
        (st)->next_hash = (char*)nonestr;        \
        (st)->next_pad = (char*)nonestr;         \
        (st)->next_id = (char*)nonestr;          \
        (st)->next_file = (char*)nonestr;        \
        (st)->next_workhash = (char*)nonestr;    \

extern int  deadbeef;

// Get public key

typedef struct _get_pub_key_struct
{
    char **err_str;
    char **err_str2;
    char *rsa_buf;
    int   rsa_len, debug;
    gcry_sexp_t  *composite;
    gcry_sexp_t  *info;
    gcry_sexp_t  *pubkey;
    gcry_sexp_t  *hash;
} get_pub_key_struct;

#define ZERO_PUBK_STRUCT(pks) memset(pks, 0, sizeof(get_pub_key_struct));

int     get_pubkey(get_pub_key_struct *pks);

// Get private key

typedef struct _get_priv_key_struct
{
    char **err_str;
    char **err_str2;  
    char *rsa_buf;
    int   rsa_len, nocrypt, debug;
    gcry_sexp_t  *composite;
    gcry_sexp_t  *info;
    gcry_sexp_t  *privkey;
    gcry_sexp_t  *pubkey;
    gcry_sexp_t  *hash;
    char *thispass;
} get_priv_key_struct;

#define ZERO_PRIVK_STRUCT(pks) memset(pks, 0, sizeof(get_priv_key_struct));

int get_privkey(get_priv_key_struct *pks);

void    rand_buff(char *str, int len);
void    rand_str(char *str, int len);
void    rand_asci_buff(char *str, int len);
void    show_str(const char* str, int len);
//void    show_hexstr(const char* str, int len);
void    genrev(char *str, int len);
char    *diba_alloc(int size);
int     read_sexp_from_file(const char *fname, gcry_sexp_t *sexp, char **err_str);
int     write_sexp_to_file(const char *fname, gcry_sexp_t *sexp, char **err_str);

int     build_next(gcry_sexp_t *chain_next, build_next_struct *bns);
char    *memcat(int *outlen, ...);
char    *triple_hash_buffer(const char *data_buf, int data_len, int *hash_len);
char    *hash_sig_buff(int algo, const char *data_buf, int data_len, int *hash_len);

// EOF

























