
/* =====[ gcry.h ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.17.2017     Peter Glen      Added dump mem
      0.00  jul.22.2017     Peter Glen      Sexp helpers

   ======================================================================= */

// /* Crash routines. */
void xerr2(const char* msg, ...);
void printerr(int err, char *str);

// /* Initialize libgcrypt. */
void gcrypt_init();

unsigned int getfsize(FILE *fp);

// /* Estimate the size of the encrypted key pair. */
size_t get_keypair_size(int nbits);

// /* Create an AES context out of a user's password. */
void    get_aes_ctx(gcry_cipher_hd_t* aes_hd, const char *passwd, int pass_len);
void    get_twofish_ctx(gcry_cipher_hd_t* aes_hd, const char *passwd, int pass_len);

void    print_cypher_details(const char *str);

char    *decode_signature(char *rsa_buf, int *prsa_len, char **err_str);
char    *decode_comp_key(char *rsa_buf, int *prsa_len, char **err_str);
char    *decode_rsa_cyph(char *rsa_buf, int *prsa_len, char **err_str);
char    *decode_pub_key(char *rsa_buf, int *prsa_len, char **err_str);

int     write_pubkey(gcry_sexp_t *rsa_keypair, const char *xfname2);
int     write_mod_exp(gcry_sexp_t *rsa_keypair, const char *xfname2);

int     pk_encrypt_buffer(const char *buf, int len, gcry_sexp_t pubk, gcry_sexp_t *ciph);
char    *zrandstr_strong(int len);
char    *hash_file(char *fname, char **err_str);
char    *hash_buff(const char *buff, int len);

char    *alloc_rand_amount();


// EOF














