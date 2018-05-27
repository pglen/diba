
/* =====[ keygen.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug03.2017     Peter Glen      Initial version.

   ======================================================================= */

// Sexp helpers

char    *sexp_sprint(gcry_sexp_t sexp, int *len, int format);
void     sexp_print(gcry_sexp_t rsa_keypair);
void    sexp_fprint(gcry_sexp_t rsa_keypair, FILE *fp);

char    *sexp_decode(gcry_sexp_t list, int *olen, const char *findstr);
char    *sexp_get_buff(gcry_sexp_t sexp, int *plen);
char    *sexp_nth_data(gcry_sexp_t  element, int num, int *plen);
char    *sexp_hash(gcry_sexp_t pubk, int *olen);
int      sexp_list(gcry_sexp_t list);
char    *sexp_get_val(gcry_sexp_t sexp, const char *key, int *polen, char **err_str);
















