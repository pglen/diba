
/* =====[ dibastr.h ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.17.2017     Peter Glen      Added dump mem
      0.00  jul.22.2017     Peter Glen      Sexp helpers

   ======================================================================= */

// Consistant naming throughout the files

#define DIBACRYPT_HASH  "dibacrypt-hash"
#define DIBACRYPT_KEY   "dibacrypt-key"
#define DIBACRYPT_SIG   "dibacrypt-signature"
#define PRIVATE_CRYPTED "private-crypted"

#define PUBLIC_KEY      "public-key"
#define PRIVATE_KEY     "private-key"
#define GCRYPT_KEY      "gcrypt-key"


// Unified strings for files

const char *pub_start;
const char *pub_end;
const char *comp_start;
const char *comp_end;
const char *query_start;
const char *query_end;
const char *resp_start;
const char *resp_end;
const char *sig_start;
const char *sig_end;
const char *cyph_start;
const char *cyph_end;
const char *mod_start;
const char *mod_end;  
const char *exp_start;
const char *exp_end; 

const char *chain_start;
const char *chain_end; 

const char *keypass;

// Common messages.

const  char *nonestr;
const  char *mstr;

// Comming dirs and filenames

const  char *nullfname;
const  char *nullext;
const  char *datext;
const  char *nulldir;
const  char *dibapass;
const  char *custdbname;

// EOF








