//# -------------------------------------------------------------------------
//# Bluepoint encryption routines.
//#
//#   How it works:
//#
//#     Strings are walked chr by char with the loop:
//#         {
//#         $aa = ord(substr($_[0], $loop, 1));
//#         do something with $aa
//#         substr($_[0], $loop, 1) = pack("c", $aa);
//#         }
//#
//#   Flow:
//#         generate vector
//#         generate pass

//#         walk forward with password cycling loop
//#         walk backwards with feedback encryption
//#         walk forward with feedback encryption
//#
//#  The process guarantees that a single bit change in the original text
//#  will change every byte in the resulting block.
//#
//#  The bit propagation is such a high quality, that it beats current
//#  industrial strength encryptions.
//#
//#  Please see bit distribution study.
//#
//# -------------------------------------------------------------------------

typedef  unsigned long ulong;
typedef  unsigned int uint;
typedef  unsigned long long ulonglong;

int	bluepoint3_encrypt(char *buff, int blen, const char *pass, int plen);
int	bluepoint3_decrypt(char *str, int slen, const char *pass, int plen);

ulong   bluepoint3_hash(const char *buff, int blen);
ulong   bluepoint3_crypthash(const char *buff, int blen, char *pass, int plen);

// New Hashes:

unsigned long long bluepoint3_hash64(const char *buff, int blen);
unsigned long long bluepoint3_crypthash64(const char *buff, int blen, char *pass, int plen);

// These return the same buffer, move data before second call
#ifdef DEF_DUMPHEX
char    *bluepoint3_dump(const char *str, int len);
char    *bluepoint3_undump(const char *str, int len, int *olen);
#endif

int     bluepoint3_dump2buff(const char *str, int len, char *out, int *olen);
int     bluepoint3_undump2buff(const char *str, int len, char *out, int *olen);

// Convert to a friendly format:

char    *bluepoint3_tohex(const char *str, int len, char *out, int *olen);
char    *bluepoint3_fromhex(const char *str, int len, char *out, int *olen);

// Helpers

int     bluepoint3_set_verbose(int flag);
int     bluepoint3_set_functrace(int flag);
int     bluepoint3_set_debug(int flag);

// Encryption modifiers

int     bluepoint3_set_rounds(int xrounds);
int     bluepoint3_set_midx(int *list, int elements);

// EOF









