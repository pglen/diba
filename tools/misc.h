
/* =====[ misc.h ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  jul.17.2017     Peter Glen      Added dump mem
      0.00  aug.26.2017     Peter Glen      First push to github
      0.00  oct.28.2017     Peter Glen      Chunk added
      
   ======================================================================= */

char    *alloc_rand_amount();
void    rand_seed();
char    *base_and_lim(const char *mem, int len, int *olen);
char    *unbase_and_unlim(const char *mem, int len, int *olen);
int     num_bits_set(unsigned int ks);
char    *zusername();
char    *zhostname();
char    *zdatestr();
char    *tobase64(char *mem, int *len);
char    *pass_fromfile(const char *thispass, char **err_str);

int     frame_buff(char *back2, char **start);

// Files

char    *grabfile(const char* fname, int *olen, char **errstr);
int     putfile(const char* fname, const char *ptr, int len, char **errstr);

// Dump to screen, or file

void    dump_mem(const char *ptr, int len);
int     print_mem(char *mem, int len);
void    dump_memfp(const char *ptr, int len, FILE *fp);

// General memory helpers

char    *dohex(const char *mem, int len, int *olen);
char    *dounhex(const char *mem, int len, int *olen);

unsigned int getfsize(FILE *fp);

int     is_bin(const char *ptr, int len);
void    dibalog(int level, const char* msg, ...);

// EOF


















