/* =====[ zstr.h ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  sep.30.2017     Peter Glen      Initial version.

   ======================================================================= */

char    *zstrmcat(int maxlen, const char *str, ...);
char    *zstrcat(const char *str1, const char* str2);
char    *zstrdup(const char *str1, int maxsize);
char    *zstrcpy(char *targ, const char *src, int maxsize);
char    *zsnprintf(const char *str, ...);
   


