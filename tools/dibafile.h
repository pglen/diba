
/* =====[ dibafile.h ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank]. Diba package files.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  nov.05.2017     Peter Glen      Initial version.
      
   ======================================================================= */

#include "dibafcom.h"

FILE    *OpenDibaFile(const char *lpszPathName, char **err_str);
FILE    *CreateDibaFile(const char *fname, char **err_str);
int     CloseDibaFile(FILE *fp, int writefinal);
void    RewindDibaFile(FILE *Diba);
char*   GetNextDibaChunk(FILE *Diba, int *len, int *type, char **err_str);
char*   FindNextDibaKey(FILE *Diba, int *len, char **err_str);

int     GetDibaKeyVal(FILE *Diba, chunk_keypair *ptr, char **err_str);
int     PutDibaKeyVal(FILE *Diba, chunk_keypair *ptr, char **err_str);

// Lower level

void    SetDibaFileDebug(int level);
int     PutDibaSection(FILE *ff, const char *ptr, int len, int type);
int     GetDibaSection(FILE *ff, int *len, int *type, int *sum);

// EOF

