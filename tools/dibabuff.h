
/* =====[ DibaBuff.h ]=========================================================

   Description:     

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug.26.2018     Peter Glen      Initial version.
      
   ======================================================================= */

#include "dibafcom.h"

void    SetDibaBuffDebug(int level);
int     OpenDibaBuff(dibabuff *pbuff, char **err_str);

int     DumpDibabuff(dibabuff *pbuff);

char*   FindNextDibaBuffKey(dibabuff *pbuff, int *len, char **err_str);
char*   GetNextDibaBuffChunk(dibabuff *pbuff,  int *len, int *type, char **err_str);
void    RewindDibaBuff(dibabuff *pbuff);
int     CloseDibaBuff(dibabuff *pbuff);
int     CompleteDibaBuff(dibabuff *pbuff, char **err_str);

int     PutDibaBuffKeyVal(dibabuff *pbuff,  chunk_keypair *ptr, char **err_str);
int     GetDibaBuffKeyVal(dibabuff *pbuff, chunk_keypair *ptr, char **err_str);

// Lower level

int     GetDibaBuffSection(dibabuff *pbuff, int *len, int *type, int *sum);
int     PutDibaBuffSection(dibabuff *pbuff, const char *ptr, int len, int type);
  
// EOF

                                           
                                        
                                     
                               
                         

