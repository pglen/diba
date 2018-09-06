
/* =====[ dibabuff.h ]=========================================================

   Description:     

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug.26.2018     Peter Glen      Initial version.
      0.00  sep.03.2018     Peter Glen      Updated with container
      
   ======================================================================= */

#include "dibafcom.h"

void    SetDIBDebug(int level);
int     OpenDIB(dibabuff *pbuff, char **err_str);
int     CreateDIB(dibabuff *pbuff, const char *ppp, int len, char **err_str);

int     DumpDIB(dibabuff *pbuff);

char*   FindNextDIBKey(dibabuff *pbuff, int *len, char **err_str);
char*   GetNextDIBChunk(dibabuff *pbuff,  int *len, int *type, char **err_str);
void    RewindDIB(dibabuff *pbuff);
int     CloseDIB(dibabuff *pbuff);
int     CompleteDIB(dibabuff *pbuff, char **err_str);

int     PutDIBKeyVal(dibabuff *pbuff,  chunk_keypair *ptr, char **err_str);
int     GetDIBKeyVal(dibabuff *pbuff, chunk_keypair *ptr, char **err_str);

// Lower level

int     GetDIBSection(dibabuff *pbuff, int *len, int *type, int *sum);
int     PutDIBSection(dibabuff *pbuff, const char *ptr, int len, int type);
  
// EOF

                                           
                                        
                                     
                               
                         




