
/* =====[ test_chunk.c ]=========================================================

   Description:     Encryption examples. Feasability study for diba
                    [Digital Bank].
                    Test chunk written to file.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmdline.h"
#include "zmalloc.h"
#include "base64.h"
#include "misc.h"
#include "zstr.h"
#include "dibabuff.h"

char hello[] =                                                                   
"This is a test. This is a test. This is a test. This is a test. This is a test.";

int main(int argc, char** argv)
                                        
{
    int olen, ulen, flen;
    char *err_str;
                 
    //dibalog(0, "%s", "started test_chunk");
    
    zline2(__LINE__, __FILE__);
    
    dibabuff dbuff; memset(&dbuff, 0, sizeof(dbuff));
    
    int ret  = OpenDIB(&dbuff, &err_str);
    if(!ret)                           
        {
        printf("cannot open '%s'\n", err_str);
        exit(1);
        }
        
    char *k1 =  "key str";
    char *k2 =  "key str2";
    
    PutDIBSection(&dbuff, k1, strlen(k1), CHUNK_TEXT | CHUNK_KEY);
    PutDIBSection(&dbuff, "value 1", 7, CHUNK_TEXT);
    
    zline2(__LINE__, __FILE__);
    PutDIBSection(&dbuff, k2, strlen(k2), CHUNK_TEXT | CHUNK_KEY);
    PutDIBSection(&dbuff, "value 2",  7, CHUNK_TEXT | CHUNK_ZIPPED);
    
    //PutDIBSection(&dbuff, hello,  strlen(hello), CHUNK_TEXT | CHUNK_ZIPPED);
    
    //printf("zipped %d %x\n",  CHUNK_ZIPPED, CHUNK_ZIPPED);
    CompleteDIB(&dbuff, &err_str);
      
    //putfile("aa", dbuff.ptr, dbuff.clen, &err_str);
                                                       
    RewindDIB(&dbuff);   
    //DumpDIB(&dbuff);  
    //SetDIBDebug(0); 
    //exit(0);
    
    // Damage it
    //dbuff.ptr[6] = 0;
    
    int len, type, iter = 10;
    char *ccc = "Bad check";
    while(iter--)
        {
        zline2(__LINE__, __FILE__);
        char* buff = GetNextDIBChunk(&dbuff, &len, &type, &err_str);
        if(!buff)
            {
            if(strncmp(ccc, err_str, strlen(ccc)-1) == 0)
                {
                printf("Ignoring '%s'\n", err_str);
                continue;
                }   
            else
                {
                printf("end err_str: '%s'\n", err_str);
                break;
                }
            }
        else
            {
            char *key = (type & 0x80) ? "Yes" : "No";
            //printf("len=%d type=%d (0x%x) Key=%s\n", len, type, type, key); 
            printf("%s: '%s'\n", key, buff);
            zfree(buff);  
            
             if(type == CHUNK_FOOTER)
                {
                break;
                }      
            }
        }      
    CloseDIB(&dbuff);
   
    zleak();  
}

// EOF

































