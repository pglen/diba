
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

char hello[] = "\
This is a test. This is a test. This is a test. This is a test. This is a test. \n\
This is a test. This is a test. This is a test. This is a test. This is a test. \n\
This is a test. This is a test. This is a test. This is a test. This is a test. \n\
This is a test. This is a test. This is a test. This is a test. This is a test. \n\
";

char *fname = "test_chunk.diba";

int main(int argc, char** argv)
                                        
{
    int hlen = sizeof(hello);
    int olen, ulen, flen;
    char *err_str;
                 
    //dibalog(0, "%s", "started test_chunk");
    //SetDIBDebug(0);  
    
    zline2(__LINE__, __FILE__);
    
    dibabuff dbuff; memset(&dbuff, 0, sizeof(dbuff));
    
    dbuff.ptr = grabfile(fname, &dbuff.clen, &err_str);
    if(dbuff.ptr == NULL)   {
        printf("cannot open '%s'\n", err_str);
        exit(1);
    }
    
    int ret  = OpenDIB(&dbuff, &err_str);
    if(!ret)                           
        {
        printf("cannot open '%s'\n", err_str);
        exit(1);
        }
        
    //putfile("aa", dbuff.ptr, dbuff.clen, &err_str);
    
    #if 0
    PutDIBSection(&dbuff, "key str", 7, CHUNK_TEXT | CHUNK_KEY);
    PutDIBSection(&dbuff, hello, hlen, CHUNK_TEXT);
    
    PutDIBSection(&dbuff, "key str2", 9, CHUNK_TEXT | CHUNK_KEY);                  
    PutDIBSection(&dbuff, "another one", 12, CHUNK_TEXT);
    #endif
    
    //CloseDIB(fp, 1); 
                 
    RewindDIB(&dbuff);   
                                                 
    int len, type;
    char *ccc = "Bad check";
    while(1)
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
            char *key = (type & 0x80) ? "True" : "False";
            printf("len=%d type=%d (0x%x) Key=%s\n", len, type, type, key); 
            printf("buf: '%s'\n", buff);
            zfree(buff);     
            }
        }      
    CloseDIB(&dbuff);
   
    zleak();  
}

// EOF



























