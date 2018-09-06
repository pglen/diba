
/* =====[ test_buffbuff.c ]=========================================================

   Description:     Encryption examples. Feasability study for diba
                    [Digital Bank].
                    Test chunks within chunk.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug.03.2018     Peter Glen      Initial version.

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
    
void print_dbuff(dibabuff *pdb)

{    
    int len, type, iter = 10;
    
    char *err_str;

    printf("Dibabuff %p\n", pdb);
    
    char *ccc = "Bad check";
    while(iter--)
        {
        zline2(__LINE__, __FILE__);
        char* buff = GetNextDIBChunk(pdb, &len, &type, &err_str);
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
            char *key = (type & 0x80) ? "Key:  " : "Data: ";
            //printf("len=%d type=%d (0x%x)\n", len, type, type); 
            if(type == CHUNK_CHUNK)
                {
                dibabuff dbuff3; memset(&dbuff3, 0, sizeof(dbuff3));
                CreateDIB(&dbuff3, buff, len, &err_str);
                print_dbuff(&dbuff3);
                CloseDIB(&dbuff3);
                }
            else
                {
                printf("%s'%s'\n", key, buff);
                }
            zfree(buff); 
            
            if(type == CHUNK_FOOTER)
                {
                break;
                }
            }
        }      
    printf("Dibabuff ended %p\n", pdb);
}
    
char hello[] =                                                                   
"This is a test. This is a test. This is a test. This is a test. This is a test.";

int main(int argc, char** argv)
                                        
{
    int olen, ulen, flen;
    char *err_str;
     
    //dibalog(0, "%s", "started test_chunk");
    
    zline2(__LINE__, __FILE__);

    dibabuff dbuff2; memset(&dbuff2, 0, sizeof(dbuff2));
    int ret2  = OpenDIB(&dbuff2, &err_str);
    if(!ret2)                           
        {
        printf("cannot open2 '%s'\n", err_str);
        exit(1);
        }
    
    dibabuff dbuff; memset(&dbuff, 0, sizeof(dbuff));
    int ret  = OpenDIB(&dbuff, &err_str);
    if(!ret)                           
        {
        printf("cannot open '%s'\n", err_str);
        exit(1);
        }
        
    char *k1 =  "key str";
    char *k2 =  "key str2";
    char *k3 =  "key str3";
    char *k4 =  "key str4";
    
    PutDIBSection(&dbuff, k1, strlen(k1), CHUNK_TEXT | CHUNK_KEY);
    PutDIBSection(&dbuff, "value 1", 7, CHUNK_TEXT);
    
    zline2(__LINE__, __FILE__);
    PutDIBSection(&dbuff, k2, strlen(k2), CHUNK_TEXT | CHUNK_KEY);
    PutDIBSection(&dbuff, "value 2",  7, CHUNK_TEXT | CHUNK_ZIPPED);
    
    //PutDIBSection(&dbuff, hello,  strlen(hello), CHUNK_TEXT | CHUNK_ZIPPED);
    
    //printf("zipped %d %x\n",  CHUNK_ZIPPED, CHUNK_ZIPPED);
    CompleteDIB(&dbuff, &err_str);
      
    //putfile("aa", dbuff.ptr, dbuff.clen, &err_str);
    
    PutDIBSection(&dbuff2, dbuff.ptr, dbuff.clen, CHUNK_CHUNK);
    CloseDIB(&dbuff);
   
    PutDIBSection(&dbuff2, k3, strlen(k3), CHUNK_TEXT);
    CompleteDIB(&dbuff2, &err_str);
    
    RewindDIB(&dbuff2);   
    //DumpDIB(&dbuff2);  
    
    // Damage it
    //dbuff.ptr[6] = 0;
    
    print_dbuff(&dbuff2);
   
    CloseDIB(&dbuff2);
   
    zleak();  
}

// EOF




































