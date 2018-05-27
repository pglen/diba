
/* =====[ test_zstr.c ]=========================================================

   Description:     Encryption examples. Feasability study for diba
                    [Digital Bank].

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
#include "dibafile.h"

char hello[] = "\
This is a test. This is a test. This is a test. This is a test. This is a test. \n\
This is a test. This is a test. This is a test. This is a test. This is a test. \n\
This is a test. This is a test. This is a test. This is a test. This is a test. \n\
This is a test. This is a test. This is a test. This is a test. This is a test. \n\
";

char *fname = "test_chunk_zip.diba";

int main(int argc, char** argv)
                                        
{
    int hlen = sizeof(hello);
    int olen, ulen, flen;
    char *err_str;
                 
    dibalog(0, "%s", "started test_chunk");
    
    //SetDibaFileDebug(4);  
    
    zline2(__LINE__, __FILE__);
    
    FILE    *fp = CreateDibaFile(fname, &err_str);
    PutDibaSection(fp, hello, hlen, CHUNK_TEXT | CHUNK_ZIPPED);
    CloseDibaFile(fp, 1); 
    
    FILE    *fp2 = OpenDibaFile(fname, &err_str);
    if(!fp2)
        {
        printf("cannot open '%s'\n", err_str);
        exit(1);
        }
    int len, type;
    char *ccc = "Bad checksum";
    while(1)
        {
        zline2(__LINE__, __FILE__);
        char* buff = GetNextDibaChunk(fp2, &len, &type, &err_str);
        if(!buff)
            {
            if(strncmp(ccc, err_str, strlen(ccc)-1) == 0)
                {
                printf("Ignoring '%s'\n", err_str);
                //continue;
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
    CloseDibaFile(fp2, 0);
   
    zleak();  
}























