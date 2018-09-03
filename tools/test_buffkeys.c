
/* =====[ test_keys.c ]=========================================================

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
#include <signal.h>

#include "cmdline.h"
#include "zmalloc.h"
#include "base64.h"
#include "misc.h"
#include "zstr.h"

#include "dibabuff.h"

char hello[] = "\
This is a test. This is a test. This is a test. This is a test.";

char hello2[] = "\
This is a test2. This is a test2. This is a test2.";

char *kkk = "key str";
char *kkk2 = "key str2";
    
char *fname = "test_keys.diba";

void show_val(dibabuff *fp2)

{
    int len2, type2; char *err_str;
    zline2(__LINE__, __FILE__);
    char* buff2 = GetNextDIBChunk(fp2, &len2, &type2, &err_str);
    if(buff2)
        {
        printf("len2=%d Value='%s'\n", len2, buff2); 
        zfree(buff2);
        }
    else
        {           
        printf("err_str: '%s'\n", err_str);
        }
}

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation).\n", sig);
    exit(1);
}

int main(int argc, char** argv)
                                        
{
    int ret, len, type;  char *err_str;
    signal(SIGSEGV, myfunc);
    
    dibabuff dbuff; memset(&dbuff, 0, sizeof(dbuff));
    
    ret  = OpenDIB(&dbuff, &err_str);
    if(!ret)                           
        {
        printf("cannot open '%s'\n", err_str);
        exit(1);
        }
        
    printf("\nWriting chunks:\n\n");
    
    chunk_keypair kp;
    
    kp.key = kkk; kp.klen = strlen(kkk); 
    kp.val = hello; kp.vlen = strlen(hello); 
    kp.compressed = 0;
    ret = PutDIBKeyVal(&dbuff, &kp, &err_str);
    
    kp.key = kkk2; kp.klen = strlen(kkk2); 
    kp.val = hello2; kp.vlen = strlen(hello2); 
    kp.compressed = 1;
    ret = PutDIBKeyVal(&dbuff, &kp, &err_str);
    CompleteDIB(&dbuff, &err_str);
    //DumpDIB(&dbuff);  
    
    RewindDIB(&dbuff);
    printf("\nGet chunks:\n\n");
    while(1)
        {
        char *buff = GetNextDIBChunk(&dbuff, &len, &type, &err_str);
        if(!buff)
            {
            //printf("err_str: '%s'\n", err_str);
            break;
            }
        //printf("len=%d type=%d Str: '%s'\n", len, type, buff);
        printf("0x%03x '%s'\n", type, buff);
        //show_val(&dbuff);
        zfree(buff);  
        }      
  
    //////////////////////////////////////////////////////////////////////
    // Show again
    
    //SetDIBDebug(2); 

    RewindDIB(&dbuff);
    printf("\nGet keys:\n\n");
    while(1)
        {
        char *buff = FindNextDIBKey(&dbuff, &len, &err_str);
        if(!buff)
            {
            //printf("err_str: '%s'\n", err_str);
            break;
            }
        //printf("len=%d type=%d Str: '%s'\n", len, type, buff);
        printf("0x%03x '%s'\n", type, buff);
        //show_val(&dbuff);
        zfree(buff);  
        }      
  
    //////////////////////////////////////////////////////////////////////
    // Show again
    
    printf("\nGet Key / Val:\n\n");
    RewindDIB(&dbuff);
    while(1)
        {
        zline2(__LINE__, __FILE__);
        chunk_keypair kp;
        int ret = GetDIBKeyVal(&dbuff, &kp, &err_str);
        if(!ret)
            {
            //printf("err_str: %s\n", err_str);
            break;
            }
        else
            {
            printf("len=%d Key='%s'\n", kp.klen, kp.key); 
            printf("len=%d Val='%s'\n", kp.vlen, kp.val); 
            
            zline2(__LINE__, __FILE__);
            zfree(kp.key); zfree(kp.val);
            }
        }
    CloseDIB(&dbuff);
    zleak();  
}

// EOF






















