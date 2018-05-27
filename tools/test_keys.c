
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
//#include <syslog.h>

#include "cmdline.h"
#include "zmalloc.h"
#include "base64.h"
#include "misc.h"
#include "zstr.h"
#include "dibafile.h"

char hello[] = "\
This is a test. This is a test. This is a test. This is a test.";

char hello2[] = "\
This is a test2. This is a test2. This is a test2.";

char *kkk = "key str";
char *kkk2 = "key str2";
    
char *fname = "test_keys.diba";

void show_val(FILE *fp2)

{
    int len2, type2; char *err_str;
    zline2(__LINE__, __FILE__);
    char* buff2 = GetNextDibaChunk(fp2, &len2, &type2, &err_str);
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
    int ret, len;  char *err_str;
    signal(SIGSEGV, myfunc);
    
    //syslog(LOG_DEBUG, "Started test_keys");
    //SetDibaFileDebug(3);  
    
    FILE    *fp = CreateDibaFile(fname, &err_str);
    if(!fp)
        {
        printf("cannot create file %s: '%s'\n", fname, err_str);
        exit(1);
        }
         
    chunk_keypair kp;
    
    kp.key = kkk; kp.klen = strlen(kkk); 
    kp.val = hello; kp.vlen = strlen(hello); 
    kp.compressed = 0;
    ret = PutDibaKeyVal(fp, &kp, &err_str);
    
    kp.key = kkk2; kp.klen = strlen(kkk2); 
    kp.val = hello2; kp.vlen = strlen(hello2); 
    kp.compressed = 1;
    ret = PutDibaKeyVal(fp, &kp, &err_str);
    
    CloseDibaFile(fp, 1);
    
    printf("\nGet chunks:\n\n");
    FILE    *fp2 = OpenDibaFile(fname, &err_str);
    if(!fp2)
        {
        printf("cannot open '%s'\n", err_str);
        exit(1);
        }
    while(1)
        {
        char *buff = FindNextDibaKey(fp2, &len, &err_str);
        if(!buff)
            {
            printf("err_str: '%s'\n", err_str);
            break;
            }
            
        printf("Key: '%s' keylen=%d\n", buff, len);
        show_val(fp2);
        zfree(buff);  
        }      
  
    //////////////////////////////////////////////////////////////////////
    // Show again
    
    printf("\nGet Key / Val:\n\n");
    RewindDibaFile(fp2);
    while(1)
        {
        zline2(__LINE__, __FILE__);
        chunk_keypair kp;
        int ret = GetDibaKeyVal(fp2, &kp, &err_str);
        if(!ret)
            {
            printf("err_str: %s\n", err_str);
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
    CloseDibaFile(fp2, 0);
    
    zleak();  
}























