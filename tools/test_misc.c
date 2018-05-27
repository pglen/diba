
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


char hello[] = "\
This is a test. This is a test. This is a test.\0 This is a test. This is a test. \n\
This is a test. This is a test. This is a test. This is a test. This is a test. \n\
This is a test. This is a test. This is a test. This is a test. This is a test. \n\
This is a test. This is a test. This is a test. This is a test. This is a test. \n\
";

int main(int argc, char** argv)
                                        
{
    int len = sizeof(hello);
    int olen, ulen, flen;
    
    printf("'%s'\n", hello);
    dump_mem(hello, len);
    char *bb = base_and_lim(hello, len, &olen);
    printf("'%s'\n", bb);
    
    char    *err_str2 = NULL;
    putfile("aa", bb, strlen(bb), &err_str2); 
    
    char    *err_str3 = NULL;
    char    *cc = grabfile("aa", &flen, &err_str3);
    //cc[flen] = '\0';
    
    //printf("'%s'\n", cc);
    
    printf("Test file boolean %d\n", memcmp(bb, cc, len));
    
    char *dd = unbase_and_unlim(cc, flen, &ulen);
    printf("'%s'\n", dd);
    dump_mem(dd, ulen);
    printf("Test boolean %d\n", memcmp(hello, dd, ulen));
    zfree(bb); zfree(cc); zfree(dd);
    zleak();  
}















