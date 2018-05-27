
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

#ifndef MAX_PATH
    #ifndef PATH_MAX
        // Keep it safe
        #define MAX_PATH 255
    #else
        #define MAX_PATH PATH_MAX
    #endif    
#endif            

char *junk = "\
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\
";

int main(int argc, char** argv)
                                        
{
    char    *res = zstrmcat(MAX_PATH, "aa", "bb", "cc", NULL);
    printf("result: '%s'\n", res);
    zfree(res);
    
    char    *res2 = zsnprintf("ERR %s", "Hello zsnprintf");
    printf("result2: '%s'\n", res2);
    zfree(res2);

    char    *res3 = zsnprintf("Junc test: %s", junk);
    printf("result3: '%s'\n", res3);
    zfree(res3);
    
    //char    *res4 = zsnprintf("Error %d %d\n", "error", 22);
    //printf("result4: '%s'\n", res4);
    //zfree(res4);
    
    zleak();  
}














