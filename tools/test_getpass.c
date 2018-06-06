
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
#include "getpass.h"

int main(int argc, char** argv)
                                        
{
    char buff[12];
                          
    getpassx ppp; ZERO_GETP_STRUCT(&ppp);
    ppp.maxlen = sizeof(buff);
    ppp.pass = buff;
    ppp.prompt = "Enter pass:";
    ppp.nodouble = 1;
    getpass2(&ppp);
    
    //int ret = dibagetpass("pass here", ppp, sizeof(ppp)-1);
    printf("Got pass '%s'\n", ppp.pass);
    
    return 0;
}

// EOF















