
/* =====[ dibafcom.c ]=========================================================

   Description:     common routined for DIBA file / DIBA buffer  

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
     0.00  nov.05.2017     Peter Glen      Initial version.
 
   ======================================================================= */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "misc.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"
#include "dibafile.h"

#include "zlib.h"

#ifndef MAX_PATH
    #ifndef PATH_MAX
        // Keep it safe
        #define MAX_PATH 255
    #else
        #define MAX_PATH PATH_MAX
    #endif    
#endif            


unsigned int calc_buffer_sum(const char *ptr, int len)

{
    unsigned int ret = 0;
    //printf("calc_buffer_sum %p %d\n", ptr, len);
    for(int loop = 0; loop < len; loop++)
        {
        ret += (unsigned char)ptr[loop];
        ret = (ret << 3) | ret >> 21;
        }
    //printf("sum ret = %x\n", ret);
    return ret;   
}


