
/* =====[ zstr.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].  Safer copy routines.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  aug.26.2017     Peter Glen      First push to github
      0.00  sep.30.2017     Peter Glen      Extracted to file

   ======================================================================= */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>

#include "zstr.h"
#include "misc.h"
#include "zmalloc.h"
#include "zstr.h"

//////////////////////////////////////////////////////////////////////////
// Multi cat every string in the argument list. Strings only.
// Not the most efficient, but takes generalized number of args.
// Terminate with NULL or empty string.
// RELIES on STRCPY terminating zeros. (all platforms do it)

char    *zstrmcat(int maxlen, const char *str, ...)
{
    int len = strlen(str);
    int sum = len;
    
    va_list ap;
    va_start(ap, str);
    
    // Add the lengths
    //printf("%p %s %d\n", str, str, len);
    while(1)
        {
        char *ptr =  va_arg(ap, char *);
        if(ptr == NULL)
            break;
         if(ptr[0] == '\0')
            break;
        sum += strlen(ptr);
        //printf("%p %s %d\n", ptr, ptr, strlen(ptr)); 
        }
    va_end(ap);
    
    // Safety valve
    if(maxlen != 0 && sum + 4 > maxlen)
        {
        printf("zstrmcat: Exceeded maxlen.\n");
        return NULL;
        }
        
    zline2(__LINE__, __FILE__);
    char *ret = zalloc(sum + 4);
    if(ret == NULL)
        return NULL;
        
    // Copy them back to back
    char *ret2 = ret;
    strcpy(ret2, str);
    ret2 += len;
    va_start(ap, str);
    while(1)
        {
        char *ptr2 =  va_arg(ap, char *);
         if(ptr2 == NULL)
            break;
         if(ptr2[0] == '\0')
            break;
        strcpy(ret2, ptr2);
        ret2 += strlen(ptr2);
        }
    va_end(ap);
    *ret2 = '\0';   
    return ret;
}

//////////////////////////////////////////////////////////////////////////
//

char    *zstrcat(const char *str1, const char* str2)
{
    //printf("cat %s + %s\n", str1, str2);
    int len1 = strlen(str1), len2 = strlen(str2);
    zline2(__LINE__, __FILE__);
    char *ret = zalloc(len1 + len2 + 4);
    strcpy(ret, str1);
    strcat(ret, str2);
    zcheck(ret, __LINE__);
    //printf("cat out %s\n", ret);
    return ret;
}

//////////////////////////////////////////////////////////////////////////
//

char    *zstrdup(const char *str1, int maxsize)

{
    zline2(__LINE__, __FILE__);
    char *ret = zalloc(maxsize + 1);
    if(ret == NULL)
        return NULL;
    strncpy(ret, str1, maxsize);
    zcheck(ret, __LINE__);
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Remedy the security issue of stccpy

char    *zstrcpy(char *targ, const char *src, int maxsize)

{
    int loop;
    
    if(targ == NULL)
        return targ;
    if(src == NULL)
        return targ;
    if(maxsize < 0)
        return targ;
        
    for(loop = 0; loop < maxsize - 1; loop++)
        {
        char chh = src[loop];
        targ[loop] = chh;
        if(chh == '\0')
            break;
        }
    targ[loop] == '\0';  
    
    return targ;
}

//////////////////////////////////////////////////////////////////////////

char    *zsnprintf(const char *str, ...)

{
    int len = 256;
    char *mystr = zalloc(len + 1);
    
    va_list ap; va_start(ap, str);
    int ret = vsnprintf(mystr, len, str, ap);
    // Error in format str
    if(ret < 0)
        {
        zfree(mystr);
        return(NULL);
        }
        
    // Bigger buffer needed
    if(ret >= len )
        {
        //printf("re doing alloc\n");
        zfree(mystr);
        len = ret + 1;
        mystr = zalloc(len + 1);
        va_list ap; va_start(ap, str);
        ret = vsnprintf(mystr, len, str, ap);
        }
    mystr[ret] = '\0';
    return(mystr);       
}

// EOF






