
/* =====[ blueutil.c ]=========================================================

   Description:         File encryption helper.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug.27.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <signal.h>

#include "bluepoint3.h"
#include "base64.h"
#include "zmalloc.h"
#include "misc.h"

//////////////////////////////////////////////////////////////////////////
// Return sha hash string

char *bluepoint_hash_file(char *fname, char **err_str)

{ 
    FILE *fp = fopen(fname, "rb");
    if(fp == NULL) {
        *err_str = "Cannot open executable for hashing.";
        return(NULL);
        }
    unsigned int file_len = getfsize(fp);
    zline2(__LINE__, __FILE__);
    char* file_buf = zalloc(file_len + 1);
    if (!file_buf) {
        fclose(fp);
        *err_str = "malloc: could not allocate file buffer for hashing.";
        return(NULL);
        }
    if (fread(file_buf, file_len, 1, fp) != 1) {
        zfree(file_buf);
        fclose(fp);
        *err_str = "Cannot read self (exe) file for hashing.";
        return(NULL);
        }
    unsigned long long  hhh = bluepoint3_hash64(file_buf, file_len);
    //unsigned long  hhh = bluepoint2_hash(file_buf, file_len);
    
    zfree(file_buf);
    int olen;
    char *hash_str = base_and_lim((const char *)&hhh, sizeof(hhh), &olen);
    
    return hash_str;
}
    



