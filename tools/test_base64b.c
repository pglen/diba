
/* =====[ test_base64.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  aug.04.2017     Peter Glen      Terminator added

   ======================================================================= */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "zmalloc.h"
#include "base64.h"

void xerr2(const char* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    
    vfprintf(stderr, msg, ap);
    exit(2);                                
}

unsigned int getfsize(FILE *fp)

{
    size_t org_pos = ftell(fp);
    fseek(fp, 0, SEEK_END);
    size_t file_len = ftell(fp);
    fseek(fp, org_pos, SEEK_SET);
    
    return  file_len;
}

int main(int argc, char** argv)
{
    //printf("Testing base64b.\n");
    FILE* dataf = fopen(argv[1], "rb");
    if (!dataf) {
        xerr2("Cannot open data file: '%s'", argv[1]);
        }
    int data_len = getfsize(dataf);
    //printf("data file size %d\n", data_len);
    zline2(__LINE__, __FILE__);
    char *data_buf = zalloc(data_len + 1);
    if (!data_buf) {
        xerr2("dibadecrypt: Cannot allocate data buffer.");
        }
    if (fread(data_buf, data_len, 1, dataf) != 1) {
        xerr2("dibadecrypt: Cannot read data file '%s'.", argv[1]);
        }
        
    int slen =  data_len;
    char *str = data_buf;
    //printf("org: len=%d\n'%s'\n\n", slen, str);
    int outlen = base64_calc_encodelen(slen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(outlen + 1);
    //printf("base64 encode pre outlen=%d\n", outlen);                                           
    base64_encode(str, slen, mem, &outlen);
    //mem[outlen] = '\0';
    //printf("base64 encode outlen=%d\n'%s'\n", outlen, mem);                                           
    zcheck(mem, __LINE__);             
    
    int dlen = outlen;
    char *dmem = zalloc(dlen + 2);
    //printf("base64 decode pre dlen=%d\n", dlen);                                           
    base64_decode(mem, outlen, dmem, &dlen);
    //dmem[dlen] = '\0';
    //printf("base64 decode dlen=%d\n'%s'\n", dlen, dmem);                                           
    zcheck(dmem, __LINE__);             
    //dump_mem(dmem, outlen);
    
    if(dlen != slen)
        {
        printf("\nError! Decode length does not match\n");
        }
    else if (strcmp(str, dmem) != 0)
        {
        printf("\nError! Decode does not match\n");
        }
    else
        {
        printf("\nDecoded OK\n");
        }    
    zfree(mem); zfree(dmem);   zfree(str);
    
    zleak();  
}










