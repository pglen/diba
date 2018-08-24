
/* =====[ misc.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  jul.17.2017     Peter Glen      Added dump mem
      0.00  aug.26.2017     Peter Glen      First push to github

   ======================================================================= */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>

#include "misc.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"

//////////////////////////////////////////////////////////////////////////
// The following section allocates a useless random amount of memory.
// This will assure that strings appear in different places between runs.

char    *alloc_rand_amount()

{
    char *dummy;
    rand_seed();
    int ttt = rand() % 900 + 100;
    //printf("Using rand memory size %d\n", ttt);

    zline2(__LINE__, __FILE__);
    dummy = zalloc(ttt);
    if(dummy == NULL)
        return NULL;
    // Fill it up with crap
    for(int loop = ttt / 4; loop < (3 * ttt) / 4; loop++)
        {
        //printf("%c", rand() % (128 - 32) + 32);
        dummy[loop] = rand() % (128 - 32) + 32;
        }
    return dummy;
 }

//////////////////////////////////////////////////////////////////////////
// Best execute at the beggining:

void    rand_seed()

{
     // Up-seed the random number generator
    srand(time(NULL)); int sss = rand();  srand(sss);
    // Consume some numbers, random amont
    int ccc = rand() % 20 + 10;
    for(int loop = 0; loop < ccc; loop++)
        {
        rand();
        }
}

//////////////////////////////////////////////////////////////////////////
// Return file size

unsigned int getfsize(FILE *fp)

{
    size_t org_pos = ftell(fp);
    fseek(fp, 0, SEEK_END);
    size_t file_len = ftell(fp);
    fseek(fp, org_pos, SEEK_SET);

    return  file_len;
}

//////////////////////////////////////////////////////////////////////////
// Return an allocated base64 line limited string.
// Must use zfree to free pointer

char    *base_and_lim(const char *mem, int len, int *olen)

{
    int outlen = base64_calc_encodelen(len);
    zline2(__LINE__, __FILE__);
    char *mem2 = zalloc(outlen + 1);
    int ret = base64_encode(mem, len, mem2, &outlen);
    if(ret < 0)
        return NULL;
    zcheck(mem2, __LINE__);
    zline2(__LINE__, __FILE__);

    int linelen = 64, limlen = outlen + 4 + outlen / linelen ;
    char *mem3 = zalloc(limlen + 1);
    int ret2 = base64_limline(mem2, outlen, mem3, &limlen, linelen);
    zfree(mem2);
    if(ret2 < 0)
        return NULL;
    *olen = limlen;
    // Make sure it has a terminator
    mem3[limlen] = '\0';

    return mem3;
}

// Turn base64 back to memory (binary) representation
// Must free with zfree
// The decoder may truncate to %4 if wrong lenth passed

char    *unbase_and_unlim(const char *mem, int len, int *olen) 

{
    int cleanlen = len;
    zline2(__LINE__, __FILE__);
    char *memc = zalloc(cleanlen);
    if(!memc)
        return memc;
    base64_clean(mem, len, memc, &cleanlen);
    
    int outlen = base64_calc_decodelen(cleanlen);
    zline2(__LINE__, __FILE__);
    char *mem2 = zalloc(outlen);
    if(!mem2)
        return mem2;
        
    int ret = base64_decode(memc, cleanlen, mem2, &outlen);
    if(ret < 0)
        {
        // Our decoder failed, let them know
        zfree(memc); zfree(mem2);
        return NULL;
        }
    //zcheck(mem2, __LINE__);
    zfree(memc);
    *olen = outlen;
    return mem2;
}

//////////////////////////////////////////////////////////////////////////
// get user name, return pointer.
// must free with zfree

char    *zusername()

{
    char *name = getenv("USERNAME");
    if(name == NULL)
        name = "unknown name";

    int len = strlen(name);
    zline2(__LINE__, __FILE__);
    char *nnn = zalloc(len + 1);
    strncpy(nnn, name, len);
    nnn[len] = '\0';
    return nnn;
}

char    *zhostname()

{
    char *name = getenv("USERDOMAIN");
    if(name == NULL)
        name = "unknown host";

    int len = strlen(name);
    zline2(__LINE__, __FILE__);
    char *nnn = zalloc(len + 1);
    strncpy(nnn, name, len);
    nnn[len] = '\0';
    return nnn;
}

//////////////////////////////////////////////////////////////////////////
// Get current date, return pointer.
// must free with zfree

#if 0
      int  tm_sec;          /* Seconds: 0-60 (to accommodate leap seconds) */
      int  tm_min;          /* Minutes: 0-59 */
      int  tm_hour;         /* Hours since midnight: 0-23 */
      int  tm_mday;         /* Day of the month: 1-31 */
      int  tm_mon;          /* Months *since* January: 0-11 */
      int  tm_year;         /* Years since 1900 */
      int  tm_wday;         /* Days since Sunday (0-6) */
      int  tm_yday;         /* Days since Jan. 1: 0-365 */
      int  tm_isdst;        /* +1=Daylight Savings Time, 0=No DST, -1=unknown */
    #endif

char    *zdatestr()

{
    int allocsize = 64;
    zline2(__LINE__, __FILE__);
    char *ttt = zalloc(allocsize);
    time_t tme = time(NULL);
    struct tm *tmm = localtime(&tme);
    int len = snprintf(ttt, allocsize, "%4d/%02d/%02d %02d:%02d:%02d",
               tmm->tm_year + 1900, tmm->tm_mon + 1, tmm->tm_mday,
                tmm->tm_hour, tmm->tm_min, tmm->tm_sec );
    zcheck(ttt, __LINE__);
    return ttt;
}

// Date with no spaces

char    *zdatename()

{
    int allocsize = 64;
    zline2(__LINE__, __FILE__);
    char *ttt = zalloc(allocsize);
    time_t tme = time(NULL);
    struct tm *tmm = localtime(&tme);
    int len = snprintf(ttt, allocsize, "%4d%02d%02d%02d%02d%02d",
               tmm->tm_year + 1900, tmm->tm_mon + 1, tmm->tm_mday,
                tmm->tm_hour, tmm->tm_min, tmm->tm_sec );
    zcheck(ttt, __LINE__);
    return ttt;
}

// Turn memory to base64 representation
// Must free with zfree

char    *tobase64(char *mem, int *len)

{
    int outlen = base64_calc_encodelen(*len);
    zline2(__LINE__, __FILE__);
    char *mem2 = zalloc(outlen);
    int ret = base64_encode(mem, *len, mem2, &outlen);
    if(ret < 0)
        return NULL;
    zcheck(mem2, __LINE__);
    *len = outlen;
    return(mem2);
}

// Grab a file into memory

char    *grabfile(const char* fname, int *olen, char **errstr)

{
     *errstr = NULL; *olen = 0;
    FILE* lockf = fopen(fname, "rb");
    if (!lockf) 
        {
        //xerr2("Cannot open  file '%s'", fname);
        *errstr = "Cannot open file";  
        return NULL;
        }
    unsigned int rsa_len = getfsize(lockf);
    zline2(__LINE__, __FILE__);
    char* rsa_buf = zalloc(rsa_len + 1);
    if (!rsa_buf) 
        {
        fclose(lockf);
        //xerr2("malloc: could not allocate buffer");
        *errstr = "malloc: cannot allocate buffer";
        }
    if (fread(rsa_buf, rsa_len, 1, lockf) != 1) 
        {
        zfree(rsa_buf);
        fclose(lockf);
        //xerr2("Read on file failed.");
        *errstr = "Read on file failed";
        return NULL;
        }
    fclose(lockf);
    // Make a string out of it
    rsa_buf[rsa_len]  = '\0';
    *olen =  rsa_len;
    return rsa_buf;
}

// Put a memory into file

int     putfile(const char* fname, const char *ptr, int len, char **errstr)

{
    *errstr = NULL;
    FILE* lockf = fopen(fname, "wb");
    if (!lockf) 
        {
        //xerr2("Cannot open  file '%s'", fname);
        *errstr = "Cannot create file";  
        return 0;
        }
    if (fwrite(ptr, len, 1, lockf) != 1) 
        {
        fclose(lockf);
        //xerr2("Read on file failed.");
        *errstr = "Write on file failed";
        return 0;
        }
    fclose(lockf);
    return 1;
}

// See if keysize has more than one bit set (if it is a power of two)

int     num_bits_set(unsigned int ks)

{
    int bits = 0;
    //printf("bits of %d (0x%x)\n", ks, ks);
    while(1==1)
        {
        if(ks & 1)
            bits++;
        ks >>= 1;
        if (ks == 0)
            break;
        }
    //printf("ks bits %d\n", bits);
    return bits;
}

// See if the user provided a file

char    *pass_fromfile(const char *thispass, char **err_str)

{
    *err_str = "";

    if(thispass[0] != '@')
        return NULL;

    const char *passfile = &thispass[1];
    FILE *fp = fopen(passfile, "rb");
    if(fp == NULL) {
        *err_str = "Cannot open pass file";
        return NULL;
        }
    unsigned int pass_len = getfsize(fp);
    zline2(__LINE__, __FILE__);
    char* pass_buf = zalloc(pass_len + 1);
    if (!pass_buf) {
        fclose(fp);
        *err_str = "could not allocate password file buffer";
        return NULL;
        }
    if (fread(pass_buf, pass_len, 1, fp) != 1) {
        fclose(fp);
        *err_str = "Cannot read password from file.";
        return NULL;
        }
    // Just in case ...
    pass_buf[pass_len] = '\0';

    // Terminate at the end of line
    char *found = strstr(pass_buf, "\n");
    if (found != NULL)
        *found = '\0';
    char *found2 = strstr(pass_buf, "\r");
    if (found2 != NULL)
        *found2 = '\0';

    fclose(fp);

    return(pass_buf);
}


int print_mem(char *mem, int len)

{
    printf("print mem %d len\n", len);
    for(int loop = 0; loop < len; loop++)
        printf("%c", mem[loop]);
    return 0;
}

void dump_mem(const char *ptr, int len)

{
    dump_memfp(ptr, len, stdout);
}

void dump_memfp(const char *ptr, int len, FILE *fp)

{
    int loop, cut = 16, base = 0;

    if (ptr == NULL)
        {
        fprintf(fp, "NULL\n");
        return;
        }

    fprintf(fp, "Begin: %p (len=%d)\n", ptr, len);
    while(1==1)
        {
        fprintf(fp, "%4d   ", base);
        for(loop = 0; loop < 16; loop++)
            {
            if(base + loop < len)
                {
                fprintf(fp, "%.02x", ptr[base + loop] & 0xff);
                if((loop % 4) == 3)
                    fprintf(fp, "  ");
                else if(loop < 15)
                    fprintf(fp, "-");
                }
            else
                {
                fprintf(fp, "  ");
                if((loop % 4) == 3)
                    fprintf(fp, "  ");
                else if(loop < 15)
                    fprintf(fp, " ");
                }
            }
        fprintf(fp, "   ");
        for(loop = 0; loop < 16; loop++)
            {
            if(base + loop < len)
                {
                unsigned char chh = ptr[base + loop] & 0xff;
                if(chh < 128 && chh >= 32 )
                    fprintf(fp, "%c", chh);
                else
                    fprintf(fp, ".");
                }
            else
                fprintf(fp, " ");
            }
        fprintf(fp, "\n");
        base += 16;
        if(base >= len)
            break;
        }
    fprintf(fp, "End\n");
}

// Output memory into a hex representation. returns new mem, olen is filled in.
// Free returned pointer with zfree

char *dohex(const char *mem, int len, int *olen)

{
    zline2(__LINE__, __FILE__);
    char *ptr = zalloc(3*len + 1);
    if(ptr == NULL)
        return ptr;
    int prog = 0;
    for(int loop = 0; loop < len; loop++)
        {
        prog += snprintf(ptr + prog, 3*len - prog, "%02x", mem[loop] & 0xff);
        }
    ptr[prog] = '\0';
    *olen = prog;
    return ptr;
}

// Reverse what dogex did. olen filled in.
// Free returned pointer with zfree

char *dounhex(const char *mem, int len, int *olen)

{
    //printf("dounhex %s %p %d len\n", mem, mem, len);
    zline2(__LINE__, __FILE__);
    char *ptr = zalloc(3*len);
    if(ptr == NULL)
        return ptr;
    int prog = 0;
    for(int loop = 0; loop < len; loop+= 2)
        {
        int cch, cchh;
        sscanf(mem + loop, "%02x", &cch);
        ptr[prog] = (char)(cch & 0xff);
        prog++;
        }
    *olen = prog;
    //printf("dounhex %p %d len\n", mem, len);
    return ptr;
}

// Give pointers to second and second to last lines. 
// Return lenght between the two. 

int     frame_buff( char *back2, char **start)

{
    char    *end;
    
    *start = strchr(back2, '\n');
    // Walk back to last line
    if (*start)
        {
        end = strrchr(back2 , '\n');
        if(end)
            {
            *end =  '\0';
            end = strrchr(back2 , '\n');  
            if(end)
                *end =  '\0';
            //printf("start:\n%.*s\nend\n", end - start, start + 1);
            }
        }
    if(!start || !end)
        {
        //xerr2("Unexpected file format\n");
        return 0;
        }
    else
        {
        return end - *start; 
        }           
}

// Test if the string is binary.
// Simple test if string contains negative chars (chh > 127)

int     is_bin(const char *ptr, int len)

{
    int ret = 0;
    for(int loop = 0; loop < len; loop++)
        {
        if(ptr[loop] < '\0')
            {
            ret = 1;
            break;
            }
        }
    return ret;
}

static FILE *log_fp = NULL;

void    dibalog(int level, const char* msg, ...)

{
    if(log_fp == NULL)
        log_fp = fopen("dibalog.txt", "a+");
   
    // Could not log ...
    if(log_fp == NULL)
        {
        printf("Cannot open / create log file,\n");
        return;
        }
        
    fseek(log_fp, 0, SEEK_END);
    va_list ap;
    va_start(ap, msg);
    
    char *ttt3 = zdatestr();
    fprintf(log_fp, "%s [%d]: ", ttt3, getpid()); 
    vfprintf(log_fp, msg, ap);
    
    if(strchr(msg, '\n') == NULL)
        fprintf(log_fp, "\n");
    
    zfree(ttt3);
}

/* EOF */






