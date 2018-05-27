
/* =====[ bluepoint3.c ]=========================================================

   Description:         File encryption block by block.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug.31.2017     Peter Glen      Initial version.

   ======================================================================= */

// -------------------------------------------------------------------------
// Bluepoint encryption routines.
//
//   How it works:
//
//     Strings are walked char by char with the loop:
//
//    for (loop = 0; loop < slen; loop++)
//        {
//        aa = str[loop]; aa = aa OP bb; str[loop] = aa
//        }
//  Note: 'OP' stands for multiple kind of operations
//
//   Flow:
//         generate vector
//         generate pass
//         walk forward with password cycling loop
//         walk backwards with feedback encryption
//          ... virtual machine induced intermediate steps ...
//         walk forward with feedback encryption
//
//  The process guarantees that a single bit change in the original text
//  will change every byte in the resulting block.
//
//  The bit propagation is such a high quality, that it beats current
//  industrial strength encryptions.
//
//  The process also guarantees that a single bit change in the cypher text
//  will change every byte in the decryptrd block.
//
//  Please see bit distribution study.
//
// -------------------------------------------------------------------------
//
// How to use:
//
//  !!! Make sure the passed buffer is even sized !!!
//
//  bluepoint3_encrypt($orig, $pass);                -- encrypted in place
//  bluepoint3_decrypt($cypher, $pass);              -- decrypted in place
//
//  $hash       = bluepoint3_hash($orig, $pass);
//  $crypthash  = bluepoint3_crypthash($orig, $pass);
//
//////////////////////////////////////////////////////////////////////////

#include "stdio.h"
#include "string.h"
#include "stdlib.h"

//define DEF_DUMPHEX  1   // undefine this if you do not want bluepoint3_dumphex

///////////////////////////////////////////////////////////////////////////
// The following defines are used to test multi platform steps.
// These will generate a cypher text incompatible with other implementations
// FOR TESTING ONLY

//define NOROTATE        1   // uncomment this if you want no rotation
//define NOPASSCRYPT     1   // uncomment this if you want no pass crypt

#include "bluepoint3.h"

// Private to the algorithm

#define     ROTATE_LONG_LONG_RIGHT(x, n) (((x) >> (n))  | ((x) << (64 - (n))))
#define     ROTATE_LONG_LONG_LEFT(x, n) (((x) << (n))  | ((x) >> (64 - (n))))

#define     ROTATE_LONG_RIGHT(x, n) (((x) >> (n))  | ((x) << (32 - (n))))
#define     ROTATE_LONG_LEFT(x, n) (((x) << (n))  | ((x) >> (32 - (n))))

#define     ROTATE_SHORT_RIGHT(x, n) (((x) >> (n))  | ((x) << (16 - (n))))
#define     ROTATE_SHORT_LEFT(x, n) (((x) << (n))  | ((x) >> (16 - (n))))

#define     ROTATE_CHAR_RIGHT(x, n) (((x) >> (n))  | ((x) << (8 - (n))))
#define     ROTATE_CHAR_LEFT(x, n) (((x) << (n))  | ((x) >> (8 - (n))))

#define     PASSLIM 64

#include "bluemac.h"

static  void    do_encrypt(char *str, int slen, char *pass, int plen);
static  void    do_decrypt(char *str, int slen, char *pass, int plen);
static  void    prep_pass(const char *pass, int plen, char *newpass);

//# -------------------------------------------------------------------------
//# These vars can be set to make a custom encryption:

static  char vector[]  = "crypt";       //# influence encryption algorythm
char hector[]  = "eahfdlaskjhl9807089609kljhkljfsdhlf";

char    forward    = 0x55;      //# Constant propagated on forward pass
char    backward   = 0x5a;      //# Constant propagated on backward pass
char    addend     = 17;        //# Constant used adding to encrypted values

//# -------------------------------------------------------------------------
//# These vars can be set show op details

static int verbose    = 0;              //# Specify this to show working details
static int debug      = 0;              //# Specify this to show debug strings
static int functrace  = 0;              //# Specify this to show function args

//# -------------------------------------------------------------------------
//# These vars can be set to influence encryption

static  int     rounds = 96;             //# How many rounds. 
                                         //# Initial value is experimental


//# -------------------------------------------------------------------------
//# Tis section is involved with the virtual machine

#include "bluefunc.c"

static  cfunc vmstack[] = {
    mixit,   
    passloop,
    mixit2,  
    hectorx, 
    mixit2r, 
    mixitr,  
    fwloop,  
    bwloop,  
    triloop,  
    };

static  cfunc vmstackr[] = {
    mixit3,                // 0 
    passloop3,             // 1  
    mixit23,               // 2    
    hectorx3,              // 3        
    mixit2r3,              // 4            
    mixitr3,               // 5
    fwloop3,               // 6
    bwloop3,               // 7
    triloop3,              // 8
    };

#if 0
    PASSLOOP(+)    MIXIT2(+)   MIXIT2R(+)   HECTOR(+)   FWLOOP(+)
    MIXIT2(+)   MIXIT2R(+)     PASSLOOP(+) FWLOOP(+)     HECTOR(+)   
    FWLOOP(+)    MIXIT(+)        MIXITR(+)    BWLOOP(+)   HECTOR(+)
#endif
  
// Bluepoint2 compatible  
//int   midx_list[] = {1, 2, 4, 3, 6, 0, 5, 1, 6, 3, 6, 0, 5, 7, 3, -1};

// Bluepoint3 experimental
//int   midx_list[] = { 1,  2, 1, 4, 3, 6, 0, 5, 1, 6, 3, 6, 0, 5, 7, 8, -1 };

// Version 3.0
int   midx_list[128] = {7, 1, 6, 1, 3, 1, 4, 3, 5, 3, 6, 1, 8, 3, -1};

//# -------------------------------------------------------------------------
//# Following functions set values

int     bluepoint3_set_midx(int *list, int elements)

{
    int maxlist = elements;
    int litems = sizeof(midx_list) / sizeof(int);
    // Limit to allocated memory
    if(maxlist > litems - 1)
        {
        maxlist = litems - 1;
        }
    for(int loop = 0; loop < maxlist; loop++)
        {
        midx_list[loop] = list[loop]; // Copy in 
        }
    midx_list[maxlist] = -1;  // Terminate, if user did not provide one
}

//////////////////////////////////////////////////////////////////////////

int    *bluepoint3_get_midx()

{
    return(midx_list);
}


int    bluepoint3_set_verbose(int flag)
{
    int old = verbose;
    verbose = flag;
    return old;
}

int    bluepoint3_set_debug(int flag)
{
    int old = debug;
    debug = flag;
    return old;
}

int    bluepoint3_set_functrace(int flag)
{
    int old = functrace;
    functrace = flag;
    return old;
}

int    bluepoint3_set_rounds(int xrounds)
{
    int old = rounds; rounds  =  xrounds;
    // Prevent no encryption
    if (rounds < 1) rounds = 1;
    return old;
}
       
//# -------------------------------------------------------------------------
//# Use: encrypt($str, $password);

int    bluepoint3_encrypt(char *buff, int blen, const char *pass, int plen)

{
    int ret = 0; char newpass[PASSLIM + 2]; 
    int loop;

    if (blen % 2)
        {
        blen --; ret = 1;
        }
        
    if(plen == 0 || blen == 0)
        {
        return ret;
        }

   if(functrace)
       {
       #ifdef DEF_DUMPHEX
       printf("bluepoint3_encrypt len=%d\nbuff='%s'\n", blen, 
                        bluepoint3_dumphex(buff, blen));
       printf("plen=%d pass='%s'\n", plen, bluepoint3_dumphex(pass, plen) );
       #endif
       }

    prep_pass(pass, plen, newpass);

     if(functrace)
            {
            #ifdef DEF_DUMPHEX
            printf("After prep_pass %d '%s\n", plen,     
                                             bluepoint3_dumphex(newpass, plen));
            #endif
            }
    
    for (loop = 0; loop < rounds; loop++)
        {
        do_encrypt(buff, blen, newpass, PASSLIM);
        }
        
    if(functrace)
        {
        #ifdef DEF_DUMPHEX
        //printf("After LOOP %d '%s\n", blen, 
        //                        bluepoint3_dumphex(buff, blen));
        #endif
        }
        
    return ret;
}

//# -------------------------------------------------------------------------
//# Use: bluepoint3_decrypt($str, $password);

int    bluepoint3_decrypt(char *buff, int blen, const char *pass, int plen)

{
    int ret = 0; char newpass[PASSLIM + 2]; int loop;
    
    if (blen % 2)
        {
        blen --; ret = 1;
        }

    if(plen == 0 || blen == 0)
        {
        return ret;
        }

    if(functrace)
        {
        #ifdef DEF_DUMPHEX
       
        //printf("bluepoint3_decrypt()\nbuff=%s\n", 
        //                        bluepoint3_dumphex(buff, blen));
        //printf("pass=%s\n", bluepoint3_dumphex(pass, plen));
        #endif
        }

    prep_pass(pass, plen, newpass);

    for (loop = 0; loop < rounds; loop++)
        {
        do_decrypt(buff, blen, newpass, PASSLIM);
        }
    return ret;
}

///////////////////////////////////////////////////////////////////////////
// Prepare pass

void    prep_pass(const char *pass, int plen, char *newpass)

{
    int loop; char vec2[PASSLIM];

    // Duplicate vector
    int vlen = strlen(vector);
    strcpy(vec2, vector);
    newpass[0] = 0;

    int loop2 = 0;
    for(loop = 0; loop < PASSLIM; loop++)
        {
        newpass[loop] = pass[loop2];
        // Increment, wrap
        loop2++; if (loop2 >= plen) loop2 = 0;
        }
    // Terminate
    newpass[PASSLIM] = 0;

    if(verbose)
        printf("prep_pass() newpass: %s\n", newpass);

#ifndef NOPASSCRYPT
    do_encrypt(vec2, vlen, vector, vlen);
#endif

    if(verbose)
        {
        printf("prep_pass() eVEC: ");
        #ifdef DEF_DUMPHEX
        //bluepoint3_dumphex(vec2, vlen);
        #endif
        printf("\n");
        }

#ifndef NOPASSCRYPT
    do_encrypt(newpass, PASSLIM, vec2, vlen);
#endif

}

//# -------------------------------------------------------------------------
//# Hash:
//# use: hashvalue = hash($str)
//#
//# Implementing the following 'C' code
//#
//#   ret_val ^= (unsigned long)*name;
//#   ret_val  = ROTATE_LONG_RIGHT(ret_val, 10);          /* rotate right */sub hash
//#

ulong   bluepoint3_hash(const char *buff, int blen)

{
    unsigned long    sum = 0;
    int     loop;
    char    aa, aa2, aa3;

    for (loop = 0; loop < blen; loop++)
        {
        sum ^= (unsigned char)buff[loop];
        sum = ROTATE_LONG_RIGHT(sum, 10);          /* rotate right */
        }

    return sum;
}

unsigned long long   bluepoint3_hash64(const char *buff, int blen)

{
    unsigned long long  sum = 0;
    int     loop;

    for (loop = 0; loop < blen; loop++)
        {
        sum ^= (unsigned char)buff[loop];
        sum = ROTATE_LONG_LONG_RIGHT(sum, 20);    /* rotate right */
        }
    return sum;
}

//# -------------------------------------------------------------------------
//# Crypt and hash:
//# use: crypthash = bluepoint3_crypthash($str, "pass")

ulong   bluepoint3_crypthash(const char *buff, int blen, char *pass, int plen)

{
    unsigned long  sum = 0;

    // Duplicate buffer
    char *duplicate = (char *)malloc(blen + 4);
    if(!duplicate)
        {
        return(0LL);
        }
    memcpy(duplicate, buff, blen);

    bluepoint3_encrypt(duplicate, blen, pass, plen);
    sum = bluepoint3_hash(duplicate, blen);

    free(duplicate);
    return(sum);
}

unsigned long long bluepoint3_crypthash64(const char *buff, int blen, char *pass, int plen)

{
    unsigned long long  sum = 0;

    // Duplicate buffer
    char *duplicate = (char *)malloc(blen + 4);
    if(!duplicate)
        {
        return(0LL);
        }
    memcpy(duplicate, buff, blen);

    bluepoint3_encrypt(duplicate, blen, pass, plen);
    sum = bluepoint3_hash64(duplicate, blen);

    free(duplicate);
    return(sum);
}

//# The encryption stack:

void    ENCRYPT(char *str, int slen, char *pass, int plen)
{
    int loop, loop2 = 0;  unsigned char  aa, bb, cc;
    
    //return;
    
    int items = sizeof(midx_list) / sizeof(int);
    for(int loop = 0; loop < items; loop++)
        {
        int idx =  midx_list[loop];
        if(idx < 0)
            break;
        //printf("ENC: %d %p\n", idx, vmstack[loop]);
        if(idx < sizeof(vmstack) / sizeof(void*) )
            vmstack[idx](str, slen, pass, plen);
        //else
        //    printf("Warn: idx larger then func list\n");
        }
    
    #if 0
    PASSLOOP(+)
    MIXIT2(+)   MIXIT2R(+)
    HECTOR(+)   FWLOOP(+)
    MIXIT2(+)   MIXIT2R(+)
    PASSLOOP(+) FWLOOP(+)
    HECTOR(+)   FWLOOP(+)
    MIXIT(+)    
    MIXITR(+)
    BWLOOP(+)   HECTOR(+)
    #endif
}   
         
void    DECRYPT(char *str, int slen, char *pass, int plen)
{
    int loop, loop2 = 0; unsigned char aa, bb, cc;
    
    int items = sizeof(midx_list) / sizeof(int);
    
    // Find list end, walk backwards
    for(loop = 0; loop < items; loop++)
        {
        if(midx_list[loop] < 0)
            break;
        }
    loop--;     
    for( ; loop >= 0; loop--)
        {
        int idx =  midx_list[loop];
        if(idx < 0)
            break;
        if(idx < sizeof(vmstackr) / sizeof(void*) )
            vmstackr[idx](str, slen, pass, plen);
        //else
        //    printf("Warn: idx larger then func list\n");
        }
        
    //return;
    
    #if 0
    HECTOR(-)   BWLOOP2(-)
    MIXITR(-)   
    MIXIT(-)
    FWLOOP2(-)  HECTOR(-)
    FWLOOP2(-)  PASSLOOP(-)
    MIXIT2R(-)  MIXIT2(-)
    FWLOOP2(-)  HECTOR(-)
    MIXIT2R(-)  MIXIT2(-)
    PASSLOOP(-)
    #endif
}

//# -------------------------------------------------------------------------
//# The following routines are internal to this module:

void    do_encrypt(char *str, int slen, char *pass, int plen)

{
    if(verbose)
        {
        printf( "encrypt str='%s' len=%d pass='%s' plen=%d\n",
                 str, slen, pass, plen);
        }
      ENCRYPT(str, slen, pass, plen);
}

//# -------------------------------------------------------------------------
//# Internal to this module:

void    do_decrypt(char *str, int slen, char *pass, int plen)

{
    if(verbose)
        {
        printf( "decrypt(inp) str=%s len=%d pass=%s plen=%d\n",
                  str, slen, pass, plen);
        }
      DECRYPT(str, slen, pass, plen);
}

#ifdef DEF_DUMPHEX

static unsigned char buff[4096];

//# -------------------------------------------------------------------------
// use it for testing only as it has a xx byte buffer limit
//# Use: mystr = bluepoint3_dump($str)

char    *bluepoint3_dump(const char *str, int len)

{
    unsigned int loop = 0, pos = 0;
    buff[0] = 0;  
    
    if(verbose)
        {
        printf("bluepoint3_dump str=%p len=%d ", str, len);
        }

    for (loop = 0; loop < len; loop++)
        {
        pos += sprintf(buff + pos, "%02x", (unsigned char)str[loop]);

        if(pos >= (sizeof(buff) - 8))
            {
            //# Show that string is incomplete
            //printf("Overflow ...\n");
            buff[pos++] = ' ';
            buff[pos++] = '.';
            buff[pos++] = '.';
            buff[pos++] = '.';
            break;
            }
        }
    buff[pos] = '\0';
    return(buff);
}

//# -------------------------------------------------------------------------
// Use it for decoding the dump to cyphertext
//# Use: mystr = bluepoint3_undump($str, len)

char    *bluepoint3_undump(const char *str, int len, int *olen)

{
    unsigned int loop = 0, pos = 0, val = 0;
    if(verbose)
        {
        printf("bluepoint3_undump str=%p len=%d ", str, len);
        }
    //memset(buff, 0, sizeof(buff));
    buff[0] = '\0';
    
    for (loop = 0; loop < len; loop += 2)
        {
        sscanf(str + loop, "%02x", &val);
        //printf("%02x ", val & 0xff);
        
        // Safety check for buffer overflow
        if(pos >= (sizeof(buff) - 8))
            {
            break;
            }
        buff[pos++] = (unsigned char)(val & 0xff);
        }
    // pos points to next, unfilled    
    *olen = pos - 1;
    //printf("\n");
    return(buff);
}
#endif

// -------------------------------------------------------------------------
// Dump binary to hex buffer.
// Pass in buffer size, will fill in actual length
// return 1 for OK, return 0 if not big enough buffer
//

int     bluepoint3_dump2buff(const char *str, int len, char *out, int *olen)

{
    int ret = 1;
    unsigned int loop = 0, pos = 0;
    // Clear all
    memset(out, 0, *olen);
    if(verbose)
        {
        printf("bluepoint3_dump2buff str=%p len=%d ", str, len);
        }
    for (loop = 0; loop < len; loop++)
        {
        pos += sprintf(out + pos, "%02x", (unsigned char)str[loop]);
        if(pos >= (*olen - 2))
            {
            ret = 0; break;
            }
        }
    out[pos] = '\0';
    return(ret);
}

// -------------------------------------------------------------------------
// UnDump binary to hex buffer.
// Pass in buffer size, will fill in actual length
// return 1 for OK, return 0 if not big enough buffer
//

int     bluepoint3_undump2buff(const char *str, int len, char *out, int *olen)

{
    int ret = 1;
    unsigned int loop = 0, pos = 0, val = 0;
    if(verbose)
        {
        printf("bluepoint3_undump str=%p len=%d ", str, len);
        }
    memset(out, 0, *olen);
    for (loop = 0; loop < len; loop += 2)
        {
        sscanf(str + loop, "%02x", &val);
        //printf("%02x ", val & 0xff);
        
        // Safety check for buffer overflow
        if(pos >= (*olen - 2))
            {
            ret = 0; break;
            }
        out[pos++] = val & 0xff;
        }
    // pos points to next, unfilled    
    *olen = pos - 1;
    //printf("\n");
    return(ret);
}

//# -------------------------------------------------------------------------
// convert binary str to hex string
//# char    *bluepoint_tohex(char *str, int len, char *out, int *len)

char    *bluepoint3_tohex(const char *str, int len, char *out, int *olen)

{
    int loop = 0, pos = 0;
    for (loop = 0; loop < len; loop++)
        {
        pos += sprintf(out + pos, "%02x", ( unsigned char) str[loop]);

        if(pos >= *olen - 4)
            break;
        }
    *olen = pos;
    return(out);
}

//# -------------------------------------------------------------------------
// convert hex string to binary str
//# char    *bluepoint_fromhex(char *str, int len, char *out, int *len)

char    *bluepoint3_fromhex(const char *str, int len, char *out, int *olen)

{
    unsigned char *str2 = (unsigned char *)str;

    char chh[3]; chh[2] = 0;

    int loop = 0, pos = 0;
    for (loop = 0; loop < len; loop += 2)
        {
        long vv;

        chh[0] =  *(str + loop);
        chh[1] =  *(str + loop + 1);

        vv = strtol(chh, NULL, 16);

             if(pos > *olen - 3)
            break;

        out[pos++] =(char)vv;
        }

    // It aborted for just enough space to zero terminate
    out[pos] = 0;
    *olen = pos;
    return(out);
}















