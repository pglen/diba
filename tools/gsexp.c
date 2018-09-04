
/* =====[ gsexp.c ]=========================================================

   Description:     Sexp routines.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug.03.2017     Peter Glen      Initial version.
      0.00  oct.20.2017     Peter Glen      Work 

   ======================================================================= */

#include <stdio.h>

#include "gcrypt.h"
#include "gcry.h"
#include "gsexp.h"
#include "zmalloc.h"
#include "misc.h"

//////////////////////////////////////////////////////////////////////////
// Print sexp to memory
// Free the resulting pointer with zfree

char *sexp_sprint(gcry_sexp_t sexp, int *len, int format)

{
    int slen = gcry_sexp_sprint(sexp, format, NULL, 0);
    *len = 0;
    zline2(__LINE__, __FILE__);
    char *ppp = (char*)zalloc(slen+1);
    if(ppp == NULL)
        return NULL;

    gcry_sexp_sprint(sexp, format, ppp, slen);
    *len = slen;
    // Zero terminate
    ppp[slen-1] = '\0';
    return(ppp);
}

//////////////////////////////////////////////////////////////////////////
// Print sexp to file (for logs)

void    sexp_fprint(gcry_sexp_t rsa_keypair, FILE *fp)

{
    int len;
    char *ppp = sexp_sprint(rsa_keypair, &len, GCRYSEXP_FMT_ADVANCED);
    if(ppp == NULL)
        return;
    fprintf(fp, "%s\n", ppp);
    zfree(ppp);
}

//////////////////////////////////////////////////////////////////////////
// Print sexp to stdout

void    sexp_print(gcry_sexp_t rsa_keypair)

{
    int len;
    char *ppp = sexp_sprint(rsa_keypair, &len, GCRYSEXP_FMT_ADVANCED);
    if(ppp == NULL)
        return;
    printf("%s\n", ppp);
    zfree(ppp);
}

char    *stack[12];
int     depth = 0;

static char *sexp_decode_one(gcry_sexp_t list, int *plen, const char *findstr)

{
    char *ret = NULL;
    int  onelen = gcry_sexp_length(list);

    //printf( "one: %d\n", onelen);
    sexp_print(list);
    
    for(int loop = 0; loop < onelen; loop++)
        {
        size_t len;
        const char *data = gcry_sexp_nth_data(list, loop, &len);
        if(data == NULL)
            {
            gcry_sexp_t element = gcry_sexp_nth(list, loop);
            if(element)
                {   
                size_t len3;
                const char *data3 = gcry_sexp_nth_data(element, 0, &len3);
                //printf("element: '%.*s'\n", len3, data3);
                char *memx = zalloc(len3 + 1);
                memcpy(memx, data3, len3);
                memx[len3] = '\0'; 
                stack[depth] = memx;  
                // We know it is going to be 3 at max
                if(depth < 12)
                    depth++;
                ret = sexp_decode_one(element, plen, findstr);
                if(ret)
                    break;
                }
            }
        else
            {
            //printf("data: %d '%.*s'\n", loop, len, data);

            size_t  len2;
            if(strncmp(findstr, data, len) == 0 || findstr[0] == '\0' )
                {
                const char *data2 = gcry_sexp_nth_data(list, loop + 1, &len2);
                if(data2)
                    {
                    //printf("'/");
                    for(int loop3 = 0; loop3 < depth; loop3++)
                        printf("/%s", stack[loop3]);
                    printf("'");
    
                    if(is_bin(data2, len2))
                        {
                        int olen;
                        zline2(__LINE__, __FILE__);
                        char *mem2 = dohex(data2, len2, &olen);
                        printf(" #%s#\n", mem2); 
                        zfree(mem2);
                        }
                    else
                        {
                        printf(" '%.*s'\n", (int)len2, data2);
                        }
                    zline2(__LINE__, __FILE__);
                    ret =  zalloc(len2 + 1);
                    memcpy(ret, data2, len2);
                    ret[len2] = '\0'; 
                    *plen = len2; 
                    break;
                    }
                }
            }
        } 
    if(depth)
        zfree(stack[depth-1]); 
    depth--;
    return ret;
}

// Depth search for sexp. Reurn duplicate data. Free it with zfree.

char    *sexp_decode(gcry_sexp_t list, int *olen, const char *findstr)

{
    char *ret = NULL;
    depth = 0;   // Just in case it was misused
    stack[depth] = gcry_sexp_nth_string(list, 0); depth++;
    ret = sexp_decode_one(list, olen, findstr);
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Get sexp as a buffer
// Free return value with zfree

char    *sexp_get_buff(gcry_sexp_t sexp, int *plen)

{
    char *ret = NULL;
    int len = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, NULL, 0);
    zline2(__LINE__, __FILE__);
    ret = zalloc(len + 1);
    *plen = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, ret, len);
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Get a list ot an element, zero terminated
// Must free pointer with zfree

char    *sexp_nth_data(gcry_sexp_t  element, int num, int *plen)

{
    char *ret;
    const char *buff = gcry_sexp_nth_data(element, num, (size_t *)plen);
    zline2(__LINE__, __FILE__);
    ret = zalloc(*plen + 1);
    if(ret != NULL)
        {
        memcpy(ret, buff, *plen);
        ret[*plen] = '\0';
        }
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Return a base64 encoded hash string

char    *sexp_hash (gcry_sexp_t pubk, int *olen)

{
    int klen;
    char pub_hash[32];
    char *kptr = sexp_sprint(pubk, &klen, GCRYSEXP_FMT_CANON);
    if(!kptr)  {
        xerr2("sprint failed. %s %d", __FILE__, __LINE__);
    }

    gcry_md_hash_buffer(GCRY_MD_SHA256, (void*) &pub_hash,
                        (const void*) kptr, klen);
    zfree(kptr);
    char *hash_str = base_and_lim(pub_hash, sizeof(pub_hash), olen);

    return hash_str;
}

//////////////////////////////////////////////////////////////////////////
// List sexpr to console
// Return the number of items printed

int     sexp_list (gcry_sexp_t list)

{
    int ret = 0;
    printf("\n");
    for (int loop = 1; loop < gcry_sexp_length(list); loop++)
        {
        gcry_sexp_t element = gcry_sexp_nth(list, loop);

        unsigned int plen;
        char *buff = sexp_nth_data(element, 0, &plen);
        unsigned int plen2;
        char *buff2 = sexp_nth_data(element, 1, &plen2);

        //int olen;
        //char *hh = dohex(buff2, plen2, &olen);

        printf("%-20s - '%s'\n", buff, buff2);
        //printf("#%s#\n", hh);
        //zfree(hh); 
        
        zfree(buff); zfree(buff2);
        ret++;
        }
    printf("\n");
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Get an sexp value, alloc buff  term nul

char    *sexp_get_val(gcry_sexp_t sexp, const char *key, int *polen, char **err_str)

{
    *err_str = NULL;
    gcry_sexp_t nhh = gcry_sexp_find_token(sexp, key, 0);
    if(!nhh)
        {
        *err_str = "No key found."; return NULL;
        }
    size_t olen;
    const char *ddd2 =  gcry_sexp_nth_data(nhh, 1, &olen);
    if(!ddd2)
        {
        *err_str = "No data on key.";  return NULL;
        }
    char *ret = zalloc(olen + 2);   
    memcpy(ret, ddd2, olen);
    ret[olen] = '\0';
    *polen = olen;
    return  ret;      
}

/* EOF */






















