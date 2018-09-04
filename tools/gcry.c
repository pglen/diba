
/* =====[ gcry.c ]=========================================================

   Description:     Encryption examples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  jul.17.2017     Peter Glen      Added dump mem
      0.00  aug.26.2017     Peter Glen      First push to github

   ======================================================================= */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "gcrypt.h"
#include "gcry.h"
#include "gsexp.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"
#include "dibastr.h"
#include "misc.h"

#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif

void    xerr2(const char* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    
    vfprintf(stderr, msg, ap);
    exit(2);                                
}

//////////////////////////////////////////////////////////////////////////

void    printerr(int err, char *str)

{
    if(str)
        fprintf (stderr, "%s\n", str);
        
    fprintf (stderr, "Failure: %s/%s\n",
                    gcry_strsource (err),
                        gcry_strerror (err));
                        
    //fprintf (stdout, "Failure: %s/%s\n",
    //                gcry_strsource (err),
    //                    gcry_strerror (err));
}       

//////////////////////////////////////////////////////////////////////////

void    gcrypt_init()

{
    /* Version check should be the very first call because it
       makes sure that important subsystems are intialized. */
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        //xerr2("gcrypt: library version mismatch\n");
        //printf("Warn: library version mismatch\n");
    }

    gcry_error_t err = 0;

    /* We don't want to see any warnings, e.g. because we have not yet
       parsed program options which might be used to suppress such
       warnings. */
       
    //err = gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    /* ... If required, other initialization goes here.  Note that the
       process might still be running with increased privileges and that
       the secure memory has not been intialized.  */

    /* Allocate a pool of 16k secure memory.  This make the secure memory
       available and also drops privileges where needed.  */
    //err |= gcry_control (GCRYCTL_INIT_SECMEM, 1638400, 0);

    /* It is now okay to let Libgcrypt complain when there was/is
       a problem with the secure memory. */
    //err |= gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    /* ... If required, other initialization goes here.  */

    err |= gcry_control(GCRYCTL_DISABLE_SECMEM);
    //err |= gcry_control(GCRYCTL_DISABLE_LOCKED_SECMEM);
        
    /* Tell Libgcrypt that initialization has completed. */
    err |= gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (err) {
        xerr2("gcrypt: failed initialization.\n");
    }
}

size_t  get_keypair_size(int nbits)
{
    size_t aes_blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128);

    // format overhead * {pub,priv}key (2 * bits)
    size_t keypair_nbits = 4 * (2 * nbits);

    size_t rem = keypair_nbits % aes_blklen;
    return (keypair_nbits + rem) / 8;
}

void    get_aes_ctx(gcry_cipher_hd_t* aes_hd, const char *passwd, int pass_len)
{
    const size_t keylen = 16;
    char passwd_hash[keylen];
    
    int err = gcry_cipher_open(aes_hd, GCRY_CIPHER_AES128, 
                               GCRY_CIPHER_MODE_CFB, 0);
    if (err) {
        xerr2("gcrypt: failed to create aes handle");
    }

    gcry_md_hash_buffer(GCRY_MD_MD5, (void*) &passwd_hash, 
                        (const void*) passwd, pass_len);

    err = gcry_cipher_setkey(*aes_hd, (const void*) &passwd_hash, keylen);
    if (err) {
        xerr2("gcrypt: could not set cipher key");
    }

    err = gcry_cipher_setiv(*aes_hd, (const void*) &passwd_hash, keylen);
    if (err) {
        xerr2("gcrypt: could not set cipher initialization vector");
    }
}

void get_twofish_ctx(gcry_cipher_hd_t* aes_hd, const char *passwd, int pass_len)
{
    const size_t keylen = 16;
    char passwd_hash[keylen];
    
    int err = gcry_cipher_open(aes_hd, GCRY_CIPHER_TWOFISH, 
                               GCRY_CIPHER_MODE_CFB, 0);
    if (err) {
        xerr2("gcrypt: failed to create aes handle");
    }

    gcry_md_hash_buffer(GCRY_MD_MD5, (void*) &passwd_hash, 
                        (const void*) passwd, pass_len);

    err = gcry_cipher_setkey(*aes_hd, (const void*) &passwd_hash, keylen);
    if (err) {
        xerr2("gcrypt: could not set cipher key");
    }

    err = gcry_cipher_setiv(*aes_hd, (const void*) &passwd_hash, keylen);
    if (err) {
        xerr2("gcrypt: could not set cipher initialization vector");
    }
}

//////////////////////////////////////////////////////////////////////////

typedef struct _armor_params
{
    char    *rsa_buf;
    int     *prsa_len;
    char    **err_str; 
    int     *cleanlen;
    const   char *starts; 
    const   char *ends;
}
armor_params;

static char *decode_armor(armor_params *params)

{
    char *sbegin = strstr(params->rsa_buf, params->starts);
    if(sbegin == NULL)
        {
        *params->err_str = "No start marker";
        return(NULL);
        }
    char *send   = strstr(params->rsa_buf, params->ends);
    if(send == NULL)
        {
        *params->err_str = "No end marker";
        return(NULL);
        }
    sbegin += strlen(params->starts);
    int slen = send - sbegin;
    *params->cleanlen = slen;
    return sbegin;
} 

//////////////////////////////////////////////////////////////////////////
// Unscramble --Begin --End marks, then base64 unexpand and decode.
// free pointer with zalloc / zfree.

char    *decode_signature(char *rsa_buf, int *prsa_len, char **err_str)

{
    armor_params params;
    int slen;
    *err_str = NULL;
    params.rsa_buf = rsa_buf;    params.prsa_len = prsa_len;
    params.err_str = err_str;    params.cleanlen = &slen;
    params.starts =  sig_start;  params.ends    = sig_end;

    char *sbegin = decode_armor(&params);
    if(!sbegin)
        return NULL;          
              
    int cleanlen = slen;
    zline2(__LINE__, __FILE__);
    char *memc = zalloc(cleanlen);
    base64_clean(sbegin, slen, memc, &cleanlen);

    int outlen = base64_calc_decodelen(cleanlen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(cleanlen);
    base64_decode(memc, cleanlen, mem, &outlen);
    zcheck(mem, __LINE__);
    zfree(memc);
    *prsa_len = outlen;
    return mem;    
}

//////////////////////////////////////////////////////////////////////////
// Unscramble --Begin --End marks, then base64 unexpand and decode.
// free pointer with zalloc / zfree.

char    *decode_pub_key(char *rsa_buf, int *prsa_len, char **err_str)

{
    armor_params params;
    int slen;
    *err_str = NULL;
    params.rsa_buf = rsa_buf;    params.prsa_len = prsa_len;
    params.err_str = err_str;    params.cleanlen = &slen;
    params.starts =  pub_start;   params.ends    = pub_end;

    char *sbegin = decode_armor(&params);
    if(!sbegin)
        return NULL;          
              
    int cleanlen = slen;
    zline2(__LINE__, __FILE__);
    char *memc = zalloc(cleanlen);
    base64_clean(sbegin, slen, memc, &cleanlen);

    int outlen = base64_calc_decodelen(cleanlen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(cleanlen);
    base64_decode(memc, cleanlen, mem, &outlen);
    zcheck(mem, __LINE__);
    zfree(memc);
    *prsa_len = outlen;
    return mem;    
}

//////////////////////////////////////////////////////////////////////////
// Unscramble --Begin --End marks, then base64 unexpand and decode.
// free pointer with zalloc / zfree.

char    *decode_rsa_cyph(char *rsa_buf, int *prsa_len, char **err_str)

{
    armor_params params;
    int slen;
    *err_str = NULL;
    params.rsa_buf = rsa_buf;    params.prsa_len = prsa_len;
    params.err_str = err_str;    params.cleanlen = &slen;
    params.starts =  cyph_start; params.ends     = cyph_end;

    char *sbegin = decode_armor(&params);
    if(!sbegin)
        return NULL;          
              
    int cleanlen = slen;
    zline2(__LINE__, __FILE__);
    char *memc = zalloc(cleanlen);
    base64_clean(sbegin, slen, memc, &cleanlen);
    zcheck(memc, __LINE__);
    
    int outlen = base64_calc_decodelen(cleanlen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(cleanlen);
    base64_decode(memc, cleanlen, mem, &outlen);
    zcheck(mem, __LINE__);
    
    zfree(memc);
    *prsa_len = outlen;
    return mem;    
}
            
//////////////////////////////////////////////////////////////////////////
// Unscramble --Begin --End marks, then base64 unexpand and decode.
// free pointer with zalloc / zfree.

char *decode_comp_key(char *rsa_buf, int *prsa_len, char **err_str)

{
    armor_params params;
    int slen;
    *err_str = NULL;
    params.rsa_buf = rsa_buf;    params.prsa_len = prsa_len;
    params.err_str = err_str;    params.cleanlen = &slen;
    params.starts = comp_start;  params.ends = comp_end;

    char *sbegin = decode_armor(&params);
    if(!sbegin)
        return(NULL);
                            
    int cleanlen = slen;
    zline2(__LINE__, __FILE__);
    
    char *memc = zalloc(cleanlen);
    base64_clean(sbegin, slen, memc, &cleanlen);

    int outlen = base64_calc_decodelen(cleanlen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(cleanlen);
    base64_decode(memc, cleanlen, mem, &outlen);
    zcheck(mem, __LINE__);
    zfree(memc);
    *prsa_len = outlen;
    return mem;    
}

void    print_cypher_details(const char *str)

{
    int cy = gcry_cipher_map_name(str);
    printf("Cypher:       %d\n", cy);
    printf("Cypher name:  '%s'\n", gcry_cipher_algo_name(cy));
    printf("Blocklen:     %d\n", (int)gcry_cipher_get_algo_blklen(cy));
    printf("Keylen:       %d\n", (int)gcry_cipher_get_algo_keylen(cy));
    printf("\n");
}    

//////////////////////////////////////////////////////////////////////////

int     pk_encrypt_buffer(const char *buf, int len, gcry_sexp_t pubk, gcry_sexp_t *ciph)

{ 
    int ret = 0;
            
    /* Create a message. */
    gcry_mpi_t msg; 
    gcry_error_t err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, buf, len, NULL);

    if (err) {
        printerr(err, "create mpi");
        //xerr2("failed to create a mpi from the buffer");
    }

    gcry_sexp_t data; 
    err = gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", msg);
    if (err) {
        printerr(err, "build");
        //xerr2("failed to create a sexp from the message");
    }

    /* Encrypt the message. */
    err = gcry_pk_encrypt(ciph, data, pubk);
    if (err) {
            sexp_print(*ciph);
            printerr(err, "encryption");
        //xerr2("gcrypt: encryption failed");
    }
    
    gcry_sexp_release(data);
    gcry_mpi_release(msg);
    ret = err;
    return ret;
}

//////////////////////////////////////////////////////////////////////////

int     write_pubkey(gcry_sexp_t *pubk, const char *fname2)

{
    int ret = TRUE;
    int klen;
    
    char *kptr = sexp_sprint(*pubk, &klen, GCRYSEXP_FMT_CANON);
    if(!kptr)  {
       //xerr2("sprint failed. %s %d", __FILE__, __LINE__);                                                              
        printf("Could not sprint S exp for %s\n", fname2);
        return -1;
    }
    int outx;
    char *mem5 = base_and_lim(kptr, klen, &outx);
    mem5[outx] = '\0';
    
    FILE* fp3 = fopen(fname2, "wb");
    if (!fp3) {
        {
        printf("Could not write public key %s\n", fname2);
        return -1;
        }
    }
    fprintf(fp3, "%s\n", pub_start);
    fprintf(fp3, "%.*s\n", outx, mem5);
    fprintf(fp3, "%s\n", pub_end);
    
    fclose(fp3); 
    zfree(mem5);
    zfree(kptr);
    
    return ret;
}    
    
int     write_mod_exp(gcry_sexp_t *rsa_keypair, const char *fname2)

{
    int ret = TRUE;
    
    gcry_sexp_t nnn = gcry_sexp_find_token(*rsa_keypair, "n", 0);
    if(nnn == NULL)
        {
        printf("Could not find public modulus. (no .mod file written)\n");
        return -1;
        }
    //sexp_print(nnn);
    
    size_t pklen = 0;
    const char *pkptr = gcry_sexp_nth_data(nnn, 1, &pklen);
    //dump_mem(ptr, pklen);
    
    gcry_sexp_t eee = gcry_sexp_find_token(*rsa_keypair, "e", 0);
    if(eee == NULL)
        {
        printf("Could not find public expenent. (no .mod file written)\n");
        return -1;
        }
    //sexp_print(eee);
    size_t elen = 0;
    const char *eptr = gcry_sexp_nth_data(eee, 1, &elen);
         
    FILE* fp2 = fopen(fname2, "wb");
    if (!fp2) {
        printf("Could not write .mod file to %s\n", fname2);
        return -1;
        //xerr2("fopen() failed");                                                              
    }
    int outx;
    zline2(__LINE__, __FILE__);
    char *mem3 = base_and_lim(pkptr, pklen, &outx);
    mem3[outx] = '\0';
    fprintf(fp2, "%s\n", mod_start);
    fprintf(fp2, "%.*s\n", outx, mem3);
    fprintf(fp2, "%s\n", mod_end);
    zline2(__LINE__, __FILE__);
    char *mem4 = base_and_lim(eptr, elen, &outx);
    mem4[outx] = '\0';
    fprintf(fp2, "%s\n", exp_start);
    fprintf(fp2, "%.*s\n", outx, mem4);
    fprintf(fp2, "%s\n", exp_end);
  
    fclose(fp2);
    zfree(mem3);
    zfree(mem4);
        
    return ret;
}

char    *hash_buff(const char *buff, int len)

{ 
    char pub_hash[32];
    gcry_md_hash_buffer(GCRY_MD_SHA256, (void*) &pub_hash, 
                    (const void*) buff, len);
    int olen;
    char *hash_str = base_and_lim(pub_hash, sizeof(pub_hash), &olen); 
    return hash_str;
}
    
//////////////////////////////////////////////////////////////////////////
// Return sha hash string

char    *hash_file(char *fname, char **err_str)

{ 
    char pub_hash[32];
    
    //printf("Arg '%s'\n", argv[0]);
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
    gcry_md_hash_buffer(GCRY_MD_SHA256, (void*) &pub_hash, 
                    (const void*) file_buf, file_len);
    
    zfree(file_buf);
    int olen;
    char *hash_str = base_and_lim(pub_hash, sizeof(pub_hash), &olen);
    }
    
    
// Must free with zfree
    
char    *zrandstr_strong(int len)

{
    zline2(__LINE__, __FILE__);
    char *rrr = zalloc(len);
    gcry_randomize(rrr, len, GCRY_STRONG_RANDOM);
    //rrr[sizeof(rrr)-1] = '\0';
    int len2 = len;
    char *ret = tobase64(rrr, &len2);
    zcheck(rrr, __LINE__);
    zfree(rrr);
    return ret;
}    

                
/* EOF */

















