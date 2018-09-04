
/* =====[ dibautils.c ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.10  Jun.22.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>

// This is a hack to get multi platform compile
#ifndef linux
int     nanosleep( const struct timespec *period, struct timespec *residual );
#endif

#include "dibautils.h"

#include "diba.h"
#include "bluepoint3.h"
#include "gcry.h"
#include "gsexp.h"
#include "base64.h"
#include "zmalloc.h"
#include "dibastr.h"
#include "misc.h"
#include "zstr.h"
#include "getpass.h"

int     deadbeef = 0xdeadbeef;

// Generate random buffer in place. Favour none.

void    rand_buff(char *str, int len)

{
    int loop;
    for(loop = 0; loop < len; loop++)
        {
        str[loop] = rand() % 255;
        }
}

// Generate random string in place. Favour lower case letters.

void    rand_asci_buff(char *str, int len)

{
    int loop;
    for(loop = 0; loop < len; loop++)
        {
        //str[loop] = rand() % 255;
        
        // Favour lower case letters
        int ttt = rand() % 6;
        if (ttt == 0)
            str[loop] = (rand() % 10) + '0';
        else if (ttt == 1)
            str[loop] = (rand() % 26) + 'A';
        else
            str[loop] = (rand() % 26) + 'a';
        }
}

void    rand_str(char *str, int len)

{
    int loop;
    for(loop = 0; loop < len - 1; loop++)
        {
        // Favour lower case letters
        int ttt = rand() % 8;
        if (ttt == 0)
            str[loop] = (rand() % 10) + '0';
        else if (ttt == 1)
            str[loop] = (rand() % 26) + 'A';
        else
            str[loop] = (rand() % 26) + 'a';
        }
   str[loop] = '\0';
}

void    show_str(const char* str, int len)

{
    int olen = 3 * len;
    char *ptr = zalloc(olen);
    bluepoint3_tohex((char*)str, len, ptr, &olen);
    printf("%s", ptr);
    zfree(ptr); 
}   

//void show_hexstr(const char* str, int len)
//
//{
//    char *str2 = bluepoint3_dumphex(str, len);
//    printf("%s\n", str2);
//}   

//////////////////////////////////////////////////////////////
// Reverse string in place

void    genrev(char *str, int len)

{
    int loop, bb;
    
    if (len <= 10)
        {
        printf("Must have more than 10 bytes\n");
        return;
        }
    
    // Init beginning
    //for (bb = 0; bb < 8; bb++)
    //    str[bb] = '\0';
        
    // Count up
    for(loop = len-(ASIZE+1); loop >= ASIZE; loop--)
        {
        unsigned char cc = str[loop];
        if(cc == 0xff)
            {
            str[loop] = 0;
            }
        else
           {
           str[loop] = ++cc;
           break;
           }
        }
}

char    *diba_alloc(int size)

{
    zline2(__LINE__, __FILE__);
    char *ret = zalloc(size); 
    
    if(ret == NULL) 
        {
        fprintf(stderr, "%s\n", mstr);
        exit(2);
        }
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Build next sexp

int     build_next(gcry_sexp_t *chain_next, build_next_struct *bns)

{
    int err = gcry_sexp_build(chain_next, NULL, 
                "(\"Next Work\" (\"Next Calc Date\" %s) "
                    "(\"Next Hash\" %s) (\"Next Padding\" %s) (\"Next ID\" %s) "
                    "(\"Next File\" %s) (\"Next Work Hash\" %s) )",
                    bns->next_calc, bns->next_hash, bns->next_pad,
                        bns->next_id, bns->next_file, bns->next_workhash) ;
    return err;                            
}

// Read in and decode file to sexp

int     read_sexp_from_file(const char *fname, gcry_sexp_t *sexp, char **err_str)

{
    int ret = 0, glen;  gcry_error_t err = 0;
    *err_str = NULL;

    char  *back = grabfile(fname, &glen, err_str);
    if(*err_str)
        {
        //xerr2("%s '%s': %s\n", err_str3, fname, strerror(errno));
        return 0;
        }
    //printf("%s\n", back);
     
    char *start2;
    int len5 = frame_buff(back, &start2);
    if(!len5 || !start2)
        {
        *err_str = "Cannot frame (invalid file syntax";
        return 0;
        }
    int xlen;
    char *ub = unbase_and_unlim(start2, len5, &xlen);
    //printf("'%s\n", ub);
    zfree(back);
    
    gcry_sexp_t backsexp;
    err = gcry_sexp_new(sexp, ub, xlen, 1);
    zfree(ub);
    if (err) 
        {
        //xerr2("Failed to decode back key sexp. %s\n", gcry_strerror (err));
        *err_str = "Failed to decode sexp.";
        return 0;
        }
   return 1;       
}

//////////////////////////////////////////////////////////////////////////

int     write_sexp_to_file(const char *fname, gcry_sexp_t *sexp, char **err_str)

{
    int plen, blen;
    *err_str = NULL;
    
    zline2(__LINE__, __FILE__);
    char    *buff = sexp_get_buff(*sexp, &plen);
    if(!buff)
        {
        *err_str = "Cannot alloc sexo decode memory\n";  return 0;
        }
    char    *lim = base_and_lim(buff, plen, &blen);
    zfree(buff);
    if(!lim)
        {
        *err_str = "Cannot alloc base and lim memory\n";  return 0;
        }
    char    *cat2 = zstrmcat(0, chain_start, "\n", lim, "\n", chain_end, "\n", NULL); 
    zfree(lim);
    if(!cat2)
        {
        *err_str = "Cannot alloc memory\n";  return 0;
        }
    putfile(fname, cat2, strlen(cat2), err_str);
    zfree(cat2); 
    if(*err_str)
        {
        //xerr2("%s '%s': %s\n", err_str4, fname, strerror(errno));
        return 0;
        }
    return 1;
}

/////////////////////////////////////////////////////////////////////
// Get public key from buffer.
// Return number of key bits or -1 for error. err_str has details

int     get_pubkey(get_pub_key_struct *pks)

{
    int outlen = pks->rsa_len;
    char *mem = decode_pub_key(pks->rsa_buf, &outlen, pks->err_str2);
    if(mem == NULL)
        {
        *pks->err_str = "Cannot decode public key";
        return -1;
        }
    gcry_sexp_t pubkey;
    gcry_error_t err;
    err = gcry_sexp_new(&pubkey, mem, outlen, 1);
    zfree(mem);
    if (err) 
        {
        *pks->err_str =  "Failed to create create public key sexp.";
        return -1;
        };
        
    *pks->pubkey = gcry_sexp_find_token(pubkey, PUBLIC_KEY, 0);
    if (err) 
        {
        *pks->err_str =  "No public key found.";
        return -1;
        };
        
    *pks->composite = gcry_sexp_find_token(pubkey, DIBACRYPT_KEY, 0);
    if (err) 
        {
        *pks->err_str =  "No public key info found.";
        return -1;
        };
        
    *pks->hash = gcry_sexp_find_token(pubkey, DIBACRYPT_HASH, 0);
    if (err) 
        {
        *pks->err_str =  "No public key hash found.";
        return -1;
        };
    
    int keylen = gcry_pk_get_nbits(*pks->pubkey);
    return keylen;
}

/////////////////////////////////////////////////////////////////////
// Get private and public key from file, prompt for pass if needed
// Return number of key bits ot -1 for error. err_str has details

int     get_privkey(get_priv_key_struct *pks)

{
    gcry_error_t err;
    int declen = pks->rsa_len, keylen = 0; 
    
    if(pks->debug > 5)
        {
        printf("get_privkey(): buff=%p len=%d\n", 
                            pks->rsa_buf, pks->rsa_len);    
        }
    if(!pks->composite) 
        {
        *pks->err_str = "Composite member cannot be NULL.";
        return -1;
        }
    if(pks->privkey) *pks->privkey = NULL;
    if(pks->pubkey)*pks->pubkey = NULL;   
    if(pks->info)*pks->info = NULL;
    if(pks->hash)*pks->hash = NULL;
        
    char *mem = decode_comp_key(pks->rsa_buf, &declen, pks->err_str2);
    if(mem == NULL)
        {
        if(pks->debug > 5)
            {
            printf("get_privkey(): Cannot decode private key"); 
            }
        *pks->err_str = "Cannot decode private key";
        return -1;
        }
    
    if(pks->debug > 9)
        {
        dump_mem(mem, declen); 
        }
    
    err = gcry_sexp_new(pks->composite, mem, declen, 1);
    if (!*pks->composite) 
        {
        zfree(mem);     
        if(pks->debug > 5)
            {
            printf("get_privkey(): composite key in this data."); 
            }
        *pks->err_str = ("No composite key in this data.");
        return -1;
        }
    if(pks->debug > 9) 
        {
        printf("get_privkey(): Composite:\n");
        sexp_print(*pks->composite);
        }
    zfree(mem);     
    
    /* Grab a key pair password */
    if(pks->thispass[0] == '\0' && !pks->nocrypt)
        {
        getpassx  passx; ZERO_GETP_STRUCT(&passx);
        
        passx.prompt  = "Enter key pass:";
        passx.pass    = pks->thispass;    
        passx.maxlen  = MAX_PATH;
        passx.minlen  = 4;
        passx.weak    = TRUE;
        passx.nodouble = TRUE;
        passx.strength = 4;
        passx.debug = pks->debug;
        int ret = getpass2(&passx);
        if(ret < 0)
            {
            *pks->err_str = "Error on password entry.";
            return -1;
            }
        }
    else
        {
        // See if the user provided a file
        if(pks->thispass[0] == '@')
            {
            char *err_str = NULL;
            char *newpass = pass_fromfile((const char*)pks->thispass, \
                                pks->err_str);
            if(newpass == NULL)
                {
                return -1;
                }
            strcpy(pks->thispass, newpass);
            zfree(newpass);
            } 
        }
    //printf("thispass '%s'\n", pks->thispass);
    gcry_sexp_t privkid = gcry_sexp_find_token(*pks->composite,
                             PRIVATE_CRYPTED, 0);
    if(privkid == NULL)
        {
        *pks->err_str = "No key found in private composite key.";
        return -1;
        }
    size_t plen3;
    char *buff3 = gcry_sexp_nth_buffer(privkid, 1, &plen3);
    
    if(!pks->nocrypt)
        {
        // Decrypt buffer
        gcry_cipher_hd_t fish_hd;
        get_twofish_ctx(&fish_hd, pks->thispass, strlen(pks->thispass));
        err = gcry_cipher_decrypt(fish_hd, (unsigned char*) buff3, 
                                  plen3, NULL, 0);
        if (err) {
            *pks->err_str = "could not decrypt with TWOFISH";
            return -1;
            }
        gcry_cipher_hd_t aes_hd;
        get_aes_ctx(&aes_hd, pks->thispass, strlen(pks->thispass));
        
        err = gcry_cipher_decrypt(aes_hd, (unsigned char*) buff3,
                                  plen3, NULL, 0);
        if (err) {
            *pks->err_str = "failed to decrypt key pair";
            return -1;
        }
        gcry_cipher_close(fish_hd);
        gcry_cipher_close(aes_hd);
    }
    
    gcry_sexp_t keydata;
    /* Load the key pair components into sexps. */
    err = gcry_sexp_new(&keydata, buff3, plen3, 0);
    if(err)
        {
        #ifdef __linux__
        #else
        // Delay a little to fool DOS attacks
        struct timespec ts = {0, 300000000};
        nanosleep(&ts, NULL);
        #endif
        *pks->err_str = "Failed to load composite key. (pass?)";
        return -1;
        }
    if(pks->privkey)
        {
        *pks->privkey = gcry_sexp_find_token(keydata, PRIVATE_KEY, 0);
        
        if(pks->debug > 9) {
            printf("get_privkey(): key_data:\n");
            sexp_print(*pks->privkey);
            }
        }
    if(pks->pubkey)
        {
        *pks->pubkey = gcry_sexp_find_token(keydata, PUBLIC_KEY, 0);
        if(pks->debug > 9) {
            printf("get_privkey() key:\n");
            sexp_print(*pks->pubkey);
            }
        }
    if(pks->hash)
        {
        *pks->hash = gcry_sexp_find_token(*pks->composite, DIBACRYPT_HASH, 0);
        if(pks->debug > 9) {
            printf("get_privkey(): hash:\n");
            sexp_print(*pks->hash);
            }
        }
    if(pks->info)
        {
        *pks->info = gcry_sexp_find_token(*pks->composite, DIBACRYPT_KEY, 0);
        if(pks->debug > 9) {
            printf("get_privkey(): info:\n");
            sexp_print(*pks->info);
            }
        }
    gcry_sexp_release(keydata);
    
    gcry_sexp_t rsa_keypair;
    rsa_keypair = gcry_sexp_find_token(*pks->privkey, PRIVATE_KEY, 0);
    if(rsa_keypair == NULL)
        {     
        if(pks->debug > 0) 
            {
            printf("No private key present in buffer.");
            }
        *pks->err_str = "No private key present in buffer.";
        return -1;
        }
    zline2(__LINE__, __FILE__);
    keylen =  gcry_pk_get_nbits(rsa_keypair) / 8 ;
    if(pks->debug > 2) {
        printf("get_privkey(): Key length: %d\n", keylen * 8);
        }
    return(keylen);   
}    

//////////////////////////////////////////////////////////////////////////
// Multi every buffer in the argument list. 
// Buffers are passed as PTR_1, LEN_1 ... PTR_N, LEN_N
// Not the most efficient, but takes generalized number of args.

char    *memcat(int *outlen,  ...)

{
    int sum = 0;
    
    va_list ap;
    va_start(ap, outlen);
    
    // See how much mem we need
    while(1)
        {
        char *ptr =  va_arg(ap, void *);
        if(ptr == NULL)
            break;
        int len =  va_arg(ap, int);   
        sum += len;
        if(len < 0)
            break;
        //printf("args: %p %d\n", ptr, len);
        }
    va_end(ap);
    //printf("sum %d\n", sum);
    zline2(__LINE__, __FILE__);
    char *ret = zalloc(sum + 4);
    if(ret == NULL)
        return NULL;
    // Copy them back to back
    char *ret2 = ret;
    va_start(ap, outlen);
    while(1)
        {
        char *ptr2 =  va_arg(ap, char *);
         if(ptr2 == NULL)
            break;
        int len2 =  va_arg(ap, int);
        if(len2 < 0)
            break;
        // Copy out     
        memcpy(ret2, ptr2, len2);
        ret2 += len2;
        }
    va_end(ap);
    // We allocated more, so feel free to zero terminate
    ret[sum] = '\0';
    *outlen = sum;  
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Return the triple hash of the buffer
// Free pointer with zfree()

char    *triple_hash_buffer(const char *data_buf, int data_len, int *hash_len)

{
    // Hash the message first, three different hashes
    char hash_one[32]; 
    gcry_md_hash_buffer(GCRY_MD_SHA256, (void*) &hash_one, 
                    (const void*) data_buf, data_len);
    //dump_mem(hash_one, sizeof(hash_one));
    
    char hash_two[32];
    gcry_md_hash_buffer(GCRY_MD_SHA256, (void*) &hash_two, 
                    (const void*) data_buf, data_len);
    //dump_mem(hash_two, sizeof(hash_two));
    
    unsigned long long hhhh;
    hhhh = bluepoint3_hash64(data_buf, data_len);
    
    char *hash_buf = memcat(hash_len,  
                       hash_one, sizeof(hash_one),
                            hash_two, sizeof(hash_two),
                                &hhhh, sizeof(hhhh), NULL);
    
    return (hash_buf);
}

char    *hash_sig_buff(int algo, const char *data_buf, int data_len, int *hash_len)

{
    *hash_len = 64;
    char *hash_ptr = zalloc(*hash_len + 1); 
    
    switch(algo)
        {
        case 0:
            gcry_md_hash_buffer(GCRY_MD_SHA512, (void*) hash_ptr, 
                    (const void*) data_buf, data_len);
            break;
            
        case 1:
            gcry_md_hash_buffer(GCRY_MD_SHA512, (void*) hash_ptr, 
                    (const void*) data_buf, data_len);
            break;
        case 2:
            gcry_md_hash_buffer(GCRY_MD_WHIRLPOOL, (void*) hash_ptr, 
                    (const void*) data_buf, data_len);
            break;
            
        default:
            //xerr2("Unexpected algo number.\n");
            zfree(hash_ptr);
            return NULL;
        }       
    return hash_ptr;
}

void show_prepoc()
{
    #if defined __linux__ 
        printf("defined __linux__\n");
    #endif    
    #if defined unix 
        printf("defined unix\n");
    #endif    
    #if defined __WINNT__ 
        printf("defined __WINNT__\n");
    #endif    
    #if defined WINNT 
        printf("defined WINNT\n");
    #endif    
    #if defined __WIN32__ 
        printf("defined __WIN32__\n");
    #endif    
    #if defined WIN32 
        printf("defined WIN32\n");
    #endif    
}
        
// EOF
















