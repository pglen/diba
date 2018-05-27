
/* =====[ dibachestinfo.c ]=========================================================

   Description:     Key examination for DIBA [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  nov.21.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "diba.h"
#include "gcrypt.h"
#include "gcry.h"
#include "getpass.h"
#include "gsexp.h"
#include "base64.h"
#include "zmalloc.h"
#include "cmdline.h"
#include "dibastr.h"
#include "misc.h"
#include "zstr.h"
#include "dibafile.h"

// This was needed as no POSIX var is defined
#ifdef __linux__
    // Empty    
#else
    int nanosleep( const struct timespec *period, struct timespec *residual );
#endif

static  unsigned int keysize = 2048;

static int weak = 0;
static int force = 0;
static int check = 0;
static int verbose = 0;
static int dump = 0;
static int test = 0;
static int nocrypt = 0;
static int prkeys = 0;
static int prlen = 0;
static int pinfo = 0;
static int version = 0;
static int calcsum = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

char descstr[] = "Show various information about a DIBA chest.";
char usestr[] = "dibachestinfo [options] chestfile\n"
                "Where chestfile is the basename for .chest file. ";
               
static int get_pass();
static int need_pass = FALSE;

static char   *thispass = NULL;    

static char    *errout   = NULL;

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {
                    'p',   "pass",   NULL,  &thispass, 0, 0,    NULL, 
                    "-p val         --pass val    - pass in for key (@file for pass file)",
                    
                    'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
                    "-v             --verbose     - Verbosity on",
                    
                    'd',   "dump",  NULL, NULL,  0, 0, &dump, 
                    "-d             --dump        - Dump to screen",
                    
                    't',   "test",  NULL,  NULL, 0, 0, &test, 
                    "-t             --test        - gcrypt self Test on",
                    
                    'c',   "check",  NULL,  NULL, 0, 0, &check, 
                    "-c             --check       - check key signature(s)",
                    
                    'i',   "pinfo",  NULL,  NULL, 0, 0, &pinfo, 
                    "-i             --pinfo       - print key info",

                    's',   "sum",  NULL,  NULL, 0, 0, &calcsum, 
                    "-s             --sum         - print sha sum before proceeding",
                            
                    'k',   "pkey",  NULL,  NULL, 0, 0,  &prkeys, 
                    "-k             --pkey        - print public / private key",
                    
                    'l',   "plen",  NULL,  NULL, 0, 0, &prlen , 
                    "-l             --plen        - print key length",
                                        
                    'n',   "nocrypt",  NULL,  NULL, 0, 0, &nocrypt, 
                    "-n             --nocrypt     - do not decrypt key",
                   
                    'V',   "version",  NULL, NULL,  0, 0, &version, 
                    "-V             --version     - Print version numbers and exit",
        

                    0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
                    };


void my_progress_handler (void *cb_data, const char *what,
                            int printchar, int current, int total)
{
    printf(".");
    //printf("%c", printchar);
}

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

// -----------------------------------------------------------------------
// Chain to err routine, dup error to file first 
// See if any other freeing action is requested

void    xerr3(const char *str, ...)

{
    va_list ap;
    va_start(ap, str);    
    
    FILE* errf = fopen(errout, "wb");
    // Ignore error, empty or non existant file will indicate error to caller
    if (errf) {
        vfprintf(errf, str, ap);
        fclose(errf);
    }
    
    va_list ap2;
    va_start(ap2, str);    
    xerr2(str, ap2); 
}


//char *mstr = "No Memory";
    
static int    operate_pubkey(const char *fname, const char *basename);
static int    operate_privkey(const char *fname, const char *basename);
static int    operate_chest(const char *fname, const char *basename);

// -----------------------------------------------------------------------

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);
    
    // The following section allocates a useless random amount of memory.
    // This will assure that strings appear in different places between runs.
    
    char    *dummy = alloc_rand_amount();
    
    zline2(__LINE__, __FILE__);
    thispass = zalloc(MAX_PATH); if(thispass == NULL) xerr2(mstr);
    
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data); exit(2);
        }
    
    if(version)
        {
        printf("dibachestinfo version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
        exit(1);
        }
    
    // Check for key size correctness    
    if(num_bits_set(keysize) != 1)
        {
        xerr2("Keysize must be a power of two. ( ... 1024, 2048, 4096 ...)");
        } 
        
    gcrypt_init();

    if(calcsum)
        {
        char *err_str;
        char *hash_str = hash_file(argv[0], &err_str);
        if(hash_str)
            {
            printf("Executable sha hash: '%s'\n", hash_str);
            zfree(hash_str);
            }
        else 
            {
            xerr2("dibakeygen: %s\n", err_str);
            }
        }
        if(test)
        {
        printf("Excuting self tests ... ");
        gcry_error_t err = 0;
        err = gcry_control(GCRYCTL_SELFTEST);
        if(err)
            {
            printf("fail.\n");
            exit(3);
            }
        else
            {
            printf("pass.\n");
            }
        }
        
    gcry_set_progress_handler(my_progress_handler, NULL);

    if (argc - nn != 2) {
        //fprintf(stderr, "Usage: dibachestinfo.exe outfile\n");
        //xerr2("Invalid arguments.");
        usage(usestr, descstr, opts_data); exit(2);
    }
    
    /* Grab a key pair password and create an encryption context with it. */

    // Figure out if pub or private
    char *fname = argv[nn+1];
    int len = strlen(fname);
    int done = 0;
    if(len > 4)
        {            
        //printf("str '%s' '%s'\n", fname, &fname[strlen(fname) - 4]);
    
        if(strstr(&fname[len - 4], ".pub") != 0)
            {
            //printf("Pub %s\n", &fname[len - 4]);
            operate_pubkey(fname, fname);
            done = 1;
            } 
        else if(strstr(&fname[len - 4], ".key") != 0)
            {
            //printf("Key %s\n", &fname[len - 4]);
            operate_privkey(fname, fname);
            done = 1;
            }
        }
    if(!done)        
        {
        char* fname4 = zstrcat(fname, ".chest");
        operate_chest(fname4, fname);
        zfree(fname4);
        
        #if 0
        char* fname2 = zstrcat(fname, ".pub");
        char* fname3 = zstrcat(fname, ".key");
        operate_pubkey(fname2, fname);
        operate_privkey(fname3, fname);
        zfree(fname2); zfree(fname3);
        #endif
        } 
    
    zfree(dummy); zfree(thispass);    
    zleak();
        
    return 0;
}


int    operate_chest(const char *fname, const char *basename)

{
    gcry_error_t err; char *err_str;
    
    FILE   *cfp = OpenDibaFile(fname, &err_str);
    if(!cfp)
        {
        xerr3("dibachest: Cannot open chest file.");
        }
        
    chunk_keypair kp;
    
    while(1)
        {
        int ret =   GetDibaKeyVal(cfp, &kp, &err_str);
        if(!ret)
            break;
            
        printf("'%s'\n", kp.key);
        //printf("'%s'\n", kp.val);
        
        int xlen;
        char *ub = unbase_and_unlim(kp.val, kp.vlen, &xlen);
        
        gcry_sexp_t xkey;
        err = gcry_sexp_new(&xkey, ub, xlen, 1);
        if(err)
            {
            printerr(err, "reading key");
            //xerr2("Failed to create private key sexp.");
            }
            
        if(dump)
            sexp_print(xkey);
        
        zfree(kp.key); zfree(kp.val); zfree(ub);
        }
        
    return 1;   
}

//////////////////////////////////////////////////////////////////////////

int    operate_pubkey(const char *fname, const char *basename)

{
    gcry_error_t err;
    
    FILE* lockf = fopen(fname, "rb");
    if (!lockf) {
        xerr2("Cannot open key file '%s'", basename);
    }

    /* Grab the public key and key size */
    unsigned int rsa_len = getfsize(lockf);
    //if(verbose)
    //    printf("Key file size %d\n", rsa_len);
        
    zline2(__LINE__, __FILE__);
    char* rsa_buf = zalloc(rsa_len + 1);
    if (!rsa_buf) {
        xerr2("malloc: could not allocate rsa buffer");
    }
    if (fread(rsa_buf, rsa_len, 1, lockf) != 1) {
        xerr2("Read on public key failed");
    }
    
    fclose(lockf);

    //rsa_buf[rsa_len] = '\0';
    int outlen = rsa_len;
    char *dec_err_str;
    char *mem = decode_pub_key(rsa_buf, &outlen, &dec_err_str);
    if(mem == NULL)
        {
        //printf("%s\n", dec_err_str);
        //xerr2("Cannot decode public key");
        xerr2("Cannot decode public key: %s", dec_err_str);
        }
    gcry_sexp_t pubkey;
    err = gcry_sexp_new(&pubkey, mem, outlen, 1);
    zfree(mem);
    if (err) {
        //printerr(err, "encrypt");
        xerr2("Failed to create create public key sexp. %s\n", gcry_strerror (err));
        }
    
    gcry_sexp_t keyid = gcry_sexp_find_token(pubkey, "Key ID", 0);
    if(keyid != NULL)
        {
        unsigned int plen;
        char *buff = gcry_sexp_nth_buffer(keyid, 1, &plen);
        
        zline2(__LINE__, __FILE__);
        char *buff2 = zalloc(plen + 1);
        memcpy(buff2, buff, plen);
        buff2[plen] = '\0';
        gcry_free(buff);
        printf("Public KeyID '%s'\n", buff2); 
        zfree(buff2);
        }
    zfree(rsa_buf);
    
    
    gcry_sexp_t info_key = gcry_sexp_find_token(pubkey, "gcrypt-key", 0);
    if(pinfo)
        sexp_list(info_key);
        //sexp_print(info_key);
        
    if(prlen)
        {
        int keylen = gcry_pk_get_nbits(pubkey);
        printf("Public key length is %d bits.\n", keylen);
        }
        
    if(prkeys)
        sexp_print(pubkey);
    
    if(check)
        {
        gcry_sexp_t shax = gcry_sexp_find_token(pubkey, "Public hash", 0);
        if(shax)
            {
            //sexp_print(shax);
            
            gcry_sexp_t pk = gcry_sexp_find_token(pubkey, "public-key", 0);
            int olen;
            char *hash_str = sexp_hash(pk, &olen);
            unsigned int plen2;
            char *buff2 = sexp_nth_data(shax, 1, &plen2);
            
            if(verbose)
                printf("'%s' \t '%s'\n", hash_str, buff2);
            
            if(strncmp(hash_str, buff2, plen2) == 0)
            {
                printf("Public key hashes match OK\n");
            }
            else
            {
                printf("Error: Hashes DO NOT match\n");
            }
            
            zfree(buff2); zfree(hash_str);
            }
        else
            {
            printf("No hash with this key");
            }
        printf("");
        }  
                
    return(0);
}

//////////////////////////////////////////////////////////////////////////

int    operate_privkey(const char *fname, const char *basename)

{
    gcry_error_t err;
    
    FILE* lockf = fopen(fname, "rb");
    if (!lockf) {
        xerr2("Cannot open file '%s'", basename);
    }

    /* Grab the public key and key size */
    unsigned int rsa_len = getfsize(lockf);
    
    //if(verbose)
    //    printf("Key file size %d\n", rsa_len);
        
    zline2(__LINE__, __FILE__);
    char* rsa_buf = zalloc(rsa_len + 1);
    if (!rsa_buf) {
        xerr2("malloc: could not allocate rsa buffer");
    }
    if (fread(rsa_buf, rsa_len, 1, lockf) != 1) {
        xerr2("Read on private key failed.");
    }
    
    fclose(lockf);

    int outlen = rsa_len;
    char *dec_err_str;
    char *mem = decode_comp_key(rsa_buf, &outlen, &dec_err_str);
    if(mem == NULL)
        {
        //printf("%s\n", dec_err_str);
        //xerr2("Cannot decode public key");
        xerr2("Cannot decode private key: %s", dec_err_str);
        }
    gcry_sexp_t compkey;
    err = gcry_sexp_new(&compkey, mem, outlen, 1);
    zfree(mem);
    if (err) {
        printerr(err, "encrypt");
        xerr2("Failed to create private key sexp.");
        }
        
    //sexp_print(compkey);
    
    gcry_sexp_t keyid = gcry_sexp_find_token(compkey, "Key ID", 0);
    if(keyid != NULL)
        {
        //sexp_print(keyid);
        unsigned int plen;
        char *buff = gcry_sexp_nth_buffer(keyid, 1, &plen);
        
        zline2(__LINE__, __FILE__);
        char *buff2 = zalloc(plen + 1);
        memcpy(buff2, buff, plen);
        buff2[plen] = '\0';
        gcry_free(buff);
        printf("Private KeyID '%s'\n", buff2); 
        zfree(buff2);
        }
    
    zfree(rsa_buf);
    
    gcry_sexp_t info_key = gcry_sexp_find_token(compkey, "gcrypt-key", 0);
    if(pinfo)
        sexp_list(info_key);
    
    gcry_sexp_t privkid = gcry_sexp_find_token(compkey, "private-crypted", 0);
    if(privkid == NULL)
        {
        xerr2("No key found in private composite key.");
        }
    unsigned int plen3;
    char *buff3 = gcry_sexp_nth_buffer(privkid, 1, &plen3);
    
    // Only ask pass if needed
    if(!prlen && !check && !prkeys) 
        {
        // Stop, no more info needed
        return 0;
        }
    
    get_pass();
    
    zline2(__LINE__, __FILE__);
    if(!nocrypt)
        {
        gcry_cipher_hd_t fish_hd;
        get_twofish_ctx(&fish_hd, thispass, strlen(thispass));
        // Decrypt buffer
        err = gcry_cipher_decrypt(fish_hd, (unsigned char*) buff3, 
                                  plen3, NULL, 0);
        if (err) {
            xerr2("Could not decrypt with TWOFISH");
            }

        gcry_cipher_hd_t aes_hd;
        get_aes_ctx(&aes_hd, thispass, strlen(thispass));
        err = gcry_cipher_decrypt(aes_hd, (unsigned char*) buff3,
                                  plen3, NULL, 0);
        if (err) {
            xerr2("Could not decrypt with TWOFISH");
        }
        gcry_cipher_close(fish_hd);
        gcry_cipher_close(aes_hd);
    }
    
    /* Load the key pair components into sexps. */
    gcry_sexp_t rsa_keypair;
    err = gcry_sexp_new(&rsa_keypair, buff3, plen3, 0);
    if(err)
        {
        #ifdef __linux__
            // empty
        #else
            // Delay a little to fool DOS attacks
            struct timespec ts = {0, 300000000};
            nanosleep(&ts, NULL);
            xerr2("Failed to load composite key. (pass?)");
        #endif
        }
        
    gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);
    if(privk == NULL)
        {                           
        xerr2("No private key present in '%s'", fname);
        }
    //sexp_print(privk);
        
    if(prlen)
        {
        int keylen = gcry_pk_get_nbits(privk);
        printf("Private key length is %d bits.\n", keylen);
        }
        
    if(check)
        {
        gcry_sexp_t shax = gcry_sexp_find_token(compkey, "Private hash", 0);
        if(shax)
            {
            //sexp_print(shax);
            
            gcry_sexp_t pk = gcry_sexp_find_token(privk, "private-key", 0);
            int olen;
            char *hash_str = sexp_hash(pk, &olen);
            unsigned int plen2;
            char *buff2 = sexp_nth_data(shax, 1, &plen2);
            
            if(verbose)
                printf("'%s' \t '%s'\n", hash_str, buff2);
            
            if(strncmp(hash_str, buff2, plen2) == 0)
            {
                printf("Private key hashes match OK\n");
            }
            else
            {
                printf("Error: Hashes DO NOT match\n");
            }
            
            zfree(buff2); zfree(hash_str);
            }
        else
            {
            printf("No hash with this key");
            }
       } 
    
    if(prkeys)
        sexp_print(privk);
        
    return(0);
}

// 
// Worker function to ge the pass if we are dealing with the private key
//

static int get_pass()

{
    if(prkeys)
        {
        printf("Warning: this will show private key unencrypted. "
        "Are you sure?  Ctrl-C to quit.\n");
        }

    if(thispass[0] == '\0')
        {
        if(!nocrypt) 
            {
            int ret;
            getpassx  passx;
            passx.prompt  = "Enter  keypair  pass:";
            //passx.prompt2 = "Confirm keypair pass:";
            passx.pass = thispass;      passx.maxlen = MAX_PATH;
            passx.minlen = 4;           passx.strength = 0;
            passx.weak = weak;          passx.nodouble = TRUE;
            ret = getpass2(&passx);
            if(ret < 0)
                {
                xerr2("Error on entering pass, no keys are decoded.\n");
                }
            }
        }
    else
        {
        if(nocrypt)
            xerr2("\nConflicting options, cannot provide key with the 'nocrypt' flag.\n");
            
        // See if the user provided a file
        if(thispass[0] == '@')
            {
            char *err_str = NULL;
            char *newpass = pass_fromfile((const char*)thispass, &err_str);
            if(newpass == NULL)
                xerr2("dibachestinfo: %s\n", err_str);
                
            strcpy(thispass, newpass);
            zfree(newpass);
            }
        }
    need_pass = FALSE;
}

// EOF















