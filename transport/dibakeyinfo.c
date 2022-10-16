
/* =====[ dibakeyinfo.c ]=========================================================

   Description:     Key examination for DIBA [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  aug.10.2017     Peter Glen      Moved to DIBA
      0.00  aug.17.2017     Peter Glen      Hash checking
      0.00  aug.23.2017     Peter Glen      Additional fields
      0.00  dec.03.2017     Peter Glen      Print dumps.

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
#include "dibautils.h"

// This was needed as no POSIX var is defined
#ifdef __linux__
    // Empty    
#else
    int nanosleep( const struct timespec *period, struct timespec *residual);
#endif

static  unsigned int keysize = 2048;

static int weak = 0;
static int force = 0;
static int check = 0;
static int verbose = 0;
static int test = 0;
static int nocrypt = 0;
static int dump = 0;
static int prkeys = 0;
static int prlen = 0;
static int pinfo = 0;
static int version = 0;
static int calcsum = 0;
static int debug = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

char descstr[] = "Show various information about a DIBA key.";
char usestr[] = "dibakeyinfo [options] keyfile\n"
                "Where 'keyfile' is the basename for .key .pub files.\n"
                "Individual files may be specified also. Example: file.key or file.pub";
               
static int get_pass();
static int need_pass = FALSE;

static char   *thispass = NULL;    

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {
                    'p',   "pass",   NULL,  &thispass, 0, 0,    NULL, 
                    "-p val         --pass val    - Pass in for key (@file for pass file)",
                    
                    'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
                    "-v             --verbose     - Verbosity on",
                    
                    't',   "test",  NULL,  NULL, 0, 0, &test, 
                    "-t             --test        - Switch gcrypt selftest on",
                    
                    'c',   "check",  NULL,  NULL, 0, 0, &check, 
                    "-c             --check       - Check key signature(s)",
                    
                    'i',   "pinfo",  NULL,  NULL, 0, 0, &pinfo, 
                    "-i             --pinfo       - Print key info",

                    's',   "sum",  NULL,  NULL, 0, 0, &calcsum, 
                    "-s             --sum         - Print executable checksum before proceeding",
                            
                    'k',   "pkey",  NULL,  NULL, 0, 0,  &prkeys, 
                    "-k             --pkey        - Print key (public / private)",
                    
                    'l',   "plen",  NULL,  NULL, 0, 0, &prlen , 
                    "-l             --plen        - Print key length",
                                        
                    'n',   "nocrypt",  NULL,  NULL, 0, 0, &nocrypt, 
                    "-n             --nocrypt     - Do not decrypt key",
                   
                    'd',   "debug",  &debug, NULL, 0, 10, &debug, 
                    "-d level       --debug level - Output debug data (level 1-9)",
                    
                    'u',   "dump",  NULL,  NULL, 0, 0, &dump, 
                    "-u             --dump        - Dump key to console (private key printed enrypted) ",
                   
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

//char *mstr = "No Memory";
    
static int    operate_pubkey(const char *fname, const char *basename);
static int    operate_privkey(const char *fname, const char *basename);

// -----------------------------------------------------------------------

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);
    int ret = 0;
    
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
        printf("dibakeyinfo version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
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
        //char *err_str;
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
        //fprintf(stderr, "Usage: dibakeyinfo.exe outfile\n");
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
            ret = operate_pubkey(fname, fname);
            done = 1;
            } 
        else if(strstr(&fname[len - 4], ".key") != 0)
            {
            //printf("Key %s\n", &fname[len - 4]);
            ret = operate_privkey(fname, fname);
            done = 1;
            }
        }
    if(!done)        
        {
        char* fname2 = zstrcat(fname, ".pub");
        char* fname3 = zstrcat(fname, ".key");
    
        ret  = operate_pubkey(fname2, fname);
        ret |= operate_privkey(fname3, fname);
        
        zfree(fname2); zfree(fname3);
        } 
    
    zfree(dummy); zfree(thispass);    
    zleak();
        
    return ret;
}

//////////////////////////////////////////////////////////////////////////

int    operate_pubkey(const char *fname, const char *basename)

{
    gcry_error_t err;
    int ret = 0;
    
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
        
   if(dump)        
        sexp_print(pubkey);
     
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
        
    if(prlen)
        {
        int keylen = gcry_pk_get_nbits(pubkey);
        printf("Public key length is %d bits.\n", keylen);
        }
        
    if(prkeys)
        sexp_print(pubkey);
    
    if(check)
        {
        gcry_sexp_t shax = gcry_sexp_find_token(pubkey, "Public Hash", 0);
        if(!shax)
            {
            printf("No hash with this key.");
            ret = 3;
            return ret;
            }
        else
            {
            // Hash and check
            gcry_sexp_t pubkc = gcry_sexp_find_token(pubkey, "public-key", 0);
            
            int olen;
            char *hash_str = sexp_hash(pubkc, &olen);
            unsigned int plen2;
            char *buff2 = sexp_nth_data(shax, 1, &plen2);
            
            if(verbose)
                printf("'%s' \t '%s'\n", hash_str, buff2);
            
            if(strncmp(hash_str, buff2, plen2) == 0)
                {
                printf("Public key hashes match OK.\n");
                }
            else
                {
                printf("Error: Public Key Hashes DO NOT match.\n");
                ret = 3;
                }
            zfree(buff2); zfree(hash_str);
            }
            
        // Now check info hash of keys    
        gcry_sexp_t keyhash = 
            gcry_sexp_find_token(pubkey, DIBACRYPT_KEY , 0);
            
        if(keyhash == NULL)
            {                           
            xerr2("No 'dibacrypt keys' section is present in '%s'", fname);
            ret = 4;
            return ret;
            }
        int olen;
        char *hash_str = sexp_hash(keyhash, &olen);
        
        gcry_sexp_t shainf = 
            gcry_sexp_find_token(pubkey, "Info Hash", 0);
            
        if(shainf == NULL)
            {                           
            xerr2("No 'Info Hash' section present in '%s'", fname);
            ret = 4;
            return ret;
            }
            
        unsigned int plen2;
        char *buff2 = sexp_nth_data(shainf, 1, &plen2);
        
        if(verbose)
            printf("'%s' \t '%s'\n", hash_str, buff2);
        
        if(strncmp(hash_str, buff2, plen2) == 0)
            {
            printf("Public key info hashes match OK.\n");
            }
        else
            {
            printf("Error: Public key Info Hashes DO NOT match.\n");
            ret = 3;
            }
        zfree(buff2); zfree(hash_str);
            
        printf("");
        }  
    gcry_sexp_release(pubkey);    
    
    return(ret);
}

//////////////////////////////////////////////////////////////////////////

int    operate_privkey(const char *fname, const char *basename)

{
    char *err_str, *err_str2;
    gcry_error_t err;
    int ret = 0;
    
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

    get_priv_key_struct pks; memset(&pks, 0, sizeof(pks));
    gcry_sexp_t composite, info, privkey, pubkey, hash;
    
    pks.err_str   = &err_str;
    pks.err_str2  = &err_str2;
    pks.rsa_buf   = rsa_buf;
    pks.rsa_len   = rsa_len;
    pks.nocrypt   = nocrypt;
    pks.privkey   = &privkey;
    pks.pubkey    = &pubkey;
    pks.info      = &info;
    pks.composite = &composite;
    pks.hash      = &hash;
    pks.debug     = debug;
    pks.thispass  = thispass;
    
    int keylen = get_privkey(&pks);
    if(keylen < 0)
        xerr2("Decode on private key failed. (%s)", err_str);
    
    if(err_str2 == NULL)
        err_str2 = "";
    
    if(dump)        
        {
        //printf("composite: :");
        //sexp_print(composite);
        printf("info: ");
        sexp_print(info);
        printf("privkey: ");
        sexp_print(privkey);
        printf("pubkey: ");
        sexp_print(pubkey);
        printf("hash: ");
        sexp_print(hash);
        }
    
    gcry_sexp_t keyid = gcry_sexp_find_token(info, "Key ID", 0);
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
    
    if(check)
        {
        // Check private key hash
        gcry_sexp_t shax = gcry_sexp_find_token(info, "Private Hash", 0);
        if(shax)
            {
            gcry_sexp_t pk = gcry_sexp_find_token(privkey, "private-key", 0);
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
                ret = 3;
                }
            zfree(buff2); zfree(hash_str);
            }
        else
            {
            printf("No hash with this private key");
            ret = 3;
            return ret;
            }
        
        // Now check info hash of keys    
        gcry_sexp_t keyhash = 
            gcry_sexp_find_token(info, DIBACRYPT_KEY , 0);
            
        if(keyhash == NULL)
            {                           
            xerr2("No 'dibacrypt keys' section is present in '%s'", fname);
            ret = 4;
            return ret;
            }
        int olen;
        char *hash_str = sexp_hash(keyhash, &olen);
        
        gcry_sexp_t shainf = 
            gcry_sexp_find_token(hash, "Info Hash", 0);
            
        if(shainf == NULL)
            {                           
            xerr2("No 'Info Hash' section present in '%s'", fname);
            ret = 4;
            return ret;
            }
            
        unsigned int plen2;
        char *buff2 = sexp_nth_data(shainf, 1, &plen2);
        
        if(verbose)
            printf("'%s' \t '%s'\n", hash_str, buff2);
        
        if(strncmp(hash_str, buff2, plen2) == 0)
            {
            printf("Private key info hashes match OK.\n");
            }
        else
            {
            printf("Error: Info Hashes DO NOT match.\n");
            ret = 3;
            }
        zfree(buff2); zfree(hash_str);
        } // check
        
    if(prkeys)
        sexp_print(privkey);
    
    // Release what sexp_new created 
    //gcry_sexp_release(rsa_keypair);    
    gcry_sexp_release(info);    
    
    return(ret);
}

////////////////////////////////////////////////////////////////////////// 
// Worker function to ge the pass if we are dealing with the private key

static int get_pass()

{
    if(thispass[0] == '\0')
        {
        if(prkeys)
            {
            printf("\nWarning: this will show private key unencrypted. "
            "Are you sure?  Ctrl-C to quit.\n");
            }
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
                xerr2("dibakeyinfo: %s\n", err_str);
                
            strcpy(thispass, newpass);
            zfree(newpass);
            }
        }
    need_pass = FALSE;
}

// EOF

















