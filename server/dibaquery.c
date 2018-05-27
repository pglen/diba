
/* =====[ dibaquery.c ]=========================================================

   Description:     Query examination for DIBA [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jan.31.2018     Peter Glen      Initial version.

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

// This was needed as no POSIX var is defined
#ifdef __linux__
    // Empty    
#else
    int nanosleep( const struct timespec *period, struct timespec *residual);
#endif

static int weak = 0;
static int force = 0;
static int check = 0;
static int verbose = 0;
static int test = 0;
static int noop = 0;
static int nocrypt = 0;
static int dump = 0;
static int prkeys = 0;
static int prlen = 0;
static int pinfo = 0;
static int version = 0;
static int calcsum = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

char descstr[] = "Execute query for testing DIBA transaction.";
char usestr[] = "dibaquery [options] infile outfile\n"
                "Where 'infile' contains the query sexpr, "
                "and 'outfile' is the response sexp to the query.";
               
static int get_pass();
static int need_pass = FALSE;

static char   *thispass = NULL;    
static char   *infile = NULL;    
static char   *outfile = NULL;    

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
                    
                    't',   "test",  NULL,   NULL, 0, 0, &test, 
                    "-t             --test        - Switch gcrypt selftest on",
                    
                    'c',   "check",  NULL,  NULL, 0, 0, &check, 
                    "-c             --check       - Check key signature(s)",
                    
                    'i',   "infile",  NULL,  &infile, 0, 0, NULL, 
                    "-i             --infile      - Input file with sexp ",

                    'n',   "noop",  NULL,   NULL, 0, 0, &noop, 
                    "-n             --noop        - create noop query ",

                    'o',   "outfile",  NULL,  &outfile, 0, 0, NULL, 
                    "-o             --outfile     - Output (result) file with sexp ",

                    's',   "sum",  NULL,  NULL, 0, 0, &calcsum, 
                    "-s             --sum         - Print executable checksum before proceeding",
                            
                    'k',   "pkey",  NULL,  NULL, 0, 0,  &prkeys, 
                    "-k             --pkey        - Print key (public / private)",
                    
                    'd',   "dump",  NULL,  NULL, 0, 0, &dump, 
                    "-d             --dump        - Dump key to console (private key printed enrypted) ",
                   
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
    infile = zalloc(MAX_PATH); if(infile == NULL) xerr2(mstr);
    outfile = zalloc(MAX_PATH); if(outfile == NULL) xerr2(mstr);
    
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data); exit(2);
        }
    
    if(version)
        {
        printf("dibaquery version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
        exit(1);
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
        printf("Executing self tests ... ");
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

    int issue = 3;
    // See if we have infile
    if(infile[0] != '\0' || noop)
        {
        issue--;
        }
    if(outfile[0] != '\0')
        {
        issue--;
        }
        
    // See if we have correct args
    if (argc - nn != issue) {
        //fprintf(stderr, "Usage: dibaquery.exe infile outfile\n");
        //xerr2("Invalid arguments.");
        usage(usestr, descstr, opts_data); exit(2);
    }
    
    gcry_error_t err = 0; 
    gcry_sexp_t snoop;
    
    if(noop)
        {
        //printf("Noop \n");
        err = gcry_sexp_build(&snoop, NULL, 
                                "(DibaQuery (Type %s Subtype %d))", 
                                    "noop", 0 );
        }
    else
        {
        // Read and interpret infile
        }
        
    //sexp_print(snoop);
    
    int comp_len = gcry_sexp_sprint(snoop, GCRYSEXP_FMT_CANON, NULL, 0);                
    zline2(__LINE__, __FILE__);
    char *comp_buf = zalloc(comp_len + 1);
    comp_len = gcry_sexp_sprint(snoop, GCRYSEXP_FMT_CANON, comp_buf, comp_len);
                   
    FILE* lockf = fopen(outfile, "wb");
    if (!lockf) {
        xerr2("dibaquery: fopen() on '%s' failed.", outfile); 
    }
    int limlen = comp_len;
    char *mem6 = base_and_lim(comp_buf, comp_len, &limlen);
   
    fprintf(lockf, "%s\n", query_start);
    fprintf(lockf, "%*s\n", limlen, mem6);
    fprintf(lockf, "%s\n", query_end);
    
    fclose(lockf);
    zfree(mem6);
    zfree(comp_buf);        
                    
    zfree(infile);
    zfree(outfile);
    
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
    
    if(dump)        
        sexp_print(compkey);
    
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
            xerr2("Failed to load composite (private) key. (pass?)");
        #endif
        }
        
    gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);
    if(privk == NULL)
        {                           
        xerr2("No private key present in '%s'", fname);
        ret = 4;
        }
    //sexp_print(privk);
    if(prlen)
        {
        int keylen = gcry_pk_get_nbits(privk);
        printf("Private key length is %d bits.\n", keylen);
        }
    gcry_sexp_t glib_hashes 
                    = gcry_sexp_find_token(compkey, DIBACRYPT_HASH, 0);
                    
    if(glib_hashes == NULL)
        {                           
        xerr2("No dibacrypt hash section present in '%s'", fname);
        ret = 4;
        return ret;
        }
    if(dump)
        {
        sexp_print(glib_hashes);
        }
        
    if(check)
        {
        // Check private key hash
        gcry_sexp_t shax = gcry_sexp_find_token(compkey, "Private Hash", 0);
        if(shax)
            {
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
            gcry_sexp_find_token(compkey, DIBACRYPT_KEY , 0);
            
        if(keyhash == NULL)
            {                           
            xerr2("No 'dibacrypt keys' section is present in '%s'", fname);
            ret = 4;
            return ret;
            }
        int olen;
        char *hash_str = sexp_hash(keyhash, &olen);
        
        gcry_sexp_t shainf = 
            gcry_sexp_find_token(glib_hashes, "Info Hash", 0);
            
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
        sexp_print(privk);
    
    // Release what sexp_new created 
    gcry_sexp_release(rsa_keypair);    
    gcry_sexp_release(compkey);    
    
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
                xerr2("dibaquery: %s\n", err_str);
                
            strcpy(thispass, newpass);
            zfree(newpass);
            }
        }
    need_pass = FALSE;
}

// EOF




















