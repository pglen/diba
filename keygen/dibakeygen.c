
/* =====[ dibakeygen.c ]=========================================================

   Description:     Key generation for DIBA [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  aug.10.2017     Peter Glen      Moved to DIBA
      0.00  aug.23.2017     Peter Glen      Version info added 
      0.00  aug.26.2017     Peter Glen      First push to github

   ======================================================================= */

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
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

static  unsigned int keysize = 2048;

static int weak = FALSE;
static int force = FALSE;
static int dump = 0;
static int verbose = 0;
static int list = 0;
static int test = 0;
static int calcsum = 0;
static int nocrypt = 0;
static int version = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 5;

static char descstr[] = 
    "Generate Public / Private keypair, write them into a set of key files.";

static char usestr[] = "dibakeygen [options] keyfile\n"
    "Where 'keyfile' is the basename for the .key and .pub files. "
                "[keyfile.pub, keyfile.key]";

static char *keytype = "RSA";   // Will change when ECC implemented 
                                
static char    *thispass = NULL;
static char    *keyname  = NULL;
static char    *keydesc  = NULL;
static char    *creator  = NULL;
static char    *errout   = NULL;

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {

        'k',   "keylen",   &keysize,  NULL,  1024, 32768,    NULL, 
        "-k             --keylen      - key length in bits (def: 2048)",
        
        'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
        "-v             --verbose     - Verbosity on (keys not listed)",
        
        'l',   "list",  NULL, NULL,  0, 0, &list, 
        "-l             --list        - List details (keys not listed)",
        
        'V',   "version",  NULL, NULL,  0, 0, &version, 
        "-V             --version     - Print version numbers and exit",
        
        'u',   "dump",  NULL, NULL,  0, 0,    &dump, 
        "-u             --dump        - Dump key to terminal",
        
        't',   "test",  NULL,  NULL, 0, 0, &test, 
        "-t             --test        - run self test before proceeding",
        
        's',   "sum",  NULL,  NULL, 0, 0, &calcsum, 
        "-s             --sum         - print sha sum before proceeding",
        
        'f',   "force",  NULL,  NULL, 0, 0, &force, 
        "-f             --force       - force clobbering files",
        
        'w',   "weak",  NULL,  NULL, 0, 0, &weak, 
        "-w             --weak        - allow weak pass",
        
        'n',   "nocrypt",  NULL,  NULL, 0, 0, &nocrypt, 
        "-n             --nocrypt     - do not encrypt key (testing only)",
        
        'p',   "pass",   NULL,   &thispass, 0, 0,    NULL, 
        "-p val         --pass val    - pass in for key (@file from file)",
        
        'm',   "keyname",  NULL,   &keyname, 0, 0, NULL, 
        "-m name        --keyname nm  - user legible key name",
       
        'd',   "desc",  NULL,      &keydesc, 0, 0, NULL, 
        "-d desc        --desc  desc  - key description",
       
        'e',   "errout",  NULL,  &errout, 0, 0, NULL, 
        "-e fname       --errout fnm  - dup stderr to file. (for GUI)",
       
        'c',   "creator",  NULL,   &creator, 0, 0, NULL, 
        "-c name        --creator nm  - creator name (def: logon name)",
       
        0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
        };


void my_progress_handler (void *cb_data, const char *what,
                            int printchar, int current, int total)
{
    printf("%s", "."); fflush(stdout);
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
    
// -----------------------------------------------------------------------

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);
    
    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();
    
    // Pre allocate all string items    
    //char *mstr = "No Memory";
    zline2(__LINE__, __FILE__);
    thispass = zalloc(MAX_PATH); if(thispass == NULL) xerr3(mstr);
    keyname  = zalloc(MAX_PATH); if(keyname  == NULL) xerr3(mstr);
    keydesc  = zalloc(MAX_PATH); if(keydesc  == NULL) xerr3(mstr);
    creator  = zalloc(MAX_PATH); if(creator  == NULL) xerr3(mstr);
    errout   = zalloc(MAX_PATH); if(errout   == NULL) xerr3(mstr);
    
    char *err_str = NULL;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    
    //printf("Processed %d comline entries\n", nn);
    
    if (err_str)
        {
        printf("%s", err_str);
        usage(usestr, descstr, opts_data); exit(2);
        }
    if(errout[0] != '\0')
        {
        //printf("removing %s\n", errout);
        unlink(errout);
        }
    if(version)
        {
        printf("dibakeygen version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
        exit(1);
        }
    if(thispass[0] != '\0')
        {
        if(nocrypt)
            xerr3("dibakeygen: \nConflicting options, cannot provide key with the 'nocrypt' flag.\n");
        }
    if(num_bits_set(keysize) != 1)
        {
        xerr3("dibakeygen: Keysize must be a power of two. ( ... 1024, 2048, 4096 ...)");
        } 
    gcrypt_init();

    if(calcsum)
        {
        char *err_str, *hash_str = hash_file(argv[0], &err_str);
        if(hash_str != NULL)
            {
            printf("Executable sha hash: '%s'\n", hash_str);
            zfree(hash_str);
            }
        else 
            {
            xerr3("dibakeygen: %s\n", err_str);
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
   
    if (argc - nn != 2) {
        printf("dibakeygen: Missing argument");
        usage(usestr, descstr, opts_data); exit(2);
        }
    
    char* fname = zstrcat(argv[nn+1], ".key");
    //printf("fname %s\n", fname);
    char* fname2 = zstrcat(argv[nn+1], ".pub");
    //printf("fname2 %s\n", fname2);
    
    //char* fname3 = zstrcat(argv[nn+1], ".mod");
    //printf("fname3 %s\n", fname3);
    
    if(access(fname, F_OK) >= 0 && !force)
        {
        xerr3("dibakeygen: File already exists, use different name or delete the file.\n"
                    "You may use -f (--force) option to override.");
        }
        
    /* Generate a new RSA key pair. */
    printf("\nRSA key generation (of %d bits) may take a few minutes. \nYour computer "
           "needs to gather random entropy.\n\n", keysize);
    printf("%s", "Please wait ");

    gcry_set_progress_handler(my_progress_handler, NULL);

    gcry_error_t err = 0;
    gcry_sexp_t rsa_parms;
    gcry_sexp_t rsa_keypair;
    
    char *key_str = zalloc(64); 
    snprintf(key_str, 64, "(genkey (rsa (nbits 4:%d)))", keysize);
    err = gcry_sexp_build(&rsa_parms, NULL, key_str);
    zfree(key_str);
    if (err) {
        printerr(err, "create rsa params");
        xerr3("dibakeygen: Failed to create rsa params");
    }
    
    err = gcry_pk_genkey(&rsa_keypair, rsa_parms);
    if (err) {
        printerr(err, "create keypair");
        xerr3("dibakeygen: Failed to create rsa key pair");
    }
    memset(key_str, sizeof(key_str), '\0'); 
        
    printf("\n\nRSA key generation complete.\n\n");
    
    /* Grab a key pair password and create an encryption context with it. */
        
    int ret = 0;
    if(thispass[0] == '\0' && !nocrypt)
        {
        printf("Please enter a password to lock your key pair.\n");
        printf("This password must be retained for later use. Do not loose this password.\n\n");
        if(weak)
            printf("Warning! Weak option specified, recommended for testing only.\n");
        getpassx  passx;
        passx.prompt  = "Enter  keypair  pass:";
        passx.prompt2 = "Confirm keypair pass:";
        passx.pass = thispass;    
        passx.maxlen = MAX_PATH;
        passx.minlen = 4;
        passx.strength = 6;
        passx.weak = weak;
        passx.nodouble = FALSE;
        
        ret = getpass2(&passx);
        if(ret < 0)
            {
            xerr3("dibakeygen: Error on entering pass, no keys are written.\n");
            }
        }
    else
        {
        // See if the user provided a file
        if(thispass[0] == '@')
            {
            char *err_str = NULL;
            char *newpass = pass_fromfile((const char*)thispass, &err_str);
            if(newpass == NULL)
                xerr3("dibakeygen: %s\n", err_str);
                
            zstrcpy(thispass, newpass, MAX_PATH);
            zfree(newpass);
            }
        }   
    //printf("thispass '%s'\n", thispass);
    
    char *ttime     = zdatestr();
    char *user      = zusername();
    char *host      = zhostname();
    char *randkeyid = zrandstr_strong(24); 
    
    if(creator[0] != '\0')
        {
        zfree(user);
        user = zstrdup(creator, MAX_PATH);
        }
    char *keyver = zalloc(MAX_PATH);
    snprintf(keyver, MAX_PATH, "%d.%d.%d", ver_num_major, ver_num_minor, ver_num_rele);

    gcry_sexp_t pubk = gcry_sexp_find_token(rsa_keypair, PUBLIC_KEY, 0);
    int olen;
    char *hash_str = sexp_hash(pubk, &olen);
    
    gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, PRIVATE_KEY, 0);
    char *hash_str2 = sexp_hash(privk, &olen);
    
    //if(verbose)
    //    sexp_print(pubk);
    //if(list)
    //    sexp_list(pubk);
        
    if(keyname[0] == '\0')
        zstrcpy(keyname, "unnamed key",  MAX_PATH);
    if(keydesc[0] == '\0')
        zstrcpy(keydesc, "no description", MAX_PATH);
        
    gcry_sexp_t glib_keys;
    err = gcry_sexp_build(&glib_keys, NULL, 
                    "(" DIBACRYPT_KEY " "
                    "(\"Key Creation Date\" %s) "
                    "(\"Key Version\" %s) (\"Key Name\" %s) "
                    "(\"Key Type\" %s) "
                    "(\"Key Description\" %s) "
                    "(\"Key ID\" %s) (\"Key Creator\" %s) "
                    "(\"Key Hostname\" %s) "
                    "(\"Public Filename\" %s)  (\"Public Hash\" %s) "
                    "(\"Private Filename\" %s) (\"Private Hash\" %s) )",  
                        ttime, keyver, keyname, keytype, keydesc, 
                            randkeyid, user, host, 
                                fname2, hash_str, fname, hash_str2);
                         
    if(err)
        xerr3("dibakeygen: Cannot create sexpr: '%s'\n", gcry_strerror (err));
      
    if(verbose)
        sexp_print(glib_keys);
    
    if(list)
       sexp_list(glib_keys);
                    
    //////////////////////////////////////////////////////////////////////
    // Create hashes of everything
                                    
    int olenh;                                                  
    char *hash_info = sexp_hash(glib_keys, &olenh);
    gcry_sexp_t glib_hashes;
    err = gcry_sexp_build(&glib_hashes, NULL, 
                    "( " DIBACRYPT_HASH " "
                    "(\"Hash Creation Date\" %s) "
                    "(\"Hash Version\" %s) "
                    "(\"Key ID\" %s) " 
                    "(\"Public Filename\" %s) (\"Public Hash\" %s) "
                    "(\"Private Filename\" %s) (\"Private Hash\" %s) "
                    "(\"Info Hash\" %s) ) ",
                        ttime, keyver, randkeyid,  
                            fname2, hash_str, fname, 
                                hash_str2, hash_info);
    
    if(err)
        xerr3("dibakeygen: Cannot create hash sexpr: '%s'\n", 
                                                    gcry_strerror (err));
    if(verbose)
      sexp_print(glib_hashes);
      
    if(list)
       sexp_list(glib_hashes);
    
    zfree(keyver);    zfree(hash_info);                             
    zfree(hash_str); zfree(hash_str2); 
    
    gcry_sexp_t glib_pub;
    err = gcry_sexp_build(&glib_pub, NULL, "%S %S %S", 
                                glib_keys, pubk, glib_hashes);
        
    if(write_pubkey(&glib_pub, fname2) < 0)
        xerr3("dibakeygen: Could not write pubic key");
    
    /* Encrypt the RSA key pair. */
    size_t rsa_len = get_keypair_size(keysize);
    zline2(__LINE__, __FILE__);
    void* rsa_buf = zalloc(rsa_len);
    if (!rsa_buf) {
        xerr3("dibakeygen: malloc: could not allocate rsa buffer");
    }
    rsa_len = gcry_sexp_sprint(rsa_keypair, GCRYSEXP_FMT_CANON, rsa_buf, rsa_len);
    //rsa_len = gcry_sexp_sprint(glib_priv, GCRYSEXP_FMT_CANON, rsa_buf, rsa_len);
    if(rsa_len == 0)
        {
        xerr3("dibakeygen: Cannot sprint keypair");
        }
        
    if(dump)
        dump_mem(rsa_buf, rsa_len);
        
    if(nocrypt)
        {
        printf("Warning: This key is unencrypted.\n");
        }
    else
        {
        gcry_cipher_hd_t aes_hd;
        get_aes_ctx(&aes_hd, thispass, strlen(thispass));
        
        
        err = gcry_cipher_encrypt(aes_hd, (unsigned char*) rsa_buf, 
                                  rsa_len, NULL, 0);
        if (err) {
            xerr3("dibakeygen: Could not encrypt with AES");
            }
            
        gcry_cipher_hd_t fish_hd;
        get_twofish_ctx(&fish_hd, thispass, strlen(thispass));
        err = gcry_cipher_encrypt(fish_hd, (unsigned char*) rsa_buf, 
                                  rsa_len, NULL, 0);
        if (err) {
            xerr3("dibakeygen: Could not encrypt with TWOFISH");
            }
        gcry_cipher_close(aes_hd);
        gcry_cipher_close(fish_hd);
        }
    
    gcry_sexp_t glib_crypted;
    err = gcry_sexp_build(&glib_crypted, NULL, 
                "(" PRIVATE_CRYPTED " %b)", rsa_len, rsa_buf);
                
    // Not displaying private key info            
    //if(verbose)
    //    sexp_print(glib_crypted);
    //if(list)
    //    sexp_list(glib_crypted);
        
    gcry_sexp_t glib_priv;
    err = gcry_sexp_build(&glib_priv, NULL, "%S %S %S", 
                            glib_keys, glib_crypted, glib_hashes);
    
    //if(verbose)
    //    sexp_print(glib_priv);
    //if(list)
    //    sexp_list(glib_priv);
    
    int comp_len = gcry_sexp_sprint(glib_priv, GCRYSEXP_FMT_CANON, NULL, 0);                
    zline2(__LINE__, __FILE__);
    char *comp_buf = zalloc(comp_len + 1);
    comp_len = gcry_sexp_sprint(glib_priv, GCRYSEXP_FMT_CANON, comp_buf, comp_len);
                   
    FILE* lockf = fopen(fname, "wb");
    if (!lockf) {
        xerr3("dibakeygen: fopen() on '%s' failed.", fname);                                                              
    }
    ///* Write the encrypted base64 key pair to disk. */
    int limlen = comp_len;
    char *mem6 = base_and_lim(comp_buf, comp_len, &limlen);
   
    fprintf(lockf, "%s\n", comp_start);
    fprintf(lockf, "%*s\n", limlen, mem6);
    fprintf(lockf, "%s\n", comp_end);
    
    fclose(lockf);
    zfree(mem6);
    
    printf("Key '%s' successfully saved.\nFiles: '%s' and '%s'.\n", 
                                                randkeyid, fname, fname2);
    
    /* Release build contexts. */
    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(rsa_parms);
    gcry_sexp_release(glib_crypted);
    gcry_sexp_release(glib_keys);
    gcry_sexp_release(glib_priv);
    
    // Free all memory
    zfree(rsa_buf);     zfree(comp_buf);
    zfree(ttime);       zfree(randkeyid); 
    zfree(user);        zfree(host);
    zfree(fname);       zfree(fname2);
    zfree(thispass);    zfree(keyname);      
    zfree(keydesc);     zfree(creator);
    zfree(errout);
    
    zfree(dummy);
    
    zleak();
    return 0;
}

/* EOF */









