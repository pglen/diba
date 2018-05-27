
/* =====[ dibachest.c ]=========================================================

   Description:     Chest generation for DIBA [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  nov.21.2017     Peter Glen      Initial
      
   ======================================================================= */

#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "diba.h"
#include "gcrypt.h"
#include "gcry.h"
#include "gsexp.h"

#include "getpass.h"
#include "base64.h"
#include "zmalloc.h"
#include "cmdline.h"
#include "dibastr.h"
#include "misc.h"
#include "zstr.h"
#include "dibafile.h"

static  unsigned int keysize = 2048;

static int weak = FALSE;
static int force = FALSE;
static int dump = 0;
static int verbose = 0;
static int test = 0;
static int calcsum = 0;
static int nocrypt = 0;
static int version = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

static char descstr[] = "Generate chest, include a Public / Private keypair";
static char usestr[]  = "dibachest [options] chestfile\n"
                "Where 'chestfile' is the basename for .chest ";
                
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
        "-k             --keylen      - key length in bits (default 2048)",
        
        'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
        "-v             --verbose     - Verbosity on",
        
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
        "-p val         --pass val    - pass in for key (@file reads pass from file)",
        
        'm',   "keyname",  NULL,   &keyname, 0, 0, NULL, 
        "-m name        --keyname nm  - user legible key name",
       
        'd',   "desc",  NULL,      &keydesc, 0, 0, NULL, 
        "-d desc        --desc  desc  - key description",
       
        'e',   "errout",  NULL,  &errout, 0, 0, NULL, 
        "-e fname       --errout fnm  - dup stderr to file. (for GUI deployment)",
       
        'c',   "creator",  NULL,   &creator, 0, 0, NULL, 
        "-c name        --creator nm  - override creator name (def: logon name)",
       
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
        printf(err_str);
        usage(usestr, descstr, opts_data); exit(2);
        }
    if(errout[0] != '\0')
        {
        //printf("removing %s\n", errout);
        unlink(errout);
        }
    if(version)
        {
        printf("dibachest version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
        exit(1);
        }
    if(thispass[0] != '\0')
        {
        if(nocrypt)
            xerr3("dibachest: \nConflicting options, cannot provide key with the 'nocrypt' flag.\n");
        }
    if(num_bits_set(keysize) != 1)
        {
        xerr3("dibachest: Keysize must be a power of two. ( ... 1024, 2048, 4096 ...)");
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
            xerr3("dibachest: %s\n", err_str);
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
        printf("dibachest: Missing argument");
        usage(usestr, descstr, opts_data); exit(2);
        }
    
    char* fname = zstrcat(argv[nn+1], ".chest");
    //printf("fname %s\n", fname);
    //char* fname2 = zstrcat(argv[nn+1], ".pub");
    //printf("fname2 %s\n", fname2);
    
    //char* fname3 = zstrcat(argv[nn+1], ".mod");
    //printf("fname3 %s\n", fname3);
    
    if(access(fname, F_OK) >= 0 && !force)
        {
        xerr3("dibachest: File already exists, use different name or delete the file or use -f (--force) option.");
        }
        
    /* Generate a new RSA key pair. */
    printf("\nRSA key generation (of %d bits) can take a few minutes. \nYour computer "
           "needs to gather random entropy.\n\n", keysize);
    printf("Please wait ");

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
        xerr3("dibachest: Failed to create rsa params");
    }
    
    err = gcry_pk_genkey(&rsa_keypair, rsa_parms);
    if (err) {
        printerr(err, "create keypair");
        xerr3("dibachest: Failed to create rsa key pair");
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
        passx.prompt  = "Enter  chest keypair  pass:";
        passx.prompt2 = "Confirm chest keypair pass:";
        passx.pass = thispass;    
        passx.maxlen = MAX_PATH;
        passx.minlen = 4;
        passx.strength = 6;
        passx.weak = weak;
        passx.nodouble = FALSE;
        
        ret = getpass2(&passx);
        if(ret < 0)
            {
            xerr3("dibachest: Error on entering pass, no keys are written.\n");
            }
        }
    else
        {
        // See if the user provided a file
        if(thispass[0] == '@')
            {
            //char *err_str = NULL;
            char *newpass = pass_fromfile((const char*)thispass, &err_str);
            if(newpass == NULL)
                xerr3("dibachest: %s\n", err_str);
                
            zstrcpy(thispass, newpass, MAX_PATH);
            zfree(newpass);
            }
        }
           
    //printf("thispass '%s'\n", thispass);
    
    char *ttt = zdatestr();
    char *user = zusername();
    char *host = zhostname();
    char *rrr  = zrandstr_strong(48); 
    
    if(creator[0] != '\0')
        {
        zfree(user);
        user = zstrdup(creator, MAX_PATH);
        }
    char *keyver = zalloc(MAX_PATH);
    snprintf(keyver, MAX_PATH, "%d.%d.%d", ver_num_major, ver_num_minor, ver_num_rele);

    gcry_sexp_t pubk = gcry_sexp_find_token(rsa_keypair, "chest-public-key", 0);
    int olen;
    char *hash_str = sexp_hash(pubk, &olen);
    
    gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, "chest-private-key", 0);
    char *hash_str2 = sexp_hash(privk, &olen);
    
    if(keyname[0] == '\0')
        strcpy(keyname, "unnamed key");
    if(keydesc[0] == '\0')
        strcpy(keydesc, "no description");
        
    gcry_sexp_t glib_keys;
    err = gcry_sexp_build(&glib_keys, NULL, 
                "(dibachest-key (\"Key creation date\" %s) "
                    "(\"Key Version\" %s) (\"Key Name\" %s) (\"Key Description\" %s)  "
                    "(\"Key ID\" %s) (\"Key Creator\" %s) (\"Hostname\" %s) "
                    "(\"Public Filename\" %s)  (\"Public Hash\" %s) "
                    "(\"Private Hash\" %s) )",  
                        ttt, keyver, keyname, keydesc, rrr, user, host, 
                            fname, hash_str, hash_str2);
                         
    if(err)
        xerr3("dibachest: Cannot create sexpr: '%s'\n", gcry_strerror (err));
      
    //sexp_print(glib_keys);
    
    if(verbose)
       sexp_list(glib_keys);
    
    gcry_sexp_t glib_pub;
    err = gcry_sexp_build(&glib_pub, NULL, "%S %S", glib_keys, pubk);
    int plen;
    zline2(__LINE__, __FILE__);
    char    *buff = sexp_get_buff(glib_pub, &plen);
    if(!buff)
        {
        xerr3("dibachest: Cannot alloc pubkey decode memory\n"); 
        }
    int plimlen = plen;
    char *mem6p = base_and_lim(buff, plen, &plimlen);
    char *rrr2  = zrandstr_strong(48); 
        
    gcry_sexp_t diba_chestinfo;
    err = gcry_sexp_build(&diba_chestinfo, NULL, 
                "(dibachest-info (\"Chest Creation Date\" %s) "
                    "(\"Chest Version\" %s) (\"Chest Name\" %s) "
                    "(\"Chest Description\" %s)  "
                    "(\"Chest ID\" %s) (\"Chest Creator\" %s) "
                    "(\"Chest Hostname\" %s) "
                    "(\"Chest Filename\" %s)  (\"Chest Hash\" %s) "
                    "(\"Chest Private Hash\" %s) )",  
                        ttt, keyver, keyname, keydesc, rrr2, user, host, 
                            fname, hash_str, hash_str2);
                            
    //sexp_print(diba_chestinfo);
   
    zfree(rrr2);
   
    int     clen;
    zline2(__LINE__, __FILE__);
    char    *buff2 = sexp_get_buff(diba_chestinfo, &clen);
    
    zfree(keyver);                              
    zfree(hash_str); zfree(hash_str2); 
    
    if(!buff2)
        {
        xerr3("dibachest: Cannot alloc chestinfo decode memory\n"); 
        }
    int clen2 = clen;
    char *mem6c = base_and_lim(buff2, clen, &clen2);
        
    zfree(buff); zfree(buff2);                                
    
    //if(write_pubkey(&glib_pub, fname2) < 0)
    //    xerr3("dibachest: Could not write pubic key");
    
    /* Encrypt the RSA key pair. */
    size_t rsa_len = get_keypair_size(keysize);
    zline2(__LINE__, __FILE__);
    void* rsa_buf = zalloc(rsa_len);
    if (!rsa_buf) {
        xerr3("dibachest: malloc: could not allocate rsa buffer");
    }
    
    rsa_len = gcry_sexp_sprint(rsa_keypair, GCRYSEXP_FMT_CANON, rsa_buf, rsa_len);
    //rsa_len = gcry_sexp_sprint(glib_priv, GCRYSEXP_FMT_CANON, rsa_buf, rsa_len);
    if(rsa_len == 0)
        {
        xerr3("dibachest: Cannot sprint keypair");
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
            xerr3("dibachest: Could not encrypt with AES");
            }
            
        gcry_cipher_hd_t fish_hd;
        get_twofish_ctx(&fish_hd, thispass, strlen(thispass));
        err = gcry_cipher_encrypt(fish_hd, (unsigned char*) rsa_buf, 
                                  rsa_len, NULL, 0);
        if (err) {
            xerr3("dibachest: Could not encrypt with TWOFISH");
            }
        gcry_cipher_close(aes_hd);
        gcry_cipher_close(fish_hd);
        }
    
    gcry_sexp_t glib_crypted;
    err = gcry_sexp_build(&glib_crypted, NULL, 
                "(private-crypted %b)", rsa_len, rsa_buf);
                
    //sexp_print(glib_crypted);
        
    gcry_sexp_t glib_priv;
    err = gcry_sexp_build(&glib_priv, NULL, "%S %S", glib_keys, glib_crypted);
    //sexp_print(glib_priv);
    
    int comp_len = gcry_sexp_sprint(glib_priv, GCRYSEXP_FMT_CANON, NULL, 0);                
    zline2(__LINE__, __FILE__);
    char *comp_buf = zalloc(comp_len + 1);
    comp_len = gcry_sexp_sprint(glib_priv, GCRYSEXP_FMT_CANON, comp_buf, comp_len);
  
    /* make it base64. */
    int limlen = comp_len;
    char *mem6 = base_and_lim(comp_buf, comp_len, &limlen);
   
    /* Write the base64 keys to disk. */
    FILE   *cfp = CreateDibaFile(fname, &err_str);
    if(!cfp)
        {
        xerr3("dibachest: Cannot create chest file.");
        }
        
    chunk_keypair kp;
    
    kp.key = "Chest Info"; kp.klen = strlen(kp.key); 
    kp.val = mem6c; kp.vlen = clen2;
    kp.compressed = 1;
    ret = PutDibaKeyVal(cfp, &kp, &err_str);
    zfree(mem6c);
    
    kp.key = "Chest Public Key"; kp.klen = strlen(kp.key); 
    kp.val = mem6p; kp.vlen = plimlen;
    kp.compressed = 1;
    ret = PutDibaKeyVal(cfp, &kp, &err_str);
    zfree(mem6p);
    
    kp.key = "Chest Private Key"; kp.klen = strlen(kp.key); 
    kp.val = mem6; kp.vlen = limlen;
    kp.compressed = 1;
    ret = PutDibaKeyVal(cfp, &kp, &err_str);
    zfree(mem6);
    CloseDibaFile(cfp, TRUE);
    
#if 0                                                                        
    FILE* lockf = fopen(fname, "wb");
    if (!lockf) {
        xerr3("dibachest: fopen() failed");                                                              
    }
    /* Write the encrypted base64 key pair to disk. */
    int limlen = comp_len;
    char *mem6f = base_and_lim(comp_buf, comp_len, &limlen);
   
    fprintf(lockf, "%s\n", comp_start);
    fprintf(lockf, "%*s\n", limlen, mem6f);
    fprintf(lockf, "%s\n", comp_end);
    
    fclose(lockf);
    zfree(mem6f);
#endif
    
    /* Release contexts. */
    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(rsa_parms);
    zfree(rsa_buf);
    zfree(comp_buf);
    
    printf("Chest '%s'  successfully saved to '%s'.\n", rrr, fname);
    zfree(ttt);  zfree(rrr); zfree(user); zfree(host);
    
    zfree(fname);       
    //zfree(fname2);
    zfree(thispass);    zfree(keyname);      
    zfree(keydesc);     zfree(creator);
    zfree(errout);
    
    zfree(dummy);
    
    zleak();
    return 0;
}

/* EOF */








