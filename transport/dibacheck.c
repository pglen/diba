
/* =====[ dibacheck.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.22.2017     Peter Glen      Initial version.
      0.00  aug.18.2017     Peter Glen      Added random sequence to buffer.
      0.00  aug.26.2017     Peter Glen      Shortened buffer passed to _pk_
      0.00  aug.26.2017     Peter Glen      First push to github
      0.00  nov.04.2017     Peter Glen      Added priv. key encrypt
      0.00  dec.16.2017     Peter Glen      Check started.

   ======================================================================= */

#include <signal.h>
#include <stdio.h>
#include <time.h>

#include "diba.h"
#include "gcrypt.h"
#include "gcry.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"
#include "gsexp.h"
#include "cmdline.h"
#include "dibastr.h"
#include "bluepoint3.h"
#include "misc.h"
#include "dibautils.h"

//#define TEST_PK
//#define TEST_BLUE

// This was needed as no POSIX var is defined
#ifdef __linux__
    // Empty    
#else
    int nanosleep( const struct timespec *period, struct timespec *residual );
#endif

static int nocrypt = 0;
static int dump = 0;
static int verbose = 0;
static int psexp = 0;
static int test = 0;
static int ppub = 0;
static int use_stdin = 0;
static int version = 0;
static int calcsum = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

static char    *infile  = NULL;
static char    *outfile = NULL;
static char    *keyfile = NULL;
static char    *sigfile = NULL;
static char    *thispass = NULL;

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {
                    'i',  "infile",  NULL, &infile,  0, 0, NULL, 
                    "-i <filename>  --infile <filename>     - Input file name",
                    
                    //'o',  "outfile",  NULL, &outfile,  0, 0, NULL, 
                    //"-o <filename>  --outfile <filename>    - Output file name",

                    'k',  "keyfile",  NULL, &keyfile,  0, 0, NULL, 
                    "-k <filename>  --keyfile <filename>    - Key file name",

                    'g',  "sigfile",  NULL, &sigfile,  0, 0, NULL, 
                    "-g <filename>  --sigfile <filename>    - Signature file name",

                    'V',   "version",  NULL, NULL,  0, 0, &version, 
                    "-V             --version               - Print version numbers and exit",
                    
                            'r',  "stdin",    NULL, NULL,  0, 0, &use_stdin, 
                    "-r             --stdin                 - Use stdin as input",

                    's',   "sum",  NULL,  NULL, 0, 0, &calcsum, 
                    "-s             --sum                   - Print sha sum before proceeding",
                    
                    'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
                    "-v             --verbose               - Verbosity on",
                    
                    'd',   "dump",  NULL, NULL,  0, 0, &dump, 
                    "-d             --dump                  - Dump buffers (debug)",
                    
                    'p',   "pass",   NULL,  &thispass, 0, 0,    NULL, 
                    "-p             --pass                  - Pass in for key (testing only)",
                            
                    'x',   "psexp",  NULL,  NULL, 0, 0, &psexp, 
                    "-x             --psexp                 - Print sexp as we go (debug)",
                   
                    't',   "test",  NULL,  NULL, 0, 0, &test, 
                    "-t             --test                  - Test on",
                    
                    'b',   "printpub",  NULL,  NULL, 0, 0, &ppub, 
                    "-b             --printpub              - Print public key",
       
                     0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
                    };

char descstr[] = "Check a file with a Public Key\n";
char usestr[]  = "dibacheck [options] pubkeyfile";

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

static void log_func(void *my, int val, const char *str, va_list va)

{
    //printf("From logger: %d %d ", *((int*)my), val);
    vfprintf(stdout, str, va);
}

static void term_func(void *my, int val, const char *str)

{
    printf("%s %d\n",  str, val);
    exit(3);
}

//char *mstr = "No Memory";

//////////////////////////////////////////////////////////////////////////

int main(int argc, char** argv)

{
    int mainret = 0;
    signal(SIGSEGV, myfunc);
    
    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();
    
    zline2(__LINE__, __FILE__);
    infile   = zalloc(MAX_PATH); if(infile == NULL) xerr2(mstr);
    outfile  = zalloc(MAX_PATH); if(outfile == NULL) xerr2(mstr);
    keyfile  = zalloc(MAX_PATH); if(keyfile == NULL) xerr2(mstr);
    sigfile  = zalloc(MAX_PATH); if(sigfile == NULL) xerr2(mstr);
    thispass = zalloc(MAX_PATH); if(thispass == NULL) xerr2(mstr);
        
    char *err_str = "", *err_str2 = "";
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data); exit(2);
        }
    //printf("Processed %d comline entries\n", nn);
    
    if(version)
        {
        printf("dibacheck version %d.%d.%d\n", 
                    ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
        exit(1);
        }
    if(verbose)
        {
        printf("infile='%s' outfile='%s' keyfile='%s' sigfile='%s'\n", 
                                infile, outfile, keyfile, sigfile);
        }

    if (argc - nn != 2 && strlen(keyfile) == 0) {
        printf("dibacheck: Missing argument");
        usage(usestr, descstr, opts_data); exit(2);
    }
    
    if(argc - nn >= 2)
        {
        strncpy(keyfile, argv[nn + 1], MAX_PATH);
        }
         
    //zverbose(1);
    gcry_error_t err;
    err = gcry_control(GCRYCTL_ENABLE_M_GUARD);
    if(err)
        {
        printerr(err, "guard");
        xerr2("Cannot set debug");
        }
    gcrypt_init();
    
    err = gcry_control(GCRYCTL_ENABLE_M_GUARD);
    if(err)
        {
        printerr(err, "guard");
        xerr2("Cannot set debug");
        }
    
    int  logval = 4;
    gcry_set_fatalerror_handler(term_func, &logval);
    gcry_set_log_handler(log_func, &logval);
    
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
    err = gcry_control(GCRYCTL_DISABLE_SECMEM);
   
     // See if we have a sigfile
    if(sigfile[0] == '\0')
        {
        xerr2("No signature file specified.");
        }
    int sig_len;
    char  *sig_buf = grabfile(sigfile, &sig_len, &err_str);
    if(sig_buf == NULL)
        {
        xerr2("Cannot read signature file. (%s)", err_str);
        }
    //dump_mem(sig_buf, sig_len);
    char *sig_ptr = decode_signature(sig_buf, &sig_len, &err_str);
    if(sig_ptr == NULL)
        {
        xerr2("dibacheck: Invalid file format on signature. (%s)", err_str);
        }
    zfree(sig_buf);
    
    //printf("Signature:\n");  
    //dump_mem(sig, sig_len);
    
    #ifndef TEST_BLUE
    int bret = bluepoint3_decrypt(sig_ptr, sig_len, keypass, strlen(keypass));
    #endif
    
    if(dump)
        {
        dump_mem(sig_ptr, sig_len);
        }
        
    gcry_sexp_t ssig;
    err = gcry_sexp_new(&ssig, sig_ptr, sig_len , 1);
    if(err)         
        {
        xerr2("Cannot create sexp from signature. (damaged sig?)");
        }
    zfree(sig_ptr);     
    
    if(psexp)
        sexp_print(ssig);
           
     /* Read in keyfile */
    int rsa_len;
    char  *rsa_buf = grabfile(keyfile, &rsa_len, &err_str);
    if(rsa_buf == NULL)
        {
        xerr2("dibacheck: Cannot read key file. (%s)", err_str);
        }
    gcry_sexp_t check_key, composite, info, shash;
    get_pub_key_struct pks; ZERO_PUBK_STRUCT(&pks);

    pks.err_str   = &err_str;
    pks.err_str2  = &err_str2;
    pks.rsa_buf   = rsa_buf;
    pks.rsa_len   = rsa_len;
    pks.pubkey    = &check_key;
    pks.composite = &info;
    pks.hash      = &shash;
    
    int keylen = get_pubkey(&pks);
    if(keylen < 0)
        {
        xerr2("dibacheck: %s. (%s)", err_str, err_str2);
        }
        
    //printf("Key length : %d\n", keylen);
    
    if(ppub)
        {
        sexp_print(info);
        sexp_print(check_key);
        sexp_print(shash);
        }
    
    gcry_sexp_t keyid = gcry_sexp_find_token(info, "Key ID", 0);
    if(keyid == NULL)
        {
        xerr2("dibacheck: Invalid key, it has no keyid.");
        }
    int plen2;
    char *buff = gcry_sexp_nth_buffer(keyid, 1, &plen2);
    // Means test
    if(buff == NULL)
        {
        xerr2("dibasign: no KeyID in this signature.");
        }
    zline2(__LINE__, __FILE__);
    char *buff_kid = zalloc(plen2 + 1);
    memcpy(buff_kid, buff, plen2);
    buff_kid[plen2] = '\0';
    if(verbose)
        {
        printf("Using KeyID '%s'\n", buff_kid); 
        }
    /* Read in data buffer */
    char    *data_buf;
    unsigned int  data_len;
    
    if(use_stdin)
        {
        int stdin_size = 20000;
        //printf("Using stdin\n");
        zline2(__LINE__, __FILE__);
        data_buf = zalloc(stdin_size + 10);
        if(data_buf == NULL) 
            {
            xerr2("dibacheck: Cannot allocate data for stdin.");
            }
        int  xidx = 0;
        while(TRUE)
            {
            char chh = getc(stdin);
            if(feof(stdin))
                {
                data_len = xidx;
                break;
                }
            data_buf[xidx++] = chh;
            if(xidx > stdin_size)
                xerr2("dibacheck: Out of pre allocated stdin buffer. (%d bytes)\n", stdin_size);
            }
        //printf("Got stdin buffer %d bytes:\n'%s'\n", data_len, data_buf);
        }
    else if(strlen(infile))
        {
        FILE* dataf = fopen(infile, "rb");
        if (!dataf) {
            xerr2("dibacheck: Cannot open data file: '%s'", infile);
            }
        data_len = getfsize(dataf);
        //printf("data file size %d\n", rsa_len);
        zline2(__LINE__, __FILE__);
        data_buf = zalloc(data_len + 1);
        if (!data_buf) {
            xerr2("dibacheck: Cannot allocate data buffer.");
            }
        if (fread(data_buf, data_len, 1, dataf) != 1) {
            xerr2("dibacheck: Cannot read data file '%s'.", infile);
            }
        }
    else
        {        
        xerr2("dibacheck: No data specified for checking. (use option -i)");
        }
    
    zline2(__LINE__, __FILE__);
        
    int olen; 
    char *ttime = sexp_get_val(ssig, "Sig Date", &olen, &err_str);
    //printf("ttime = '%s'\n", ttime);
    char *randsid = sexp_get_val(ssig, "Sig ID", &olen, &err_str);
    //printf("sig sid = '%s'\n", randsid);
    char *skeyid = sexp_get_val(ssig, "Sig Key ID", &olen, &err_str);
    //printf("sig key id = '%s'\n", skeyid);
    
    if(strcmp(skeyid, buff_kid) != 0)
        {
        xerr2("Wrong key. Signature key and supplied key ID does not match.");
        }
    
    int xloop;
    for(xloop = 0; xloop < NUMSIG; xloop++)
        {
        zline2(__LINE__, __FILE__);
        int  hash_len;
        char *hash_buf = 
                hash_sig_buff(xloop, data_buf, data_len, &hash_len);
        if(hash_buf == NULL)
            {
            xerr2("Cannot hash buffer.\n");
            }
    
        // Include the ID of the key with the signature
        // This defeats key substitution attacks.
        
        unsigned long long hash_hash;
        hash_hash = bluepoint3_hash64(hash_buf, hash_len);
        int hhh_len = sizeof(long long);
        char   *hhh_base = tobase64((char *)&hash_hash, &hhh_len);
                
        int base_len = data_len;
        char    *hash_base = tobase64(hash_buf, &hash_len);
              
        // Create the hash to be (message to be) signed. 
        gcry_sexp_t sdata;
        err = gcry_sexp_build(&sdata, NULL,
            "( diba_sig "
               "(\"Sig Key\" %s) "
               "(\"Sig Date\" %s) "
                "(\"Sig ID\" %s) "
                "(\"Sig Hash\" %s) )",
                    skeyid, ttime, randsid, hash_base);
        
        if(err)
            {
            xerr2("Cannot build signature sexp.");
            }
        
        if(psexp)
            sexp_print(sdata);  
        
        int block_len = 0;
        char *block_buf = sexp_sprint(sdata, &block_len, 1);
        
        if(verbose)
            printf("block_len %d keylen %d (%d bits)\n", 
                                    block_len, keylen, keylen * 8);
        if(block_len >= keylen)
            {
            xerr2("Key length must be larger than hash lengths.");
            }
        
        zfree(hhh_base); 
        zfree(hash_base); 
        
        gcry_sexp_t sign_data;
            
    #ifndef TEST_PK
        /* Check the signature of the message. */
        gcry_mpi_t msg;   int scanned;
        err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, block_buf,
                            block_len, &scanned);
                            
        if (err) {
            xerr2("dibacheck: Failed to create a mpi from the message.");
            }
        //printf("mpi scanned len=%d\n", scanned);
        
        err = gcry_sexp_build(&sign_data, NULL,
                               "(data (flags raw) (value %m))", msg);
        if (err) {
            //printerr(err, "building sexp");
            xerr2("dibacheck: Failed to create a sexp from the message.");
        }
        char src_str[MAX_PATH + 1];
        snprintf(src_str, MAX_PATH, "Signature%d", xloop+1);
        //printf("'%s'\n", src_str); 
        gcry_sexp_t ssig2 = gcry_sexp_find_token(ssig, src_str, 0);
        if(ssig2 == NULL)
            {
            xerr2("This signature does not contain valid data.\n");
            }    
        //sexp_print(ssig2);
        // Actual verification call
        err = gcry_pk_verify(ssig2, sign_data, check_key);        
        if(err == 0)
            {
            }
        else
            {
            if(verbose)
                {
                printf("Verification failed at stage %d\n", xloop);
                }
            mainret = 4;
            }
        gcry_mpi_release(msg);
        gcry_sexp_release(sign_data);
    
    zfree(hash_buf); 
 
#else   
        // This is a NULL signature check, testing ONLY
        err = 0;
#endif   
        zfree(block_buf);    
        }  // End of xloop
        
    zfree(buff_kid);  
    zfree(ttime); zfree(randsid); zfree(skeyid); 
       
    if(mainret == 0)
        {
        printf("Signature verified.\n");
        }
    else
        {
        printf("Signature verification FAILED.\n");
        }
        
    zfree(data_buf);      
        
    /* Release contexts. */
    gcry_sexp_release(check_key);
    
    zline2(__LINE__, __FILE__);
    zfree(rsa_buf);  
    zfree(infile); zfree(outfile); zfree(sigfile); 
    zline2(__LINE__, __FILE__);
    zfree(keyfile);  zfree(dummy); zfree(thispass);
    zleak();
    
    //gcry_control(GCRYCTL_DUMP_RANDOM_STATS);
    gcry_control(GCRYCTL_DUMP_MEMORY_STATS);
    
    return mainret;
}

/* EOF */

























