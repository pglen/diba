
/* =====[ dibasign.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.22.2017     Peter Glen      Initial version.
      0.00  aug.18.2017     Peter Glen      Added random sequence to buffer.
      0.00  aug.26.2017     Peter Glen      Shortened buffer passed to _pk_
      0.00  aug.26.2017     Peter Glen      First push to github
      0.00  nov.40.2017     Peter Glen      Added priv. key encrypt

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
static int test = 0;
static int psexp = 0;
static int use_stdin = 0;
static int version = 0;
static int calcsum = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

static char    *infile  = NULL;
static char    *outfile = NULL;
static char    *keyfile = NULL;
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
                    
                    'o',  "outfile",  NULL, &outfile,  0, 0, NULL, 
                    "-o <filename>  --outfile <filename>    - Output file name",

                    'k',  "keyfile",  NULL, &keyfile,  0, 0, NULL, 
                    "-k <filename>  --keyfile <filename>    - Key file name",

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
                            
                    't',   "test",  NULL,  NULL, 0, 0, &test, 
                    "-t             --test                  - Test on",
                    
                    'x',   "psexp",  NULL,  NULL, 0, 0, &psexp, 
                    "-x             --psexp                 - Print sexp as we go (debug)",
                    
                    'n',   "nocrypt",  NULL,  NULL, 0, 0, &nocrypt, 
                    "-n             --nocrypt               - Do not decypt private key",
       
                     0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
                    };

char descstr[] = "Sign a file with a Private Key\n";
char usestr[]  = "dibasign [options] privkeyfile";

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
    signal(SIGSEGV, myfunc);
    
    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();
    
    zline2(__LINE__, __FILE__);
    infile   = zalloc(MAX_PATH); if(infile == NULL) xerr2(mstr);
    outfile  = zalloc(MAX_PATH); if(outfile == NULL) xerr2(mstr);
    keyfile  = zalloc(MAX_PATH); if(keyfile == NULL) xerr2(mstr);
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
        printf("dibasign version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
        exit(1);
        }
        
    if (argc - nn != 2 && strlen(keyfile) == 0) {
        printf("dibasign: Missing argument");
        usage(usestr, descstr, opts_data); exit(2);
    }
    
    if(argc - nn >= 2)
        {
        strncpy(keyfile, argv[nn + 1], MAX_PATH);
        }
    if(verbose)
        {
        printf("infile='%s' outfile='%s' keyfile='%s'\n", 
            infile, outfile, keyfile);
        }
     
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
    
    zline2(__LINE__, __FILE__);
    // Read keyfile
    FILE* keyfp = fopen(keyfile, "rb");
    if (!keyfp) {
        xerr2("dibasign: Cannot open keyfile '%s'.", keyfile);
    }

    /* Grab the public / private key and key size */
    unsigned int rsa_len = getfsize(keyfp);
    
    //if(verbose)
    //    printf("Key file size %d\n", rsa_len);
        
    zline2(__LINE__, __FILE__);
    char* rsa_buf = zalloc(rsa_len + 1);
    if (!rsa_buf) {
        xerr2("dibasign: Cannot allocate rsa buffer.");
    }
    if (fread(rsa_buf, rsa_len, 1, keyfp) != 1) {
        xerr2("dibasign: Cannot read public key.");
    }
    rsa_buf[rsa_len] = '\0';
    //printf("'%s'\n", rsa_buf);
    fclose(keyfp);
    
    get_priv_key_struct pks; ZERO_PRIVK_STRUCT(&pks);
    gcry_sexp_t composite, info, enckey, pubkey, hash;
    
    pks.err_str   = &err_str;
    pks.err_str2  = &err_str2;
    pks.rsa_buf   = rsa_buf;
    pks.rsa_len   = rsa_len;
    pks.nocrypt   = nocrypt;
    pks.privkey   = &enckey;
    pks.pubkey    = &pubkey;
    pks.composite = &composite;
    pks.hash      = &hash;
    pks.info      = &info;
    pks.thispass  = thispass;
    
    int keylen = get_privkey(&pks);
    
    if(err_str2 == NULL)
        err_str2 = "";
    if(keylen < 0)
        {
        xerr2("dibasign: %s. (%s)", err_str, err_str2);
        }
        
    //printf("Key length : %d\n", keylen);
    //if(verbose)
    //   sexp_print(info);
    
    gcry_sexp_t keyid = gcry_sexp_find_token(info, "Key ID", 0);
    if(keyid == NULL)
        {
        xerr2("dibasign: Invalid key, it has no keyid.");
        }
    int plen_id;
    char *buff = gcry_sexp_nth_buffer(keyid, 1, &plen_id);
    // Means test
    if(plen_id < 0)
        xerr2("dibasign: Key length cannot be negative.");
 
    zline2(__LINE__, __FILE__);
    char *buff_kid = zalloc(plen_id + 1);
    memcpy(buff_kid, buff, plen_id);
    buff_kid[plen_id] = '\0';
    if(verbose)
        {
        printf("Using KeyID '%s'\n", buff_kid); 
        }
              
    /* Read in a buffer */
    char* data_buf;
    unsigned int  data_len;
    if(use_stdin)
        {
        int stdin_size = 20000;
        //printf("Using stdin\n");
        zline2(__LINE__, __FILE__);
        data_buf = zalloc(stdin_size + 10);
        if(data_buf == NULL)
            {
            xerr2("dibasign: Cannot allocate data for stdin.");
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
                xerr2("dibasign: Out of preallocated stdin buffer. (%d bytes)\n", stdin_size);
            }
        //printf("Got stdin buffer %d bytes:\n'%s'\n", data_len, data_buf);
        }
    else if(strlen(infile))
        {
        FILE* dataf = fopen(infile, "rb");
        if (!dataf) {
            xerr2("dibasign: Cannot open data file: '%s'", infile);
            }
        data_len = getfsize(dataf);
        //printf("data file size %d\n", rsa_len);
        zline2(__LINE__, __FILE__);
        data_buf = zalloc(data_len + 1);
        if (!data_buf) {
            xerr2("dibasign: Cannot allocate data buffer.");
            }
        if (fread(data_buf, data_len, 1, dataf) != 1) {
            xerr2("dibasign: Cannot read data file '%s'.", infile);
            }
        }
    else
        {        
        xerr2("dibasign: No data specified for signing. (use option -i)");
        }
    
    // Build output structures
    
    char *ttime     = zdatestr();
    char *user      = zusername();
    char *host      = zhostname();
    char *randsid   = zrandstr_strong(24); 
    
    gcry_sexp_t sinfo;
    err = gcry_sexp_build(&sinfo, NULL,
            "( " DIBACRYPT_SIG " "
            "(\"Sig Date\" %s) "
            "(\"Sig Key ID\" %s) " 
            "(\"Sig User\" %s) " 
            "(\"Sig Host\" %s) " 
            "(\"Sig ID\" %s) )",
                ttime, buff_kid, user, 
                  host, randsid);
    if(err)
        {
        xerr2("Cannot build signature info sexp.");
        }
        
    // Hash the message first, three different hashes.
    // The odds to hash it back to the original are exponential
    // and we are using bluepoint64 to really mix things up
    
    gcry_sexp_t signat[NUMSIG];
    int     xloop;
    
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
                    buff_kid, ttime, randsid, hash_base);
        
        if(err)
            {
            xerr2("Cannot build signature sexp.");
            }
        
        zfree(hhh_base);
        
        if(psexp)
            sexp_print(sdata);  
        
        int block_len = 0;
        char *block_buf = sexp_sprint(sdata, &block_len, 1);
        
        //if(verbose)
        //    printf("block_len %d keylen %d (%d bits)\n", 
        //                            block_len, keylen, keylen * 8);
        
        if(block_len >= keylen)
            {
            xerr2("Key length must be larger than hash lengths.");
            }
        
        //if(dump)    
        //    dump_mem(block_buf, block_len);
        
        gcry_sexp_t ciph, sign_data;
        
    #ifndef TEST_PK
        /* Sign the message. */
        gcry_mpi_t msg;   int scanned;
        err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, block_buf,
                            block_len, &scanned);
                            
        if (err) {
            xerr2("dibasign: Failed to create a mpi from the message.");
            }
        //printf("mpi scanned len=%d\n", scanned);
        
        err = gcry_sexp_build(&sign_data, NULL,
                               "(data (flags raw) (value %m))", msg);
        if (err) {
            //printerr(err, "bulding sexp");
            xerr2("dibasign: Failed to create a sexp from the message.");
        }
        //sexp_print(sign_data);
        //dump_mem(sign_data, block_len);
        
        err = gcry_pk_sign(&ciph, sign_data, enckey);        
        gcry_mpi_release(msg);
        gcry_sexp_release(sign_data);
        gcry_sexp_release(sdata);
        
    #else   
        // This is a NULL signature, testing ONLY
        err = gcry_sexp_build(&ciph, NULL,
                "(sig-val (rsa (s %b)))", block_len, block_buf );
    #endif   
        if (err) {
            //printerr(err, "encryption");
            xerr2("dibasign: signing  of data failed.");
        }
        err = gcry_sexp_build(&signat[xloop], NULL,
                "%S %S", ciph);
        if (err) 
            {
            xerr2("dibasign: Failed to build intermediate signature.");
            }
        //sexp_print(ciph);
        gcry_sexp_release(ciph);
        zfree(hash_base); zfree(block_buf); zfree(hash_buf);
        }
     
    zfree(user); zfree(host); zfree(randsid);
       
    gcry_sexp_t outdata;
    err = gcry_sexp_build(&outdata, NULL,
                "%S (triple-sigs "
                "(\"Signature1\" %S) "
                "(\"Signature2\" %S) " 
                "(\"Signature3\" %S) )", 
                    sinfo, signat[0], signat[1], signat[2] );
                
    if (err) {
        xerr2("dibasign: Failed to build triple signature.");
        }
    zfree(ttime);  zfree(buff_kid); 
    if(psexp)
        sexp_print(outdata);
    
    unsigned int outlen;
    char *outptr = sexp_sprint(outdata, &outlen, 1);
    
    if(dump)
        dump_mem(outptr, outlen);
    
    int hhh2 = bluepoint3_hash(outptr, outlen);
        
    #ifndef TEST_BLUE
    int bret = bluepoint3_encrypt(outptr, outlen, keypass, strlen(keypass));
    #endif
    int outx, plen3;
    char *mem3 = base_and_lim(outptr, outlen, &outx);
    zfree(outptr);
    
    FILE* outf = stdout;
    if(strlen(outfile))
        {
        outf = fopen(outfile, "wb");
        if(!outf)
            {
            xerr2("dibasign: Cannnot create outfile '%s'.", outfile);
            }
        }
    int fullen =  strlen(sig_start) + strlen(sig_end) + outx + 10;
    zline2(__LINE__, __FILE__);
    char *mem4 = zalloc(fullen);
    if(!mem4) 
        xerr2("dibasign: Cannot allocate memory for output.");
    
    int add = snprintf(mem4, fullen, "%s\n", sig_start);
    // Big no no. Will terminate at the first null (random error introduced)
    //add += snprintf(mem4 + add, fullen - add, "%.*s\n", outx, mem3);
    memcpy(mem4 + add, mem3, outx);  add += outx;
    add += snprintf(mem4 + add, fullen - add, "\n%s\n", sig_end);
    //print_mem(mem4, add);
    int retf = fwrite(mem4, add, 1, outf); 
    //fflush(outf);
    if(retf != 1)
        {
        xerr2("dibasign: Cannot write to output file '%s'.\n", outfile);
        }
    zfree(mem4);
    if(outf != stdout)
        {
        fclose(outf);
        }
    zfree(mem3);
    zfree(data_buf);
    
    /* Release contexts. */
    gcry_sexp_release(enckey);
    
    zline2(__LINE__, __FILE__);
    zfree(rsa_buf);  zfree(infile); zfree(outfile); 
    zline2(__LINE__, __FILE__);
    zfree(keyfile);  zfree(dummy); zfree(thispass);
    zleak();
    
    //gcry_control(GCRYCTL_DUMP_RANDOM_STATS);
    gcry_control(GCRYCTL_DUMP_MEMORY_STATS);
    
    return 0;
}

/* EOF */

























