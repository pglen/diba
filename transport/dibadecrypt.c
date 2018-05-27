
/* =====[ dibadecrypt.c ]=================================================

   Description:     Decryption. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  aug.23.2017     Peter Glen      Converted to DIBA project 
      0.00  aug.26.2017     Peter Glen      First push to github

   ======================================================================= */

#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "diba.h"
#include "gcrypt.h"
#include "gcry.h"
#include "zmalloc.h"
#include "getpass.h"
#include "gsexp.h"
#include "cmdline.h"
#include "dibastr.h"
#include "bluepoint3.h"
#include "misc.h"

//#define TEST_PK
//#define TEST_BLUE

// This was needed as no POSIX var is defined
#ifdef __linux__
    // Empty    
#else
    int nanosleep( const struct timespec *period, struct timespec *residual );
#endif

static int verbose = 0;
static int test = 0;
static int ppub = 0;
static int raw = 0;
static int nocrypt = 0;
static int use_stdin = 0;
static int version = 0;
static int calcsum = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

static char    *infile   = NULL;
static char    *outfile  = NULL;
static char    *keyfile  = NULL;
static char    *thispass = NULL;

char  descstr[] = "Decrypt file with Private key.\n";
char usestr[] = "asdecrypt [options] keyfile";

opts opts_data[] = {
        'i',  "infile",  NULL, &infile,  0, 0, NULL, 
        "-i <filename>  --infile <filename>     - input file name",
        
        'o',  "outfile",  NULL, &outfile,  0, 0, NULL, 
        "-o <filename>  --outfile <filename>    - output file name",
       
        'p',   "pass",   NULL,  &thispass, 0, 0,    NULL, 
         "-p             --pass                 - pass in for key (testing only)",
        
        'k',  "keyfile",  NULL, &keyfile,  0, 0, NULL, 
        "-k <filename>  --keyfile <filename>    - key file name",

        'r',  "stdin",    NULL, NULL,  0, 0, &use_stdin, 
        "-r             --stdin                 - use stdin as input",
        
        //'w',  "raw",    NULL, NULL,  0, 0,   &raw, 
        //"-w             --raw                    - read raw input",
        
        'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
        "-v             --verbose               - Verbosity on",
        
        's',   "sum",  NULL,  NULL, 0, 0, &calcsum, 
        "-s             --sum         - print sha sum before proceeding",
                   
        'V',   "version",  NULL, NULL,  0, 0, &version, 
        "-V             --version     - Print version numbers and exit",
                't',   "test",  NULL,  NULL, 0, 0, &test, 
        "-t             --test                  - test on",
        
        'n',   "nocrypt",  NULL,  NULL, 0, 0, &nocrypt, 
        "-n             --nocrypt               - do not decypt private key",
       
        'x',   "printpub",  NULL,  NULL, 0, 0, &ppub, 
        "-x             --printpub              - print public key",
        
         0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
        };


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
    
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data); exit(2);
        }

    if(version)
        {
        printf("dibadecrypt: version %d.%d.%d\n", 
                                ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
        exit(1);
        }
    
    //zverbose(TRUE);
    //gcry_set_allocation_handler(zalloc, NULL, NULL, zrealloc, zfree);
    
    gcrypt_init();
    gcry_error_t err;
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
            xerr2("dibadcrypt: %s\n", err_str);
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
     
     if (argc - nn != 2 && strlen(keyfile) == 0) {
        printf("Missing argument for ascrypt.");
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
   if (argc - nn != 2 && strlen(keyfile) == 0) {
        printf("dibaencrypt: Missing argument");
        usage(usestr, descstr, opts_data); exit(2);
    }
    

    FILE* lockf = fopen(keyfile, "rb");
    if (!lockf) {
        xerr2("dibadecrypt: Opening of composite key failed on file '%s'.\n", 
                            keyfile);
    }
    
    /* Read and decrypt the key pair from disk. */
    unsigned int flen = getfsize(lockf);
    zline2(__LINE__, __FILE__);
    char* fbuf = zalloc(flen + 1);
    if (!fbuf) {
        xerr2("dibadecrypt: malloc: could not allocate rsa buffer");
    }
    if (fread(fbuf, flen, 1, lockf) != 1) {
        xerr2("dibadecrypt: Reading of composite key failed on file '%s'.\n", 
                    keyfile);
    }
    fclose(lockf);
    
    //fbuf[flen] = '\0';
    zcheck(fbuf, __LINE__);
    
    zline2(__LINE__, __FILE__);
    int  rsa_len = flen;
    char *rsa_buf = decode_comp_key(fbuf, &rsa_len, &err_str);
    zfree(fbuf);
    
    if (!rsa_buf) {
        //printf("%s\n", err_str);
        xerr2("dibadecrypt: Decode key failed. %s", err_str);
    }
    
    gcry_sexp_t compkey;
    err = gcry_sexp_new(&compkey, rsa_buf, rsa_len, 1);
    
    if (!compkey) {
        //printf("%s\n", err_str);
        xerr2("dibadecrypt: No composite key in this file.");
    }
    //print_sexp(compkey);
    /* Grab a key pair password */
    if(thispass[0] == '\0' && !nocrypt)
        {
        getpassx  passx;
        passx.prompt  = "Enter keypair pass:";
        passx.pass = thispass;    
        passx.maxlen = MAX_PATH;
        passx.minlen = 4;
        passx.weak   = TRUE;
        passx.nodouble = TRUE;
        passx.strength = 4;
        int ret = getpass2(&passx);
        if(ret < 0)
            xerr2("dibadecrypt: Error on password entry.");
        }
    else
        {
        // See if the user provided a file
        if(thispass[0] == '@')
            {
            char *err_str = NULL;
            char *newpass = pass_fromfile((const char*)thispass, &err_str);
            if(newpass == NULL)
                xerr2("dibadecrypt: %s\n", err_str);
                
            strcpy(thispass, newpass);
            zfree(newpass);
            } 
        }
            
    //printf("thispass '%s'\n", thispass);
    
    gcry_sexp_t privkid = gcry_sexp_find_token(compkey, "private-crypted", 0);
    if(privkid == NULL)
        {
        xerr2("dibadecrypt: No key found in private composite key.\n");
        }
        
    unsigned int plen3;
    char *buff3 = gcry_sexp_nth_buffer(privkid, 1, &plen3);
    
    if(!nocrypt)
    {
        // Decrypt buffer
        
        gcry_cipher_hd_t fish_hd;
        get_twofish_ctx(&fish_hd, thispass, strlen(thispass));
        err = gcry_cipher_decrypt(fish_hd, (unsigned char*) buff3, 
                                  plen3, NULL, 0);
        if (err) {
            xerr2("dibadecrypt: could not encrypt with TWOFISH");
            }
        
        gcry_cipher_hd_t aes_hd;
        get_aes_ctx(&aes_hd, thispass, strlen(thispass));
        
        err = gcry_cipher_decrypt(aes_hd, (unsigned char*) buff3,
                                  plen3, NULL, 0);
        if (err) {
            xerr2("dibadecrypt: failed to decrypt key pair");
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
        #else
        // Delay a little to fool DOS attacks
        struct timespec ts = {0, 300000000};
        nanosleep(&ts, NULL);
        xerr2("dibadecrypt: Failed to load composite key. (pass?)");
        #endif
        }
    gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);
    if(privk == NULL)
        {                           
        xerr2("dibadecrypt: No private key present in '%s'.\n", keyfile);
        }
    //print_sexp(privk);
        
    zline2(__LINE__, __FILE__);
    int keylen =  gcry_pk_get_nbits(privk) / 8 ;
    //printf("Key length : %d\n", keylen);
    
    char *data_buf = NULL;
    unsigned int data_len;
    
    if(use_stdin)
        {
        //printf("Using stdin\n");
        zline2(__LINE__, __FILE__);
        char *fbuf2 = zalloc(20000);
        int  xidx = 0;
        while(TRUE)
            {
            char chh = getc(stdin);
            if(feof(stdin))
                {
                data_len = xidx;
                break;
                }
            fbuf2[xidx++] = chh;
            if(xidx > 10000)
                xerr2("dibadecrypt: Out of preallocated stdin buffer\n");
            }
            
        //printf("Got stdin buffer %d byte\n%s\n", data_len, fbuf2);
        char *err_str;
        data_buf  = decode_rsa_cyph(fbuf2, &data_len, &err_str);
        if(!data_buf)
            {
            xerr2("dibadecrypt: Cannot decode input file. %s\n", err_str);
            }
        zfree(fbuf2); 
        }
    else if(infile[0] != '\0')
       {
        FILE* lockf2 = fopen(infile, "rb");
        if (!lockf2) {
            xerr2("dibadecrypt: Cannot open input file '%s'.\n", infile);
        }
        
        /* Read and decrypt the key pair from disk. */
        data_len = getfsize(lockf2);
        zline2(__LINE__, __FILE__);
        char* fbuf2 = zalloc(data_len + 1);
        if (!fbuf2) {
            xerr2("dibadecrypt: Could not allocate plain text buffer");
        }
        if (fread(fbuf2, data_len, 1, lockf2) != 1) {
            xerr2("dibadecrypt: Cannot reead input data.");
        }
        fclose(lockf2);
        
        char *err_str;
        data_buf  = decode_rsa_cyph(fbuf2, &data_len, &err_str);
        if(!data_buf)
            {
            xerr2("dibadecrypt: Cannot decode input file. %s\n", err_str);
            }
        zfree(fbuf2);     
       }
    else
        {
        xerr2("dibadecrypt: Need data to decrypt.\n");
        }
    
    #ifndef TEST_BLUE
    int bret = bluepoint3_decrypt(data_buf, data_len, keypass, strlen(keypass));
    #endif
    
    int  outlen2 = 0;
    zline2(__LINE__, __FILE__);
    int lim_len =  data_len * 2 + keylen;
    char *outptr = zalloc(lim_len);
    if(!outptr)
        {
        xerr2("dibadecrypt: Cannot allocate output memory.");
        }
    
    int loop = 0;
    char pub_hash[32];
    // Get key hash out of the way
    short hash_len = *( (short*) (data_buf + loop) );
    if(hash_len < 0)
        xerr2("dibadecrypt: unexpected hash length");
    
    loop += sizeof(short);   
    memcpy(pub_hash, data_buf + loop, sizeof(pub_hash));
    loop += hash_len;
    if(loop >= data_len)
        xerr2("dibadecrypt: Reading past end of data. "
            "(possible data corruption)");    
        
    // Get key id out of the way
    short keyid_len = *( (short*) (data_buf + loop) );
    if(keyid_len < 0)
        xerr2("dibadecrypt: unexpected Key ID length");
    loop += sizeof(short);   loop += keyid_len;
    if(loop >= data_len)
        xerr2("dibadecrypt: Reading past end of data. "
            "(possible data corruption)");    
    
     #if 0
    // Decrypt in place
    gcry_cipher_hd_t aes_hd2; char *keypass = "12345678";
    get_twofish_ctx(&aes_hd2, keypass, strlen(keypass));
    err = gcry_cipher_decrypt(aes_hd2, 
                    (unsigned char*) data_buf + sizeof(short),
                              keyid_len, NULL, 0);
    if (err) {
        xerr2("dibadecrypt: failed to decrypt key id");
        }
    gcry_cipher_close(aes_hd2);
    #endif
    
    //printf("Key ID from cypher: '%.*s'\n", 
    //    keyid_len, data_buf + sizeof(short) + sizeof(int)); 
    //dump_mem(data_buf + sizeof(short) + sizeof(int), keyid_len);
    
    for(; loop < data_len; /* loop += keylen */)
        {
        short curr_len = *( (short*) (data_buf + loop) );
        loop += sizeof(short);
        //printf("data %p len = %d ", data_buf + loop, curr_len);
        //printf("inlen %d\n", curr_len);
        if(loop + curr_len > data_len)
            {
            xerr2("dibadecrypt: Reading past last byte.");
            }
        
        /* Create a message. */
        gcry_sexp_t ciph;
        err = gcry_sexp_build(&ciph, NULL, 
                                    "(enc-val (rsa (a %b)))", 
                                        curr_len, data_buf + loop);
                                        
        if(err)
            {
            xerr2("dibadecrypt: sexp build failed");
            }
                
        //printf("ciph\n");                                                                  
        //print_sexp(ciph);
        
        /* Decrypt the message. */
        gcry_sexp_t plain;
        
  #ifndef TEST_PK
        err = gcry_pk_decrypt(&plain, ciph, privk);
  #else
        // This is a NULL decryption, testing ONLY
        gcry_mpi_t msg;
        err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, data_buf + loop,
                            curr_len, NULL);
        err = gcry_sexp_build(&plain, NULL, "%m", msg);
        gcry_mpi_release(msg);
  #endif
        
        //print_sexp(plain);
        
        if (err) {
            xerr2("dibadecrypt: decryption failed");
            }
        //printf("2\n");
                                                                      
        /* Pretty-print the results. */
        gcry_mpi_t out_msg = gcry_sexp_nth_mpi(plain, 0, GCRYMPI_FMT_USG);
        
        int plen = 0; unsigned char *buffm;                                     
        err = gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &plen, out_msg);
        zline2(__LINE__, __FILE__);
        buffm = zalloc(plen + 1);
        //printf("Alloc %d\n", plen);
        err = gcry_mpi_print(GCRYMPI_FMT_USG, buffm, plen, &plen, out_msg);
        if (err) 
            {
            xerr2("dibadecrypt: failed to stringify mpi");
            }
            
        //dump_mem(buffm + sizeof(int), plen - sizeof(int));
        //print_mem(buffm + sizeof(int), plen - sizeof(int));
        
        if(outlen2 + plen > lim_len)
            {
            xerr2("dibadecrypt: Could not write all mem to buffer");
            } 
        memcpy(outptr + outlen2, buffm + sizeof(int), plen - sizeof(int)); 
        zfree(buffm);
        outlen2 += plen - sizeof(int);
        loop += curr_len;
        
        gcry_mpi_release(out_msg);       
        gcry_sexp_release(plain);
        gcry_sexp_release(ciph);
        }
        
    char pub_hash2[32];
    
    gcry_md_hash_buffer(GCRY_MD_SHA256, (void*) &pub_hash2, 
                    (const void*) outptr, outlen2);
    
    if (memcmp(pub_hash, pub_hash2, 32) != 0)
        {
        if(verbose)
            {
            //print_mem(outptr, outlen2);
            //dump_mem(pub_hash, 32);
            //dump_mem(pub_hash2, 32);
            }
        //xerr2("dibadecrypt: The hash of the decrypted file does not match the original. (wrong key?)");
        }
        
    FILE* outf = stdout;
    if(strlen(outfile))
        {
        outf = fopen(outfile, "wb");
        if(!outf)
            {
            xerr2("dibadecrypt: Cannnot open outfile '%s'.\n", outfile);
            }
        }
    int retf = fwrite(outptr, outlen2, 1, outf); 
    if(retf != 1)
        {
        xerr2("dibadecrypt: Cannot write to output file.\n");
        }
    if(outf != stdout)
        {
        fclose(outf);
        }
        
    /* Release contexts. */
    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(privk);
    
    zline2(__LINE__, __FILE__);
    zfree(outptr);
    zline2(__LINE__, __FILE__);
    zfree(data_buf);
    zline2(__LINE__, __FILE__);
    zfree(rsa_buf);
    zline2(__LINE__, __FILE__);
    zfree(dummy);
    
    zfree(infile);  
    zfree(outfile); 
    zfree(keyfile);
    zfree(thispass);
    
    zleak();
    
    return 0;
}

/* EOF */



























