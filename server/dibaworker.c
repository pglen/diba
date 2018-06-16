
/* =====[ dibaworker.c ]=========================================================

   Description:     Single thread for the server for DIBA [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  nov.21.2017     Peter Glen      Initial

   ======================================================================= */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <windows.h>
#include <stdio.h>

int exitCondition;

struct threadParams{
    int param1;
    int param2;
};

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
#include "dibascom.h"
#include "bluepoint3.h"

#define TIMEOUT 4        // Seconds before server timeouts
#define HANDLE int

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

static char descstr[] = "Process DIBA transaction requests ";
static char usestr[]  = "dibaworker [options]\n";

static char    *thispass = NULL;
static char    *keyname  = NULL;
static char    *term  = NULL;
static char    *keydesc  = NULL;
static char    *creator  = NULL;
static char    *errout   = NULL;

static gcry_sexp_t pubkey;
static int pubkey_bits = 0;

static int      got_key = 0;
static int      got_sess = 0;
static int      debuglevel = 0;
static int      loglevel = 0;
static  char    *randkey = NULL;
static  char    *testkey = "1234";

static char recbuff[4096];

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

        'd',   "debug",   &debuglevel,  NULL, 0,  10, NULL,  
        "-d  level      --debug       - Debug level (1-10)",

        'l',   "log",     &loglevel, NULL, 0,  10, NULL,  
        "-l  level      --log level     - Logging level (1-10) 0 - none",

        't',   "test",  NULL,  NULL, 0, 0, &test,
        "-t             --test        - run self test before proceeding",

        'r',   "term",  NULL,  &term, 0, 0, NULL,
        "-r term        --term    - debug info to 'term' termnal",

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
        "-m keyval      --keyname keyval    - key name",

        0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
    };

// Forwards
static int printlog(char *str, ...);
static FILE *logfp = NULL;
static FILE *termfp = NULL;

int xerr_serv(const char *str, ...)
{
    char mystr[128];

    printlog("Error exit in %d.\n", getpid());
    
    va_list ap; va_start(ap, str);
    int ret = vsnprintf(mystr, sizeof(mystr), str, ap);
    
    scom_send_data(1, mystr, ret, 1);
    scom_recv_data(0,  mystr, ret, 1);
    
    char  *ddd = zsnprintf("%s error exit.", errstr);
    scom_send_data(1, ddd, strlen(ddd) + 1, 0);
    zfree(ddd);
    
    // We do not know the state of the program, free all
    zautofree();
    
    if(logfp)
        zleakfp(logfp);
        
    exit(5);
}

// Print to logfile and designated terminal

static int printlog(char *str, ...)

{
    va_list ap;  va_start(ap, str);    
        
    if(loglevel > 0)
        {
        if(logfp == NULL)
            {
            // Encode log file name
            char *tname = zdatename();
            char *tmp = zsnprintf("%s-%s-%d.%s", 
                                    "dibaworker", tname, getpid(), "log");
            zfree(tname);
            //printf("tmp=%s\n", tmp);
            logfp = fopen(tmp, "ab+");
            //zfree(tmp);
            }
        if(!logfp)
            {
            xerr_serv("Cannot open/create log file.\n");
            }
        if(logfp)
            {
            vfprintf(logfp, str, ap); fflush(logfp);
            }
        }
        
    // Print to pty if there is one
    if(term[0] != '\0')
        {
        if(termfp == NULL)
            {
            termfp = fopen(term, "r+");
            }
            
        if(termfp)
            {
            va_start(ap, str);    
            vfprintf(termfp, str, ap);  fflush(termfp);
            }
        }
    return 0;
}
        
static void myfunc(int sig)
{
    //printf("\nSignal %d (segment violation)\n", sig);
    
    printlog("\ndibaworker: Signal %d (segment violation) pid=%d.\n", 
                                sig, getpid());
                                
    xerr_serv("FATAL dibaworker: Signal %d (segment violation)\n");
    //exit(111);
}

static void myfunc2(int sig)
{
    //printf("\nServer recived Signal %d\n", sig);
    printlog("\ndibaworker: Signal %d (interrupt)\n %d.\n", sig, getpid());
    signal(sig, myfunc2);
    //exit(111);
}
    
// Functions
void closefunc(char *buff, int len);
void checkfunc(char *buff, int len);
void echofunc(char *buff, int len);
void keyfunc(char *buff, int len);
void sessfunc(char *buff, int len);

void  *cmdarr[] = {
        closecmd, checkcmd, keycmd, sesscmd, echocmd, NULL
        };

void *funcarr[] = {
        closefunc, checkfunc, keyfunc, sessfunc, echofunc, NULL
        };

// -------------------------------------------------------------------
// This drives the parser

struct dibaparse
{
    char    *cmd;
    int     len;
    void    (*func)(char *str, int len);
};

struct dibaparse parsearr[ sizeof(cmdarr) / sizeof(char *) + 2];

//////////////////////////////////////////////////////////////////////////
// Signal error, terminate with final handshake

static volatile int timeout = 0;

DWORD WINAPI Thread(void *ArgList) 

{
    HANDLE hEvent = *((HANDLE*)ArgList);
    
    while(1)
        {
        struct timespec ts = {1, 0};
         
        //printlog("Thread heartbeat %d.\n", getpid());
        
        nanosleep(&ts, NULL);
        
        timeout ++;
        if(timeout > TIMEOUT)
            {
            break;
            }
        }
    
    char  *ddd = zsnprintf("%s Server Timeout.", fatstr);
    if(got_sess)
        {
        int outx;
        char *xptr = bp3_encrypt_cp(ddd, strlen(ddd) + 1,
                                            randkey, strlen(randkey), &outx);
        scom_send_data(1, xptr, outx, 1);
        zfree(xptr);
        }
    else
        {  
        scom_send_data(1, ddd, strlen(ddd), 1);
        }
    
    printlog("Timeout exit %d.\n", getpid());

    // Allow fast shutdown
    struct linger ld = {1, 0}; int len = sizeof(ld);
    setsockopt(1, SOL_SOCKET, SO_LINGER, (char*)&ld, sizeof(ld));
    
    // Totally meaningless, but for correctness sake
    close(0); close(1);
    
    zautofree();
    if(logfp)
        zleakfp(logfp);
    
    exit(4);
    return 0;
}

//////////////////////////////////////////////////////////////////////////

static void initdibaparser()
{
    int idx = 0;
    while(1)
        {
        char *curr = cmdarr[idx];
        parsearr[idx].cmd = curr;
        if(curr == NULL)
            {
            break;
            }
        parsearr[idx].len = strlen(curr);
        parsearr[idx].func = funcarr[idx];

        idx++;
        }
}

// parse command buffer. Call command function if command recognized.
// Return -1 if no command recognized

int parse_cmd(char *buff, int len)

{
    int ret = -1, idx = 0, data_len;
    char *data_buff = NULL;

    timeout = 0;
    // If encrypted, decrypt
    if(got_sess)
        {
        data_buff = unbase_and_unlim(buff, len, &data_len);
        bluepoint3_decrypt(data_buff, data_len, randkey, strlen(randkey));
        buff = data_buff; len = data_len;    
        }

    if(debuglevel > 4)
        printlog("Parsing '%.*s'\n", len, buff);

    while(1)
        {
        struct dibaparse currp = parsearr[idx];
        if(currp.cmd == NULL)
            break;

        //if(debuglevel > 9)
        //    printlog("scanning '%s'\n", currp.cmd);

        if(strncmp(buff, currp.cmd, currp.len) == 0)
            {
            //printlog("Found cmd: '%s'\n", currp.cmd);
            ret = 0;
            currp.func(buff, len);
            }
        idx++;
        }
        
    if(data_buff) 
        zfree(data_buff);
        
    return ret;
}


void my_progress_handler (void *cb_data, const char *what,
                            int printchar, int current, int total)
{
    //printf(".");
    //printf("%c", printchar);
}


// Forward declarations
static  int     check_pubkey(gcry_sexp_t *pubkey, const char *rsa_buf, int rsa_len);
static  int     check_trans_valid(char *buff, int len, char **reason_str);

// -----------------------------------------------------------------------

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);
    signal(SIGINT, myfunc2);
    
    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();
    
    initdibaparser();

    // Pre allocate all string items
    zline2(__LINE__, __FILE__);
    thispass = zalloc(MAX_PATH); if(thispass == NULL) xerr_serv(mstr);
    keyname  = zalloc(MAX_PATH); if(keyname  == NULL) xerr_serv(mstr);
    term     = zalloc(MAX_PATH); if(term     == NULL) xerr_serv(mstr);
    keydesc  = zalloc(MAX_PATH); if(keydesc  == NULL) xerr_serv(mstr);
    creator  = zalloc(MAX_PATH); if(creator  == NULL) xerr_serv(mstr);
    errout   = zalloc(MAX_PATH); if(errout   == NULL) xerr_serv(mstr);
    
    scom_set_debuglevel(debuglevel);
    
    char *err_str = NULL;
    int nn = parse_commad_line(argv, opts_data, &err_str);

    //printf("term: %s\n", term);
    
    //if(debuglevel > 0) 
    //    printlog("Diba Worker started.\n");

    //if(debuglevel > 0) 
    //    printlog("Processed %d comline entries\n", nn);

    if (err_str)
        {
        printlog("%s", err_str);
        printf("%s", err_str);
        usage(usestr, descstr, opts_data); exit(2);
        exit(2);
        }
        
    if(errout[0] != '\0')
        {
        //printf("removing %s\n", errout);
        unlink(errout);
        }
    if(version)
        {
        printlog("dibaworker version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
        printlog("libgcrypt version %s\n", GCRYPT_VERSION);
        exit(1);
        }
    if(thispass[0] != '\0')
        {
        if(nocrypt)
            xerr_serv("dibaworker: \nConflicting options, cannot provide key with the 'nocrypt' flag.\n");
        }
    if(num_bits_set(keysize) != 1)
        {
        xerr_serv("dibaworker: Keysize must be a power of two. ( ... 1024, 2048, 4096 ...)");
        }

    gcrypt_init();

    if(calcsum)
        {
        char *err_str, *hash_str = hash_file(argv[0], &err_str);
        if(hash_str != NULL)
            {
            printlog("Executable sha hash: '%s'\n", hash_str);
            zfree(hash_str);
            }
        else
            {
            xerr_serv("dibaworker: %s\n", err_str);
            }
        }

    if(test)
        {
        printlog("Excuting self tests ... ");
        gcry_error_t err = 0;
        err = gcry_control(GCRYCTL_SELFTEST);
        if(err)
            {
            printlog("fail.\n");
            exit(3);
            }
        else
            {
            printlog("pass.\n");
            }
        }

    if(isatty(1))
        {
        printf("This program is not meant to run from the terminal.\n");
        printf("Use dibaserv to drive it.\n");
        exit(2);
        }

    // ---------------------------------------------------------------
    // Begin worker
    
    #if 1
    // Create a manual-reset nonsignaled unnamed event
    HANDLE hThread, hEvent;
    unsigned int ThreadId;
   
    DWORD threadDescriptor;
    struct threadParams params1 = {1, 2};
    exitCondition = 1; 
   
    CreateThread(
        NULL,                   /* default security attributes.   */
        0,                      /* use default stack size.        */
        Thread,                 /* thread function name.          */
        (void*)&params1,        /* argument to thread function.   */
        0,                      /* use default creation flags.    */
        &threadDescriptor);     /* returns the thread identifier. */

    #endif
    
    zline2( __LINE__, __FILE__);
    if(debuglevel > 0)
        {
        char *ttime     = zdatestr();
        printlog("Diba Worker [%d] started at %s.\n", getpid(), ttime);
        zfree(ttime);
        }

    #if 0
    if(debuglevel > 5)
        {
        printlog("Diba Worker arguments: ");
        for(int loop = 1; loop < argc; loop ++)
            {
            printlog("'%s' ", argv[loop]);
            }
        printlog("\n");
        }
    #endif
    
    // Force a fault to test log response on fault
    //int *nullp = NULL;
    // *nullp = 1;
        
    //int hhh = atoi(argv[1]);
    //int ret = scom_send_data(1, hellostr, strlen(hellostr), 1);
    char  *ddd = zsnprintf("%s %d.%d.%d", hellostr, 
                              ver_num_major, ver_num_minor, ver_num_rele);
    scom_send_data(1, ddd, strlen(ddd) + 1, 0);
    zfree(ddd);
    
    // -------------------------------------------------------------------
    // Main loop
    while(1)
        {
        int ret2 = scom_recv_data(0, recbuff, sizeof(recbuff), 1);
                 
        if(ret2 < 0)
            {
            if(debuglevel > 2)
                printlog("Error on recv %d (errno %d %s)\n", 
                                ret2, errno, strerror(errno));
            break;
            }
        if(ret2 == 0)
            {
            if(debuglevel > 2)
                printlog("Got empty buffer\n");

            break;
            }
            
        if(debuglevel > 3)
            printlog("Got data: '%.*s'\n", ret2, recbuff);
             
        int ret = parse_cmd(recbuff, ret2);
        if(ret < 0)
            {
            if(debuglevel > 2)
                printlog("Got unknown cmd: '%.*s'\n", ret2, recbuff);
            ret = print2sock(1, 1, "%s %s", errstr, nocmd, 1);
            }
        }
   
    // Allow fast shutdown
    struct linger ld = {1, 0}; int len = sizeof(ld);
    setsockopt(1, SOL_SOCKET, SO_LINGER, (char*)&ld, sizeof(ld));
     
    // Not really needed
    close(0);  close(1);
       
    zfree(thispass);    zfree(keyname);
    zfree(keydesc);     zfree(creator);
    zfree(errout);      zfree(dummy);

    if(randkey)
        zfree(randkey);

    if(debuglevel > 0)
        {
        char *ttime2     = zdatestr();
        printlog("Diba Worker [%d] exited at %s\n\n",
                                            getpid(), ttime2);
        zfree(ttime2);
        }

    // Redirect to log
    if(logfp)
        zleakfp(logfp);

    // Close all 
    if(logfp)
        fclose(logfp);
        
    if(termfp)
        fclose(termfp);

    return 0;
}

//////////////////////////////////////////////////////////////////////////
// Create pub key from recvd data

int check_pubkey(gcry_sexp_t *pubkey, const char *rsa_buf, int rsa_len)

{
    int ret = 0, outlen = rsa_len;
    char *dec_err_str;
    char *mem = decode_pub_key((char *)rsa_buf, &outlen, &dec_err_str);
    if(mem == NULL)
        {
        //printf("%s\n", dec_err_str);
        if(debuglevel > 0)
            printlog("Cannot decode public key. %s\n", dec_err_str);
        return -1;
        }
    int err = gcry_sexp_new(pubkey, mem, outlen, 1);
    zfree(mem);
    if (err) {
        if(debuglevel > 0)
            printlog("Failed to create create public key sexp. %s\n",
                                                      gcry_strerror (err));
        return -1;
        }
        
    ret = gcry_pk_get_nbits(*pubkey);
    if(debuglevel > 2)
        printlog("Created public key. %d bits\n", ret);
        
    return(ret);
}

void closefunc(char *buff, int len)

{
    int ret;

    if(debuglevel > 2)
        printlog("Got close cmd: '%.*s'\n", len, buff);

    int slen = strlen(endstr) + 1;
    // If session, encrypt
    if(got_sess)
        {
        int outx;
        char *xptr = bp3_encrypt_cp(endstr, slen, randkey, strlen(randkey), &outx);
        ret = scom_send_data(1, xptr, outx, 1);
        zfree(xptr);
        }
    else
        {
        ret = scom_send_data(1, endstr, strlen(endstr) + 1, 1);
        }
}

void    echofunc(char *buff, int len)
{
    int ret;

    if(debuglevel > 2)
        printlog("Got echo cmd: '%.*s'\n", len, buff);

    if(got_sess)
        {
        int outx;
        char *xptr = bp3_encrypt_cp(buff, len, randkey, strlen(randkey), &outx);
        if(!xptr) xerr_serv("Err Cannot alloc mem\n");
        ret = scom_send_data(1, xptr, outx, 1);
        zfree(xptr);
        }
   else
        {
        char *sum = zstrmcat(0, okstr, " ", buff + 5, NULL), 
        ret = scom_send_data(1, sum, strlen(sum), 1);
        zfree(sum);
        }
}

void    checkfunc(char *buff, int len)
{
    int ret;
    if(debuglevel > 2)
        printlog("Got check cmd: '%.*s'\n", len, buff);

    // If session, encrypt
    if(got_sess)
        {
        char *rstr;
        char *sumstr = zalloc(MAX_PATH + 1);
        int ret2 = check_trans_valid(buff, len, &rstr);
        if(ret2 == 1)
            {
            snprintf(sumstr, MAX_PATH, "%s %s", errstr, rstr);
            }
        else if(ret2 == 0)
            {
            snprintf(sumstr, MAX_PATH, "%s %s ", okstr,
                        "Transaction propsal valid");
            }
        else
            {
            snprintf(sumstr, MAX_PATH, "%s %s ", unkstr,
                        "Cannnot determine or insufficien data");
            }
        int xlen = strlen(sumstr) + 1;
        if(debuglevel > 0) 
            printlog("Sumstr: '%.*s'\n", xlen, sumstr);
            
        int outx;
        char *xptr = bp3_encrypt_cp(sumstr, xlen,
                                            randkey, strlen(randkey), &outx);
        ret = scom_send_data(1, xptr, outx, 1);
        zfree(xptr);
        zfree(sumstr);
        }
   else
        {
        ret = print2sock(1, 1, "%s %s", errstr,
                        "check not available out of session.");
        }
}

//////////////////////////////////////////////////////////////

void sessfunc(char *buff, int len)

{
    int ret;
    if(debuglevel > 2)
        printlog("Got sess cmd: '%.*s'\n", len, buff);

    if(!got_key)
        {
        ret = print2sock(1, 1, "%s Send valid key first.", errstr);
        return;
        }
    randkey = zrandstr_strong(RANDKEY_LENGTH);

    if(strlen(randkey) * 8 >  pubkey_bits)
        {
        printlog(
            "Rand key legnth (%d) bigger than public key length. (%d)\n",
                strlen(randkey) * 8, pubkey_bits);
        ret = print2sock(1, 1, "%s %s", errstr, "Public key too small.");
        }

    if(debuglevel > 1)
        printlog("Sending rand key: '%s'\n", randkey);

    #if 1
    /* Encrypt the message. */
    gcry_sexp_t ciph, enc_data;
    gcry_mpi_t msg; int scanned;
    int err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, randkey,
                        strlen(randkey) + 1, &scanned);
    if (err) {
        xerr_serv("dibaworker: Failed to create a mpi from the message.");
        }
        
    if(debuglevel > 0) 
        printlog("scanned mpi len=%d\n", scanned);
        
    err = gcry_sexp_build(&enc_data, NULL,
                           "(data (flags raw) (value %m))", msg);
    if (err) {
        //printerr(err, "bulding sexp");
        xerr_serv("dibaworker: Failed to create a sexp from the message.");
    }

    //xerr_serv("dibaworker: test error return.");

    gcry_mpi_release(msg);
    err = gcry_pk_encrypt(&ciph, enc_data, pubkey);
    if(err)
        xerr_serv("dibaworker: failed to encrypt data.");

    gcry_sexp_release(enc_data);

    //sexp_fprint(ciph, logfp);

    gcry_sexp_t ddd = gcry_sexp_find_token(ciph, "a", 1);
    if(ddd == NULL)
        {
        xerr_serv("dibaworker: failed to find token in encrypted data.");
        }

    unsigned int plen = 0, outx = 0;
    char *dptr = (char *)gcry_sexp_nth_data(ddd, 1, &plen);
    
    char *mem3 = base_and_lim(dptr, plen, &outx);
    #else
    unsigned int plen = 0, outx = 0;
    char *mem3 = randkey; 
    #endif
        
    char  *catm = zstrmcat(0, okstr, " ", mem3, NULL);
    
    if(debuglevel > 9)
        printlog("Enc Key: '%s'\n", catm);
    
    // Send session response, switch to session mode after
    ret = scom_send_data(1, catm, strlen(catm) + 1, 1);
    got_sess = 1;

    zfree(catm); zfree(mem3);
}

//////////////////////////////////////////////////////////////////////////
// Receive public key from peer
    
void keyfunc(char *buff, int len)

{
    int ret, ret3;

    if(debuglevel > 2)
        printlog("Got key cmd: '%.*s'\n", len, buff);

    if(got_key)
        {
        ret = print2sock(1, 1, "%s %s", errstr, "Key already sent");
        return;
        }
        
    #define MAX_KEYLEN 5000   // This len is enough for 4096 bit keys
    char *buff2 = zalloc(MAX_KEYLEN);
    if(!buff2)
        {
        printlog("Cannot alloc memory.\n");
        ret = print2sock(1, 1, "%s %s", errstr, "Cannot alloc memory.");
        return;
        }
    
    // Get key
    handshake_struct hs2r; memset(&hs2r, 0, sizeof(hs2r));
    hs2r.sock = 1;
    hs2r.sstr = keystr;      hs2r.slen = strlen(keystr);
    hs2r.buff = buff2;       hs2r.rlen = MAX_KEYLEN;
    hs2r.debug = debuglevel; hs2r.got_session = got_sess;
    ret = handshake(&hs2r);                    
    
    if(ret < 0)
        {
        printlog("Client did not respond.\n");   
        return;
        }
    
    if(debuglevel > 8)
        printlog("Got key body (len=%d): '%.*s'\n", ret3, 36, buff2);

    // Interpret key data, validate key
    pubkey_bits = check_pubkey(&pubkey, buff2, ret3);

    if(pubkey_bits < 0)
        {
        ret = print2sock(1, 1, "%s %s", errstr, "Bad Key");
        }
    else
        {
        got_key = 1;
        ret = print2sock(1, 1, "%s pubkey accepted, %d bits.",
                                    okstr, pubkey_bits);
        if(debuglevel > 8)
            {
            printlog("Approved key.\n");
            }
    
        if(debuglevel > 9)
            {
            if(logfp)
                sexp_fprint(pubkey, logfp);
            }
        }
    zfree(buff2);
}

//////////////////////////////////////////////////////////////////////////
// Check for the validity of the proposed transaction.

int     check_trans_valid(char *buff, int len, char **reason_str)

{
    int ret = 0;
    ret = rand() % 3 - 1;
    *reason_str = "something";
    
    if(debuglevel > 5) 
        printlog("ret %d\n", ret);
    return ret;
}
        
/* EOF */


