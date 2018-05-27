
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

//#include <winsock2.h>
//#include <netinet/in.h>
//#include <wininet.h>

#include <string.h>

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

static char descstr[] = "Listen for DIBA broadcasts ";
static char usestr[]  = "dibaworker [options]\n";

static char    *thispass = NULL;
static char    *keyname  = NULL;
static char    *keydesc  = NULL;
static char    *creator  = NULL;
static char    *errout   = NULL;

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
        "-m val      --keyname val    - key name",

        0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
    };
  
static FILE *logfp = NULL;
static gcry_sexp_t pubkey;
static int pubkey_bits = 0;

static int got_key = 0;
static int got_sess = 0;
static int loglevel = 3;
static  char    *randkey = NULL;
static  char    *testkey = "1234";

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

int xerr_serv(const char *str, ...)
{
    char mystr[128];

    fprintf(logfp, "Error exit in %d.\n", getpid());
    
    va_list ap; va_start(ap, str);
    int ret = vsnprintf(mystr, sizeof(mystr), str, ap);
    
    send_data(1, mystr, ret, 0);
    recv_data(0,  mystr, ret, 0);
    
    char  *ddd = zsnprintf("%s error exit.", errstr);
    send_data(1, ddd, strlen(ddd) + 1, 0);

    zautofree();
    zleakfp(logfp);
    exit(5);
}

static volatile int timeout = 0;

unsigned __stdcall Thread(void *ArgList) 

{
    HANDLE hEvent = *((HANDLE*)ArgList);
    
    while(1)
        {
        Sleep(1000);
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
        send_data(1, xptr, outx, 1);
        zfree(xptr);
        }
    else
        {  
        send_data(1, ddd, strlen(ddd), 1);
        }
    
    fprintf(logfp, "Timeout exit %d.\n", getpid());

    // Totally meaningless, but for correctness sake
    close(0); close(1);
    
    zautofree();
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

    if(loglevel > 4)
        fprintf(logfp, "Parsing '%.*s'\n", len, buff);

    while(1)
        {
        struct dibaparse currp = parsearr[idx];
        if(currp.cmd == NULL)
            break;

        if(loglevel > 9)
            fprintf(logfp, "scanning %s\n", currp.cmd);

        if(strncmp(buff, currp.cmd, currp.len) == 0)
            {
            //fprintf(logfp, "found cmd: '%s'\n", currp.cmd);
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
    printf(".");
    //printf("%c", printchar);
}

static void myfunc(int sig)
{
    fprintf(logfp, "\nSignal %d (segment violation)\n", sig);
    exit(111);
}

static void myfunc2(int sig)
{
    fprintf(logfp, "\nSignal %d (alarm)\n", sig);
}

// Forward declarations
static  int     check_pubkey(gcry_sexp_t *pubkey, const char *rsa_buf, int rsa_len);
static  int     check_trans_valid(char *buff, int len, char **reason_str);

// -----------------------------------------------------------------------

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);
    //signal(SIGALRM, myfunc2);

    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();

    initdibaparser();

    // Pre allocate all string items
    //char *mstr = "No Memory";
    zline2(__LINE__, __FILE__);
    thispass = zalloc(MAX_PATH); if(thispass == NULL) xerr_serv(mstr);
    keyname  = zalloc(MAX_PATH); if(keyname  == NULL) xerr_serv(mstr);
    keydesc  = zalloc(MAX_PATH); if(keydesc  == NULL) xerr_serv(mstr);
    creator  = zalloc(MAX_PATH); if(creator  == NULL) xerr_serv(mstr);
    errout   = zalloc(MAX_PATH); if(errout   == NULL) xerr_serv(mstr);

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
        printf("dibaworker version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
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
            printf("Executable sha hash: '%s'\n", hash_str);
            zfree(hash_str);
            }
        else
            {
            xerr_serv("dibaworker: %s\n", err_str);
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

    // ---------------------------------------------------------------
    // Begin worker

    int pid = getpid();
    logfp = fopen("dibaserv.log", "ab+");
    if(!logfp)
        {
        xerr_serv("Cannot open/create log file.\n");
        }

    // Create a manual-reset nonsignaled unnamed event
    HANDLE hThread, hEvent;
    unsigned int ThreadId;
   
    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    hThread = (HANDLE)_beginthreadex(NULL, 0, Thread, &hEvent, 0, &ThreadId);
    if (hThread == 0) 
        {
        fprintf(logfp, "Could not create thread %d.\n", errno);
        }
    
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
        {
        xerr_serv("Socket start failed. Error Code : %d\n", WSAGetLastError());
        }

    zline2( __LINE__, __FILE__);
    if(loglevel > 0)
        {
        char *ttime     = zdatestr();
        fprintf(logfp, "Diba Worker [%d] %s from %s on port %s\n",
                                    pid, ttime, argv[2], argv[3]);
        zfree(ttime);
        }

   if(loglevel > 5)
        {
        fprintf(logfp, "Diba Worker arguments: ", argv[1], pid);
        for(int loop = 1; loop < argc; loop ++)
            {
            fprintf(logfp, "'%s' ", argv[loop]);
            }
        fprintf(logfp, "\n");
        }
    int hhh = atoi(argv[1]);
    int ret = send_data(1, hellostr, strlen(hellostr), 1);
    while(1)
        {
        int ret2 = recv_data(0, recbuff, sizeof(recbuff), 1);

        if(ret2 < 0)
            break;

        if(ret2 == 0)
            {
            if(loglevel > 2)
                fprintf(logfp, "Got empty buffer\n");

            break;
            }
        int ret = parse_cmd(recbuff, ret2);
        if(ret < 0)
            {
            if(loglevel > 2)
                fprintf(logfp, "Got unknown cmd: '%.*s'\n", ret2, recbuff);
            //ret = write(1, buff, ret2);
            ret = print2sock(1, 1, "%s %s", errstr, nocmd, 1);
            }
        }

    zfree(thispass);    zfree(keyname);
    zfree(keydesc);     zfree(creator);
    zfree(errout);      zfree(dummy);

    if(randkey)
        zfree(randkey);

    if(loglevel > 0)
        {
        char *ttime2     = zdatestr();
        fprintf(logfp, "Diba Worker [%d] exited at %s\n\n",
                                    pid, ttime2);
        zfree(ttime2);
        }

    // Redirect to log
    zleakfp(logfp);

    fclose(logfp);

    return 0;
}

int check_pubkey(gcry_sexp_t *pubkey, const char *rsa_buf, int rsa_len)

{
    int ret = 0, outlen = rsa_len;
    char *dec_err_str;
    char *mem = decode_pub_key((char *)rsa_buf, &outlen, &dec_err_str);
    if(mem == NULL)
        {
        //printf("%s\n", dec_err_str);
        if(loglevel > 0)
            fprintf(logfp, "Cannot decode public key. %s\n", dec_err_str);
        return -1;
        }
    int err = gcry_sexp_new(pubkey, mem, outlen, 1);
    zfree(mem);
    if (err) {
        if(loglevel > 0)
            fprintf(logfp, "Failed to create create public key sexp. %s\n",
                                                      gcry_strerror (err));
        return -1;
        }
    if(loglevel > 2)
        fprintf(logfp, "Created public key.\n");

    ret = gcry_pk_get_nbits(*pubkey);

    return(ret);
}

void closefunc(char *buff, int len)

{
    int ret;

    if(loglevel > 2)
        fprintf(logfp, "Got close cmd: '%.*s'\n", len, buff);

    int slen = strlen(endstr) + 1;
    // If session, encrypt
    if(got_sess)
        {
        int outx;
        char *xptr = bp3_encrypt_cp(endstr, slen, randkey, strlen(randkey), &outx);
        ret = send_data(1, xptr, outx, 1);
        zfree(xptr);
        }
    else
        {
        ret = send_data(1, endstr, strlen(endstr) + 1, 1);
        }
}

void    echofunc(char *buff, int len)
{
    int ret;

    if(loglevel > 2)
        fprintf(logfp, "Got echo cmd: '%.*s'\n", len, buff);

    if(got_sess)
        {
        int outx;
        char *xptr = bp3_encrypt_cp(buff, len, randkey, strlen(randkey), &outx);
        if(!xptr) xerr_serv("Err Cannot alloc mem\n");
        ret = send_data(1, xptr, outx, 1);
        zfree(xptr);
        }
   else
        {
        char *sum = zstrmcat(0, okstr, " ", buff + 5, NULL), 
        ret = send_data(1, sum, strlen(sum), 1);
        zfree(sum);
        }
}

void    checkfunc(char *buff, int len)
{
    int ret;
    if(loglevel > 2)
        fprintf(logfp, "Got check cmd: '%.*s'\n", len, buff);

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
        fprintf(logfp, "Sumstr: '%.*s'\n", xlen, sumstr);
        int outx;
        char *xptr = bp3_encrypt_cp(sumstr, xlen,
                                            randkey, strlen(randkey), &outx);
        ret = send_data(1, xptr, outx, 1);
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
    if(loglevel > 2)
        fprintf(logfp, "Got sess cmd: '%.*s'\n", len, buff);

    if(!got_key)
        {
        ret = print2sock(1, 1, "%s Send valid key first.", errstr);
        return;
        }
    randkey = zrandstr_strong(RANDKEY_LENGTH);

    if(strlen(randkey) * 8 >  pubkey_bits)
        {
        fprintf(logfp,
            "Rand key legth (%d) bigger than public key length. (%d)\n",
                strlen(randkey) * 8, pubkey_bits);
        ret = print2sock(1, 1, "%s %s", errstr, "Public key too small.");
        }

    if(loglevel > 1)
        fprintf(logfp, "Sending rand key: '%s'\n", randkey);

    /* Encrypt the message. */
    gcry_sexp_t ciph, enc_data;
    gcry_mpi_t msg; int scanned;
    int err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, randkey,
                        strlen(randkey) + 1, &scanned);
    if (err) {
        xerr_serv("dibaworker: Failed to create a mpi from the message.");
        }
    //printf("mpi scanned %d\n", scanned);
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
    //dump_memfp(dptr, plen, logfp);
    char *mem3 = base_and_lim(dptr, plen, &outx);
    char  *catm = zstrmcat(0, okstr, " ", mem3, NULL);
    //dump_memfp(catm, strlen(catm) + 1, logfp);
    ret = send_data(1, catm, strlen(catm) + 1, 1);
    got_sess = 1;

    zfree(catm); zfree(mem3);
}


// Receive public key from peer

void keyfunc(char *buff, int len)

{
    char buff2[4096];
    int ret, ret3;

    if(loglevel > 2)
        fprintf(logfp, "Got key cmd: '%.*s'\n", len, buff);

    if(got_key)
        {
        ret = print2sock(1, 1, "%s %s", errstr, "Key already sent");
        return;
        }

    send_data(1, keystr, strlen(keystr), 1);
    ret3 = recv_data(0, buff2, sizeof(buff2), 1);
    if(ret3 <= 0)
        return;

    if(loglevel > 8)
        fprintf(logfp, "Got key body: '%.*s'\n", ret3, buff);

    // Interpret key data, validate key
    pubkey_bits = check_pubkey(&pubkey, buff2, ret3);

    if(pubkey_bits < 0)
        ret = print2sock(1, 1, "%s %s", errstr, "Bad Key");
    else
        {
        got_key = 1;
        ret = print2sock(1, 1, "%s pubkey accepted, %d bits.",
                                    okstr, pubkey_bits);
        //ret = send_data(1, okstr, strlen(okstr), 1);
        if(loglevel > 9)
            sexp_fprint(pubkey, logfp);
        }
}

//////////////////////////////////////////////////////////////////////////
// Check for the validity of the proposed transaction.

int     check_trans_valid(char *buff, int len, char **reason_str)

{
    int ret = 0;
    ret = rand() % 3 - 1;
    *reason_str = "something";
    
    fprintf(logfp, "ret %d\n", ret);
    return ret;
}
        
/* EOF */


