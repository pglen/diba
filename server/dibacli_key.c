
/* =====[ dibacli_key.c ]=========================================================

   Description:     Client to query DIBA server. Estabilish a key exchange.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  nov.21.2017     Peter Glen      Initial
      0.00  jan.14.2018     Peter Glen      Timeout, base64, str ...
      
   ======================================================================= */

#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
#include "dibautils.h"
#include "dibafile.h"
#include "dibascom.h"
#include "bluepoint3.h"

// Include a basic pair of public and private key.
// Used in development, can be used as testing and fallback.

#include "def_keys.c"

// -----------------------------------------------------------------------

static int weak = FALSE;
static int force = FALSE;    
static int verbose = 0;
static int test = 0;
static int debuglevel = 0;
static int calcsum = 0;
static int version = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

static char descstr[] = "Estabilish DIBA key exchange ";
static char usestr[]  = "dibacli_key [options]\n";
                
static char    *thispass = NULL;
static char    *ihost = NULL;
static char    *keyname  = NULL;
static char    *keyfile = NULL;
static char    *query = NULL;
static char    *errout   = NULL;

//static  char    *testkey = "1234";
//static char    *randkey  = NULL;

static int      got_sess = 0;

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {

        'k',  "keyfile",  NULL, &keyfile,  0, 0, NULL, 
        "-k fname       --keyfile fnm - Key file name",

        'q',  "query",  NULL, &query,  0, 0, NULL, 
        "-q fname       --query fname - Query file name",

        'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
        "-v             --verbose     - Verbosity on",
        
        'V',   "version",  NULL, NULL,  0, 0, &version, 
        "-V             --version     - Print version numbers and exit",
        
        't',   "test",  NULL,  NULL, 0, 0, &test, 
        "-t             --test        - Run self test before proceeding",
        
        'd',   "debug",  &debuglevel, NULL, 0, 10, NULL, 
        "-d level       --debug level - Output debug data (level 1-9)",
        
        's',   "sum",  NULL,  NULL, 0, 0, &calcsum, 
        "-s             --sum         - Print sha sum before proceeding",
        
        'p',   "pass",   NULL,   &thispass, 0, 0,    NULL, 
        "-p val         --pass val    - Pass in for key (@file from file)",
        
        'i',   "ihost",   NULL,   &ihost, 0, 0,    NULL, 
        "-i name        --ihost name  - Internet host name / IP address",
        
        'e',   "errout",  NULL,  &errout, 0, 0, NULL, 
        "-e fname       --errout fnm  - Dup stderr to file. (for GUI)",
       
        0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
        };

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(5);
}


// Static local functions

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
    vfprintf(stderr, str, ap2);
    zautofree();
    exit(4);
}

static char buffer[4096];
    
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
    ihost   = zalloc(MAX_PATH);  if(ihost == NULL) xerr3(mstr);
    keyname  = zalloc(MAX_PATH); if(keyname  == NULL) xerr3(mstr);
    errout   = zalloc(MAX_PATH); if(errout   == NULL) xerr3(mstr);
    keyfile  = zalloc(MAX_PATH); if(keyfile  == NULL) xerr3(mstr);
    query    = zalloc(MAX_PATH); if(query  == NULL)   xerr3(mstr);
    
    char *err_str = NULL;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    
    //printf("Processed %d comline entries\n", nn);
    
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data); 
        zautofree();
        exit(4);
        }
    if(errout[0] != '\0')
        {
        //printf("removing %s\n", errout);
        unlink(errout);
        }
    if(version)
        {
        printf("dibacli_key version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
        zautofree();
        exit(4);
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
            xerr3("dibacli_key: %s\n", err_str);
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
            zautofree();
            exit(3);
            }
        else
            {
            printf("pass.\n");
            }
        }
   
    //////////////////////////////////////////////////////////////////////
    scom_set_debuglevel(debuglevel);
    
    if(ihost[0] == '\0')
        {
        xerr3("Please specify host name.");
        }
    
    char *err_str2;
    get_priv_key_struct pks; memset(&pks, 0, sizeof(pks));
    gcry_sexp_t info, privk, composite, pubkey;
    
    if(keyfile[0] != '\0')
        {
        pks.rsa_buf = grabfile(keyfile, &pks.rsa_len, &err_str);
        if(!pks.rsa_buf)
            xerr3("dibacli_key: Cannot load keyfile. %s", err_str);
        }
    else
        {
        pks.rsa_buf   = mypkey;
        pks.rsa_len   = sizeof(mypkey);
        }
        
    pks.err_str   = &err_str;
    pks.err_str2  = &err_str2;
    pks.nocrypt   = 0;
    pks.privkey   = &privk;
    pks.composite = &composite;
    pks.pubkey    = &pubkey;
    pks.info      = &info;
    pks.debug     = debuglevel;
    pks.thispass  = thispass;
    
    int keylen = get_privkey(&pks);
    if(keylen < 0)
        {
        xerr3("dibacli_key: %s. (%s)", err_str, err_str2);
        }
    
    if(keyfile[0] != '\0')
        zfree(pks.rsa_buf);
    
    if(debuglevel > 9)
        {
        printf("pubkey: %s\n", "");
        sexp_print(*pks.pubkey);
        }
    if(debuglevel > 9)
        {
        printf("privkey: '%s'\n", ""); 
        sexp_print(*pks.privkey);
        }
    
    int clsock, xcode;
    struct sockaddr_in serverAddr;
    socklen_t addr_size;
    
    char ipp[24];
    int  reth = hostname_to_ip(ihost, ipp, sizeof(ipp)-1);
    if(reth < 0)
        {
        xerr3("Cannot resolv host '%s'.\n", ihost);
        }
        
   if(debuglevel > 5)
        {
        printf("Connecting to host: '%s'\n", ipp);   
        }     
    /*---- Create the socket. The three arguments are: ----*/
    clsock = socket(PF_INET, SOCK_STREAM, 0);
    
    /* Address family = Internet */
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(6789);
    serverAddr.sin_addr.s_addr = inet_addr(ipp);
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  
    
    /*---- Connect ----*/
    addr_size = sizeof serverAddr;
    int err = connect(clsock, (struct sockaddr *) &serverAddr, addr_size);
    if(err)
        xerr3("Error on connecting. %d (errno %d %s)\n", 
                            err, errno, strerror(errno));
    
    /*---- Read the initial message ----*/
    scom_recv_data(clsock, buffer, sizeof(buffer), 0);
    
    if(verbose || debuglevel > 0)
        printf("Initial data received: '%s'\n", buffer);   
    
    int ret;
    
    handshake_struct hs; memset(&hs, 0, sizeof(hs));
    hs.sock = clsock;
    hs.sstr = keycmd;   hs.slen = strlen(keycmd);
    hs.buff = buffer;   hs.rlen = sizeof(buffer);
    hs.debug = debuglevel;   hs.got_session = got_sess;
    ret = handshake(&hs);
    
    if(strncmp(buffer, okstr, STRSIZE(okstr)) != 0)
        {
        printf("Server does not accept the key command.\n");
        printf("Response: '%s'\n", buffer);
        
        
        zautofree();
        exit(4);
        }
        
    handshake_struct hs2; 
    
    memset(&hs2, 0, sizeof(hs2));
    hs2.sock = clsock;
    hs2.sstr = mykey; hs2.slen = strlen(mykey);
    hs2.buff = buffer;   hs2.rlen = sizeof(buffer);
    hs2.debug = debuglevel;   hs2.got_session = got_sess;
    ret = handshake(&hs2);
    
    if(strncmp(buffer, okstr, STRSIZE(okstr)) != 0)
        {
        printf("Server rejected key.\n");
        if(verbose)
            printf("Response: '%s'\n", buffer);
        
        close_conn(clsock, got_sess, "");
        close(clsock);
        zautofree();
        exit(4);
        }
        
    if(ret >= 0)
        {
        printf("Server accepted key.\n", buffer);   
        if(verbose)
            printf("Response: '%s'\n", buffer);
        }

    // Test echo
    int rlen = rand() % 32 + 24;
    char *randstr = zrandstr_strong(rlen); 
    char *sumstr = zstrmcat(0, "echo ", randstr, NULL); 
    zfree(randstr); 
    
    //handshake_struct hs2; memset(&hs2, 0, sizeof(hs2));
    hs2.sock = clsock;
    hs2.sstr = sumstr;      hs2.slen = strlen(sumstr);
    hs2.buff = buffer;      hs2.rlen = sizeof(buffer);
    hs2.debug = debuglevel; hs2.got_session = got_sess;

    ret = handshake(&hs2);                    
    zfree(sumstr);  
    
    if(ret > 0)
        {
        printf("Server responded to echo.\n");   
        }
    
    close_conn(clsock, got_sess, "");

    // Close connection
    close(clsock);
    
    if(verbose)
        printf("Closed connection.\n");
               
    zfree(thispass);    zfree(keyname);      
    zfree(errout);      zfree(keyfile);
    zfree(query);       zfree(ihost);
    //zfree(querystr);
    
    //if(randkey)
    //    zfree(randkey);
        
    zfree(dummy);
    
    zleak();
    return xcode;
}

/* EOF */



















