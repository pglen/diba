
/* =====[ dibaclient.c ]=========================================================

   Description:     Client to query DIBA server.

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

#ifdef LINUX
//#include <sys/socket.h>
#endif

#include <winsock2.h>
#include <wininet.h>

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

char mykey[] = "\
-----BEGIN DIGIBANK RSA PUBLIC KEY-----\n\
KDEzOmRpYmFjcnlwdC1rZXkoMTc6S2V5IENyZWF0aW9uIERhdGUxOToyMDE3LzEy\n\
LzIxIDAxOjA5OjI2KSgxMTpLZXkgVmVyc2lvbjU6MC4wLjQpKDg6S2V5IE5hbWUx\n\
MTp1bm5hbWVkIGtleSkoODpLZXkgVHlwZTM6UlNBKSgxNTpLZXkgRGVzY3JpcHRp\n\
b24xNDpubyBkZXNjcmlwdGlvbikoNjpLZXkgSUQzMjpONEV5M1R2bldxbE1JcTlG\n\
eUlrSkovZ2k1clpQbWl6TCkoMTE6S2V5IENyZWF0b3I5OnBldGVyZ2xlbikoMTI6\n\
S2V5IEhvc3RuYW1lMzpIUDIpKDE1OlB1YmxpYyBGaWxlbmFtZTY6YmIucHViKSgx\n\
MTpQdWJsaWMgSGFzaDQ0OkNtSThwUUM1Rnczb0o1TDNWWlFIWHJFV0JXcklBR0lL\n\
bDdEWFVSa3RPYlE9KSgxNjpQcml2YXRlIEZpbGVuYW1lNjpiYi5rZXkpKDEyOlBy\n\
aXZhdGUgSGFzaDQ0OnBzY1FyUUpWalZCY1F6akpBdm5zRXFDU2hoZy9ncnhCcmxa\n\
dGxZUlpVR1U9KSkoMTA6cHVibGljLWtleSgzOnJzYSgxOm4yNTc6AMgFTcDA/WGw\n\
TVdBuSHOyTIva2gOJcbWXuU/siYOHu594eIgn+O4fyhkp2VQM1rT5LSFjWLb4KTT\n\
A5apU5ibXF0BOzEYgN2swOfTJ2Iw3iu/aftEfKEhLaUIi8gOgZJHJNuXxUOg0+I2\n\
2f69s0DnTXXcbeuZXPZxI0wirrP5CafuSjPSH+fmrmJM08biJQ0TRmFiOOc7f95H\n\
jcnh9kPkJy7ucS4Nl7FsXqFJ+ZZn74FDy8NzwBHuoklvdL3yM+cyJddoREe6eTco\n\
XzR7zVYAbvpqZ/VU3Mc/6aoNS+irnUK2iSIK2hZSIvX73JKZLWLtlT5DctEqRBNi\n\
qSNmRoBVRvspKDE6ZTM6AQABKSkpKDE0OmRpYmFjcnlwdC1oYXNoKDE4Okhhc2gg\n\
Q3JlYXRpb24gRGF0ZTE5OjIwMTcvMTIvMjEgMDE6MDk6MjYpKDEyOkhhc2ggVmVy\n\
c2lvbjU6MC4wLjQpKDY6S2V5IElEMzI6TjRFeTNUdm5XcWxNSXE5RnlJa0pKL2dp\n\
NXJaUG1pekwpKDE1OlB1YmxpYyBGaWxlbmFtZTY6YmIucHViKSgxMTpQdWJsaWMg\n\
SGFzaDQ0OkNtSThwUUM1Rnczb0o1TDNWWlFIWHJFV0JXcklBR0lLbDdEWFVSa3RP\n\
YlE9KSgxNjpQcml2YXRlIEZpbGVuYW1lNjpiYi5rZXkpKDEyOlByaXZhdGUgSGFz\n\
aDQ0OnBzY1FyUUpWalZCY1F6akpBdm5zRXFDU2hoZy9ncnhCcmxadGxZUlpVR1U9\n\
KSg5OkluZm8gSGFzaDQ0Ok5qd2dtZDJiVVdxaHZha0VSNER0ZHhQa21QT3hOSXhQ\n\
YmhocW5icDNqeEk9KSkA\n\
-----END DIGIBANK RSA PUBLIC KEY-----\n\
";

char mypkey[] = "\
-----BEGIN DIGIBANK RSA COMPOSITE KEY-----\n\
KDEzOmRpYmFjcnlwdC1rZXkoMTc6S2V5IENyZWF0aW9uIERhdGUxOToyMDE3LzEy\n\
LzIxIDAxOjA5OjI2KSgxMTpLZXkgVmVyc2lvbjU6MC4wLjQpKDg6S2V5IE5hbWUx\n\
MTp1bm5hbWVkIGtleSkoODpLZXkgVHlwZTM6UlNBKSgxNTpLZXkgRGVzY3JpcHRp\n\
b24xNDpubyBkZXNjcmlwdGlvbikoNjpLZXkgSUQzMjpONEV5M1R2bldxbE1JcTlG\n\
eUlrSkovZ2k1clpQbWl6TCkoMTE6S2V5IENyZWF0b3I5OnBldGVyZ2xlbikoMTI6\n\
S2V5IEhvc3RuYW1lMzpIUDIpKDE1OlB1YmxpYyBGaWxlbmFtZTY6YmIucHViKSgx\n\
MTpQdWJsaWMgSGFzaDQ0OkNtSThwUUM1Rnczb0o1TDNWWlFIWHJFV0JXcklBR0lL\n\
bDdEWFVSa3RPYlE9KSgxNjpQcml2YXRlIEZpbGVuYW1lNjpiYi5rZXkpKDEyOlBy\n\
aXZhdGUgSGFzaDQ0OnBzY1FyUUpWalZCY1F6akpBdm5zRXFDU2hoZy9ncnhCcmxa\n\
dGxZUlpVR1U9KSkoMTU6cHJpdmF0ZS1jcnlwdGVkMTI4NzrGvXOqqnAaa7uCQaF8\n\
lHiBL6lux9it2iMnzxdonXwQd/xfUBHk6dJMdgJfyftX7Z1s/ff+/CxkvsKAdVdJ\n\
YmFny2CO5lraaNZjnB/9T/qmA9njCxxBzcpTRXUufggOEXzKnUtyHVvO89dhndaB\n\
5iBmyWC9PU46doK1j7FSDp3Wt8QXzF8RwMP7YSM7+6zNmLoOOU1BOOmQfaq/449S\n\
Sp5NyJguD2wCS4mw9oJQ8Q5cnSUZZgH7u9Mma/U8ew4sK9JXRq/FFGIVp+OH+0Jm\n\
hZjm7nx+G3llV0f/+It9XTVyPdVdUl6Zv0ziRZQ+gwr7SSRh6rYT7wLGYElpp1Nk\n\
1nk2o5/aisrg8dWUStG96N2356x5SxTbs4N6cSX26YtnGP2CWKnE9Yfq6v6Zsc2F\n\
no64IT3TD9SDwk4MD1qELJUwnSP1H7lH9xybza9r2ig2lRqwMh2iIOkUoZzktJoj\n\
V43OmK9AQWMu5FiF3MZ+z8Q4LlY/fbh5W46p2eejpfNcgrGSrEhJJ9tgzr7w367Y\n\
tUnU0qtgG1nGqRrhSjTbVL8mMS2h1LXEELPqkLiPWynbDXLNUYp8WlVQWWkuhT5K\n\
5KmQArp4Jo0MBKGd+K1ceWKn+DDgz4mVwB6u0b1LKjqGpl1+ZWmVHW+J/J9N0vNI\n\
Fhh4Ewr5xUOFGMhyeonEdzl6n6ZRzgwe6bltupur4vAm7n4fvkgGmwtUwxeCgXcI\n\
ug9vb+n6Bbc2aLx+q5gWf7CAec1CrUll0kZP9B/E1DUc3qEdplcOuU5qMsrBdBog\n\
yjzi2hmpvnwzPncaARuyOi0DiZbi03AtaqOJRQRWO8nVZvPmB5LnDr/QNRtzAp8W\n\
ePC6pCVJ1XjXZVkk6UrnCoaiQrfjxULMCk8OIboohTKjmSnUE/T+MK1T19NT7oJ7\n\
d9xcB7qlTK5uqq1DZ1wo5fm9dyWWzMkkgs8S2U3EgQfInQjZcRzxNk60IQvGq7Km\n\
tKiR5cFhJ5Ud0G8KbDusGl/oNFexUagBTi4EygXqcq8cfMftqhbxha2P0lqTXELT\n\
WnYbbKuu7AsCDC+i7tNBFn00XeuF9eGFi8VxvHl5zLDS36/YIklkJIlkimZRFnNl\n\
7wE6OYz+nNMnNrq9UNmCfhWGxBO6pfmFdiTssUIRCpQH7tnEe45w49PhbmC0w7Tu\n\
n8lhIsBKhtrTRRG+4uUs3Vmq9GAgUkd8yTFoNNF/V3ymjQTW0PgYtMt5CN+CXeI0\n\
ZSrRgMrCMBB/A+HEjePpCpI+alch6mUUMS6J8hUY9NOhhRp/Fwn15s0fRhUSusFM\n\
jrx/mZwLwtTDzs++NHllI4ayFih1FHiEkDyPxXBJmBVo6r4zz68RnPrOFfprkcub\n\
NSQKDQY8qeS2U5E7x2ofw1vjO5lXMOuJbJWtg1xNT/86r5i3vPaW7eSqQz7GwcdL\n\
PS58VOQNuSaQYXTBXGOvUj7+iOHtrtR2gc64s6EM/Yja68/mqL8JlWpsTAYXsbc/\n\
fJWiSva6uIOgubRy3CRVqX+VR/6k65L0Z3pj0cbSSNV6bVXw6fKuqxzXQL7A9YdO\n\
SidNNv/95l25yjQ8TM2y2bOmqonWr/P8Bv3DKKLUkvSK56puo8474deAC6oeyknC\n\
UHokH+pI+Q+C9GAmsuFWJnLrUP6cLWignZn0EGSf+qKfGsTa9sgwrJyKycyyoO1S\n\
wBCDiFtG9O81pFy4hlDfhPY08wJOM4Wi9TUpKDE0OmRpYmFjcnlwdC1oYXNoKDE4\n\
Okhhc2ggQ3JlYXRpb24gRGF0ZTE5OjIwMTcvMTIvMjEgMDE6MDk6MjYpKDEyOkhh\n\
c2ggVmVyc2lvbjU6MC4wLjQpKDY6S2V5IElEMzI6TjRFeTNUdm5XcWxNSXE5RnlJ\n\
a0pKL2dpNXJaUG1pekwpKDE1OlB1YmxpYyBGaWxlbmFtZTY6YmIucHViKSgxMTpQ\n\
dWJsaWMgSGFzaDQ0OkNtSThwUUM1Rnczb0o1TDNWWlFIWHJFV0JXcklBR0lLbDdE\n\
WFVSa3RPYlE9KSgxNjpQcml2YXRlIEZpbGVuYW1lNjpiYi5rZXkpKDEyOlByaXZh\n\
dGUgSGFzaDQ0OnBzY1FyUUpWalZCY1F6akpBdm5zRXFDU2hoZy9ncnhCcmxadGxZ\n\
UlpVR1U9KSg5OkluZm8gSGFzaDQ0Ok5qd2dtZDJiVVdxaHZha0VSNER0ZHhQa21Q\n\
T3hOSXhQYmhocW5icDNqeEk9KSk=\n\
-----END DIGIBANK RSA COMPOSITE KEY-----\n\
";

// -----------------------------------------------------------------------

static int weak = FALSE;
static int force = FALSE;    
static int verbose = 0;
static int test = 0;
static int debug = 0;
static int calcsum = 0;
static int version = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

static char descstr[] = "Connect to DIBA peers ";
static char usestr[]  = "dibaclient [options]\n";
                
static char    *thispass = NULL;
static char    *keyname  = NULL;
static char    *keyfile = NULL;
static char    *query = NULL;
static char    *errout   = NULL;

static  char    *testkey = "1234";
static char    *randkey  = NULL;
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
        
        'd',   "debug",  &debug, NULL, 0, 10, &test, 
        "-d level       --debug level  - Output debug data (level 1-9)",
        
        's',   "sum",  NULL,  NULL, 0, 0, &calcsum, 
        "-s             --sum         - Print sha sum before proceeding",
        
        'p',   "pass",   NULL,   &thispass, 0, 0,    NULL, 
        "-p val         --pass val    - Pass in for key (@file reads pass from file)",
        
        'e',   "errout",  NULL,  &errout, 0, 0, NULL, 
        "-e fname       --errout fnm  - Dup stderr to file. (for GUI deployment)",
       
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
        printf("dibaclient version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
        zautofree();
        exit(4);
        }
        
    if(query[0] == '\0')
        {
        xerr3("dibaclient: missing query file. Use -? option to see help\n");
        } 
    int qlen;
    
    char *querystr = grabfile(query, &qlen, &err_str);
    if(!querystr)
        {
        //printf("dibaclient: error on loading query file '%s'. (%s)\n", 
        //                    query, err_str);
        xerr3("dibaclient: error on loading query file %s. (%s)\n", 
                            query, err_str);
        }
        
    //printf("query %.*s\n", 64, querystr);
             
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
            xerr3("dibaclient: %s\n", err_str);
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
    
    char *err_str2;
    get_priv_key_struct pks;
    gcry_sexp_t info, privk;
    
    if(keyfile[0] != '\0')
        {
        pks.rsa_buf = grabfile(keyfile, &pks.rsa_len, &err_str);
        if(!pks.rsa_buf)
            xerr3("dibaclient: Cannot load keyfile. %s", err_str);
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
    pks.info      = &info;
    pks.thispass  = thispass;
    
    int keylen = get_privkey(&pks);
    if(keylen < 0)
        {
        xerr3("dibaclient: %s. (%s)", err_str, err_str2);
        }
    
    if(keyfile[0] != '\0')
        zfree(pks.rsa_buf);
    
    //if (argc - nn != 2) {
    //    printf("dibaclient: Missing argument");
    //    usage(usestr, descstr, opts_data); exit(2);
    //    }
    
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
    {
        xerr3("Socket start failed. Error Code : %d", WSAGetLastError());
    }
    
    int clsock, xcode;
    struct sockaddr_in serverAddr;
    socklen_t addr_size;
    
    /*---- Create the socket. The three arguments are: ----*/
    clsock = socket(PF_INET, SOCK_STREAM, 0);
    
    /* Address family = Internet */
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(6789);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  
    
    /*---- Connect ----*/
    addr_size = sizeof serverAddr;
    int err = connect(clsock, (struct sockaddr *) &serverAddr, addr_size);
    if(err)
        xerr3("Error on connecting. %d (errno %d %s)\n", 
                            err, errno, strerror(errno));
    
    /*---- Read the initial message ----*/
    recv_data(clsock, buffer, sizeof(buffer), 0);
    
    if(verbose)
        printf("Initial data received: '%s'\n", buffer);   
    
    int ret;
    
    handshake_struct hs; memset(&hs, 0, sizeof(hs));
    hs.sock = clsock;
    hs.sstr = keycmd;   hs.slen = strlen(keycmd);
    hs.buff = buffer;   hs.rlen = sizeof(buffer);
    hs.debug = debug;   hs.got_session = got_sess;
    ret = handshake(&hs);
    
    if(strncmp(buffer, okstr, STRSIZE(okstr)) != 0)
        {
        printf("Server did does not accept key command.\n");
        
        handshake_struct hs2; memset(&hs2, 0, sizeof(hs2));
        hs2.sock = clsock;
        hs2.sstr = closecmd; hs2.slen = strlen(closecmd);
        hs2.buff = buffer;   hs2.rlen = sizeof(buffer);
        hs2.debug = debug;   hs2.got_session = got_sess;
        ret = handshake(&hs2);                    
        
        zautofree();
        exit(4);
        }
    //handshake_struct hs; 
    memset(&hs, 0, sizeof(hs));
    hs.sock = clsock;
    hs.sstr = mykey; hs.slen = strlen(mykey);
    hs.buff = buffer;   hs.rlen = sizeof(buffer);
    hs.debug = debug;   hs.got_session = got_sess;
    ret = handshake(&hs);
    
    if(strncmp(buffer, okstr, STRSIZE(okstr)) != 0)
        {
        printf("Server rejected key.\n");
        handshake_struct hs; memset(&hs, 0, sizeof(hs));
        hs.sock = clsock;
        hs.sstr = closecmd; hs.slen = strlen(closecmd);
        hs.buff = buffer;   hs.rlen = sizeof(buffer);
        hs.debug = debug;   hs.got_session = got_sess;
        ret = handshake(&hs);
        
        zautofree();
        exit(4);
        }
        
    int rlen = rand() % 32 + 24;
    char *randstr = zrandstr_strong(rlen); 
    char *sumstr = zstrmcat(0, "echo ", randstr, NULL); 
    zfree(randstr);  zfree(sumstr);  
    
    //handshake_struct hs; 
    memset(&hs, 0, sizeof(hs));
    hs.sock = clsock;
    hs.sstr = closecmd;
    hs.slen = strlen(closecmd);
    hs.buff = buffer; 
    hs.rlen = sizeof(buffer);
    hs.debug = debug;
    hs.got_session = got_sess;
    
    ret = handshake(&hs);
    
    // Close connection
    close(clsock);
    
    zfree(thispass);    zfree(keyname);      
    zfree(errout);      zfree(keyfile);
    zfree(query);       zfree(querystr);
    
    if(randkey)
        zfree(randkey);
        
    zfree(dummy);
    
    zleak();
    return xcode;
}

/* EOF */







