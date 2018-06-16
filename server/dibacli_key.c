
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

char mykey[] = "\
-----BEGIN DIGIBANK RSA PUBLIC KEY-----\n\
KDEzOmRpYmFjcnlwdC1rZXkoMTc6S2V5IENyZWF0aW9uIERhdGUxOToyMDE4LzA1\n\
LzIzIDExOjMwOjI4KSgxMTpLZXkgVmVyc2lvbjU6MC4wLjQpKDg6S2V5IE5hbWUx\n\
MTp1bm5hbWVkIGtleSkoODpLZXkgVHlwZTM6UlNBKSgxNTpLZXkgRGVzY3JpcHRp\n\
b24yOjEwKSg2OktleSBJRDMyOmw0OG5kUlQxUFcwcTZuUUxEQlluenMxUGdsVE01\n\
UkE1KSgxMTpLZXkgQ3JlYXRvcjEyOnVua25vd24gbmFtZSkoMTI6S2V5IEhvc3Ru\n\
YW1lMTI6dW5rbm93biBob3N0KSgxNTpQdWJsaWMgRmlsZW5hbWU2OmJiLnB1Yiko\n\
MTE6UHVibGljIEhhc2g0NDpkOENwWWxoWEFVSEdxblkvcVp4U2czK2tOcGFhTlI0\n\
MjkvSHhpd1czbE5zPSkoMTY6UHJpdmF0ZSBGaWxlbmFtZTY6YmIua2V5KSgxMjpQ\n\
cml2YXRlIEhhc2g0NDpuNVlqRUdKNzVqTGUyZkN3NEFhZndVaTZjenovZnp6ODVa\n\
ZFU3VEJZelcwPSkpKDEwOnB1YmxpYy1rZXkoMzpyc2EoMTpuMjU3OgDQNgU1UOVz\n\
zrSVFrgJHBpRQs8vwU0OYgaTMtLN3J4Mx+XANYpwUXi45KBIzcAZPYpPCsPF0iF4\n\
ZfjrwlNgcDYpEUivtcaGIQqu5R40S4N9k3Lp3NhaapWB4nlncQ3w3jHZY3tl05+Y\n\
KPjIXnOHciZ7/Z9PcYuG6EmnVEcvqhNtc+Uoa2R7Jsgx1rhTJYmNoyqzcqPp2b3v\n\
9uqlKYc7yqWYcuu3h0MmNbSk8Td4BeXRDG2AqeTgCvDWKyGXVyvfOkSdhmyWroVJ\n\
zWImDaHY24B8aMagb/qyhlh32TaMUgyHhhbjZ5A3TDOr3ARBvqKLr33RCET+/8bI\n\
4OjXjYgQAw7pKSgxOmUzOgEAASkpKSgxNDpkaWJhY3J5cHQtaGFzaCgxODpIYXNo\n\
IENyZWF0aW9uIERhdGUxOToyMDE4LzA1LzIzIDExOjMwOjI4KSgxMjpIYXNoIFZl\n\
cnNpb241OjAuMC40KSg2OktleSBJRDMyOmw0OG5kUlQxUFcwcTZuUUxEQlluenMx\n\
UGdsVE01UkE1KSgxNTpQdWJsaWMgRmlsZW5hbWU2OmJiLnB1YikoMTE6UHVibGlj\n\
IEhhc2g0NDpkOENwWWxoWEFVSEdxblkvcVp4U2czK2tOcGFhTlI0MjkvSHhpd1cz\n\
bE5zPSkoMTY6UHJpdmF0ZSBGaWxlbmFtZTY6YmIua2V5KSgxMjpQcml2YXRlIEhh\n\
c2g0NDpuNVlqRUdKNzVqTGUyZkN3NEFhZndVaTZjenovZnp6ODVaZFU3VEJZelcw\n\
PSkoOTpJbmZvIEhhc2g0NDp1SFpRMTdvQ3gzeUZsZW1SUkdzakFTTGszczFHTDFS\n\
QlVlUGRPOEFCTkZFPSkpAA==\n\
-----END DIGIBANK RSA PUBLIC KEY-----\n\
";

char mypkey[] = "\
-----BEGIN DIGIBANK RSA COMPOSITE KEY-----\n\
KDEzOmRpYmFjcnlwdC1rZXkoMTc6S2V5IENyZWF0aW9uIERhdGUxOToyMDE4LzA1\n\
LzIzIDExOjMwOjI4KSgxMTpLZXkgVmVyc2lvbjU6MC4wLjQpKDg6S2V5IE5hbWUx\n\
MTp1bm5hbWVkIGtleSkoODpLZXkgVHlwZTM6UlNBKSgxNTpLZXkgRGVzY3JpcHRp\n\
b24yOjEwKSg2OktleSBJRDMyOmw0OG5kUlQxUFcwcTZuUUxEQlluenMxUGdsVE01\n\
UkE1KSgxMTpLZXkgQ3JlYXRvcjEyOnVua25vd24gbmFtZSkoMTI6S2V5IEhvc3Ru\n\
YW1lMTI6dW5rbm93biBob3N0KSgxNTpQdWJsaWMgRmlsZW5hbWU2OmJiLnB1Yiko\n\
MTE6UHVibGljIEhhc2g0NDpkOENwWWxoWEFVSEdxblkvcVp4U2czK2tOcGFhTlI0\n\
MjkvSHhpd1czbE5zPSkoMTY6UHJpdmF0ZSBGaWxlbmFtZTY6YmIua2V5KSgxMjpQ\n\
cml2YXRlIEhhc2g0NDpuNVlqRUdKNzVqTGUyZkN3NEFhZndVaTZjenovZnp6ODVa\n\
ZFU3VEJZelcwPSkpKDE1OnByaXZhdGUtY3J5cHRlZDEyODg6xr1zqqpwGmu7gkGh\n\
fJR4gS+pbsfYrdojJ88XaJ18EHf8X1AR5OnSTG4xFzxrT//j/4WKF1wD0Se972cR\n\
w1aQMbfdehNBr+zbkRqMcydM0DVnpoAtLo0V1KUildkrv0jbfTwSvyGMlC1tUEIY\n\
dBMl7rO5GAwCkt8xteAUXwqVpLDzAIXx6iFDckbpfuk46CmNTNAwoBgor5IRf2TA\n\
xcM+EbBBH3q25/KdFkXQBpAsKqdwIc72BU+Tqkc0spnezg/Eu2WY2BTbharx1azy\n\
84+7Q4PtS4+u2oNQyQyrFHFxQ2RmwHlEGe1P6R4jVt6EZmzFzPpAadi9J3g+yzqv\n\
u0kGzgy3IJFEFnIW6Jsdc1oECXJdnfm+4LGsF5xKfbbwbBxxzoszKlUmHkXjBSbv\n\
IBaSxQhkcTG9O43oPhiswMFS+bRkH7rlmA43cAz46A86hD13SiGNPJYI5OslqUIZ\n\
J1Cdbeb85/5iV9gK18SGkfjE9V0UZgb+7QkycdoDGhPB2Wi44fyRcD7K2fWzIRct\n\
J4vxXaufFKn1UcsxAN+KIqUGjxfwezYA2sXETU8BN3H7NZvAtfbSHuOWBrGqQp/z\n\
6QMcJZ2dsUMMc1xrSvKemjd5NxtGXn6ASHK24T+D2vICdbQTWJuwqdgpQu0q6/jB\n\
fL72JLf82K89du8VFgrcuF+m+cm3WEU3Sbl9vV4hNpr7974ngWNEQdb1Nku7V+pX\n\
4MKsm8TMipu0lZiA637p381KEx4TcgSUct/lh01Rmka0cSf8+U5Z1TL1Qq/BpUDk\n\
RL/cM1VQdnRJP7PI35scKBIyrgYhn+di+6N+wiq5F2L3dsIuxP0Oy+Eh83wczgIt\n\
QDRAPvT3Wi7fjjqDxI2IWu0w97MQ19fTVu7lGXVhGM+yUB8QvHk1RsgdWG3jiiaP\n\
1Fh/I2aQ/9iCvNNSXruVpjPTz7dvZCzvvnafpAdLnrOf/KkodyTdMQWh0sHiq8hz\n\
jqw8pBQ71BV+f+ZS/ISUv+oQn2iiAI3/vs9c+gXkaTAKYaC8dRw0WVPEkPhgOqtv\n\
z+rixTa7YUTepDsv3aEATV82E6PGA+KEBxENC8rM+ciC90WoOy9z05NnQsbjec1M\n\
0B0v5UWhK5q1WRQ1WRXmnIRRXtCoTJ1kJ8Y00FmCeo/8aQ/RDdBa3AFGptd27q+t\n\
8WWZVgp4DwVSs632qcnsr/NEEHtZD1Ku1xV/9brtxBhXDm5DebctQB5VYlvnLULY\n\
MW0rqwzqJd799EZoD53TWPInpjVIbNE7KCOXWh7eZ9dx+JtGnZtSt5wWzIlNi94t\n\
sW+3EcImroQ7ljokZ2OcsblYYWsk4rYoECOVVEAkzw/XvOOzj6Iy52DXqEcL+yii\n\
z9A1dHSoKwPbBS5uyUmgG+7GjJVcPhflzr2TJUt05PvgD90kA9cUYfZq3fDKbOHY\n\
IjJk5r4L3Rh2rgJbvPJ70eiPgfWdLWszBbelkFMdiTdARulkVBhyK7NmTJu+iNEY\n\
NTPjHjWrlOYt6O3KmZpZ4ibVAsU3/0OCIj+GzXSsczU30aPej0BdxV0Op5HIByjm\n\
iFfC9MWfiL7eLfcCrCn/++eFshf5SlB96HfSmkNPJa7NWuAC2QkMeRNUC0Md4OHh\n\
sh6d9J9htdC7JYR4qtCjIN80bRRK1igGZRTdvX4qhWlNGK6plB1dwZffAqrq49K6\n\
KOD3sP140zkGU6QdKt8oljkFdKeVFKynC4xZ8ykoMTQ6ZGliYWNyeXB0LWhhc2go\n\
MTg6SGFzaCBDcmVhdGlvbiBEYXRlMTk6MjAxOC8wNS8yMyAxMTozMDoyOCkoMTI6\n\
SGFzaCBWZXJzaW9uNTowLjAuNCkoNjpLZXkgSUQzMjpsNDhuZFJUMVBXMHE2blFM\n\
REJZbnpzMVBnbFRNNVJBNSkoMTU6UHVibGljIEZpbGVuYW1lNjpiYi5wdWIpKDEx\n\
OlB1YmxpYyBIYXNoNDQ6ZDhDcFlsaFhBVUhHcW5ZL3FaeFNnMytrTnBhYU5SNDI5\n\
L0h4aXdXM2xOcz0pKDE2OlByaXZhdGUgRmlsZW5hbWU2OmJiLmtleSkoMTI6UHJp\n\
dmF0ZSBIYXNoNDQ6bjVZakVHSjc1akxlMmZDdzRBYWZ3VWk2Y3p6L2Z6ejg1WmRV\n\
N1RCWXpXMD0pKDk6SW5mbyBIYXNoNDQ6dUhaUTE3b0N4M3lGbGVtUlJHc2pBU0xr\n\
M3MxR0wxUkJVZVBkTzhBQk5GRT0pKQ==\n\
-----END DIGIBANK RSA COMPOSITE KEY-----\n\
";

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


















