
/* =====[ algos.c ]=========================================================

   Description:     Algo test for DIBA [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug.11.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "gcrypt.h"
#include "gcry.h"
#include "getpass.h"
#include "gsexp.h"
#include "base64.h"
#include "zmalloc.h"
#include "cmdline.h"
#include "misc.h"

//static  int keysize = 1024;
static  unsigned int keysize = 2048;
//static  int keysize = 4096;

static int weak = FALSE;
static int force = FALSE;
static int verbose = 0;
static int test = 0;
static int nocrypt = 0;
static int ppub = 0;
static int plen = 0;
static int pinfo = 0;


static char descstr[] = "Generate Public / Private keypair into a set of key files.";

char usestr[] = "dibakeyinfo [options] keyfile\n"
                "Where keyfile is the basename for .key .pub files.";
static char    thispass[MAX_PATH] = {'\0'};

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {
                    
                    'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
                    "-v             --verbose               - Verbosity on",
                    
                    't',   "test",  NULL,  NULL, 0, 0, &test, 
                    "-t             --test                  - Test on",
                    
                    'f',   "force",  NULL,  NULL, 0, 0, &force, 
                    "-f             --force                 - force clobbering files",
                    
                    'i',   "pinfo",  NULL,  NULL, 0, 0, &pinfo, 
                    "-i             --pinfo                 - print key info",
                    
                    'k',   "pkey",  NULL,  NULL, 0, 0, &ppub, 
                    "-k             --pkey                  - print private or public key",
                    
                    'l',   "plen",  NULL,  NULL, 0, 0, &plen , 
                    "-l             --plen                  - print key length",
                                        
                    'n',   "nocrypt",  NULL,  NULL, 0, 0, &nocrypt, 
                    "-n             --nocrypt               - do not decrypt key",
                   
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

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);
    
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data); exit(2);
        }
    
    //if (argc - nn != 2) {
    //    //fprintf(stderr, "Usage: dibakeyinfo.exe outfile\n");
    //    //xerr("Invalid arguments.");
    //    usage(usestr, descstr, opts_data); exit(2);
    //}
    if(thispass[0] != '\0')
        {
        if(nocrypt)
            xerr2("\nConflicting options, cannot provide key with the 'nocrypt' flag.\n");
        }
    if(num_bits_set(keysize) != 1)
        {
        xerr2("Keysize must be a power of two. ( ... 1024, 2048, 4096 ...)");
        } 
        
    gcrypt_init();

    int cnt = 0;
    for(int loop = 0; loop < 1000; loop++)
        {
        const char *algos = gcry_md_algo_name(loop);
        if(algos[0] != '?')
            {
            printf("%3d %-20s ", loop, algos);
            if(cnt % 4 == 3)
                printf("\n");
            cnt++;
            }
        }
    printf("\n\n");
    
    cnt = 0;
    for(int loop = 0; loop < 1000; loop++)
        {
        const char *algos = gcry_mac_algo_name(loop);
        if(algos[0] != '?')
            {
            printf("%3d %-20s ", loop, algos);
            if(cnt % 4 == 3)
                printf("\n");
            cnt++;
            }
        }
    
    printf("\n\n");
    
    for(int loop = 0; loop < 1000; loop++)
        {
        const char *algos = gcry_pk_algo_name(loop);
        if(algos[0] != '?')
            {
            printf("%3d %-20s ", loop, algos);
            if(cnt % 4 == 3)
                printf("\n");
            cnt++;
            }
        }
    printf("\n\n");
    
    for(int loop = 0; loop < 1000; loop++)
        {
        const char *algos = gcry_cipher_algo_name(loop);
        if(algos[0] != '?')
            {
            printf("%3d %-20s ", loop, algos);
            if(cnt % 4 == 3)
                printf("\n");
            cnt++;
            }   
        }
        
    return 0;
}




