
/* =====[ dibatrans.c ]=========================================================

   Description:     Feasability study for diba. Decode generated number.
                    Tranfer money.
   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  nov.11.2015     Peter Glen      Initial version.

   ======================================================================= */

/* -------- System includes:  -------------------------------------------- */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>

#include "bluepoint3.h"
#include "diba.h"
#include "dibastr.h"
#include "dibautils.h"
#include "cmdline.h"
#include "zmalloc.h"
#include "zstr.h"
#include "gcrypt.h"
#include "gcry.h"
#include "getpass.h"

static  void  decode(char * str, int len);

static int  skip = 0;
static int  entries = 1;
static int  mode = 0;
static int  batch = TRUE;
static int  verbose = FALSE;
static int  test = FALSE;

opts opts_data[] = {
                    'n',   "--number",  &entries, NULL, 0, 0xffff, NULL, 
                    "-n[num] --number  - number of entries to generate defaults to 1, range(1-16M)",
                    's',    "--skip", &skip,  NULL, 0, 0xffff, NULL, 
                    "-s[num] --skip    - number of entries to skip defaults to 0, range(1-16M)",
                    'm',    "--mode", &skip, NULL, 0, 0xffff, NULL, 
                    "-m[num] --mode    - Mode of generation, defaults to 0, range(0-255)",
                    'v',   "--verbose",  NULL,  NULL, 0, 0, &verbose, 
                    "-v      --verbose - Verbosity on",
                    't',    "--test", NULL, NULL,  0, 0, &test, 
                    "-t      --test    - test on",
                     0,     NULL,  NULL, NULL,     0, 0,  NULL, NULL,
                    };


char *usestr = "dibatrans [options] source target amount";
char *descr = "Transfer DIBA currency.";

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

static char *fromaddr;
static char *toaddr;

//////////////////////////////////////////////////////////////////////////

int    main(int argc, char *argv[])

{
    signal(SIGSEGV, myfunc);
    
    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();
    
    // Pre allocate all string items    
    zline2(__LINE__, __FILE__);
    fromaddr = zalloc(MAX_PATH); if(fromaddr == NULL) xerr2(mstr);
    toaddr   = zalloc(MAX_PATH); if(toaddr  == NULL) xerr2(mstr);

    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descr, opts_data); 
        exit(2);
        }
    if(argc - nn < 4)
        {
        printf("Not enough arguments.");
        usage(usestr, descr, opts_data); 
        exit(2);
        }  
        
    zstrcpy(fromaddr, argv[nn + 1], MAX_PATH); 
    zstrcpy(toaddr, argv[nn + 2], MAX_PATH); 
        
    int amount = atoi(argv[nn+3]);
    if(amount <= 0)
        xerr2("Amount must be a positive number\n");
        
    if(strcmp(fromaddr, "none") == 0)
        {
        printf("Transfer %d DCU from unallocated currency from pool.\n", amount);
        }    
    else
        {
        printf("Transfer currency from:'%s' to:'%s' Amount = %d\n", 
                            argv[nn+1], argv[nn+2], amount);
        }
                                
    return 0;         
}


/* EOF */
