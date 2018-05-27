
/* =====[ dibainit.c ]=========================================================

   Description:     Initilize digital bank currenct subsystem. 
                    Executed at the inception of the bank.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  nov.6.2015     Peter Glen      Initial version.

   ======================================================================= */

/* -------- System includes:  -------------------------------------------- */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "diba.h"
#include "bluepoint3.h"
#include "gcrypt.h"
#include "gcry.h"
#include "getpass.h"
#include "gsexp.h"
#include "base64.h"
#include "zmalloc.h"
#include "cmdline.h"                                
#include "dibautils.h"
#include "dibastr.h"
#include "misc.h"
#include "zstr.h"

/* -------- Data: -------------------------------------------------------- */

static clock_t time_up;

static int  verbose = FALSE;
static int  force = FALSE;
static int  test = FALSE;

/*typedef struct _opts
{
    char    opt;
    char    *long_opt;
    int     *val;
    char    **strval;
    int     minval, maxval;
    int     *flag;
    char    *help;
} opts */

char    *newroot;

char *diba_currdir = "../data/currency";

opts opts_data[] = {
                    'v',   "--verbose",  NULL,  NULL, 0, 0, &verbose, 
                    "-v      --verbose            - Verbosity on",
                    'f',   "--force",  NULL,  NULL, 0, 0, &force, 
                    "-f      --force              - Continue on error",
                    'r',   "--root",  NULL,   &newroot, 0, 0, NULL, 
                    "-r str  --root rootdir       - Alternate root for data",
                    't',    "--test", NULL, NULL,  0, 0, &test, 
                    "-t      --test               - test on",
                     0,     NULL,  NULL, NULL,     0, 0,  NULL, NULL,
                    };


//////////////////////////////////////////////////////////////////////////
// Allocate currency onto cpath

int add_currency(char *cpath, int val)

{                      
    char fnamex[13]; char *fname = NULL; 
    char *newfile = NULL, *datfile = NULL;
    
    // Generate temp file, try NN iterations, broken if no more room
    for(int loopf = 0; loopf < 100; loopf++)
        {
        rand_asci_buff(fnamex, sizeof(fnamex));
        fname  = zstrcat(fnamex, ".money"); 
        newfile  = zstrmcat(MAX_PATH, cpath, "/", fname, NULL);
        
        if(access(newfile, F_OK) < 0)
           break;
           
        // Start new name search, clean temp names
        zline2(__LINE__, __FILE__);
        zfree(fname); zfree(newfile); 
        }
        
    printf("Got fname: '%s'\n", newfile);
    

    return(0);
}

/////////////////////////////////////////////////////////////////////////

int    main(int argc, char *argv[])

{
    srand(time(NULL));
    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();
    
            char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage("dibainit [options]", "Generate DIBA hashes.", opts_data); exit(2);
        }
    
    if(verbose)
        printf ("\
\n\
---------------------------------------------------------------------------\n\
              DibaInit written by Peter Glen.                               \n\
---------------------------------------------------------------------------\n\
\n\
");
    int ret;
    
    char   tmp_str[MAX_PATH + 1];
    unsigned int  loop;
    if(access(diba_currdir, W_OK) < 0)
        {
        xerr2("Must have target dir '%s', please create first.\n", diba_currdir);
        }
    printf("Making iniitial trillion dirs ...\n");
    for(loop = 0; loop < 100; loop++)
        {
        snprintf(tmp_str, MAX_PATH, "%s/Tr_%d", diba_currdir, loop);
        if(verbose)
            printf("Make %s\n", tmp_str);
            
        ret = mkdir(tmp_str);
        if(ret < 0 && !force)
            xerr2("Cannot make dir '%s' Error: %s\n", 
                                                tmp_str, strerror(errno));
        }   
        
    printf("Populating first 10 billion ...\n");
    for(loop = 0; loop < 10; loop++)
        {
        snprintf(tmp_str, MAX_PATH, "%s/Tr_0/Bi_%d", diba_currdir, loop);
        if(verbose)
            printf("Make %s\n", tmp_str);
        ret = mkdir(tmp_str);
        if(ret < 0 && !force)
            xerr2("Cannot make dir '%s' Error: %s\n", 
                                                tmp_str, strerror(errno));
        }   
        
    printf("Populating first 10 Million ...\n");
    for(loop = 0; loop < 10; loop++)
        {
        snprintf(tmp_str, MAX_PATH, "%s/Tr_0/Bi_0/Mi_%d", diba_currdir, loop);
        if(verbose)
            printf("Make %s\n", tmp_str);
        ret = mkdir(tmp_str);
        if(ret < 0 && !force)
            xerr2("Cannot make dir '%s' Error: %s\n", 
                                                tmp_str, strerror(errno));
        }
    printf("Populating first 10 Thousand ...\n");
    for(loop = 0; loop < 10; loop++)
        {
        snprintf(tmp_str, MAX_PATH, "%s/Tr_0/Bi_0/Mi_0/Th_%d", 
                                                    diba_currdir, loop);
        if(verbose)
            printf("Make %s\n", tmp_str);
            
        ret = mkdir(tmp_str);
        if(ret < 0 && !force)
            xerr2("Cannot make dir '%s' Error: %s\n", 
                                                tmp_str, strerror(errno));
        }   
    printf("Adding amount ...\n");
    
    snprintf(tmp_str, MAX_PATH, "%s/Tr_0/Bi_0/Mi_0/Th_%d", 
                                                    diba_currdir, 0);
    add_currency(tmp_str, 100);
         
    return 0;
}

/* EOF */








