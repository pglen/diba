
/* =====[ dibawalk.c ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

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
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

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

static int  skip = 0;
static int  entries = 1;
static int  mode = 0;
static int  batch = TRUE;
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

// Replace bsize for testing 
#undef BSIZE
#define BSIZE 512

// Protected strings

unsigned int bound = 0x41424344;
unsigned char str[BSIZE]; 
unsigned int bound2 = 0x42434445;
unsigned char str2[BSIZE]; 
unsigned int bound3 = 0x43444546;

char xpath[MAX_PATH];
char org_dir[MAX_PATH];
int org_len = 0;

int walkdirs(char *gotnew)

{
    DIR *dd; struct dirent *dir;
    int ret = chdir(gotnew);
    if(ret < 0)
        {
        xerr2("Cannot change to '%s'\n", gotnew);
        }
    char ccc[MAX_PATH];
    getcwd(ccc, sizeof(ccc) - 1);

    if(verbose)    
        printf("%s\n", ccc + org_len);
        
    dd = opendir(".");
    if (!dd)
        {
        xerr2("Cannot open dir '%s' (cwd=%s)\n", gotnew, ccc);
        }
    while (1)
        {
        dir = readdir(dd);
        if(dir == NULL)
            break;
        struct stat sb;
        ret = stat(dir->d_name, &sb);
        //printf("%s sb.st_mode %x %x\n", 
        //                    dir->d_name, sb.st_mode, dir->d_type);
        if(sb.st_mode & S_IFDIR)
            {
            if(dir->d_name[0] != '.')
                {
                walkdirs(dir->d_name);
                }
            }
        else
            {
            printf("%s/%s\n", ccc + org_len, dir->d_name);
            
            }
        }
    closedir(dd);
    chdir("..");
}

int    main(int argc, char *argv[])

{
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage("dibawalk [options]", "Generate DIBA hashes.", opts_data); exit(2);
        }
    
    if(verbose)
        printf ("\
\n\
---------------------------------------------------------------------------\n\
              dibawalk written by Peter Glen.                               \n\
---------------------------------------------------------------------------\n\
\n\
");
    int ret;
    
    char   tmp_str[MAX_PATH + 1];
    unsigned int  loop;
    if(access(diba_currdir, R_OK) < 0)
        {
        xerr2("Must have target dir '%s', please create first.\n", diba_currdir);
        }
    //snprintf(tmp_str, MAX_PATH, "%s/", diba_currdir, loop);
    ret = chdir(diba_currdir);
    if(ret < 0)
        {
        xerr2("Cannot change to '%s'\n", diba_currdir);
        }
    // Mark start offset
    getcwd(org_dir, sizeof(org_dir) - 1);
    org_len = strlen(org_dir);
    
    walkdirs(".");
    return 0;
}

/* EOF */
