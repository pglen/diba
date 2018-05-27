
/* =====[ test_comline.c ]=========================================================

   Description:     Encryption examples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmdline.h"
#include "zmalloc.h"
#include "base64.h"

#ifndef MAX_PATH
    #ifndef PATH_MAX
        // Keep it safe
        #define MAX_PATH 255
    #else
        #define MAX_PATH PATH_MAX
    #endif    
#endif            

static char    *thispass = NULL;
static char    *keyname  = NULL;
static char    *keydesc  = NULL;
static char    *creator  = NULL;

static  unsigned int keysize = 2048;

static int weak = 0;
static int force = 0;
static int dump = 0;
static int verbose = 0;
static int test = 0;
static int calcsum = 0;
static int nocrypt = 0;
static int version = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

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
        "-m name        --keyname nm  - user legible key name",
       
        'd',   "desc",  NULL,      &keydesc, 0, 0, NULL, 
        "-d desc        --desc  desc  - key description",
       
        'c',   "creator",  NULL,   &creator, 0, 0, NULL, 
        "-c name        --creator nm  - override creator name (def: logon name)",
       
        0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
        };


static char descstr[] = "Generate Public / Private keypair into a set of key files.";

static char usestr[] = "dibakeygen [options] keyfile\n"
                "Where 'keyfile' is the basename for .key .pub files. [keyfile.pub, keyfile.key]";

void xerr(const char* msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(2);                                
}

// Simulated command line arguments

char *argv2[] = { "prog", "-v", "-sf", NULL };
char *argv3[] = { "prog", "-k", "1024", "--pass", "Hello", "-v", NULL };
char *argv4[] = { "prog", "-?",  NULL };

int main(int argc, char** argv)
                                        
{
    printf("\nTesting command line parsing.\n");

    // Pre allocate all string items    
    char *mstr = "No Memory";
    zline2(__LINE__, __FILE__);
    thispass = zalloc(MAX_PATH); if(thispass == NULL) xerr(mstr);
    keyname  = zalloc(MAX_PATH); if(keyname == NULL)  xerr(mstr);
    keydesc  = zalloc(MAX_PATH); if(keydesc == NULL)  xerr(mstr);
    creator  = zalloc(MAX_PATH); if(creator == NULL)  xerr(mstr);

    char *err_str;
    int nn = parse_commad_line(argv2, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data); 
        }
            
    nn = parse_commad_line(argv3, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data);
        }
    
    nn = parse_commad_line(argv4, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data);
        }
    
    zfree(thispass);
    zfree(keyname);
    zfree(keydesc);
    zfree(creator);
      
    zleak();  
}












