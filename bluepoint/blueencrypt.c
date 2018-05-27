
/* =====[ bluedecrypt.c ]=========================================================

   Description:         File encryption block by block.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug.27.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <signal.h>

#include "getpass.h"
#include "base64.h"
#include "zmalloc.h"
#include "cmdline.h"
#include "bluepoint3.h"
#include "blueutil.h"
#include "misc.h"

#ifdef __linux__
  
#else
    extern int fileno (FILE *__stream);
#endif

#ifndef MAX_PATH
    #ifndef PATH_MAX
        // Keep it safe
        #define MAX_PATH 255
    #else
        #define MAX_PATH PATH_MAX
    #endif    
#endif            

static int weak = 0;
static int force = 0;
static int dump = 0;
static int verbose = 0;
static int test = 0;
static int calcsum = 0;
static int version = 0;
static int use_stdin = 0;
static int use_stdout = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

static char descstr[] = "Symmetric decryption utility.";
static char usestr[]  = "bluedecrypt [options]\n";
                
static char    *thispass = NULL;
static char    *keyname  = NULL;
static char    *keydesc  = NULL;
static char    *creator  = NULL;

static char    *infile  = NULL;
static char    *outfile = NULL;

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {

        'i',  "infile",  NULL, &infile,  0, 0, NULL, 
        "-i <fname>     --infile <fname>  - input file name",
                    
        'o',  "outfile",  NULL, &outfile,  0, 0, NULL, 
        "-o <fname>     --outfile <fname> - output file name",
        
        'r',  "stdin",    NULL, NULL,  0, 0, &use_stdin, 
        "-r             --stdin            - use stdin as input",
        
        //'w',  "stdout",    NULL, NULL,  0, 0, &use_stdout, 
        //"-w             --stdin            - use stdout as output",
        
        'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
        "-v             --verbose         - Verbosity on",
        
        'V',   "version",  NULL, NULL,  0, 0, &version, 
        "-V             --version         - Print version numbers and exit",
        
        's',   "sum",  NULL,  NULL, 0, 0, &calcsum, 
        "-s             --sum             - print sum before proceeding",
        
        'f',   "force",  NULL,  NULL, 0, 0, &force, 
        "-f             --force           - force clobbering files",
        
        'w',   "weak",  NULL,  NULL, 0, 0, &weak, 
        "-w             --weak            - allow weak pass",
        
        'p',   "pass",   NULL,   &thispass, 0, 0,    NULL, 
        "-p val         --pass val        - pass in for key (@file reads pass from file)",
        
        0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
        };

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

void xerr2(const char* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    
    vfprintf(stderr, msg, ap);
    exit(2);                                
}

char *bluepoint_hash_file(char *fname, char **err_str);

// -----------------------------------------------------------------------

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);
    
    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();
    
    // Pre allocate all string items    
    char *mstr = "No Memory";
    
    zline2(__LINE__, __FILE__);
    infile   = zalloc(MAX_PATH); if(infile == NULL) xerr2(mstr);
    outfile  = zalloc(MAX_PATH); if(outfile == NULL) xerr2(mstr);
    thispass = zalloc(MAX_PATH); if(thispass == NULL) xerr2(mstr);
    keyname  = zalloc(MAX_PATH); if(keyname == NULL)  xerr2(mstr);
    keydesc  = zalloc(MAX_PATH); if(keydesc == NULL)  xerr2(mstr);
    creator  = zalloc(MAX_PATH); if(creator == NULL)  xerr2(mstr);
    
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    
    //printf("Processed %d comline entries\n", nn);
    
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data); exit(2);
        }
    
    if(version)
        {
        printf("blueencrpt version %d.%d.%d\n", 
                        ver_num_major, ver_num_minor, ver_num_rele);
        exit(1);
        }
    
    if(calcsum)
        {
        char *err_str;
        char *hash_str = bluepoint_hash_file(argv[0], &err_str);
        if(hash_str)
            {
            printf("Executable bluepoint hash: '%s'\n", hash_str);
            zfree(hash_str);
            }
        else 
            {
            xerr2("bluedecrypt: %s\n", err_str);
            }
        }
    
    if(infile[0] == '\0' && !use_stdin)
        {
        printf("Must spcify infile or stdin.\n");
        usage(usestr, descstr, opts_data); exit(2);
        }
        
    if(outfile[0] == '\0' && !use_stdout)
        {
        printf("Must spcify outfile or stdout.\n");
        usage(usestr, descstr, opts_data);  exit(2);
        }
    
    if(access(outfile, F_OK) >= 0 && !force)
        {
        xerr2("blueencrpt: File already exists, use different name or delete the file or use -f (--force) option.");
        }
        
    if(access(infile, F_OK) < 0 && !use_stdin)
        {
        xerr2("blueencrpt: Input file '%s' does not exist", infile);
        }
        
    int ret = 0;
    if(thispass[0] == '\0')
        {
        printf("Please enter a password to encrypt this file.\n");
        printf("This password must be retained for later use. Do not loose this password.\n\n");
        if(weak)
            printf("Warning! Weak option specified, recommended for testing only.\n");
        getpassx  passx;
        passx.prompt  = "Enter  keypair  pass:";
        passx.prompt2 = "Confirm keypair pass:";
        passx.pass = thispass;    
        passx.maxlen = MAX_PATH;
        passx.minlen = 4;
        passx.strength = 6;
        passx.weak = weak;
        passx.nodouble = 0;
        
        ret = getpass2(&passx);
        if(ret < 0)
            {
            xerr2("blueencrpt: Error on entering pass, no keys are written.\n");
            }
        }
    else
        {
        if(thispass[0] == '@')
            {
            char *err_str = NULL;
            char *newpass = pass_fromfile((const char*)thispass, &err_str);
            if(newpass == NULL)
                xerr2("bluedecrypt: %s\n", err_str);
                
            strcpy(thispass, newpass);
            zfree(newpass);
            }
        }   
                     
    //printf("thispass '%s'\n", thispass);
    
    int fileno_in, fileno_out;
    FILE *fp, *fp2;
    unsigned int file_len, curr_len;
    unsigned int prog = 0;
    
    if(use_stdin)
        {
        fileno_in = fileno(stdin);
        //printf("fileno_in: %d\n", fileno_in);
        }
    else
        {
        fp = fopen(infile, "rb");
        if(fp == NULL) {
            xerr2("Cannot open input file '%s'.", infile);
            }
        file_len = getfsize(fp);
        }
    if(use_stdout)
        {
        fileno_out = fileno(stdout);
        //printf("fileno_out: %d\n", fileno_out);
        }
    else
        {
        fp2 = fopen(outfile, "wb");
        if(fp2 == NULL) {
            xerr2("Cannot open output file '%s'.", outfile);
            }
        }        
        
    int block_len = 4096;
    char* file_buf = zalloc(block_len + 2);
    if (!file_buf) {
        //fclose(fp);
        xerr2("bluedecrypt: could not allocate file buffer for encryption.");
        }
    
    while(1==1)
        {
        if(use_stdin)
            {
            // Read block
            unsigned int idx = 0;
            while(1==1)
                {
                int chh = fgetc(stdin) & 0xff;
                if(feof(stdin))
                    {
                    curr_len = idx;
                    break;
                    }
                file_buf[idx] = chh;
                idx++;
                if (idx >= block_len)
                    {
                    curr_len = idx;
                    break;
                    }
                }
            }
        else
            {
            curr_len = block_len;
            if(file_len - prog < block_len)
                curr_len = file_len - prog;
            
            if (fread(file_buf, curr_len, 1, fp) != 1) {
                zfree(file_buf);
                fclose(fp);
                xerr2("bluedecrypt: Cannot read file for encrypting.");
                }
            }
               
        bluepoint3_encrypt(file_buf, curr_len, thispass, strlen(thispass));    
            
        if(use_stdout)
            {
            for(int loop = 0; loop < curr_len; loop++)
                printf("%c", file_buf[loop]);
            }
        else
            {
            if (fwrite(file_buf, curr_len, 1, fp2) != 1) {
                zfree(file_buf);
                fclose(fp); fclose(fp2);
                xerr2("bluedecrypt: Cannot write encrypted file.");
                }
            }
         prog += curr_len;
         
         if(use_stdin)
            {
            if(feof(stdin))
                break;
            }
         else
            {
             // Done
             if(prog >= file_len)
                break;
            }
            
         }
         
    fclose(fp);    fclose(fp2);
    zfree(file_buf);
    
    zfree(infile);     zfree(outfile);      
    zfree(thispass);    zfree(keyname);      
    zfree(keydesc);     zfree(creator);
    
    zfree(dummy);
    
    zleak();
    return 0;
}

/* EOF */













