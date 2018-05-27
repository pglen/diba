
/* =====[ cmdline.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug.23.2017     Peter Glen      Extracted from gcry

   ======================================================================= */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cmdline.h"

// Helper for command line

#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif

#ifndef MAX_PATH
    #ifndef PATH_MAX
        // Keep it safe
        #define MAX_PATH 255
    #else
        #define MAX_PATH PATH_MAX
    #endif    
#endif            

static char tmp_error[MAX_PATH];

static int is_opts_end(opts *popts_data, int idx);
static int parse_one(const char *str, opts popts_data[], int idx);
static int is_opt_with_val(opts *popts_data, int idx);

/*
 * Read command line switches, set items passed in structure.
 *
 * In:      Arguments, array of options, place for error str
 * Out:     args parsed, pointer to an error message or NULL
 * Return:  Last index processed (num of args)
 *
 */

int     parse_commad_line(char **argv, opts *popts_data, char **err_str)

{
    int     got, nn, processed = 0, err = 0;
    char    *ret_val = NULL;
    int     inval_arg = 0;

    *err_str = NULL;
    
    for (nn = 1; argv[nn] != NULL; nn++)
        {
        got = 0;
        // Long option?
        if(strlen(argv[nn]) > 2 && (argv[nn][0] == '-' && argv[nn][1] == '-'))
            {
            char *cmdstr = &argv[nn][2];
            //printf("Long option: '%s'\n", cmdstr);
            int idx = 0;
            if(strcmp(cmdstr, "help") == 0)
                {
                *err_str = "Help requested, long form.";
                return nn;
                }
            while(TRUE)
                {
                if(is_opts_end(popts_data, idx))
                    {
                    if(got == 0)
                        {
                        err++;
                        inval_arg = nn;
                        }
                    else
                        processed++;                        
                    break;
                    } 
                //printf("long option '%s' cmdstr '%s' arg '%s'\n",
                //             popts_data[idx].long_opt, cmdstr, argv[nn]);
                             
                if(strcmp(popts_data[idx].long_opt, argv[nn]) == 0 ||
                        strcmp(popts_data[idx].long_opt, cmdstr) == 0)
                    {
                    //printf("Found long option '%s' arg '%s'\n", cmdstr, argv[nn]);
                    int ret = parse_one(argv[nn+1], popts_data, idx);
                    if(ret < 0)
                        { 
                        snprintf(tmp_error, sizeof(tmp_error), 
                            "Invalid value on option '--%s'\n", cmdstr);
                        *err_str = tmp_error;
                        return nn;
                        }
                    processed += ret;
                    got++;
                    }
                idx++;
                }
            }
        else if(argv[nn][0] == '-' ||  argv[nn][0] == '/')   
            {                                     /* option recognized */
            int idx = 0;
            char cmd = argv[nn][1];
            
            if(cmd == '?' || cmd == 'h')
                {
                *err_str = "Help requested.";
                return nn;
                }
            while(TRUE)
                {
                if(is_opts_end(popts_data, idx))
                    {
                    if(got == 0)
                        {
                        inval_arg = nn; err++;
                        }
                    else
                        processed++;
                    break;
                    }   
                if(popts_data[idx].opt == cmd)
                    {
                    int ret = 0;
                    if(is_opt_with_val(popts_data, idx))
                        {
                        // Extra char on options with arg
                        if(strlen(argv[nn]) > 2)
                            {
                            snprintf(tmp_error, sizeof(tmp_error), 
                            "Extra characters on option with argument ('-%c')\n", cmd);
                            *err_str = tmp_error;
                            return nn;
                            }
                        
                        // Next command is option value
                        if(argv[nn+1] == NULL)
                            {
                            snprintf(tmp_error, sizeof(tmp_error), 
                                "Not enough values on command line option '-%c'\n", cmd);
                            *err_str = tmp_error;
                            return nn;
                            }
                        ret = parse_one(argv[nn+1], popts_data, idx);
                        if(ret < 0)
                            { 
                            snprintf(tmp_error, sizeof(tmp_error), 
                                "Invalid value on option '-%c'\n", cmd);
                            *err_str = tmp_error;
                            return nn;
                            }
                        got++;     
                        //printf("Got %d values\n", ret); 
                        }
                    else
                        {
                        // Possible more options in command line entry
                         int clen = strlen(argv[nn]);
                         for(int loop2 = 1; loop2 < clen; loop2++)
                            {
                            got = 0;  // Reset with every option
                            int idx2 = 0;
                            char cmd2 = argv[nn][loop2];
                            while(TRUE)
                                {
                                if(is_opts_end(popts_data, idx2))
                                    {
                                    if(got == 0)
                                        { inval_arg = nn; err++; }
                                    break;
                                    }
                                if(popts_data[idx2].opt == cmd2)
                                    {
                                    got++;
                                    parse_one(&argv[nn][loop2], popts_data, idx2);
                                    }
                                idx2++;
                                }
                            }
                        }
                    processed += ret;
                    }
                 idx++;
                }
            }                 
        }
    if (err)
        {
        snprintf(tmp_error, sizeof(tmp_error), 
                   "Invalid option on command line '%s'\n", argv[inval_arg]);    
        *err_str = tmp_error;
        }
    return(processed);
}

//////////////////////////////////////////////////////////////////////////
// Parse one argument.
// Return number of elements processed, -1 for error.

static int parse_one(const char *str, opts popts_data[], int idx)

{
    int ret = 0;
    
    if(popts_data[idx].strval != NULL)
        {
        if(str == NULL)
            {   
            return -1;
            }
        strncpy(*popts_data[idx].strval, str, MAX_PATH);
        ret = 1;
        }
    else if(popts_data[idx].val != NULL)
        {
        int val = atoi(str);
        if(popts_data[idx].minval > val ||
                popts_data[idx].maxval < val) 
            {
            return -1;
            }
        *popts_data[idx].val =  val;
        ret = 1;
        } 
    else if(popts_data[idx].flag != NULL)
        {
        *popts_data[idx].flag = TRUE;
        }
    return ret;
}    

static int is_opts_end(opts *popts_data, int idx)

{
    if(popts_data[idx].long_opt == NULL && popts_data[idx].opt == 0)
        return TRUE;
        
    return FALSE;
}                

static int is_opt_with_val(opts *popts_data, int idx)

{
    if(popts_data[idx].val != NULL || popts_data[idx].strval != NULL )
        return TRUE;
        
    return FALSE;
}                

void    usage(const char *progname, const char *desc, opts *opts_data)

{
    int  idx = 0, ret_val = 0;
    
    printf("\
\n%s\n\
Usage: %s\n\
Options can be:     \n\
", desc, progname);

   while(TRUE)
        {
        if(opts_data[idx].opt == 0)
            break;
            
        printf("               %s\n", opts_data[idx].help);
        idx++;
        }
    printf("\n");
    printf(    "               -?             --help        - displays this help\n");
    printf(    "               -h             --help        - displays this help\n");
    printf(    "Option with argument needs one option per command line item.\n");
}








