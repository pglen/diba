
/* =====[ dibagen.c ]=========================================================

   Description:     Feasability study for diba [Digital Bank].
                    This file shows an encrypted hash. Also demostrates 
                    the modofication of the hash, and its decryption.
                    The singe bit in the cyphertext is propagated to 
                    every decrypted byte.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  Jan.01.2015     Peter Glen      Initial version.
      0.00  Jan.05.2015     Peter Glen      Initial version.
      0.10  Jun.21.2017     Peter Glen      Initial version.
      0.10  Jul.04.2017     Peter Glen      Initial version.
      0.11  nov.06.2017     Peter Glen      Currency started

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

/* -------- Data: -------------------------------------------------------- */

static clock_t time_up;

static int  skip = 0;
static int  entries = 1;
static int  mode = 0;
static int  batch = TRUE;
static int  verbose = FALSE;
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

// Replace bsize for testing 
#undef BSIZE
#define BSIZE 512

void show_str_lines(const char* str, int len)

{
    int linelen = 34;
    for(int loop = 0; loop < len; loop++)
        {
        printf("%02x", str[loop] & 0xff);
        if((loop % linelen) == linelen - 1)
            printf("\n");
        }
}   

// Protected strings
unsigned int bound = 0x41424344;
unsigned char str[BSIZE]; 
unsigned int bound2 = 0x42434445;
unsigned char str2[BSIZE]; 
unsigned int bound3 = 0x43444546;

int    main(int argc, char *argv[])

{
    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage("dibagen [options]", "Generate DIBA hashes.", opts_data); exit(2);
        }
    
    if(verbose)
        printf ("\
\n\
---------------------------------------------------------------------------\n\
              DibaGen written by Peter Glen.                               \n\
---------------------------------------------------------------------------\n\
\n\
");
    
    unsigned int  loop;
    
    // These are setting the default values on bluepoint
    //int   midx_list[] = {7, 1, 6, 1, 3, 1, 4, 3, 5, 3, 6, 1, 8, 3, -1};
    //bluepoint3_set_midx(midx_list, sizeof(midx_list) / sizeof(int));
    
    bluepoint3_set_rounds(BSIZE / 6);
    
    // Init string
    for (loop = 0; loop < sizeof(str); loop++)
        {
        str[loop] = (unsigned char)mode; 
        }
    for(loop = 0x0; loop < entries;  loop++)
    //for(loop = 0x0; loop < 0x3;  loop++)
        {
        genrev(str, sizeof(str));
        
        if (loop >= skip)
            {
            if (test) {
                printf("Original:\n");
                show_str(str, sizeof(str));
            }
            
            memcpy(str2, str, sizeof(str2));
            bluepoint3_encrypt(str2, sizeof(str2),  dibapass, strlen(dibapass));
            if (test)
                printf("Encrypted:\n");
            //show_str(str2, sizeof(str2));
            //printf("\n");
            
            show_str_lines(str2, sizeof(str2));
            //printf("%s\n", bluepoint3_dump(str2, sizeof(str2)));
            
            // Verify
            if (test) {
                bluepoint3_decrypt(str2, sizeof(str2),  dibapass, strlen(dibapass));
                printf("Derypted:\n");
                show_str(str2, sizeof(str2));
                printf("\n");
                
                 if (memcmp(str, str2, sizeof(str2)))
                    {
                    printf("Bad decription!\n\n");
                    }        
                   
                // Verify mutation
                //printf("Mutate: (may not match)\n");
                memcpy(str2, str, sizeof(str2));
                //show_str(str2, sizeof(str2));
        
                bluepoint3_encrypt(str2, sizeof(str2),  dibapass, strlen(dibapass));
                str2[2] = str2[2] + 1;
                //show_str(str2, sizeof(str2));
                bluepoint3_decrypt(str2, sizeof(str2),  dibapass, strlen(dibapass));
                printf("Decrypted (mutated, should not match):\n");
                show_str(str2, sizeof(str2));
                printf("\n");
                
                printf("Bounds check: %x %x %x\n", bound, bound2, bound3);
            }
         }
     }
    return 0;
}

/* EOF */









