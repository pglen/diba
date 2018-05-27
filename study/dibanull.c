
/* =====[ DigiBank.c ]=========================================================

   Description:     Feasability study for digibank. Catching the random gen
                    on three leading zeros.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      00.00  Jan.01.2015     Peter Glen      Initial version.
      00.00  Sep.xx.2017     Peter Glen      Moved to subdirs
      
   ======================================================================= */

/* -------- System includes:  -------------------------------------------- */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>

#include "gcrypt.h"
#include "gcry.h"

#include "zmalloc.h"

#define DEF_DUMPHEX
#include "bluepoint3.h"
#include "cmdline.h"
#include "misc.h"
#include "diba.h"

/* -------- Defines: ----------------------------------------------------- */

#define TAB 9

static  void    genstr(char *str, int len);
static  void    showstr(char *str, int len);

/* -------- Data: -------------------------------------------------------- */

static clock_t time_up;
static uint gl_timeout   =  4 * CLOCKS_PER_SEC;

static char batch = FALSE;
static char *pass = "digibank";
static int verbose = FALSE;

int    main(int argc, char *argv[])

{
    if(verbose)
        printf ("\
\n\
---------------------------------------------------------------------------\n\
              DibaNull written by Peter Glen.                              \n\
---------------------------------------------------------------------------\n\
\n\
");

    printf("Searching random number for leading nulls\n");
    char str[24]; 
    unsigned int aa = 0;
    
    for(aa = 0; aa < 0xffffffff; aa++)
        {
        if(aa % 2000 == 0)
            {
            printf("\r%u    ", aa); 
            }
            
        genstr(str, sizeof(str));
        //gcry_randomize(str, sizeof(str), GCRY_STRONG_RANDOM);
        
        //bluepoint3_encrypt(str, sizeof(str),  pass, sizeof(pass));
        //showstr(str, sizeof(str));

        // Verify
       // bluepoint3_decrypt(str, sizeof(str),  pass, sizeof(pass));
       // showstr(str, sizeof(str));
       // printf("\n");
        
        if(str[0] == '\0' && str[1] == '\0' && str[2] == '\0')
            {
            printf("Null Lead at %d\n", aa);
            showstr(str, sizeof(str));
            //bluepoint3_decrypt(str2, sizeof(str),  pass, sizeof(pass));
            //showstr(str2, sizeof(str));
            printf("\n");
            }
            
        //zfree(str2);
        }
    printf("\n");
    return 0;
}

//////////////////////////////////////////////////////////////

void    showstr(char *str, int len)

{
    char *str2 = bluepoint3_dumphex(str, len);
    printf("%s\n", str2);
}   
    
//////////////////////////////////////////////////////////////////////////

void    genstr(char *str, int len)

{
    int aa = 0;
    
    for(aa = 0; aa < len; aa++)
        {
        str[aa] = rand() & 0xff;
        }
}

#if 0
int     usage(void)

{
    int  ret_val;


        printf("\\
\n\\
Asking user to whether to execute a program. If no answer is given,\n\\
timeout will execute default. Great for net or win startup.\n\\
\n\\
Usage: ASKEXEC \"Prompt string\" ExecOnYes [ExecOnNo] [options]\n\\
\n\\
Where:              \"Prompt string\" - string to display to the user\n\\
                    ExecOnYes       - execute on answering yes \n\\
                    ExecOnNo        - execute on answering no\n\
\n\
Options can be:     -t[xx]  - timeout [time in seconds follow]\n\
                    -d[x]   - default answer (Y, N, A) default: Y\n\
                    -d[x]   - default answer (Y, N, A) default: Y\n\
                    -b      - supress banner (batch mode)\n\
                    -?      - displays this help\n\
\n\
Examples:\n\
\n\
ASKEXEC \"Load net ?\" net\n\
ASKEXEC \"Start windows ?\" win \n\
ASKEXEC \"Start word processing ?\" \"wprocess text.doc\"\n\
");


//    exit(0);


    return(ret_val);
}

#endif
/* EOF */


























