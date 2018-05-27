
/* =====[ DigiBank.c ]=========================================================

   Description:     Feasability study for digibank. Catching the random gen
                    on three leading zeros.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      00.00  Jan.01.2015     Peter Glen      Initial version.
      00.00  Sep.xx.2017     Peter Glen      Moved to subdirs
      
   ======================================================================= */

// DigiBank test script

/* -------- System includes:  -------------------------------------------- */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
//#include <curses.h>

#define DEF_DUMPHEX
#include "bluepoint3.h"
#include "cmdline.h"
#include "misc.h"

/* -------- Defines: ----------------------------------------------------- */

#define TRUE 1
#define FALSE 0   

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
    //parse_commad_line(argv);

    if(verbose)
        printf ("\
\n\
---------------------------------------------------------------------------\n\
              DigiBank written by Peter Glen.                              \n\
---------------------------------------------------------------------------\n\
\n\
");

    printf("Awaiting implamentation.");
    return 0;
}

/* EOF */






















