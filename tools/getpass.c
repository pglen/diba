
/* =====[ getpass.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  may.22.2018     Peter Glen      Ported to msys2, reworked terminal

   ======================================================================= */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

static int debuglev = 0;

//#if defined __linux__  
//#include <unistd.h>
//extern char *getpass (__const char *__prompt);
//#else
//#include <conio.h>
//#endif

#include "getpass.h"
#include "zmalloc.h"

#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif

#define CRTL_C     '\3'
#define CRTL_D     '\4'
#define BACKSPACE  '\b'

//////////////////////////////////////////////////////////////////////////
// Strenghts:
//     Every item kind (lowercase, number, uppercase, punctuation)
//     adds two points. 
//     (upper, lower, number, punct) -> strength of 8
//

static int getstrength(const char *pass)

{
    int ret = 0;
    if(strpbrk((char*)pass, "1234567890"))
        {
        //printf("number token\n");
        ret += 2;
        }
    if(strpbrk((char*)pass, "abcdefghijklmnopqrstuvwxyz"))
        {
        //printf("lowercase token\n");
        ret += 2;
        }
    if(strpbrk((char*)pass, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
        {
        //printf("uppercase token\n");
        ret += 2;
        }
    // Incomplete, re visit on finaliation
    if(strpbrk((char*)pass, "*&!@#$%^&*()_+"))
        {
        //printf("punctuation token\n");
        ret += 2;
        }
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Get pass from console. Return -1 for abort.

int     dibagetpass(const char *prompt, char *passptr, int maxlen)

{

    //# On linux, use the builtin one
    
#if defined __linux__ 
    char *ppp = getpass(prompt);
    strncpy(passptr, ppp, maxlen);
    memset(ppp, strlen(ppp), '\0');
#else
    // Get it from the terminal
    int ret = 0;
    unsigned int idx = 0;
    passptr[idx] = 0;
    
    printf("%s ", prompt);
    fflush(stdout);
    
    struct termios oldt;
    struct termios newt;
    
    tcgetattr(STDIN_FILENO, &oldt); /* store old settings */
    newt = oldt; 
    /* make changes to in new settings */
    newt.c_lflag &= ~(ICANON | ECHO | ECHONL | ISIG ); 
    newt.c_oflag &= ~(OPOST);
    newt.c_iflag &= ~(IXON | ICRNL);
    
    int ret2 = tcsetattr(STDIN_FILENO, TCSANOW, &newt); 
    
    //printf("Return  from setettr %d\r\n", ret2);
    if(ret2)
        {
        // Restore terminal attributes
        tcsetattr(0, TCSANOW, &oldt);
        printf("Cannot set terminal attributes.\n");
        return ret;
        }
    
    while(TRUE) {
    
        unsigned char cc = getchar(); 
        
        if(debuglev > 5)
            printf(" '%c' %d ", cc, cc & 0xff);
            
        if(cc == 224 || cc == 0)
            {
            getchar();  // Throw away
            continue;
            }    
    
        if (cc == '\n')
            break;
        if (cc == '\r')
            break;
        if (cc == EOF)
            break;
        if (cc == CRTL_C)
            { ret = -1; break; }
        if (cc == CRTL_D)
            { ret = -1; break; }
            
        if (cc == BACKSPACE)
            {
            if(debuglev > 9)
                printf("backspace\r\n");
                
            if(idx > 0)
                {
                idx--;
                passptr[idx] = '\0';
                putchar('\b'); putchar(' '); 
                putchar('\b');    
                }
            }
        else
            {
            passptr[idx] = cc;
            passptr[idx + 1] = '\0';
            putchar('*');    
            idx ++;
            }
        
        if (idx >= maxlen)
            break;
        }    
   
    // Restore terminal attributes
    tcsetattr(0, TCSANOW, &oldt);
         
    if(debuglev > 9)      
        printf("\ngot pass '%s'\n", passptr);  
        
        
    printf("\n");    
    return ret;
    
    #endif

}

//////////////////////////////////////////////////////////////////////////
// Get pass

int getpass2(getpassx *passx)

{   
    int ret = TRUE, try = 0;

    debuglev = passx->debug;
    
    if(passx->debug > 0)
        {
        //printf("getpass2(): entered\n");
        }
        
    if(passx->maxlen == 0)
        {
        if(passx->debug > 1)
            printf("getpass2(): cannot have maxlen == 0\n");
        return -1;
        }
        
    char  *ppp = zalloc(passx->maxlen + 1);
    if(ppp == NULL)
        {
        if(passx->debug > 1)
            printf("getpass2(): cannot allocate mem\n");
        return -1;
        }
    
    while((TRUE))
        {
        ret = dibagetpass(passx->prompt, ppp, passx->maxlen);
        if (ret < 0)
            {
            ret = -1;
            break;
            }    
        if(try++ >= ALLOW_TRIES)
            {
            printf("Too many tries, giving up\n");
            ret = -1;
            break;
            }
        if(!passx->weak)
            {
            if(strlen(ppp) < passx->minlen)
                printf("Must be %d characters or more, try again.\n", passx->minlen);
            else if(getstrength(ppp) < passx->strength)
                printf("Pass must have upper and lower case letters and numbers, try again.\n");
            else
                break;
            }
        else
            {
            if(strlen(ppp) <= 0)
                printf("Cannot use empty pass, try again.\n");
            else
                break;
            }
        }
    if(ret < 0)
        {
        zfree(ppp);
        return ret;   
        }
           
    if(passx->nodouble == FALSE)
        {
        char  *ppp2 = zalloc(passx->maxlen + 1);
        int try2 = 0;
        while((TRUE))
            {
            ret = dibagetpass(passx->prompt2, ppp2, passx->maxlen);
            if(ret < 0)
                break;
                
            if(strcmp(ppp, ppp2) == 0)
                break;
            
            if(try2++ >= ALLOW_TRIES)
                {
                printf("Too many tries, giving up\n");
                ret = -1;
                break;
                }
            printf("Passes do not match, try again.\n");
            }
         zfree(ppp2);
         }
         
    if(passx->debug > 9)
        printf("ppp '%s' maxlen %d", ppp, passx->maxlen);     
        
    if(ret >= 0)
        {
        strncpy(passx->pass, ppp, passx->maxlen);
        }
    zfree(ppp); 
    
    debuglev = 0;
    
    return ret;
}

// EOF


