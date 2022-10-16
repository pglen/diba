    
/* =====[ dibaserv.c ]=========================================================

   Description:     Server process for DIBA. Will spawn worker process.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  dec.21.2017     Peter Glen      Initial
      
   ======================================================================= */

#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <windows.h>
#include <ntdef.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

 #include <setjmp.h>

jmp_buf env;
    
static int resume;

static void myfunc(int sig)
{
    //signal(sig, myfunc);
    printf("\nSignal %d (segment violation)\n", sig);
    //exit(111);

    longjmp(env, 1);
}

static void myfunc2(int sig)
{
    // Ignore, reset
    //signal(sig, myfunc2);
    //exit(111);
}

// Test case for exception

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);
    signal(SIGINT, myfunc2);
    
    //signal(SIGTERM, myfunc2);
    //signal(SIGCHLD,SIG_IGN); /* ignore child */
	//signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
	//signal(SIGTTOU,SIG_IGN);
	//signal(SIGTTIN,SIG_IGN);
	//signal(SIGHUP,myfunc); /* catch hangup signal */

    printf("exception handler\n");
    
    int err = setjmp(env);
    printf("err = %d\n", err);
    if(err == 0)
        {
        // Do something to raise exception
        int *nnn = 0;
        //*nnn = 1;
        }
        
    printf("post exception\n");
    
    return 0;
}

/* EOF */



