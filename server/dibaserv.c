    
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
#include <stdio.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "diba.h"
#include "gcrypt.h"
#include "gcry.h"
#include "getpass.h"
#include "gsexp.h"
#include "base64.h"
#include "zmalloc.h"
#include "cmdline.h"
#include "dibastr.h"
#include "misc.h"
#include "zstr.h"
#include "dibafile.h"

static  unsigned int keysize = 2048;

static int weak = FALSE;
static int force = FALSE;
static int dump = 0;
static int verbose = 0;
static int test = 0;
static int stay_fg = 0;
static int calcsum = 0;
static int version = 0;
static int debuglevel = 0;
static int loglevel = 0;
static int port = 6789;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 8;

static char descstr[] = "Listen for DIBA requests. ";
static char usestr[]  = "dibaserv [options]\n";
                
static char    *errout   = NULL;
static char    *term  = NULL;

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {

        'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
        "-v             --verbose     - Verbosity on (def: off)",
        
        'V',   "version",  NULL, NULL,  0, 0, &version, 
        "-V             --version     - Print version numbers and exit",
        
        'd',   "debug",   &debuglevel, NULL, 0,  10, NULL,  
        "-d             --debug       - Debug level (0-10) (def: 0-none)",

        'p',   "port",   &port, NULL, 0,  10, NULL,  
        "-p             --port        - port to listen on (def: 6789)",

        'l',   "loglevel",   &loglevel, NULL, 0,  10, NULL,  
        "-l             --loglevel    - Logging level (0-10) (def:0-none)",

        'u',   "dump",  NULL, NULL,  0, 0,    &dump, 
        "-u             --dump        - Dump key to log / terminal",
        
        't',   "test",  NULL,  NULL, 0, 0, &test, 
        "-t             --test        - Run self test before proceeding",
        
        's',   "sum",  NULL,  NULL, 0, 0, &calcsum, 
        "-s             --sum         - Print sha sum before proceeding",
        
        'r',   "term",  NULL,  &term, 0, 0, NULL,
        "-r term        --term tname  - Debug to terminal (ex: /dev/pty1)",

        'e',   "errout",  NULL,  &errout, 0, 0, NULL, 
        "-e fname       --errout fnme - Dup stderr to file. (for GUI)",
       
        'f',   "foreground",  NULL,   NULL, 0, 0, &stay_fg, 
        "-f             --foreground  - Stay in foreground",
       
        0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
        };


void my_progress_handler (void *cb_data, const char *what,
                            int printchar, int current, int total)
{
    printf(".");
    //printf("%c", printchar);
}

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

static void myfunc2(int sig)
{
    if(stay_fg) 
        {
        printf("Terminating on signal %d\n", sig);
        fflush(stdout);
        exit(111);
        }
        
    // Ignore, reset
    signal(sig, myfunc2);
}

    
int unixfork(char *cmd, int ClientSocket)

{
    pid_t pid = fork();
    
    if(pid == 0)
        {
        // Child
        //printf("Forked, ret=%d\n", pid);
        struct sockaddr_in saddr;
        socklen_t  addrlen = sizeof(saddr);
        int retp = getpeername(ClientSocket,  
                                  (struct sockaddr *)&saddr, &addrlen);
        if(retp < 0)
            {
            printf("Error on getpeername. %d (errno %d %s)\n", 
                                retp, errno, strerror(errno));
            } 
        char *ipstr = inet_ntoa(saddr.sin_addr);
        int ppp = ntohs(saddr.sin_port);
        
        printf("Connection from: %s on port %d\n", ipstr, ppp);
        
        //printf("exec %s %s %s %s %s %s %s %s\n",
        //        cmd, cmd, "-d", tmp, "-l", tmp2, "-r", term);
        
        //pid_t pid2 = fork();
        
        //if(pid2 < 0)
        //    {
        //    printf("Could not second fork %s ret=%d\n", cmd, pid2);
        //    return -1;
        //    }
        if(pid == 0)
            {
            if (setsid() < 0)
                {
                printf("Could not set session leader.\n");
                exit(EXIT_FAILURE);
                }
            // Reshuffle fp-s
            close(0); close(1); close(2);
            dup2(ClientSocket, 0); 
            dup2(ClientSocket, 1);
            dup2(ClientSocket, 2);
         
            // Pass debug level and log level and terminal string to client       
            char tmp[12], tmp2[12];
            snprintf(tmp, sizeof(tmp), "%d", debuglevel);
            snprintf(tmp2, sizeof(tmp2), "%d", loglevel);
            int ret = execl(cmd, cmd, "-d", tmp, "-l", tmp2, "-r", term, NULL);
            
            // Not reached
            printf("Could not exec %s ret=%d\n", cmd, ret);
            exit(0);
            }
        // First parent exit
        exit(0);     
        }
    if(pid > 0)
        {
        printf("Started child process %d\n", pid);
        }
    return pid;    
}

// -----------------------------------------------------------------------
// Chain to err routine, dup error to file first 
// See if any other freeing action is requested

void    xerr3(const char *str, ...)

{
    va_list ap;
    va_start(ap, str);    
    
    FILE* errf = fopen(errout, "wb");
    // Ignore error, empty or non existant file will indicate error to caller
    if (errf) {
        vfprintf(errf, str, ap);
            fclose(errf);
    }
    
    va_list ap2;
    va_start(ap2, str);    
    xerr2(str, ap2); 
}
    
// -----------------------------------------------------------------------

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);
    signal(SIGINT, myfunc2);
    // Stops the parent waiting for the child process
        signal(SIGCHLD, SIG_IGN); 
        
    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();
    
    // Pre allocate all string items    
    //char *mstr = "No Memory";
    zline2(__LINE__, __FILE__);
    errout   = zalloc(MAX_PATH); if(errout   == NULL) xerr3(mstr);
    term     = zalloc(MAX_PATH); if(term     == NULL) xerr3(mstr);
    
    char *err_str = NULL;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    
    if(debuglevel > 0)
        {
        //printf("Processed %d comline entries\n", nn);
        printf("Term='%s' ", term);
        printf("Debug=%d ", debuglevel);
        printf("Log=%d ", loglevel);
        printf("FG=%d\n", stay_fg);
        }
    
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data); exit(2);
        }
    if(errout[0] != '\0')
        {
        //printf("removing %s\n", errout);
        unlink(errout);
        }
    if(version)
        {
        printf("dibaserv version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
        exit(1);
        }
    if(num_bits_set(keysize) != 1)
        {
        xerr3("dibaserv: Keysize must be a power of two. ( ... 1024, 2048, 4096 ...)");
        } 
    gcrypt_init();

    if(calcsum)
        {
        char *err_str, *hash_str = hash_file(argv[0], &err_str);
        if(hash_str != NULL)
            {
            printf("Executable sha hash: '%s'\n", hash_str);
            zfree(hash_str);
            }
        else 
            {
            xerr3("dibaserv: %s\n", err_str);
            }
        }
    
    if(test)
        {
        printf("Excuting self tests ... ");
        gcry_error_t err = 0;
        err = gcry_control(GCRYCTL_SELFTEST);
        if(err)
            {
            printf("fail.\n");
            exit(3);
            }
        else
            {
            printf("pass.\n");
            }
        }
   
    // Touch logfile (for debug)
    FILE *logfp = fopen("dibaserv.log", "ab+");
    if(!logfp)
        {
        xerr2("Cannot open log file.\n");
        }
    fclose(logfp);
    
    #if 0
    // Daemonize
    if(!stay_fg)
        {
        int fd0 = open("/dev/null", O_RDWR);
        if(fd0 < 0)
            {
            xerr2("Cannot open nul file.\n");
            }
        dup2(fd0, 0);
        dup2(fd0, 1);
        dup2(fd0, 2);
        }
    #endif
    
    int   welcomeSocket, newSocket;
    char  buffer[1024];
    struct sockaddr_in serverAddr;
    struct sockaddr_storage serverStorage;
    socklen_t addr_size;
    
    welcomeSocket = socket (PF_INET, SOCK_STREAM, 0);
    
    if (setsockopt(welcomeSocket, SOL_SOCKET, SO_REUSEADDR, 
                    &(int){ 1 }, sizeof(int)) < 0)
        {
        xerr2("setsockopt(SO_REUSEADDR) failed");
        }
    
    /*---- Configure settings of the server address struct ----*/
    serverAddr.sin_family = AF_INET;
    /* Set port number, using htons function to use proper byte order */
    serverAddr.sin_port = htons(port);
    
    /* Set IP address to localhost */
    //serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    //serverAddr.sin_addr.s_addr = inet_addr(INADDR_ANY);
    serverAddr.sin_addr.s_addr = inet_addr("0.0.0.0");
    
    /* Set all bits of the padding field to 0 */
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  
    
    /*---- Bind the address struct to the socket ----*/
    int err = bind(welcomeSocket, (struct sockaddr *) &serverAddr, 
                            sizeof(serverAddr));
    if(err < 0)
       xerr2("Error on socket bind. %d (errno %d %s)\n", 
                            err, errno, strerror(errno));
    
    /*---- Listen on the socket, with 5 max connection requests queued ----*/
    
    if(debuglevel > 0)
        printf("Server stared. (pid=%d) \n", getpid());
    while(1)
        {
        err = listen(welcomeSocket, 5);
        if(err)
            xerr2("Error on socket listening. %d (errno %d %s)\n", 
                                err, errno, strerror(errno));
      
        if(debuglevel > 0)  
            printf("Listening on port %d .... \n", port);
        
        // Force a fault to test log response on fault
        //int *nullp = NULL;
        //*nullp = 1;
        
        /*----  the incoming connection ----*/
        addr_size = sizeof serverStorage;
        newSocket = accept(welcomeSocket, (struct sockaddr *) &serverStorage,
                             &addr_size);
        if(newSocket < 0)
            xerr2("Error on socket accept. %d (errno %d %s)\n", 
                                err, errno, strerror(errno));
        
        //printf("Accepted connection from on handle: %d\n", newSocket);
        
        pid_t chh = unixfork("./dibaworker.exe", newSocket);
        
        if(chh == -1)
            {
            // Child
            printf("Child could not fork. err %d\n", chh);
            }
        }
    zfree(errout);
    zfree(term);
    zfree(dummy);
    zleak();
    return 0;
}

/* EOF */














