// Test terminal stuff

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>    
#include <windows.h>
#include <locale.h>

#include <termios.h>

#define READ_INTR -1

struct termios oldt;
 
void resetterm()

{
    tcsetattr(0, TCSANOW, &oldt);
}    
//struct termios oldterm;
 
int main()

{
    setlocale(LC_ALL, "");
     
    //setvbuf (stdout, NULL, _IONBF, 0);
    //setvbuf (stdin, NULL, _IONBF, 0);
    
    printf("Test keyboard routine isatty=%d\n", isatty(1)); fflush(stdout);  
    
    struct termios newt;
    
    tcgetattr(STDIN_FILENO, &oldt); /* store old settings */
    newt = oldt; 
    /* make changes to in new settings */
    newt.c_lflag &= ~(ICANON | ECHO | ECHONL | ISIG ); 
    newt.c_oflag &= ~(OPOST);
    newt.c_iflag &= ~(IXON | ICRNL);
    
    int ret = tcsetattr(STDIN_FILENO, TCSANOW, &newt); 
    printf("Return  from setettr %d\r\n", ret);
    
    atexit(resetterm);
    while(1)
        {   
        int ddd = 0; 
        ddd = getchar();
        printf("'%c' %d\r\n", ddd, ddd); 
        //sleep(0.3);
        if(ddd == 27)
            {
            int dddd = getchar();
            int dddd2 = getchar();
            printf("esc '%c' %d\r\n", dddd2, dddd2); 
            }
        if(ddd == 'q')
            {
            break;
            }
        }
    return 0;
    }
// EOF




