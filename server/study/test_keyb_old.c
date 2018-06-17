// Test terminal stuff

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>    
#include <windows.h>
#include <locale.h>

//#include <conio.h>
             
#include <ncurses/curses.h>
#include <termios.h>

#define READ_INTR -1

//termios oldterm;

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

static DWORD console_mode = 0;
static int keyCount = 0;
static int tty;
static int pending_scancode = 0;

struct keyRecord
{
        int ascii;
        int scan;
} currentKey;

#if 0
/*
 * Determine whether an input character is waiting to be read.
 */

static int win32_kbhit(tty)
        HANDLE tty;
{
        INPUT_RECORD ip;
        DWORD read;

        if (keyCount > 0)
                return (TRUE);

        currentKey.ascii = 0;
        currentKey.scan = 0;


        /*
         * Wait for a real key-down event, but
         * ignore SHIFT and CONTROL key events.
         */
        do
        {
                PeekConsoleInput(tty, &ip, 1, &read);
                if (read == 0)
                        return (FALSE);
                ReadConsoleInput(tty, &ip, 1, &read);
        } while (ip.EventType != KEY_EVENT ||
                ip.Event.KeyEvent.bKeyDown != TRUE ||
                ip.Event.KeyEvent.wVirtualScanCode == 0 ||
                ip.Event.KeyEvent.wVirtualKeyCode == VK_SHIFT ||
                ip.Event.KeyEvent.wVirtualKeyCode == VK_CONTROL ||
                ip.Event.KeyEvent.wVirtualKeyCode == VK_MENU);

        currentKey.ascii = ip.Event.KeyEvent.uChar.AsciiChar;
        currentKey.scan = ip.Event.KeyEvent.wVirtualScanCode;
        keyCount = ip.Event.KeyEvent.wRepeatCount;

 if (ip.Event.KeyEvent.dwControlKeyState &
                (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED))
        {
                switch (currentKey.scan)
                {
                case PCK_ALT_E:     /* letter 'E' */
                        currentKey.ascii = 0;
                        break;
                }
        } else if (ip.Event.KeyEvent.dwControlKeyState &
                (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED))
        {
                switch (currentKey.scan)
                {
                case PCK_RIGHT: /* right arrow */
                        currentKey.scan = PCK_CTL_RIGHT;
                        break;
                case PCK_LEFT: /* left arrow */
                        currentKey.scan = PCK_CTL_LEFT;
                        break;
                case PCK_DELETE: /* delete */
                 currentKey.scan = PCK_CTL_DELETE;
                        break;
                }
        } else if (ip.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED)
        {
                switch (currentKey.scan)
                {
                case PCK_SHIFT_TAB: /* tab */
                        currentKey.ascii = 0;
                        break;
                }
        }

        return (TRUE);
}

#endif

/*
 * Read a character from the keyboard.
 */

#if 0

char    WIN32getch(int tty)
{
    int ascii;
    
    if (pending_scancode)
    {
            pending_scancode = 0;
            return ((char)(currentKey.scan & 0x00FF));
    }
    
    while (win32_kbhit((HANDLE)tty) == FALSE)
    {
            Sleep(20);
            if (ABORT_SIGS())
                    return ('\003');
            continue;
    }
    keyCount --;
    ascii = currentKey.ascii;
    /*
     * On PC's, the extended keys return a 2 byte sequence beginning
     * with '00', so if the ascii code is 00, the next byte will be
     * the lsb of the scan code.
     */
    pending_scancode = (ascii == 0x00);
    return ((char)ascii);
}    

#endif

int getchr2(HANDLE hInput)
{
    char    cc;
    int     result = 0;
    DWORD   read = 0;
    INPUT_RECORD ip;
    
    while(1)
        {
        PeekConsoleInput(hInput, &ip, 1, &read);
        if (read != 0)
            {        
            //int ret = ReadConsole(hInput, &result, sizeof(int), &read, NULL);
            int ret = ReadConsoleInput(hInput, &ip, 1, &read);
            cc = ip.Event.KeyEvent.uChar.AsciiChar;
            printf("Got key '%d' -> read = %d ret %d\n", result, read, ret); 
            fflush(stdout);
            }
        else
            {
            cc = ip.Event.KeyEvent.uChar.AsciiChar;
            printf("no key '%c'\n", cc);
            fflush(stdout);
            }    
        sleep(1);
        }
    
    return (int)cc;
}

#if 0

unsigned int input(){

    unsigned int input_data;
    if (_kbhit()){
        input_data = (unsigned int)_getch();
    }
    else{
        input_data = 0;
    }
    return input_data;
}

#endif

char tmp[128];

CHAR GetCh (VOID)
{
  HANDLE hStdin = GetStdHandle (STD_INPUT_HANDLE);
  INPUT_RECORD irInputRecord;
  DWORD dwEventsRead;
  CHAR cChar;

  while(ReadConsoleInputA (hStdin, &irInputRecord, 1, &dwEventsRead)) /* Read key press */
    if (irInputRecord.EventType == KEY_EVENT
	&&irInputRecord.Event.KeyEvent.wVirtualKeyCode != VK_SHIFT
	&&irInputRecord.Event.KeyEvent.wVirtualKeyCode != VK_MENU
	&&irInputRecord.Event.KeyEvent.wVirtualKeyCode != VK_CONTROL)
    {
	ReadConsoleInputA (hStdin, &irInputRecord , 1, &dwEventsRead); /* Read key release */
    cChar = irInputRecord.Event.KeyEvent.uChar.AsciiChar;
	return cChar;
    }
  return EOF;
}
//////////////////////////////////////////////////////////////////////////

 struct termios oldterm;
 
int main()

{
    tcgetattr(0, &oldterm);
    
    //setlocale(LC_ALL, "");
    //initscr(); 
    cbreak(); noecho();
     
    //setvbuf (stdout, NULL, _IONBF, 0);
    //setvbuf (stdin, NULL, _IONBF, 0);
    
    printf("Test keyboard routine isatty=%d\n", isatty(1)); fflush(stdout);  

    #if 1
    while(1)
        {   
        int ddd = 0; 
        //if (_kbhit())
        //    {
        //    ddd = (int)_getch();
        //    }
        ddd = getch();
        printf("%c %d\n", ddd, ddd); 
        sleep(1);
        }
    #endif
    
    
    tcsetattr(0, TCSANOW, &oldterm);
    
    return 0;
    //getch(); //hitkb();
    
    ///char ccc; // = input();
    //printf("got key '%c'\n", ccc);  
    
    //printf("ENABLE_LINE_INPUT %u\n", ENABLE_LINE_INPUT);
	//printf("ENABLE_ECHO_INPUT %u\n", ENABLE_ECHO_INPUT);
	//printf("ENABLE_PROCESSED_INPUT %u\n", ENABLE_PROCESSED_INPUT);
	//printf("ENABLE_PROCESSED_OUTPUT %u\n", ENABLE_PROCESSED_OUTPUT);
	//printf("ENABLE_WRAP_AT_EOL_OUTPUT %u\n", ENABLE_WRAP_AT_EOL_OUTPUT);
    //AllocConsole();
    //freopen("CONIN$", "r", stdin); 
    //freopen("CONOUT$","w", stdout); 
    //freopen("CONOUT$","w", stderr);  
    
    HANDLE hInput;
    //hInput = GetStdHandle(STD_INPUT_HANDLE);
    //fflush(stdout);  
    
    #if 0
    /* Need this to let child processes inherit our console handle */
    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    hInput = CreateFile("CONIN$", GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                    OPEN_EXISTING, 0L, NULL);
    printf("hInput %d (%d)\n", hInput, INVALID_HANDLE_VALUE);  
                    
    int rret = GetConsoleMode(hInput, &console_mode);
    printf("getconsolemode rret = %d mode = %x\n", rret, console_mode);  
    fflush(stdout);  
    
    /* Make sure we get Ctrl+C events. */
    
    //SetConsoleMode((HANDLE)tty, ENABLE_PROCESSED_INPUT);
    //console_mode |= ENABLE_PROCESSED_INPUT;
    //console_mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    console_mode |= ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT; 
    console_mode &= ~ENABLE_LINE_INPUT;
    //console_mode |= ENABLE_LINE_INPUT;
    console_mode &= ~ENABLE_ECHO_INPUT;
    //console_mode |= ENABLE_ECHO_INPUT;
    
    int ret = SetConsoleMode(hInput, console_mode);
    printf("setconsolemode ret = %d mode %x\n", ret, console_mode);  
    fflush(stdout);  
    #endif
    
    char cccc;
    
    //cccc = GetCh();
    //cccc = _getch();
    //printf("got cccc=%c\n", cccc);  fflush(stdout);  
    
    //scanf("%c", &cccc);
    //printf("Printing  %c\n", cccc);fflush(stdout);
 
    printf("loop\n");fflush(stdout);
    while (1)
        {
        //if(_kbhit())
        //    {
        //    int cc = getch();
        //    printf("got cc=%c\n", cc);  fflush(stdout);  
        //    }
        printf("got delay\n");  fflush(stdout);  
        sleep(1);
        }
    return 0;
}

// EOF

