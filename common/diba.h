
/* =====[ diba.h ]=========================================================

   Description:     Common header for the [Digital Bank] project.
                    Include this after system headers, so it can patch the
                    missing defines like TRUE / FALSE / _MAX_PATH ... etc

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      00.00  Jan.05.2015     Peter Glen      Initial version.
      00.00  Sep.29.2017     Peter Glen      Moved to subdirs
      00.00  Oct.20.2017     Peter Glen      Multi platform defines

   ======================================================================= */

/* -------- Defines: ----------------------------------------------------- */

// This section is for multi platform compile. We identify Win32 by seeing
// the MAX_PATH or WINNT defined, and identify LINUX by seeing 

// Print preprocessor defined value
#define STRING2(xx) #xx
#define STRING(xx) STRING2(xx)

//#ifdef _MAX_PATH
//    #pragma message "_max_path defined, value " STRING(_MAX_PATH)
//#endif 
           
//#ifdef MAX_PATH
//    #pragma message "max_path defined, value " STRING(MAX_PATH)
//#endif            

#ifndef MAX_PATH
    #ifndef PATH_MAX
        // Keep it safe
        #define MAX_PATH 255
    #else
        #define MAX_PATH PATH_MAX
    #endif    
#endif            

#ifndef UINT 
    #define UINT unsigned int
#endif            

#ifndef UCHAR 
    #define UCHAR unsigned char
#endif            

#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif

#define ASSERT  assert

#define TAB 9

#ifndef MIN
#define MIN(a, b) a>b?b:a
#endif

#ifndef MAX
#define MAX(a, b) a>b?a:b
#endif

//#define UCHAR unsigned char
//#define UINT unsigned int

/* -------- Configurables: ----------------------------------------------- */

#define BSIZE 1024          // Number of bytes for one entry (*8 for bits)

#define ASIZE 16            // Leading and trailing fills. 
                            // Yields close to 2 billion tokens

//static char *pass = "digibankdigibankdigibankdigibank";
//static char *pass = "digibank";






