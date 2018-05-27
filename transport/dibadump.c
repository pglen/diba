
/* =====[ dump.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <unistd.h>

#include "gcrypt.h"
#include "gcry.h"
#include "gsexp.h"
#include "getpass.h"
#include "zmalloc.h"
#include "misc.h"

//////////////////////////////////////////////////////////////////////////

int main(int argc, char** argv)

{
    if (argc != 2) {
        fprintf(stderr, "Usage: dibadump.exe filename\n");
        xerr2("Invalid arguments.");
    }
    
    char* fname = argv[1];
    
    FILE* lockf = fopen(fname, "rb");
    if (!lockf) {
        xerr2("fopen() of file '%s' failed.", fname);
    }

    /* Grab the file */
    
    unsigned int mem_len = getfsize(lockf);
    //printf("File size %d\n", mem_len);
    
    zline(__LINE__);
    void* mem_buf = zalloc(mem_len);
    if (!mem_buf) {
        xerr2("malloc: could not allocate rsa buffer");
    }

    if (fread(mem_buf, mem_len, 1, lockf) != 1) {
        xerr2("fread() failed");
    }
    dump_mem(mem_buf, mem_len);  
    //printf("%s\n", mem_buf);
    zfree(mem_buf);
    zleak();
}





