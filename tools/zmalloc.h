
/* =====[ zmalloc.h ]=========================================================

   Description:     Encryption examples. Feasability study for diba 
                    [Digital Bank]. Testing libgcrypt library.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.23.2017     Peter Glen      Initial version.
      0.00  jul.24.2017     Peter Glen      Added

   ======================================================================= */

// Public entry points

void *zalloc(unsigned int msize);
void *zrealloc(void *ptr, unsigned int msize);
void zfree(void *mem);

// Convenience

void zautofree(void);

// Informational 

void zline(int line);
void zline2(int line, const char *fname);
void zverbose(int flag);

void zcheck(void *mem, int line);
void zfree2(void *mem, int line);

// Tweeking
extern void *zmalloc_zarr[];
extern int  zmalloc_sum_on;
extern int  zmalloc_verbose_on;

int  zleak();
int  zleakfp(FILE *fp);

// EOF









