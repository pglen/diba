
/* =====[ DibaBuff.h ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank]. Diba package files.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  nov.05.2017     Peter Glen      Initial version.
      
   ======================================================================= */

//# Do not change these defines, add at the end if needed

#define	CHUNK_HEADER	1
#define	CHUNK_COMMENT   2
#define	CHUNK_OBJECT	3
#define	CHUNK_TEXT		4
#define	CHUNK_IMAGE		5
#define	CHUNK_EMAIL		6
#define	CHUNK_FNAME 	7
#define	CHUNK_TRAIL		8
#define	CHUNK_AUTHOR	9
#define	CHUNK_BINARY	10
#define	CHUNK_DATE		11
#define	CHUNK_LABEL		12
#define	CHUNK_FOOTER	13

// Flag to signify if it is a key
#define	CHUNK_KEY	    0x80
#define	CHUNK_ZIPPED    0x800

#define BUFFSIZE	    4096      // Common cluster size
#define CHUNKSIZE	    30        // Add header str len together
#define MINCHSIZE       12        // Smallest chunk header

// Do NOT change these lines, will cause read / iden failure

#define	CHUNK_HEADER_STR   "\nDIBA %x %x %x\n"  	
#define	FILE_HEADER_STR    "Diba File. Version: %d Subversion %d\n"

typedef struct _chunk_keypair
{
    char *key;
    int klen; 
    char *val; 
    int vlen; 
    int compressed;

}  chunk_keypair;

typedef struct _dibabuff
{
    char *ptr;
    int   clen;     // Current length              
    int   mlen;     // Malloc length
    int   pos; 
}  dibabuff;

unsigned int calc_buffer_sum(const char *ptr, int len);

// Diba Files

void    SetDibaBuffDebug(int level);
int     OpenDibaBuff(dibabuff *pbuff, char **err_str);

char*   FindNextDibaBuffKey(dibabuff *pbuff, int *len, char **err_str);
char*   GetNextDibaBuffChunk(dibabuff *pbuff,  int *len, int *type, char **err_str);
void    RewindDibaBuff(dibabuff *pbuff);
int     CloseDibaBuff(dibabuff *pbuff);

int     PutDibaBuffKeyVal(dibabuff *pbuff,  chunk_keypair *ptr, char **err_str);
int     GetDibaBuffKeyVal(dibabuff *pbuff, chunk_keypair *ptr, char **err_str);

// Lower level

int     GetDibaBuffSection(dibabuff *pbuff, int *len, int *type, int *sum);
int     PutDibaBuffSection(dibabuff *pbuff, const char *ptr, int len, int type);






