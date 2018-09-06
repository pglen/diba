
/* =====[ dibacom.h ]=========================================================

   Description:     Common file for diba buffer

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug.26.2018     Peter Glen      Initial version.
      
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

#define	CHUNK_CHUNK 	20

// Flag to signify if it is a key
#define	CHUNK_KEY	    0x80
#define	CHUNK_ZIPPED    0x800

#define BUFFSIZE	    1024      // Common alloc size
#define CHUNKSIZE	    30        // Add header str len together
#define MINCHSIZE       12        // Smallest chunk header

// Do NOT change these lines, will cause read / identity failure

#define	CHUNK_HEADER_STR   "\nDIBA %x %x %x\n"  	
#define	FILE_HEADER_STR    "Begin Diba File. Ver: %d Sub: %d\n"
#define	FILE_FOOTER_STR    "End Diba File.\n"
 
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

// EOF



