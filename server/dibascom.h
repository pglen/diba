
/* =====[ dibascom.h ]=========================================================

   Description:     Common components for server.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jan.1.2018      Peter Glen      Initial version.

   ======================================================================= */

#define STRSIZE(sss) (strlen(sss) - 1)
#define DEFSOCKBUFF 4096
#define RANDKEY_LENGTH 128

typedef const char cchar;

extern char hellostr[];
extern char keystr[];
extern char nocmd[];
extern char endstr[];

extern char okstr[];
extern char nostr[];
extern char errstr[];
extern char fatstr[];
extern char unkstr[];

// Commands:

extern char closecmd[];
extern char checkcmd[];
extern char keycmd[] ;
extern char sesscmd[];
extern char echocmd[];

typedef const char cchar;

typedef struct _handshake_struct
{
    int     sock; 
    cchar   *sstr; 
    int     slen; 
    char    *buff;
    int     rlen;
    int     debug;
    char    *rand_key;
    int     got_session;
    
} handshake_struct;

int send_data(int socket, const char *str, int len, int uw);
int recv_data(int sock, char *buff, int len, int ur);
int print2sock(int sock, int uw, char *fmt, ...);
char *bp3_encrypt_cp(cchar *buff, int len, cchar *key, int klen, int *outx);
int  handshake(handshake_struct *hs);

char *decrypt_session_key(gcry_sexp_t *privk, char *buffer, int len);

// EOF










