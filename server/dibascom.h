
/* =====[ dibascom.h ]=========================================================

   Description:     Common components for server.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jan.1.2018      Peter Glen      Initial version.

   ======================================================================= */

#define STRSIZE(sss) (strlen(sss) - 1)
#define DEFSOCKBUFFLEN 4096
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

typedef struct _session_key
{
    gcry_sexp_t *privk, *plain; 
    char    *buffer;
    int     blen;
    char    *randkey;
    int     klen;
    int     got_sess;
} session_key;

int    close_conn(int clsock, int got_sess, char *rand_key);

#define ZERO_HANDSHAKE_STRUC(ptr) memset(ptr, '\0', sizeof(handshake_struct));
int     handshake(handshake_struct *hs);

void    scom_set_debuglevel(int level);
int     scom_send_data(int socket, const char *str, int len, int uw);
int     scom_recv_data(int sock, char *buff, int len, int ur);

int     print2sock(int sock, int uw, char *fmt, ...);
char    *bp3_encrypt_cp(cchar *buff, int len, cchar *key, int klen, int *outx);

int     decrypt_session_key(session_key *sk);

int     hostname_to_ip(char *hostname, char *ip, int lim);

// EOF
















