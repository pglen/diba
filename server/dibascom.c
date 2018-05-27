
/* =====[ dibascom.c ]=========================================================

   Description:     Common components for server.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jan.1.2018      Peter Glen      Initial version.

   ======================================================================= */

#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <time.h>

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
#include "dibascom.h"
#include "bluepoint3.h"

// -------------------------------------------------------------------
// Server strings, client uses the same ones 
// We define them as char arrays, so sizeof will yield correct
// Lengths (see macro: STRSIZE)

// -------------------------------------------------------------------
// Server handshake definitions:

char hellostr[] = "Hello from DIBA server.";
char keystr[]   = "OK Send public key.";
char nocmd[]    = "No such command.";
char endstr[]   = "OK Bye from DIBA server.";
char okstr[]    = "OK";
char nostr[]    = "NO";
char errstr[]   = "ERROR";
char fatstr[]   = "FATAL";
char unkstr[]   = "UKNOWN";

// Commands:

char closecmd[] = "close";
char checkcmd[] = "check";
char keycmd[]   = "key";
char sesscmd[]  = "session";
char echocmd[]  = "echo";
char noopcmd[]  = "noop";

//////////////////////////////////////////////////////////////////////////
// Send data. The UW flag instructs to use write instead of send. 
// The server will use write as the worker recives the socket 
// as a handle, the client will use send as it is a socket.
// Not strickly needed, but makes for a cleaner transfer.

int send_data(int socket, const char *str, int len, int uw)

{
    int ret = 0, ret2 = 0;
    if(len >= SHRT_MAX)
        {
        printf("Cannot send larger than MAXSHORT\n");
        }
    
    short  xlen = (short)len & 0xffff;
    //printf("Sending %d bytes\n", xlen);
    
    if(uw)
        ret2 += write(socket, (const char*)&xlen, sizeof(short));
    else
        ret2 += send(socket, (const char*)&xlen, sizeof(short), 0);
        
    // TEST, send one char at a time
    //ret += send(socket, (const char*)&xlen, 1, 0);
    //ret += send(socket, (const char*)&xlen + 1, 1, 0);
    //for(int aa = 0; aa < len; aa++)
    //    {
    //    ret += send(socket, &(str[aa]), 1, flag);
    //    }
        
    if(uw)
        ret += write(socket, str, len);
    else
        ret += send(socket, str, len, 0);
        
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Receive length and data.
// Structure of receive: lenght (type short) bytes (len bytes)
// If short is negative, error
// If no response within timout, the process sends FATAL
// and the server termnates, after attemts to close connection.

int recv_data(int socket, char *buff, int len, int ur)

{
    int ret3, ret2, idx2 = 0;
    short xlen = 0; 
    
    //fprintf(stderr, "recv_data: %p %d\n", buff, len);
    
    if(ur)
        ret3 = read(socket, (char*)&xlen, sizeof(short));
    else
        ret3 = recv(socket, (char*)&xlen, sizeof(short), 0);
        
    if(ret3 <= 0)
        {
        return ret3;
        }
    // In case it only read one char
     if (ret3 < sizeof(short))
        {
        char *ppp = (char*)(((char*)&xlen) + ret3);
        if(ur)
            ret3 += read(socket, ppp, sizeof(short) - ret3);
        else
            ret3 += recv(socket, ppp, sizeof(short) - ret3, 0);
        } 
        
    //fprintf(stderr, "Got len: %d\n", xlen &0xffff);
    
    while(1)
        {
        if(ur)
            ret2 = read(socket, buff + idx2, len - idx2);
        else
            ret2 = recv(socket, buff + idx2, len - idx2, 0);
        if(ret2 < 0)
            {
            return idx2;
            }
        idx2 += ret2;
            
        //fprintf(stderr, "all: '%.*s'\n", idx2, buff);
        
        if(idx2 >= xlen)
            break;
        }
        
    if(idx2 < len)
        buff[idx2] = '\0';
        
    return idx2;      
}

// Assemble and send a socket string

int print2sock(int sock, int uw, char *fmt, ...)

{
    va_list ap;  va_start(ap, fmt);    
    
    char *buff = zalloc(DEFSOCKBUFF);
    if(!buff)
        return -1;
    int ret = vsnprintf(buff, DEFSOCKBUFF, fmt, ap);
    int ret2 = send_data(sock, buff, strlen(buff), uw);
    
    zfree(buff);
    return ret2;
}

//////////////////////////////////////////////////////////////////////////
// Encrypt and hex buffer.
// The windows version choked on binary, so we base16 them
// It adds 4/3 (33%) data, but this way it is multi platform
// capable with no modifications

char *bp3_encrypt_cp(cchar *buff, int len, cchar *key, int klen, int *outx)

{
    char *xptr = zalloc(len + 1);
    if(!xptr) return NULL;
    memcpy(xptr, buff, len);
    bluepoint3_encrypt(xptr, len, key, klen);
    char *mem3 = base_and_lim(xptr, len, outx);
    zfree(xptr);
    return(mem3);
}

//typedef struct _handshake_struct
//{
//    int     sock; 
//    cchar   *sstr; 
//    int     slen; 
//    char    *buff;
//    int     rlen;
//    int     debug;
//    char    *rand_key;
//    int     got_session;
//} handshake_struct;

//////////////////////////////////////////////////////////////////////////
// Play forward one handshake iteration
// Send / Recv
// Return -1 if error or fatal response

//int     handshake(int sock, cchar *sstr, int slen, char *buff, int rlen)

int  handshake(handshake_struct *hs)

{
    int rets = 0;
    // Quick check
    if(hs->rlen <= 0 || hs->buff == NULL)
        {
        if(hs->debug > 0)
           printf("Invalid parameters\n");
        return -1;
        }
    
    *hs->buff = '\0'; 
    // If session, encrypt
    if(hs->got_session)
        {
        int outx;                    
        char *xptr = bp3_encrypt_cp(hs->sstr, hs->slen, 
                        hs->rand_key, strlen(hs->rand_key), &outx);
        rets = send_data(hs->sock, xptr, outx, 0);
        zfree(xptr);
        }
    else
        {
        rets = send_data(hs->sock, hs->sstr, hs->slen, 0);
        }
    if(rets <= 0)
        {
        if(hs->debug > 0)
           printf("handshake: Could not send data: '%.*s'\n", min(36, rets), hs->sstr);   
        return rets;
        }
    if(hs->debug > 8)
        printf("handshake: Data sent: '%.*s'\n", min(64, rets), hs->sstr);   
    
    // Get answer
    int retr = recv_data(hs->sock, hs->buff, hs->rlen, 0);
    if(retr <= 0)
        {
        if(hs->debug > 0)
            printf("handshake: Could not recv data: '%.*s'\n", min(64, retr), hs->buff);   
        return retr;
        }
    // If session, decrypt
    if(hs->got_session)
        {
        int data_len; char *data_buff;
        data_buff = unbase_and_unlim(hs->buff, retr, &data_len);
        bluepoint3_decrypt(data_buff, data_len, 
                        hs->rand_key, strlen(hs->rand_key));
        // Put it back to buffer and len
        memcpy(hs->buff, data_buff, data_len);       
        retr = data_len;    
        zfree(data_buff);
        }
    // Error return if fatal recived
    if(strncmp(hs->buff, fatstr, strlen(fatstr) - 1) == 0)
        {
        if(hs->debug > 0)
            printf("handshake: Fatal %s\n", hs->buff);
        return -1;
        }
    if(hs->debug > 8)
        printf("handshake: Data recd: '%.*s'\n", min(64, retr), hs->buff);   
    return retr;
}

//////////////////////////////////////////////////////////////////////////
// Session key is back, decrypt it

char *decrypt_session_key(gcry_sexp_t *privk, char *buffer, int len)

{
    char *ret = 0;
    gcry_error_t err = 0;  int data_len;
    char *data_buf = unbase_and_unlim(buffer + 3, len - 3, &data_len);
    
    /* Create a message. */
    gcry_sexp_t ciph;
    err = gcry_sexp_build(&ciph, NULL, 
                                "(enc-val (rsa (a %b)))", 
                                    data_len, data_buf );
    if(err)
        {
        //xerr3("dibaclient: sexp build failed");
        ret = NULL;
        return ret;
        }
            
    //sexp_print(ciph);
    zfree(data_buf);
        
    /* Decrypt the message. */
    gcry_sexp_t plain;  gcry_error_t gerr;
    gerr = gcry_pk_decrypt(&plain, ciph, *privk);
    if(gerr)
        {
        //xerr3("dibaclient: cannot decrypt session key.");
        ret = NULL;
        return ret;
        }
    //sexp_print(plain);
    int plen;
    ret = sexp_nth_data(plain, 0, &plen);
    
    //if(debug > 5)
    //    printf("Session (random) key: '%s'\n", randkey);
        
    return ret;
}

// EOF








