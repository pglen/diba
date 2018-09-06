
/* =====[ dibabuff.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank]. Buffer format code.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
     0.00  nov.05.2017     Peter Glen      Initial version.
     0.00  sep.03.2018     Peter Glen      Buffer ported
 
   ======================================================================= */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "misc.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"
#include "dibabuff.h"

#include "zlib.h"

#ifndef MAX_PATH
    #ifndef PATH_MAX
        // Keep it safe
        #define MAX_PATH 255
    #else
        #define MAX_PATH PATH_MAX
    #endif    
#endif            

static int debuglevel = 0;

int    DumpDIB(dibabuff *pbuff)

{
   printf("Diba buffer %p len=%d mlen=%d\n",
        pbuff->ptr, pbuff->clen, pbuff->mlen);
          
    dump_mem(pbuff->ptr, pbuff->clen);
    
    return 0;
}

static int    assure_len(dibabuff *pbuff, int tlen)

{
    int ret = 0;
    
    if(pbuff->pos + tlen > pbuff->mlen)
        {
        if(debuglevel >= 2)
           printf("assure_len() realloc from %d to %d\n", 
                        pbuff->mlen, pbuff->mlen + tlen + CHUNKSIZE); 
           
        char *nnn = malloc(pbuff->mlen + tlen + CHUNKSIZE);
        if(nnn == NULL)
            return -1; 
            
        memcpy(nnn, pbuff->ptr, pbuff->mlen);
        zfree(pbuff->ptr);
        pbuff->ptr = nnn;
        }        
    return ret;                
}

static int     append_pbuff(dibabuff *pbuff, const char *ptr, int len)

{
    if(assure_len(pbuff, len) < 0)
        return -1;
    memcpy(pbuff->ptr + pbuff->pos, ptr, len);
    pbuff->pos += len;
    pbuff->clen += len;
    return 0;
}    
    
void   SetDIBDebug(int level)

{
    debuglevel = level;
}

///////////////////////////////////////////////////////////////////////////
// Return TRUE if OK, else -1 and fill in err_str if not

int     OpenDIB(dibabuff *pbuff, char **err_str)

{
    int ret = 1;
    if(debuglevel >= 1)
        printf("Opening Diba Buff: '%p'\n", pbuff);
        
    if(!pbuff)
        {
        *err_str = "Cannot open NULL"; 
        return -1;
        }
        
    //////////////////////////////////////////////////////////////////////
    char header[MAX_PATH];
                  
    if(pbuff->ptr == 0)
        {    
        pbuff->mlen =  pbuff->clen =  pbuff->pos =  0;
        pbuff->ptr = zalloc(BUFFSIZE);
        if(pbuff->ptr == NULL)
            return 0;
        pbuff->mlen =  BUFFSIZE;
        snprintf(header, MAX_PATH, FILE_HEADER_STR, 1, 1);
        PutDIBSection(pbuff, header, strlen(header) + 1, CHUNK_HEADER);
        }
    else
        {
        // Read / verify header, reset position.
        pbuff->pos = 0;
        }    
    return ret;
}

int     CreateDIB(dibabuff *pbuff, const char *ppp, int len, char **err_str)

{
    pbuff->mlen = len + BUFFSIZE;
    pbuff->ptr = zalloc(pbuff->mlen + 1);
    if(pbuff->ptr == NULL)
        {
        *err_str = "No Memory";
        return -1;
        }
    pbuff->pos = 0;   pbuff->clen = len;
    memcpy(pbuff->ptr, ppp, pbuff->clen);
    return 0;
}

//////////////////////////////////////////////////////////////////////////

int     CompleteDIB(dibabuff *pbuff, char **err_str)

{
    char footer[MAX_PATH];
    snprintf(footer, MAX_PATH, "%s", FILE_FOOTER_STR);
    int ret = PutDIBSection(pbuff, footer, 
                    strlen(footer), CHUNK_FOOTER);
    return ret;
}        
        
//////////////////////////////////////////////////////////////////////////
// Start reading Diba file from the beginning

void    RewindDIB(dibabuff *pbuff)

{
    pbuff->pos = 0;                                             
}

//////////////////////////////////////////////////////////////////////////
// Return the next diba key, 
// FILE is positioned at the beginning of value

char*   FindNextDIBKey(dibabuff *pbuff, int *len, char **err_str)

{
    char* buff = NULL; 
    
    // Initial values
    *err_str = NULL; *len = 0;
    
    while(1==1)
        {
        int slen, stype, ssum;
        
        if(GetDIBSection(pbuff, &slen, &stype, &ssum) < MINCHSIZE)
            {
            *err_str = "End of file.";
            return(buff);
            }
        //if(debuglevel >= 2)
        //      printf("FindNextDIBKey: stype=%x slen=%x ssum %x \n\n", 
        //                            stype, slen, ssum);
    
        if(slen < 0)
            {
            *err_str = "Unexpected length.";
            return(buff);
            }
        // Is it a key?
        if(stype & 0x80)
            {
            zline2(__LINE__, __FILE__);
            buff =  zalloc(slen + 1);
            if(!buff)
                {
                *err_str = "Cannot allocate memory.";
                return(buff);
                }
            //int ret = fread(buff, 1, slen, Diba);
            memcpy(buff, pbuff->ptr + pbuff->pos, slen);
            pbuff->pos += slen;
   
            //printf("read %d\n", ret);
            buff[slen] = '\0';
            *len = slen;
            break;
            }   
      else
            {
            pbuff->pos += slen;
            }       
        // Skip this chunk, get next
        //fseek( slen, SEEK_CUR);
        }
    return(buff);
}                                                                
             
//////////////////////////////////////////////////////////////////////////                                                                                   
// Get key / value pair, fill into structure
 
int     GetDIBKeyVal(dibabuff *pbuff, chunk_keypair *ptr, char **err_str)

{
    int ret = 0, len; char* buff = NULL;
    *err_str = NULL; 
    
    // Init them
    ptr->key = ptr->val = NULL;  ptr->klen = ptr->vlen = 0;
    
    buff = FindNextDIBKey(pbuff, &len, err_str);
    if(!buff)
        {
        return ret; 
        }
    int len2, type2;     
    char* buff2 = GetNextDIBChunk(pbuff, &len2, &type2, err_str);
    if(!buff2)
        {
        return ret; 
        }  
    // All working, fill in structure
    ptr->key = buff;    ptr->klen = len;
    ptr->val = buff2;   ptr->vlen = len2;
    ret = 1;
    return ret;    
}         

//////////////////////////////////////////////////////////////////////////
// Put key / val pair to file

int   PutDIBKeyVal(dibabuff *pbuff,  chunk_keypair *ptr, char **err_str)

{
    if(debuglevel >= 2)
        printf("PutDibaKeyVal() key='%s' len=%d val='%s' len=%d\n", 
                        ptr->key, ptr->klen, ptr->val, ptr->vlen);
                        
    PutDIBSection(pbuff, ptr->key, ptr->klen, CHUNK_TEXT | CHUNK_KEY);
           
    int flag =  CHUNK_TEXT;
    if(ptr->compressed)
        flag |= CHUNK_ZIPPED;
        
    PutDIBSection(pbuff, ptr->val, ptr->vlen, flag);
    return(1);
}

//////////////////////////////////////////////////////////////////////////
// 

char*   GetNextDIBChunk(dibabuff *pbuff,  int *len, int *type, char **err_str)
        
{       
    char *buff = NULL;         
    *err_str = NULL; *len = 0; *type = 0;
    int   sum = 0;
    
    if(GetDIBSection(pbuff, len, type, &sum) < MINCHSIZE)
        {
        *err_str = "End of file.";
        return(NULL);
        }
    if(*len < 0)
        {
        *err_str = "Unexpected length.";
        return(buff);
        }
    zline2(__LINE__, __FILE__);
    buff =  zalloc(*len + 1);
    if(!buff)
        {
        *err_str = "Cannot allocate memory.";
        return(buff);
        }
    
    if(pbuff->clen - pbuff->pos <= *len)
        {
        //*err_str = "End of data.";
        //zfree(buff);
        //return NULL;
        }
        
    //int ret = fread(buff, 1, *len, Diba);
    
    memcpy(buff, pbuff->ptr + pbuff->pos, *len);
    pbuff->pos += *len;
    
    if(debuglevel >= 5)
        printf("buffer read: '%s' len=%d\n", buff, *len);
    
    buff[*len] = '\0';
     if(*type & CHUNK_ZIPPED)
        {
        unsigned long  ucomprLen;
        int err; char *mem; 
        for(int loop = 1; loop < 10; loop++)
            {
            if(debuglevel >= 4)
                printf("unZipping stage %d ... \n", loop);
                
            ucomprLen  = loop * 4 * (*len); 
            mem = zalloc(ucomprLen + 1);
            err = uncompress(mem, &ucomprLen, (const Bytef*)buff, *len);
            if(err != Z_BUF_ERROR)
                break;
            zfree(mem);
            }
        if(err == Z_OK)
            {
            if(debuglevel >= 3)
                printf("un ratio %d %d %f\n", (int)ucomprLen, *len, 
                                        (float)(ucomprLen)/(*len));
            *len = ucomprLen; 
            zfree(buff);
            buff = mem;
            }
        else
            {
            if(debuglevel >= 3)
                printf("Error on unzip %d\n", err);
                
            zfree(mem);
            }
        }        
     // Check SUM      
    unsigned int org = calc_buffer_sum(buff, *len);
    
    if(debuglevel >= 3)
        printf("sum %x org %x\n", sum, org);
        
    if(sum != org)
        {
        // Force kill data
        *err_str = "Bad checksum on chunk.";
        zfree(buff);
        return(NULL);
        }
    if(debuglevel >= 4)
        printf("GetNextDibaChunk: '%s'\n", buff);
    return buff;
}

///////////////////////////////////////////////////////////////////////////

int     CloseDIB(dibabuff *pbuff)

{
    //if(writefinal)
    //    {
    //    char footer[MAX_PATH];
    //    snprintf(footer, MAX_PATH, "%s", "End of Diba File.\n");
    //    PutDibaSection(fp, footer, strlen(footer), CHUNK_FOOTER);
    //    }
    // fclose(fp);
    
    if(pbuff->ptr)
        zfree(pbuff->ptr);
        
    if(debuglevel >= 1)
            printf("Closed DIBA buffer.\n");
        
    return 1;
}
                               
////////////////////////////////////////////////////////////////
// Return number of bytes read, negative on error
//

int     GetDIBSection(dibabuff *pbuff, int *len, int *type, int *sum)

{
    // Surround string with zeros, so debug print is ok
    char  trail  = 0, buff[CHUNKSIZE + 1], trail2 = 0;
    
    // Assure defaults
    *len = *type = *sum = 0;
    
    int ret = CHUNKSIZE;
    memcpy(buff, pbuff->ptr + pbuff->pos, CHUNKSIZE);
    buff[ret] = '\0';
    
    if(pbuff->clen - pbuff->pos < CHUNKSIZE)
        {
        if(debuglevel >= 2)
            printf("Stream ended before file end.\n");
            
        return 0;
        }
    if(ret > CHUNKSIZE)
        {
        if(debuglevel >= 1)
            printf("Unexpected read return value\n");
        return ret;
        }
    
    if(debuglevel >= 3)
        printf("Read buffer '%s' len=%d\n", buff, ret);
    
    if(buff[1] != 'D' || buff[2] != 'I')
        {
        // TODO Mark the buffer tainted ... 
        if(debuglevel >= 1)
            printf("Invalid Section. Skipping ....");
        ret = -2;
        }
    // Start from a position other then the first new line
    char *end = strchr(buff + 1, '\n');
    if (end)
        {
        *(end+1) = '\0';
    
        // Go to end of first line
        int eee = end - buff; 
        pbuff->pos = pbuff->pos + eee + 1;
        ret = eee;
        }
    else
        {
        ret = -2;
        }
        
    int ret2 = sscanf(buff, CHUNK_HEADER_STR, type, len, sum);
    
    if(debuglevel >= 2)
        printf("getdibasection: ret2=%d type=%x len=%x sum %x \n\n", 
                                ret2, *type, *len, *sum);
    
    return(ret);
}

////////////////////////////////////////////////////////////////
// Return payload size written, negative on error

int     PutDIBSection(dibabuff *pbuff, const char *ptr, int len, int type)

{
    char tmp[MAX_PATH];    
    int ret = 0;
    unsigned int sum = calc_buffer_sum(ptr, len);
    char *mem = NULL;
    
    if(debuglevel >= 2)
        printf("Type %x\n", type);
        
    if((type & CHUNK_ZIPPED) == CHUNK_ZIPPED)
        {
        unsigned long  comprLen = len;
        
        if(debuglevel >= 1)
            printf("Zipping ... \n '%s'\n", ptr);
        
        mem = zalloc(comprLen + 1);
        int err = compress(mem, &comprLen, (const Bytef*)ptr, len);
        if(!err)
            {
            if(debuglevel >= 1)
                printf("Zipped ... \n '%s'\n", mem);
                
            if(debuglevel >= 2)
                printf("ratio %d %d %f\n", (int)comprLen, len, (float)(comprLen)/len);
                
            len = comprLen; ptr = mem;
            }
        else
            {
            if(debuglevel >= 1)
                printf("stored not Zipped ... \n");
               
            // Just store it ...
            type = type & (~CHUNK_ZIPPED);
            zfree(mem);
            }
        }
        
    snprintf(tmp, MAX_PATH, CHUNK_HEADER_STR, type, len, sum);
    
    if(debuglevel >= 2)
        printf("writing DIBA header '%s' strlen=%d\n", tmp, (int)strlen(tmp));
        
    //fwrite(tmp, 1, strlen(tmp), ff);
    int tlen = strlen(tmp);
    if(append_pbuff(pbuff, tmp, tlen) < 0)
        return -1;
    
    //ret = fwrite(ptr, 1, len, ff);
    if(append_pbuff(pbuff, ptr, len) < 0)
        return -1;
        
    if(type & CHUNK_ZIPPED)
        {
        zfree(mem);   
        }
    return(ret);
}

/* EOF */
















