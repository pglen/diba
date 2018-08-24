
/* =====[ DibaBuff.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank]. File format code.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
     0.00  nov.05.2017     Peter Glen      Initial version.
 
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
#include "DibaBuff.h"

#include "zlib.h"

#ifndef MAX_PATH
    #ifndef PATH_MAX
        // Keep it safe
        #define MAX_PATH 255
    #else
        #define MAX_PATH PATH_MAX
    #endif    
#endif            

unsigned int calc_buffer_sum(const char *ptr, int len)

{
    unsigned int ret = 0;
    //printf("calc_buffer_sum %p %d\n", ptr, len);
    for(int loop = 0; loop < len; loop++)
        {
        ret += (unsigned char)ptr[loop];
        ret = (ret << 3) | ret >> 21;
        }
    //printf("sum ret = %x\n", ret);
    return ret;   
}

static int debuglevel = 0;

int    DumpDibabuff(dibabuff *pbuff)

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
    
void   SetDibaBuffDebug(int level)

{
    debuglevel = level;
}

///////////////////////////////////////////////////////////////////////////
// Return TRUE if OK, fill in err_str if not

int     OpenDibaBuff(dibabuff *pbuff, char **err_str)

{
    if(debuglevel >= 1)
        printf("Opening Diba Buff: '%p'\n", pbuff);
        
    if(!pbuff)
        {
        *err_str = "Cannot open NULL"; 
        return 0;
        }
    pbuff->mlen =  pbuff->clen =  pbuff->pos =  0;
    pbuff->ptr = zalloc(BUFFSIZE);
    if(pbuff->ptr == NULL)
        return 0;
    pbuff->mlen =  BUFFSIZE;
    char header[MAX_PATH];
    snprintf(header, MAX_PATH, FILE_HEADER_STR, 1, 1);
    PutDibaBuffSection(pbuff, header, strlen(header) + 1, CHUNK_HEADER);

    return 1;
}

//////////////////////////////////////////////////////////////////////////
// Start reading Diba file from the beginning

void    RewindDibaBuff(dibabuff *pbuff)

{
    pbuff->pos = 0;                                             
}

//////////////////////////////////////////////////////////////////////////
// Return the next diba key, 
// FILE is positioned at the beginning of value

char*   FindNextDibaBuffKey(dibabuff *pbuff, int *len, char **err_str)

{
    char* buff = NULL; 
    
    // Initial values
    *err_str = NULL; *len = 0;
    
    while(1==1)
        {
        int slen, stype, ssum;
        
        if(GetDibaBuffSection(pbuff, &slen, &stype, &ssum) < MINCHSIZE)
            {
            *err_str = "End of file.";
            return(buff);
            }
        if(*len < 0)
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
            //printf("read %d\n", ret);
            buff[slen] = '\0';
            *len = slen;
            break;
            }    
        // Skip this chunk, get next
        //fseek( slen, SEEK_CUR);
        }
    return(buff);
}                                                                
             
//////////////////////////////////////////////////////////////////////////                                                                                   
// Get key / value pair, fill into structure
 
int     GetDibaBuffKeyVal(dibabuff *pbuff, chunk_keypair *ptr, char **err_str)

{
    int ret = 0, len; char* buff = NULL;
    *err_str = NULL; 
    
    // Init them
    ptr->key = ptr->val = NULL;  ptr->klen = ptr->vlen = 0;
    
    buff = FindNextDibaBuffKey(pbuff, &len, err_str);
    if(!buff)
        {
        return ret; 
        }
    int len2, type2;     
    char* buff2 = GetNextDibaBuffChunk(pbuff, &len2, &type2, err_str);
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

int   PutDibaBuffKeyVal(dibabuff *pbuff,  chunk_keypair *ptr, char **err_str)

{
    if(debuglevel >= 2)
        printf("PutDibaKeyVal() key='%s' len=%d val='%s' len=%d\n", 
                        ptr->key, ptr->klen, ptr->val, ptr->vlen);
                        
    PutDibaBuffSection(pbuff, ptr->key, ptr->klen, CHUNK_TEXT | CHUNK_KEY);
           
    int flag =  CHUNK_TEXT;
    if(ptr->compressed)
        flag |= CHUNK_ZIPPED;
        
    PutDibaBuffSection(pbuff, ptr->val, ptr->vlen, flag);
    return(1);
}

//////////////////////////////////////////////////////////////////////////
// 

char*   GetNextDibaBuffChunk(dibabuff *pbuff,  int *len, int *type, char **err_str)
        
{       
    char *buff = NULL;         
    *err_str = NULL; *len = 0; *type = 0;
    int   sum = 0;
    
    if(GetDibaBuffSection(pbuff, len, type, &sum) < MINCHSIZE)
        {
        *err_str = "End of file.";
        return(buff);
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
    //int ret = fread(buff, 1, *len, Diba);
    if(pbuff->clen - pbuff->pos <= *len)
        {
        *err_str = "End of data.";
        return NULL;
        }
        
    memcpy(buff, pbuff->ptr + pbuff->pos, *len);
    
    //if(debuglevel >= 3)
    //    printf("buffer read: '%s' len=%d\n", buff, ret);
    
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
            //printf("un ratio %d %d %f\n", ucomprLen, *len, 
            //                            (float)(ucomprLen)/(*len));
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
    }
   //printf("GetNextDibaChunk: '%s'\n", buff);
    return buff;
}

///////////////////////////////////////////////////////////////////////////

int     CloseDibaBuff(dibabuff *pbuff)

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

int     GetDibaBuffSection(dibabuff *pbuff, int *len, int *type, int *sum)

{
    // Surround string with zeros, so debug print is ok
    char  trail  = 0, buff[CHUNKSIZE + 1], trail2 = 0;
    
    // Assure defaults
    *len = *type = *sum = 0;
    
    int ret = CHUNKSIZE;
    memcpy(buff, pbuff->ptr + pbuff->pos, CHUNKSIZE);
    if(ret <= 0)
        {
        if(debuglevel >= 2)
            printf("Stream ended before file end.\n");
            
        return ret;
        }
    if(ret > CHUNKSIZE)
        {
        if(debuglevel >= 1)
            printf("Unexpected read return value\n");
        return ret;
        }
    buff[ret] = '\0';
    
    if(debuglevel >= 3)
        printf("Read buffer '%s' len=%d\n", buff, ret);
    
    if(buff[1] != 'D' || buff[2] != 'I')
        {
        // TODO Mark the buffer tainted ... 
        //*err_str = ("Invalid Section. Skipping ....");
        if(debuglevel >= 1)
            printf("Invalid Section. Skipping ....");
        }
    // Start from a position other then the first new line
    char *end = strchr(buff + 1, '\n');
    if (end)
        {
        // Go back to end of real input
        int num = end - buff;     
        pbuff->pos = pbuff->pos -(CHUNKSIZE - 1 - num);
        }
        
    int ret2 = sscanf(buff, CHUNK_HEADER_STR, type, len, sum);
    
    if(debuglevel >= 2)
        printf("getdibasection: ret2=%d type=%x len=%x sum %x \n\n", 
                                ret2, *type, *len, *sum);
    
    return(ret);
}

////////////////////////////////////////////////////////////////
// Return payload size written, negative on error

int     PutDibaBuffSection(dibabuff *pbuff, const char *ptr, int len, int type)

{
    char tmp[MAX_PATH];    int ret = 0;
    unsigned int sum = calc_buffer_sum(ptr, len);
    char *mem = NULL;
    
    if(type & CHUNK_ZIPPED)
        {
        unsigned long  comprLen = len;
        //printf("Zipping ... \n '%s'\n", ptr);
        mem = zalloc(comprLen + 1);
        int err = compress(mem, &comprLen, (const Bytef*)ptr, len);
        if(!err)
            {
            //printf("Zipped ... \n '%s'\n", mem);
            //printf("ratio %d %d %f\n", comprLen, len, (float)(comprLen)/len);
            len = comprLen; ptr = mem;
            }
        else
            {
            // Just store it ...
            type = type & (~CHUNK_ZIPPED);
            }
        }
        
    snprintf(tmp, MAX_PATH, CHUNK_HEADER_STR, type, len, sum);
    
    if(debuglevel >= 2)
        printf("writing DIBA header '%s' strlen=%d\n", tmp, strlen(tmp));
        
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





