#include <stdio.h>

#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <signal.h>

void xerr2(const char* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    
    vfprintf(stderr, msg, ap);
    exit(2);                                
}

unsigned int getfsize(FILE *fp)

{
    size_t org_pos = ftell(fp);
    fseek(fp, 0, SEEK_END);
    size_t file_len = ftell(fp);
    fseek(fp, org_pos, SEEK_SET);
    
    return  file_len;
}

char val[4046];
int validx = 0;

char decval[4560];
int decidx = 0;

int freq[256] = {0};

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

void main(int argc, char *argv[])

{
    signal(SIGSEGV, myfunc);

    FILE* lockf = fopen(argv[1], "rb");
    if (!lockf) {
        xerr2("dibadecrypt: Cannot open keyfile '%s'.", argv[1]);
    }

    /* Grab the public key and key size */
    unsigned int rsa_len = getfsize(lockf);
    
    char* rsa_buf = malloc(rsa_len + 4);
    if (!rsa_buf) {
        xerr2("dibadecrypt: Cannot allocate rsa buffer.");
    }
    if (fread(rsa_buf, rsa_len, 1, lockf) != 1) {
        xerr2("dibadecrypt: Cannot read public key.");
    }
    //rsa_buf[rsa_len] = '\0';
    fclose(lockf);
    
    //printf("org '%s'", rsa_buf);     
    
    for(int loop = 0; loop < rsa_len; loop++)
        {
        char chh = rsa_buf[loop];
         // Lower it
        //if(chh >= 'A' && chh <= 'Z')
        //    {
        //    chh += 32;
        //    }
        val[validx++] = chh;
        
        if(validx > sizeof(val))
           xerr2("expected buffer\n");
        }
    val[validx] = '\0';
            
    //printf("val '%s'", val);     
    
    // Parsed, ready to go    
    int minx = 1000; int maxx = 0; int avg = 0;
    char vvv2;
    for(int loop = 0; loop < validx; loop++)
        {
        unsigned int vvv = val[loop] & 0xff;
        
        freq[vvv] ++;
        
        //printf("%4d %c", vvv, vvv2); 
        //decval[decidx++] = vvv2;
        
        //if(loop % 10 == 9)
        //    printf("\n");
            
        if(minx > vvv) minx = vvv;    
        if(maxx < vvv) maxx = vvv;    
        
        avg += vvv;
        }
        
    decval[decidx++] = '\0';
    
    int maxf = 0, minf = 10000, avg2 = 0;
    for(int loop = 0; loop < 256; loop++)
        {
        int chh = freq[loop];
        if(chh < minf) minf = chh;
        if(chh > maxf) maxf = chh;
        avg2 += chh;
        
        //printf("%3d = %-2d  ", loop, freq[loop]);
        //if(loop % 10 == 9)
        //    printf("\n");
        }
    
    //printf("\n");
    
    for(int loop = 0; loop < 256; loop++)
        {
        //printf("loop %d ", loop);
        int maxf = 0; int idxf = 0;
        for(int loop2 = 0; loop2 < 256; loop2++)
            {
            int ifreq = freq[loop2];
            if(ifreq > maxf)
                {
                maxf = ifreq;
                idxf = loop2;
                //printf("assigned %d %d", maxf, loop2);
                }
            }
        // Now we have the maxx and location
        if(maxf == 0)
            break;
            
        int idxf2 = idxf;
        if(idxf2 == '\r') idxf2 = ' ';     
        if(idxf2 == '\n') idxf2 = ' ';
        if(idxf2  < ' ') idxf2 = ' ';
        
        //printf("%3d = %-3d '%c' ", maxf, idxf, idxf2);
        //if(loop % 8 == 7)
        //        printf("\n");
            
        //put code instead:
        //if(isprint(idxf))
        //    {
        //    printf("%3d, %3d, ", maxf, idxf);
        //    if(loop % 6 == 5)
        //        printf("\n");
        //    }   
        // erase it ...    
        freq[idxf] = 0;    
        }
        
    printf("\n\nmaxf = %d minf = %d avg = %d\n", maxf, minf, avg2 / 256);
    
} 









             





