///////////////////////////////////////////////////////////////////////////
// Bluepoint test suite
///////////////////////////////////////////////////////////////////////////

#include "stdlib.h"
#include "stdio.h"
#include "string.h"

//#define DEF_DUMPHEX  1   // undefine this if you do not want bluepoint3_dumphex
#include "bluepoint3.h"

char copy[128] = "";
char bound[] = "1234";
char orig[] = "abcdefghijklmnopqrstuvwxyz";
char bound2[] = "1234";
char pass[128] = "1234";

char *dump_buff(const char *ptr, int len)

{
    int olen = 3 * len;
    char *ret = malloc(olen);
    if(!ret) return ret;
    //int iret = 
    bluepoint3_tohex(ptr, len, ret, &olen);
    //if(!iret)
    //    { free(ret); return NULL; }
    return ret;  
}

int main(int argc, char *argv[])

{
    long hh;
    int ret = 0;

    strncpy(copy, orig, sizeof(copy));

    if(argc > 1)
        {
        //printf("argv[1]=%s\n", argv[1]);
        strncpy(orig, argv[1], sizeof(orig));
        strncpy(copy, argv[1], sizeof(copy));
        }

    if(argc > 2)
        {
        //printf("argv[2]=%s\n",argv[2]);
        strncpy(pass, argv[2], sizeof(pass));
        }

    //printf("bound '%s'\n", bound);
    printf("orignal='%s' pass='%s'\n", orig, pass);
    //printf("bound2 '%s'\n", bound2);

#if 0
    // Verify if declaration follows source order
    printf("Dump bounds\n");
    int tot = sizeof(bound) + sizeof(orig) + sizeof(bound2) + 6;
    for (int aa = 0; aa < tot; aa++)
         printf("%x", bound[aa]);
    printf("\n");   
#endif
    
    int slen = strlen(orig); int plen = strlen(pass);

    //bluepoint3_set_functrace(1);
    //bluepoint3_set_verbose(1);
    
    char orig2[128]; 
    strcpy(orig2, orig);
    bluepoint3_encrypt(orig2, slen, pass, plen);

    printf("ENCRYPTED: \n");
    char *tmp = dump_buff(orig2, slen);
    printf("'%s'\n", tmp); 
    free(tmp);
    printf("END ENCRYPTED\n");

    printf("HASH:\n");
    hh = bluepoint3_hash(copy, slen);
    printf("%u 0x%08x\n", hh, hh);

    printf("CRYPTHASH: \n");
    hh = bluepoint3_crypthash(copy, slen, pass, plen);
    printf("%u 0x%08x\n", hh, hh);

    printf("HASH64:\n");
    unsigned long long int hhh = bluepoint3_hash64(copy, slen);
    printf("%llu 0x%llx\n", hhh, hhh);

    printf("CRYPTHASH64: \n");
    hhh = bluepoint3_crypthash64(copy, slen, pass, plen);
    printf("%llu 0x%llx\n", hhh, hhh);

    char   dumped[256];
    memset(dumped, 'x', sizeof(dumped));
    int olen = sizeof(dumped);

    bluepoint3_tohex(orig2, slen, dumped, &olen);

    printf("TOHEX: \n");
    printf("'%s'", dumped);
    printf("\nEND TOHEX\n");

    char   dumped2[256];
    memset(dumped2, 'y', sizeof(dumped2));
    int olen2 = sizeof(dumped2);
    bluepoint3_fromhex(dumped, olen, dumped2, &olen2);
    if (memcmp(dumped2, orig2, olen2))
        {
        printf("Decrypt error.");
        } 
    printf("FROMHEX: \n");
    //printf("'%s'", dumped2);
    char *tmp2 = dump_buff(dumped2, olen2);
    printf("'%s'\n", tmp2); 
    free(tmp2);
    printf("END FROMHEX\n");

    bluepoint3_decrypt(dumped2, olen2, pass, plen);
    printf("decrypted='%s'\n", dumped2);
    
    //bluepoint3_decrypt(orig2, slen, pass, plen);
    //printf("orig2='%s'\n", orig2);
    
    // Verify if declaration follows source order
    //printf("Dump bounds\n");
    //for (int aa = 0; aa < tot; aa++)
    //     printf("%x", bound[aa] & 0xff);
    //printf("\n");   

    if(memcmp(dumped2, orig, strlen(orig)) != 0)
        {
        printf("ERROR decrypted str does not match\n"); 
        ret = 1;
        }
    return ret;    
}





