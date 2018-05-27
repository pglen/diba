///////////////////////////////////////////////////////////////////////////
// Bluepoint test suite
///////////////////////////////////////////////////////////////////////////

#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "bluepoint3.h"

char copy[128] = "";
char bound[] = "12345678";
char orig[] = 
            "abcdefghijklmnopqrstuvwxyz"
            "abcdefghijklmnopqrstuvwxyz"
            "abcdefghijklmnopqrstuvwxyz"
            "abcdefghijklmnopqrstuvwxyz"
            "abcdefghijklmnopqrstuvwxyz"
            "abcdefghijklmnopqrstuvwxyz"
;
char bound2[] = "12345678";

char pass[128] = "1234";

int main(int argc, char *argv[])

{
    long hh;
    int ret = 0;

    printf("ORIG: \n");
    printf("'%s'\n", orig);
    printf("END ORIG\n");

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

    int olen = 3 * sizeof(orig);
    char   *dumped = malloc(olen);
    memset(dumped, 'x', olen);
    bluepoint3_tohex(orig, strlen(orig), dumped, &olen);

    printf("TOHEX: \n");
    printf("'%s'\n", dumped);
    printf("END TOHEX\n");

    int olen2 = 2 * sizeof(orig);
    char   *dumped2 = malloc(olen2);
    memset(dumped2, 'y', olen2);
    bluepoint3_fromhex(dumped, olen, dumped2, &olen2);
    
    if (memcmp(dumped2, orig, olen2))
        {
        printf("Decrypt error.");
        } 
    printf("FROMHEX: \n");
    printf("'%s'\n", dumped2); 
    printf("END FROMHEX\n");

    return ret;    
}






