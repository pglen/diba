// Test sexpr encode / decode

#include <signal.h>
#include <stdio.h>

#include "gcrypt.h"
#include "gcry.h"
#include "zmalloc.h"

int main(int argc, char** argv)

{
    gcry_error_t err;
    err = gcry_control(GCRYCTL_ENABLE_M_GUARD);
    if(err)
        {
        printerr(err, "guard");
        xerr("Cannot set debug");
        }
    gcrypt_init();

    err = gcry_control(GCRYCTL_SET_DEBUG_FLAGS, 100);
    if(err)
        {
        printerr(err, "debug");
        xerr("Cannot set debug");
        }
    err = gcry_control(GCRYCTL_SET_VERBOSITY, 0);
    if(err)
        {
        printerr(err, "verbose");
        xerr("Cannot set dverbose");
        }
    
    int iter = 0;
    while(1)
        {
        int bsize = 1000;
        char *tmp_buf = zalloc(bsize + 1);
        //memset(tmp_buf, 'a', bsize);
        memset(tmp_buf, '\0', bsize);
        //gcry_randomize(tmp_buf, sizeof(int), GCRY_STRONG_RANDOM);
            
        gcry_sexp_t ciph;
            
        err = gcry_sexp_build(&ciph, NULL,
                    "(enc-val (rsa (a %b)))", bsize, tmp_buf );
    
        gcry_sexp_t ddd = gcry_sexp_find_token(ciph, "a", 1);
            
        if(ddd == NULL)
        if (err) {
                xerr("dibadecrypt: find token in encrypted result failed");
               }
        //print_sexp(ddd);
        
        unsigned int plen2 = 0;
        char *dptr2 = (char *)gcry_sexp_nth_buffer(ddd, 1, &plen2);
        
        //dptr2[-1] = 'a';
        
        //dump_mem(dptr2, plen2);
        if(memcmp(dptr2, tmp_buf, bsize) != 0)
            {
            printf("Bad compare\n");
            break;
            }
        zfree(tmp_buf);
        gcry_free(dptr2);
        
        iter++;
        if(iter % 100 == 99)
            printf("%d ", iter);
        }
        
}

