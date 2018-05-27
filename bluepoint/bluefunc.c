//# Use these functions for the virtual machine of the crypt process.
//#
//# Example: 
//#

typedef void    (*cfunc)(char *, int, char *, int);

#define DEF_CFUNC(funcname, xmacro, arg)                      \
                                                              \
void    funcname(char *str, int slen, char *pass, int plen)   \
                                                              \
{                                                             \
    int loop, loop2 = 0;  unsigned char  aa, bb, cc;          \
    xmacro(arg)                                               \
}                                                             \

DEF_CFUNC( mixit,       MIXIT, +);
DEF_CFUNC( passloop,    PASSLOOP, +) 
DEF_CFUNC( mixit2,      MIXIT2, +)   
DEF_CFUNC( hectorx,     HECTOR, +)   
DEF_CFUNC( fwloop,      FWLOOP, +)
DEF_CFUNC( mixit2r,     MIXIT2R, +)
DEF_CFUNC( mixitr,      MIXITR, +)
DEF_CFUNC( bwloop,      BWLOOP, +)   
DEF_CFUNC( triloop,     TRILOOP, +)   
           
DEF_CFUNC( mixit3,      MIXIT, -);
DEF_CFUNC( passloop3,   PASSLOOP, -) 
DEF_CFUNC( mixit23,     MIXIT2, -)   
DEF_CFUNC( hectorx3,    HECTOR, -)   
DEF_CFUNC( fwloop3,     FWLOOP2, -)
DEF_CFUNC( mixit2r3,    MIXIT2R, -)
DEF_CFUNC( mixitr3,     MIXITR, -)
DEF_CFUNC( bwloop3,     BWLOOP2, -)   
DEF_CFUNC( triloop3,     TRILOOP, -)   





