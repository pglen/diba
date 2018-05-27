
/* =====[ dibapow.c ]=========================================================

   Description:     Feasability study for diba [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  Jan.01.2015     Peter Glen      Initial version.
      0.00  Jan.05.2015     Peter Glen      Initial version.
      0.10  Jun.21.2017     Peter Glen      Initial version.
      0.10  Jul.04.2017     Peter Glen      Adapted to high round processing
      0.10  oct.02.2017     Peter Glen      Filling in next field
      0.10  may.22.2018     Peter Glen      Ported to msys

   ======================================================================= */

// Dibapow proof of work. It takes about a millon calculations for the hash 
// to go below 0x2000. On avarage 10 million tryes lead to 8 - 10 hits.

// ATTN: bug in the gcrypt library prevents re-reading zero lenth field.
// Always add someting to every field (like the string "none" in our case)

/* -------- System includes:  -------------------------------------------- */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef linux
#include <limits.h>
#include <errno.h>
#endif

#include "diba.h"
#include "bluepoint3.h"
#include "gcrypt.h"
#include "gcry.h"
#include "getpass.h"
#include "gsexp.h"
#include "base64.h"
#include "zmalloc.h"
#include "cmdline.h"                                
#include "dibautils.h"
#include "dibastr.h"
#include "misc.h"
#include "zstr.h"

// How many times to loop before giving up.
#define MAXLOOP    1000000

// This is for developing
#define HASH_TRESH   0x800000

// This is for testing
//#define HASH_TRESH   0x80000

// Real hash criteria
//#define HASH_TRESH 0x10000

#define MAX_PAYLOAD 60000

int    main(int argc, char *argv[]);
                                     
static void myfunc(int sig)
{
    int mem = 0xdeadbeef;
    int mem2 = 0xaabbccdd;
    int len = 128;
    
    printf("\nSignal %d (segment violation).\n", sig);
    
    #if 0
    //Stack dump follows:
    //printf("stack - arg: %d\n", &len - &sig);
    printf("main: %p myfunc %p libfunc: %p\n", 
                &main, &myfunc, *read_sexp_from_file);
    dump_mem((const char *)(&mem) - len, 2 * len);
    printf("\nEnd stack dump.\n");
    #endif
    
    exit(111);
}

static ulong    calc_padding(const char *str, int len, char *out, int *olen, uint tresh);
static int      check_entry(gcry_sexp_t sexp);
static int      update_next_field(const char *backfile, const char *newfile, const char *nexid);

/* -------- Data: -------------------------------------------------------- */

static clock_t time_up;

static int  skip = 0;
static int  entries = 1;
static int  mode = 0;
static int  nobatch = FALSE;
static int  verbose = FALSE;
static int  print = FALSE;
static int  show = FALSE;
static int  check = FALSE;
static int  test = FALSE; 
static int  nullfile = FALSE;

opts opts_data[] = {
                    'n',    "--null", NULL, NULL, 0, 0, &nullfile, 
                    "-n             --null        - Create null file",      
                    's',    "--show", NULL, NULL, 0, 0, &show, 
                    "-s             --show        - Show chain element",   
                    'c',    "--check", NULL, NULL, 0, 0, &check, 
                    "-c             --check        - Check chain element",               
                    'v',    "--verbose", NULL, NULL, 0, 0, &verbose, 
                    "-v             --verbose     - Verbosity on",                  
                    'p',    "--print", NULL, NULL, 0, 0, &print, 
                    "-p             --print       - Print final sexp ",        
                    'b',    "--batch", NULL, NULL, 0, 0, &nobatch, 
                    "-b             --batch       - Batch mode, no progress display",
                     0,     NULL,  NULL, NULL,     0, 0,  NULL, NULL,
                    };
   
static char    use_str[] = "dibapow [options] backlink payload";
static char    summary[] = "Generate blockchain member, and add it to chain.";
              
static char test_pass[] = "12345678";
              
///////////////////////////////////////////////////////////////////////////////

int    main(int argc, char *argv[])

{
    char *err_str;     gcry_error_t err = 0;
    
    signal(SIGSEGV, myfunc);
    srand(time(NULL));
    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();
    
    zline2(__LINE__, __FILE__);
   
    char *backfile = diba_alloc(MAX_PATH);
    char *payfile  = diba_alloc(MAX_PATH);
    char *backlink = diba_alloc(MAX_PATH);
    
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        //printf(err_str);
        usage(use_str, summary, opts_data ); 
        exit(2);
        }
             
    // Make sure it is there. 
    if(access(nulldir, F_OK) < 0)
        {
        mkdir(nulldir, 0777);
        }
        
    if(access(nulldir, F_OK) < 0)
        xerr2("dibapow: cannot access data dir.");
        
    if (show || check)
        {
        if(argc - nn < 2) {
            printf("dibapow: must provide file name to show / check.");
            usage(use_str, summary, opts_data );  exit(2);
            }
         
        zstrcpy(backfile, argv[nn + 1], MAX_PATH);   
        //printf("Showing '%s'\n", backfile);
        
        char *err_str = NULL;
        gcry_sexp_t showsexp;
        read_sexp_from_file(backfile, &showsexp, &err_str);
        if(err_str)
            {
            xerr2("Cannot read sexp: %s\n", err_str);
            }
        
        if(show)
            {
            sexp_print(showsexp);
            }
        else    // check
            {
            int ret =  check_entry(showsexp);
            }
        zfree(backfile);  zfree(backlink); zfree(dummy); zfree(payfile);
        zleak();
        exit(0);
        }
        
    zline2(__LINE__, __FILE__);
    char *ttt = zdatestr();
    char *user = zusername();
    char *host = zhostname();
    char *recid  = zrandstr_strong(24);
    
    char fnamex[13]; char *fname = NULL, *newfile = NULL, *datfile = NULL;
    
    strcpy(backfile, nonestr);
    strcpy(backlink, nonestr);
        
    if(nullfile)
        {
        strcpy(fnamex, nullfname);
        fname  = zstrcat(fnamex, nullext); 
        newfile  = zstrmcat(MAX_PATH, nulldir, fname, NULL); 
        datfile  = zstrmcat(MAX_PATH, nulldir, fnamex, datext, NULL); 
        if(access(newfile, F_OK) >= 0)
             xerr2("dibapow: Root file already exists. Please create in a different directory.");
        }
    else
        {
        // Try NN iterations, broken if no more room
        for(int loopf = 0; loopf < 100; loopf++)
            {
            rand_str(fnamex, sizeof(fnamex));
            fname  = zstrcat(fnamex, nullext); 
            newfile  = zstrmcat(MAX_PATH, nulldir, fname, NULL);
            datfile  = zstrmcat(MAX_PATH, nulldir, fnamex, datext, NULL); 
            
            if(access(newfile, F_OK) < 0)
               break;
               
            // Start new name search, clean temp names
            zline2(__LINE__, __FILE__);
            zfree(fname); zfree(newfile); zfree(datfile);
            }
            
        if(access(newfile, F_OK) >= 0)
            xerr2("dibapow: file already exists, cannot overwrite, try again ...");
            
        if(argc - nn < 3) {
            printf("dibapow: must provide backlink and payload.");
            usage(use_str, summary, opts_data );  exit(2);
            }
        zstrcpy(backfile, argv[nn + 1], MAX_PATH);
        if(access(backfile, F_OK) < 0)
            {
            xerr2("dibapow: backlink file (%s) does not exist.", backfile);
            }
              
        zstrcpy(payfile, argv[nn + 2], MAX_PATH);
        if(access(payfile, F_OK) < 0)
            {
            xerr2("dibapow: payload file (%s) does not exist.", payfile);
            }
        if(access(backfile, W_OK) < 0)
            {
            xerr2("dibapow: backlink file cannot be written to (%s)", backfile);
            }
        }
    
    // Details of our entry
    char *ver = "1.0";
    char *desc = "No description";
    
    char *payload = NULL, *err_str6 = NULL, *hash_str;
    int paylen;
    if(nullfile)
        {   
        // Create dummy payload
        paylen = 128;
        payload = zrandstr_strong(paylen);
        hash_str  = hash_buff(payload, paylen);
        
        }
    else
        {
        // Load new payload
        int pl_len;
        char *pl = grabfile(payfile, &pl_len, &err_str6);
        if(err_str6)
            {
            xerr2("%s '%s': %s\n", err_str6, backfile, strerror(errno));
            }
        payload = base_and_lim(pl, pl_len, &paylen);
        zfree(pl);
        if(!payload)
            {
            xerr2("Cannot load payload file");
            }
        hash_str  = hash_buff(payload, paylen);
        
        // See if we need to store it in a file
        if(paylen > MAX_PAYLOAD)
            {
            //xerr2("Payload too big, (%d) using file payload.", paylen, datfile);
            if(verbose)
                printf("Payload stored in file '%s'\n", datfile);
            char *err_str;
            putfile(datfile, payload, paylen, &err_str);
            if(err_str)
                xerr2("Cannot save payload: '%s'\n", err_str);
            // Replace payload with message, do lengths
            zfree(payload);
            payload = zstrmcat(MAX_PATH, "Saved in file: '", datfile, "'", NULL);     
            paylen = strlen(payload);
            }
            
        // Read backfile for ID
        char *err_str2;
        gcry_sexp_t backsexp;                                                                 
        read_sexp_from_file(backfile, &backsexp, &err_str2);
        
        // See if it has a next already
        gcry_sexp_t  nid = gcry_sexp_find_token(backsexp, "Next File", 0);
        if (!nid)
                xerr2("Failed to find 'Next File' in back sexp. %s\n", gcry_strerror (err));
        int nlen;
        char  *nnn  = sexp_nth_data(nid, 1, &nlen);
        if (!nnn)
            xerr2("Failed to read 'Next File' member in back sexp. %s\n", gcry_strerror (err));
                               
        if(strcmp(nnn, nonestr) != 0)
            xerr2("This entry already has a 'Next File' member: '%s'\n", nnn);
             
        zfree(nnn);
        
        gcry_sexp_t  bl = gcry_sexp_find_token(backsexp, "ID", 0);
        if (!bl)
                xerr2("Failed to find ID in back sexp. %s\n", gcry_strerror (err));
        
        int olen;
        char *ddd2 =  sexp_nth_data(bl, 1, &olen);
        zstrcpy(backlink, ddd2, MAX_PATH);
        //backlink[olen] = '\0';
        zfree(ddd2);
        //printf("Backlink '%s'\n", backlink);
        }
    gcry_sexp_t chain_payload;
    err = gcry_sexp_build(&chain_payload, NULL, 
                "(\"Chain Payload\" (\"Payload Size\" %d)"
                        " (\"Payload Data\" %s) "
                                "(\"Payload Hash\" %s) )",
                                      paylen, payload, hash_str);
    if(err)
        xerr2("dibapow: Cannot create payload sexpr: '%s'\n", gcry_strerror (err));
    
    gcry_sexp_t chain_element;
    err = gcry_sexp_build(&chain_element, NULL, 
                "(\"Chain Element\" (\"Creation Date\" %s) "
                    "(\"Version\" %s) (\"File Name\" %s) (\"Description\" %s)  "
                    "(\"ID\" %s) (\"Creator\" %s) (\"Hostname\" %s) "
                    "(\"Backlink\" %s) (\"Backfile\" %s)) ",
                        ttt, ver, fname, desc, recid, user, host, 
                                backlink, backfile);
    if(err)
        xerr2("dibapow: Cannot create sexpr: '%s'\n", gcry_strerror (err));
        
    if(verbose)
        sexp_print(chain_element);      
    
    if(!nobatch)
        printf("Creating hashes and padding ... \n");
        
    int sum_lena, sum_lenb, sum_len;
    char *sum_stra =  sexp_get_buff(chain_payload, &sum_lena);
    char *sum_strb =  sexp_get_buff(chain_element, &sum_lenb);
    sum_len =  sum_lena + sum_lenb;
    char *sum_str = zalloc(sum_len + 2);
    memcpy(sum_str, sum_stra, sum_lena);
    memcpy(sum_str + sum_lena, sum_strb, sum_lenb);
    zfree(sum_stra);    zfree(sum_strb);
    
    char *all_hash = hash_buff(sum_str, sum_len);
    
    char padding2[32];
    int pad_len = sizeof(padding2);
    ulong ret = calc_padding(sum_str, sum_len, padding2, &pad_len, HASH_TRESH);
    if(ret ==  0)
        xerr2("dibapow: Cannot create padding, try again.");
     
    if(!nobatch)
        printf("\n");
        
    int pad64len;
    char *pad64 = base_and_lim(padding2, sizeof(padding2), &pad64len);
    int hlen = 0;
    char *ttt2 = zdatestr();
    
    gcry_sexp_t chain_proof;  
    err = gcry_sexp_build(&chain_proof, NULL, 
                "(\"Proof of Work\" (\"Calc Date\" %s) "
                "(\"All Hash\" %s) (\"Padding\" %s) (\"Orig ID\" %s) "
                "(\"Orig File\" %s) )",
                     ttt2, all_hash, pad64, 
                          backlink, backfile);
                         
    if(err)
        xerr2("dibapow: Cannot create proof sexpr: '%s'\n", gcry_strerror (err));
    
    //if(verbose)
    //    sexp_print(chain_proof);
        
    char padding[32];
    memset(padding, 'x', sizeof(padding));
     
    gcry_sexp_t chain_next;  
    build_next_struct ns;  INIT_NEXT_STRUCT(&ns)
    err = build_next(&chain_next, &ns);
    if(err)
        xerr2("dibapow: Cannot create next field sexpr: '%s'\n", gcry_strerror (err));
    
    gcry_sexp_t chain_link;
    err = gcry_sexp_build(&chain_link, NULL, 
                "(\"Chain Link\" %S %S %S %S)", 
                       chain_payload, chain_element, 
                            chain_proof, chain_next);
    if(err)
        xerr2("dibapow: Cannot create final sexpr: '%s'\n", gcry_strerror (err));
           
    if(print)
        sexp_print(chain_link);      
    
    char *err_str5;
    write_sexp_to_file(newfile, &chain_link, &err_str5);
    
    if(!nullfile)
        {
        update_next_field(backfile, newfile, recid );
        }
      
    printf("Wrote file: %s\n", newfile);
    
    zline2(__LINE__, __FILE__);
    zfree(dummy); 
    zline2(__LINE__, __FILE__);
    zfree(ttt); zfree(ttt2);  zfree(user); zfree(host);
    zfree(recid);  zfree(backlink); zfree(payfile);
    zline2(__LINE__, __FILE__);
    zfree(backfile); 
    zfree(newfile);
    zfree(datfile);
    zfree(fname);  zfree(pad64);
    zline2(__LINE__, __FILE__);
    zfree(payload); zfree(hash_str); zfree(all_hash);
    zfree(sum_str);
    
    zleak();
    return 0;
}

//////////////////////////////////////////////////////////////////////////
// Calculate padding needed to hash into criteria. Proof or work.
//
// str, len     -  input buffer
// out, olen    -  padding calculated
// tresh        -  criteria to coply with (less than))

ulong   calc_padding(const char *str, int len, char *out, int *olen, uint tresh)

{        
    ulong found = 0;
    int sum_len = len + *olen;
    int pass_len = strlen(test_pass);
     
    char *sum_str = zalloc(sum_len + 2);
    memcpy(sum_str, str, len);
    
    //bluepoint3_set_verbose(TRUE);
    bluepoint3_set_rounds(3);
    
    UINT loop, looping = MAXLOOP;
    for(loop = 0; loop < looping; loop++)
        {
        //rand_str(out, *olen);
        //rand_buff(out, *olen);
        gcry_randomize(out, *olen, GCRY_STRONG_RANDOM);
        memcpy(sum_str + len, out, *olen);
        ulong   hash = bluepoint3_crypthash64(sum_str, sum_len, test_pass, pass_len);
        //printf("Iter: %8u", loop);
        if (hash < tresh || loop % (looping / 1000) == 0)
                {
                //show_str((const char *)sum_str, sum_len);
                //printf("iter: %08d - hash: %8x str: ", loop, hash);
                //show_str((const char *)out, *olen);
                //printf("\b\b\b\b\b\b\b\bIter: %8u", loop);
                
                if(!nobatch)
                    printf("\rIter: %8u", loop);
                
                //printf("%08d - %I64x ", loop, hash);
                if (hash < tresh)
                    {
                    //printf("\nMatch: %8x ", hash);
                    //show_str((const char *)out, *olen);
                    //printf("\n");
                    found = hash;
                    break;
                    }
                }
        }
    zfree(sum_str);    
    return found;      
}

//////////////////////////////////////////////////////////////////////////
// Check / show

int     check_entry(gcry_sexp_t sexp)

{
    //sexp_print(sexp);
    
    // Check Payload Hash
    char *err_str; int olen, olen2;
    char *hhh = sexp_get_val(sexp, "Payload Data", &olen, &err_str);
    if(!hhh)
        {
        printf("No Payload: %s", err_str); return 0;
        }
    char *hash_str = hash_buff(hhh, olen);
    char *hhh2 = sexp_get_val(sexp, "Payload Hash", &olen2,  &err_str);
    if(!hhh2)
        {
        printf("No Hash %s", err_str); return 0;
        }
    //printf("hashed '%s' '%s'\n", hash_str, hhh2);
    if(strcmp(hash_str, hhh2) != 0)
        {
        printf("Hash does not match %s", err_str); return 0;
        }
    
    zfree(hhh2); zfree(hash_str);
    
    // Check padding
    int olen4, err = 0;
    gcry_sexp_t chain_payload = gcry_sexp_find_token(sexp, "Chain Payload", 0);
    if (!chain_payload)
        xerr2("Failed to find chain_payload sexp. %s\n", gcry_strerror (err));
    
    gcry_sexp_t chain_element = gcry_sexp_find_token(sexp, "Chain Element", 0);
    if (!chain_element)
        xerr2("Failed to find chain_element sexp. %s\n", gcry_strerror (err));
    
    int sum_lena, sum_lenb, sum_len;
    char *sum_stra =  sexp_get_buff(chain_payload, &sum_lena);
    char *sum_strb =  sexp_get_buff(chain_element, &sum_lenb);
    sum_len =  sum_lena + sum_lenb;
    char *sum_str = zalloc(sum_len + 2);
    memcpy(sum_str, sum_stra, sum_lena);
    memcpy(sum_str + sum_lena, sum_strb, sum_lenb);
    zfree(sum_stra);    zfree(sum_strb);
   
    bluepoint3_set_rounds(3);
    ulong   hash = bluepoint3_crypthash64(sum_str, sum_len, test_pass, strlen(test_pass));
    printf("Hash 0x%x\n", hash);
      
    zfree(hhh);    
             
    return 1;
}

//////////////////////////////////////////////////////////////////////////
// Add this entry to backlink:

int    update_next_field(const char *backf, const char *newf, const char *nexid)

{
    gcry_error_t err = 0; int plen, glen;
    char *err_str;
           
    // Read in and decode backfile
    gcry_sexp_t backsexp;
    read_sexp_from_file(backf, &backsexp, &err_str);
    if(err_str)
        {
        printf("Cannot read sexp %s\n", err_str);
        return 0;
        }
    //printf("Decoded back exp");
    //sexp_print(backsexp);
    
    gcry_sexp_t  chain_payload2 = gcry_sexp_find_token(backsexp, "Chain Payload", 0);
    if (!chain_payload2)
        xerr2("Failed to find chain_payload2 sexp. %s\n", gcry_strerror (err));
        
    gcry_sexp_t  chain_element2 = gcry_sexp_find_token(backsexp, "Chain Element", 0);
    if (!chain_element2)
        xerr2("Failed to find chain_element2 sexp. %s\n", gcry_strerror (err));
     
    gcry_sexp_t  chain_proof2 = gcry_sexp_find_token(backsexp, "Proof of Work", 0);
    if (!chain_proof2) 
        xerr2("Failed to decode chain_proof2 sexp. %s\n", gcry_strerror (err));
             
    gcry_sexp_t  chain_payload3 = gcry_sexp_find_token(backsexp, "Payload Data", 0);
    if (!chain_payload3)
        xerr2("Failed to find chain_payload data sexp. %s\n", gcry_strerror (err));
    
    int sum_len, sum_lena, sum_lenb;
    char *sum_stra =  sexp_get_buff(chain_payload2, &sum_lena);
    char *sum_strb =  sexp_get_buff(chain_element2, &sum_lenb);
    sum_len =  sum_lena + sum_lenb;
    
    zline2(__LINE__, __FILE__);
    char *sum_str = zalloc(sum_len + 2);
    memcpy(sum_str, sum_stra, sum_lena);
    memcpy(sum_str + sum_lena, sum_strb, sum_lenb);
    zfree(sum_stra);    zfree(sum_strb);
    
    char padding3[32]; 
    int pad_len3 = sizeof(padding3);
    
    ulong ret = calc_padding(sum_str, sum_len, padding3, &pad_len3, HASH_TRESH);
    
    if(ret ==  0)
        xerr2("dibapow: Cannot create padding, try again.");
     
    if(!nobatch)
        printf("\n");
    
    int len64;
    char *pad64 = base_and_lim(padding3, pad_len3, &len64);
    
    char *hash_str2 = (char *)nonestr;
    
    char *ttt3 = zdatestr();
    gcry_sexp_t chain_next2;  
    
    build_next_struct ns;  INIT_NEXT_STRUCT(&ns)
    
    ns.next_calc = ttt3;
    ns.next_hash = hash_str2;
    ns.next_pad  = pad64;
    ns.next_id   = (char*)nexid;
    ns.next_file = (char *)newf;
    //ns.next_workhash;
    
    err = build_next(&chain_next2, &ns);
    if(err)
        xerr2("dibapow: Cannot create next field sexpr: '%s'\n", gcry_strerror (err));
    
    zfree(ttt3); zfree(pad64);
    
    // Re Build
    gcry_sexp_t chain_link2;
    err = gcry_sexp_build(&chain_link2, NULL, 
            "(\"Chain Link\" %S %S %S %S)", 
                    chain_payload2, chain_element2,
                         chain_proof2, chain_next2);
    if(err)
        xerr2("dibapow: Cannot create next field backlink sexpr: '%s'\n", gcry_strerror (err));        
      
    write_sexp_to_file(backf, &chain_link2, &err_str);
      
    //zfree(hash_str2); 
    zfree(sum_str);
    if(err_str)
         {
         xerr2("Cannot write to file. %s\n", err_str);
         } 
    return 1;
}

/* EOF */






