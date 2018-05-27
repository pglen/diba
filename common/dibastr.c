
/* =====[ dibastr.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.17.2017     Peter Glen      Added dump mem
      0.00  jul.22.2017     Peter Glen      Sexp helpers

   ======================================================================= */

#include "dibastr.h"

// -----------------------------------------------------------------------
// Unified strings for key files, definitons

const char *pub_start  = "-----BEGIN DIGIBANK RSA PUBLIC KEY-----";
const char *pub_end    = "-----END DIGIBANK RSA PUBLIC KEY-----";

const char *comp_start = "-----BEGIN DIGIBANK RSA COMPOSITE KEY-----";
const char *comp_end   = "-----END DIGIBANK RSA COMPOSITE KEY-----";

const char *query_start = "-----BEGIN DIGIBANK QUERY-----";
const char *query_end   = "-----END DIGIBANK QUERY-----";

const char *resp_start = "-----BEGIN DIGIBANK RESPONSE-----";
const char *resp_end   = "-----END DIGIBANK RESPONSE-----";

const char *cyph_start = "-----BEGIN DIGIBANK RSA CIPHER-----";
const char *cyph_end   = "-----END DIGIBANK RSA CIPHER-----";

const char *sig_start  = "-----BEGIN DIGIBANK RSA SIGNATURE-----";
const char *sig_end    = "-----END DIGIBANK RSA SIGNATURE-----";

const char *mod_start  = "-----BEGIN DIGIBANK PUBLIC MODULUS-----";
const char *mod_end    = "-----END DIGIBANK PUBLIC MODULUS-----";
    
const char *exp_start  = "-----BEGIN DIGIBANK PUBLIC EXPONENT-----";
const char *exp_end    = "-----END DIGIBANK PUBLIC EXPONENT-----";

const char *chain_start  = "-----BEGIN DIGIBANK BLOCKCHAIN ENTRY-----";
const char *chain_end    = "-----END DIGIBANK BLOCKCHAIN ENTRY-----";
    
// The default pass for many items. 
// Will make old data INCOMPATIBLE, exercise care on fiddling.
// DO NOT CHANGE

const char *keypass = "12345678";

const char *nonestr = "none";
const  char *mstr   = "No Memory";

const  char *nullfname = "000000000000";
const  char *nullext  = ".bce"; 
const  char *datext   = ".dat"; 

// End dirs with a backslash

const  char *nulldir  = "../data/blockchain/";        
const  char *custdbname = "../data/customers/data.mysql";
       
// Central point for encryption pass.
// The actual value is meaningless, as hashes are generated with it.
// Make sure to change it on both encryption / decryption side.
// Will make old data INCOMPATIBLE, exercise care on fiddling.
// DO NOT CHANGE
         
const  char *dibapass = "1234567890";

// EOF








