// test sqlite

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>

#include    "sqlite3.h"
          
char *fields[] = { "lob",  "city", "cname", "zip", "freetext", "dob", 
        "country", "numid", "email2", "county", "phone", "addr2",
        "comments", "addr1", "phone2", "email", "log", "custid" 
        };
        
char cq[] = "CREATE TABLE clients (pri INTEGER PRIMARY KEY, entryid string, "
            "lob text, city text, cname text, zip text, freetext text, "
            "dob text, country text, numid text, email2 text, county text, "
            "phone text, addr2 text, comments text, addr1 text, phone2 text, "
            "email text, log text, custid text";

static int callback(void *NotUsed, int argc, char **argv, char **azColName)
        
{
    int i;
    for(i=0; i<argc; i++){
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
  }
  
  int main(int argc, char **argv){
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
  
    if( argc!=3 ){
      fprintf(stderr, "Usage: %s DATABASE SQL-STATEMENT\n", argv[0]);
      return(1);
    }
    
    rc = sqlite3_open(argv[1], &db);
    if( rc ){
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      return(1);
    }
    
    rc = sqlite3_exec(db, argv[2], callback, 0, &zErrMsg);
    if( rc!=SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }
    
    sqlite3_close(db);
    return 0;
}




