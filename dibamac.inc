# Macros used in all makefiles for DIBA. Adjust here if needed.
# Test with 'make all'.

# The version abd location of GCRYPT
GDIR = ../../libgcrypt/libgcrypt-1.8.2
#GDIR = ../../libgcrypt/libgcrypt-1.7.8

# The version abd location of GCRYPT error routines
GERR=../../libgcrypt/libgpg-error-1.27

# The version of zlib
ZDIR=../../zlib/zlib-1.2.11

# GCC need to be told on Linux, W32 does it by default
CC=gcc -std=c99

# ------------------------------------------------------------------------
# USER ADJUSTABLE includes above, edit below with care

#INC2=$(GERR)/src 
#INC3=$(GDIR)/src

INC4=../bluepoint
#INC5=$(ZDIR)
INC6=../common
INC7=../tools

#LIB2=$(GDIR)/src/.libs/ 
#LIB3=$(GERR)/src/.libs/

#LIB4=$(ZDIR)

TOOLDIR=../tools
BLUEDIR=../bluepoint
COMMON=../common

TOOLS=$(TOOLDIR)/gcry.c $(TOOLDIR)/gsexp.c   \
            $(TOOLDIR)/base64.c $(TOOLDIR)/getpass.c $(TOOLDIR)/zmalloc.c \
                $(TOOLDIR)/cmdline.c $(TOOLDIR)/misc.c $(TOOLDIR)/zstr.c  \
                        $(TOOLDIR)/dibafile.c \
                            $(COMMON)/dibastr.c $(COMMON)/dibautils.c \
                                $(BLUEDIR)/bluepoint3.c

LIBS2= -l gpg-error 
LIBS=-l z -l gcrypt -l ncurses
#OPT_LIBS= -L $(LIB2) -L $(LIB3) -L $(LIB4) 

#OPT2= -I $(INC2) -I $(INC3) -I $(INC5) 
OPT2=-I $(INC4) -I $(INC6) -I $(INC7) 
OPT3=  $(OPT2) 

ALL_OPTS = $(OPT2) $(OPT3)
ALL_LIBS = $(OPT_LIBS) $(LIBS) 

SQLDIR=../../sqlite/sqlite-amalgamation-3200100
OPT4=-I $(SQLDIR) -L $(SQLDIR) 
SQLSRC=$(SQLDIR)/sqlite3.c
SQLOBJ=$(SQLDIR)/sqlite3.o

CRYPTER=$(BLUEDIR)/bluepoint3.c 

## This is to create templates for test expectations. We substitue memory 
## locations with zeros, so diff is happy
#

FILTER=sed s/0x[0-9A-F]*/0x00000000/g

HELLO="Hello World"

# EOF





