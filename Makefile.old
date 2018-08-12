# ----------------------------------------------------------------------------------
# Makefile for digibank (diba)
#
# This makefile usues a bare minimum of features. Can be run both on windows
# and posix tools with a help of batch files. Both make and nmake will work.
#
# Top level, call all subdirs
# ----------------------------------------------------------------------------------

# Makefile to build and test the tools for DIBA. Here you find tools
# for self checking malloc, base64 codec, inteface to libcrypt

# These macros point to already built sub parts. Edit here if you move
# the files to a different directory. This is done, so one can use 
# these sub parts without installation.

INC2=../../libgcrypt/libgpg-error-1.27/src 
#INC3=../../libgcrypt/libgcrypt-1.7.8/src 
INC3=../../libgcrypt/libgcrypt-1.8.2/src 

INC4=../bluepoint
INC5=../../zlib/zlib-1.2.11
INC6=../common

#LIB2=../../libgcrypt/libgcrypt-1.7.8/src/.libs/ 
LIB2=../../libgcrypt/libgcrypt-1.8.2/src/.libs/ 
LIB3=../../libgcrypt/libgpg-error-1.27/src/.libs/
LIB4=../../zlib/zlib-1.2.11

LIBS= -l gcrypt -l gpg-error -l z 

OPT_LIBS= -L $(LIB2) -L $(LIB3) -L $(LIB4) 

# GCC need to be told on Linux, W32 does it by default
CC=gcc -std=c99
OPT2= -I $(INC2) -I $(INC3) -I $(INC4) -I $(INC5) -I $(INC6) 
OPT3=  $(OPT2) $(OPT_LIBS) 

.c.o:
	$(CC) $(OPT3) -c $<
  
all:
	@./alldirs.sh

# Notice the plural on tests in subdirs.
tests: test
test: 
	@./alldirs.sh tests

publish:
	git add .
	git commit -m 'makefile auto commit'	
	git push

clean:
	@./alldirs.sh clean
	-@rm -f *.o *.obj
	-@rm -f a.out
	-@rm -f *.exe

distclean: clean
	@./alldirs.sh distclean

checksum:
    # we use a file for stderr instead of /dev/nul as in MSYS /dev does ot exist
	@-rm -f md5sum.txt
	-md5sum `find . -path ./.git -prune -o -print`  > md5sum.txt 2> stderr
	@rm -f aa stderr

check:
	@# Filter out good responses, so we see better
	-md5sum  -c md5sum.txt | grep -v "OK"








