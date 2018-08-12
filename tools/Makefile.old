##########################################################################
#
# Makefile to build and test the tools for DIBA. Here you find tools
# for self checking malloc, base64 codec, inteface to libcrypt
#
# The macros point to already built sub parts. Edit here if you move
# the files to a different directory. This is done, so one can use 
# these sub parts without installation. -- Moved to ../dibamac.inc
#
# Execute make tests for confidence checks
#

include ../dibamac.inc

#INC2=../../libgcrypt/libgpg-error-1.27/src 
#INC3=../../libgcrypt/libgcrypt-1.7.8/src 
#INC3=../../libgcrypt/libgcrypt-1.8.2/src 
#INC4=../bluepoint
#INC5=../../zlib/zlib-1.2.11
#INC6=../common
#
##LIB2=../../libgcrypt/libgcrypt-1.7.8/src/.libs/ 
##LIB2=../../libgcrypt/libgcrypt-1.8.2/src/.libs/ 
##LIB3=../../libgcrypt/libgpg-error-1.27/src/.libs/
#LIB4=../../zlib/zlib-1.2.11
#
#LIBS= -l gcrypt -l gpg-error -l z 
#
#OPT_LIBS= -L $(LIB2) -L $(LIB3) -L $(LIB4) 
#
## GCC need to be told on Linux, W32 does it by default
#CC=gcc -std=c99
#OPT2= -I $(INC2) -I $(INC3) -I $(INC4) -I $(INC5) -I $(INC6) 
#OPT3=  $(OPT2) $(OPT_LIBS) 
#
#.c.o:
#	$(CC) $(OPT3) -c $<
  
# This is to create templates for test expectations. We substitue memory 
# locations with zeros, so diff is happy
#FILTER=awk -f awk.txt

FILTER=sed -e "s/0x[0-9a-fA-F]*/0x00000000/g"

# Exclude lines with 'Begin' so diff is happy
FILTER2=grep -v Begin

SRCS =  base64.c getpass.c zmalloc.c cmdline.c misc.c zstr.c
SRCS2= $(SRCS) gsexp.c gcry.c dibafile.c 

all:  $(SRCS) 
 
# zmalloc needs FILTER to nullify pointer strings
# misc needs FILTER2 to erase PID strings
	        
tests:  build_tests
	@echo Tests pass if diffs are silent.
	@./test_one.sh ./test_base64.exe
	@./test_one.sh ./test_base64a.exe
	@./test_one.sh ./test_comline.exe
	@./test_one.sh ./test_zstr.exe
	@./test_one.sh ./test_keys.exe
	@./test_one.sh ./test_chunk.exe
	@./test_one.sh ./test_zip.exe
	@./test_two.sh ./test_misc.exe "$(FILTER2)"  
	@./test_two.sh ./test_zmalloc.exe "$(FILTER)"
	@-rm -f test.tmp 
	
# 
getpass_test:
	@echo please press ENTER as a fake pass for testing
	@./test_one.sh ./test_getpass.exe
	   
build_tests: test_base64.exe test_base64a.exe test_base64b.exe \
        test_zmalloc.exe test_comline.exe test_zstr.exe test_misc.exe \
            test_chunk.exe test_keys.exe test_zip.exe test_getpass.exe

prep_tests:  build_tests
	@./test_prep2.sh ./test_zmalloc.exe "$(FILTER)"
	@./test_prep2.sh ./test_misc.exe "$(FILTER2)"
	@./test_prep.sh ./test_base64.exe
	@./test_prep.sh ./test_base64a.exe
	@./test_prep.sh ./test_comline.exe
	@./test_prep.sh ./test_zstr.exe
	@./test_prep.sh ./test_zip.exe
	@./test_prep.sh ./test_chunk.exe
	@./test_prep.sh ./test_keys.exe
	@echo Please press ENTER key for getpass  ...
	@./test_prep.sh ./test_getpass.exe
	             
test_base64.exe:  test_base64.c   $(SRCS)
	$(CC) test_base64.c  base64.c zmalloc.c -o test_base64 
 
test_misc.exe:  test_misc.c   $(SRCS)
	$(CC) test_misc.c  $(SRCS) -o test_misc

test_getpass.exe:  test_getpass.c   $(SRCS)
	$(CC) test_getpass.c  $(SRCS) -lncurses -o test_getpass.exe

test_zip.exe:  test_zip.c  $(SRCS2)
	 $(CC) $(OPT3) $(SRCS2) test_zip.c $(LIBS)  -o test_zip.exe

test_chunk.exe:  test_chunk.c  dibafile.c  $(SRCS2)
	 $(CC) $(OPT3) $(SRCS2) test_chunk.c $(LIBS) -lz -o test_chunk.exe

test_keys.exe:  test_keys.c  dibafile.c  $(SRCS)
	$(CC)  $(OPT3) $(SRCS2) test_keys.c -lgcrypt -lz -o test_keys

test_zstr.exe:  test_zstr.c  $(SRCS)
	$(CC) test_zstr.c  $(SRCS) -o test_zstr

test_comline.exe:  test_comline.c $(SRCS)
	$(CC) test_comline.c $(SRCS) -o test_comline

test_base64a.exe:  test_base64a.c    $(SRCS)
	$(CC) test_base64a.c  base64.c zmalloc.c -o test_base64a 

test_base64b.exe:  test_base64b.c  $(SRCS)
	$(CC) test_base64b.c  base64.c zmalloc.c -o test_base64b

test_zmalloc.exe:  test_zmalloc.c  $(SRCS)
	$(CC) test_zmalloc.c  zmalloc.c -o test_zmalloc

clean:
	@-rm -f aa*  
	@-rm -f bb*  
	@-rm -f cc*  
	@-rm -f *.o   
	@-rm -f test2.tmp test.tmp
	
allclean:  clean
	@-rm -f *.exe 
	
distclean: allclean

checksum:
    # we use a file for stderr instead of /dev/nul as in MSYS /dev does ot exist
	@-rm -f md5sum.txt
	@-md5sum `find . -path ./.git -prune -o -print`  > md5sum.txt 2> stderr
	@rm -f aa stderr
    
# This will force refreshing tests
distclean:  clean allclean
	@rm -f *.org

