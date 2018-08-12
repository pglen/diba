# Makefile for digibank blockchain
#
# This makefile usues a bare minimum of features. Can be run both on windows
# and posix tools with a help of batch files. Both make and nmake will work.

# GCC will error check better than cl, use for build test

include ../dibamac.inc

# ----------------------------------------------------------------------------------

all:   dibapow.exe dibachain.exe 
    
dibapow.exe:  dibapow.c   $(TOOLS) $(OBJS) $(CRYPTER) 
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@
                                                      
dibachain.exe:  dibachain.c   $(TOOLS) $(OBJS) $(CRYPTER)
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

test: tests

tests:
	@echo "No tests here"

clean:
	-@rm -f *.o *.obj
	-@rm -f a.out
	-@rm -f *.exe

cleandata:
	@rm -rf data

testdata: cleandata
	dibapow.exe -n
	dibapow.exe ./data/000000000000.bce payload

distclean: clean cleandata
























