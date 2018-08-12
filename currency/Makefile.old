# Makefile for console digibank client
# This makefile usues a bare minimum of features. Can be run both on windows
# and posix tools with a help of batch files. Both make and nmake will work.

include ../dibamac.inc

# ----------------------------------------------------------------------------------
                
# Included in dependencies, as they change over time
HEADERS = $(BLUEDIR)/bluepoint3.h $(COMMON)/diba.h

all:   dibagen.exe dibadec.exe dibainit.exe \
        dibawalk.exe dibatrans.exe
    
dibainit.exe:  dibainit.c  $(TOOLS)  $(HEADERS)
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

dibawalk.exe:  dibawalk.c  $(TOOLS)  $(ENCFILE)  $(HEADERS)
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

dibagen.exe:  dibagen.c  $(TOOLS)  $(HEADERS)
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) $(ENCFILE) -o $@

dibadec.exe:  dibadec.c  $(TOOLS)  $(ENCFILE)   $(HEADERS)
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) $(ENCFILE) -o $@

dibatrans.exe:  dibatrans.c  $(TOOLS)  $(ENCFILE)   $(HEADERS)
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) $(ENCFILE) -o $@

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

distclean:    clean cleandata
















