# The macros point to already built sub parts. Edit it if you move the files to 
# a different directory. This is done, so one can use the parts without 
# explicit installation.

# History
#   0.00  jun.17.2018     Peter Glen        Moved to keygen dir, restructured

include ../dibamac.inc

# Test macros

KEYTEST=./dibakeygen.exe -p 1111 -f bb  
KEYTEST2=./dibakeyinfo.exe -p 1111 -c bb  

OBJS  =   $(COMMON)/dibastr.c $(COMMON)/dibautils.c

all:  dibakeygen.exe dibakeyinfo.exe

bluepoint3.o:
	$(CC) $(OPT2) -c ../bluepoint/bluepoint3.c  

test: tests

tests:  build_tests
	@echo Tests pass if diffs are silent.
	@echo Keytest:
	@$(KEYTEST) > test2.tmp; $(KEYTEST2) > test2.tmp
	@cat test2.tmp | grep OK > test.tmp
	@diff test.tmp keytest.org 
	@-rm -f test2.tmp test.tmp *.enc *.dec bb.*
    
build_tests:    dibakeygen.exe dibakeyinfo.exe

prep_tests:  build_tests sigtest.org
	@$(KEYTEST) > test.tmp; $(KEYTEST2) > test.tmp
	@cat test.tmp | grep OK > keytest.org 
	@rm test.tmp
	             
dibakeygen.exe:  dibakeygen.c $(TOOLS) $(OBJS) $(CRYPTER)
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

dibakeyinfo.exe: $(OBJS) dibakeyinfo.c $(TOOLS) $(OBJS) $(CRYPTER) 
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

clean:
	@-rm -f aa.* bb.* cc.*  
	@-rm -f *.o  *.enc *.dec
	@-rm -f test2.tmp test.tmp 
	
allclean:  clean
	@-rm -f *.exe  
	
distclean:    clean allclean
	@-rm -f *.key *.pub  

	












