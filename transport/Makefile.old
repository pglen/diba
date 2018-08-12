# The macros point to already built sub parts. Edit it if you move the files to 
# a different directory. This is done, so one can use the parts without 
# explicit installation.

# History
#   0.00  aug.26.2017     Peter Glen      First push to github
#   0.00  sep.29.2017     Peter Glen      Push to github, new dir struct
#   0.00  dec.02.2017     Peter Glen      Added signing
#   0.00  may.12.2018     Peter Glen      Recompiled msys2
#   0.00  may.17.2018     Peter Glen      msys2 works
#   0.00  may.22.2018     Peter Glen      Terminal works, dynamic recompile

include ../dibamac.inc

# Test macros

ENCTEST=./dibaencrypt.exe -i sample.txt -o sample.enc testkey/testkey.pub  
ENCTEST2=./dibadecrypt.exe -i sample.enc -o sample.dec -p 1111 testkey/testkey.key

ENCTEST3=./dibaencrypt.exe -i blocksample.txt -o blocksample.enc testkey/testkey.pub  
ENCTEST4=./dibadecrypt.exe -i blocksample.enc -o blocksample.dec -p 1111 testkey/testkey.key

KEYTEST=./dibakeygen.exe -p 1111 -f bb  
KEYTEST2=./dibakeyinfo.exe -p 1111 -c bb  

SIGTEST=./dibasign.exe -p 1111 -i test.txt -o test.sig testkey/testkey.key
SIGTEST2=./dibacheck.exe -p 1111 -i test.txt -g test.sig testkey/testkey.pub

ENCTEST5=echo $(HELLO) | ./dibaencrypt.exe -r testkey/testkey.pub | \
            ./dibadecrypt.exe -r -p 1111 testkey/testkey.key

OBJS  =   $(COMMON)/dibastr.c $(COMMON)/dibautils.c

all:  build_tests dibadump.exe

bluepoint3.o:
	$(CC) $(OPT2) -c ../bluepoint/bluepoint3.c  

bigtest: build_tests
	@cat bigsample.txt >test.tmp ;cat bigsample.txt >test.tmp
	@cat bigsample.txt >>test.tmp ;cat bigsample.txt >>test.tmp
	@dibaencrypt.exe  -i test.tmp -o test.enc testkey/testkey.pub 
	@dibadecrypt.exe  -i test.enc -o test.dec -p 1111 testkey/testkey.key 
	@echo Test passes if diffs are silent.
	@diff test.tmp test.dec    
	@-rm -f test2.tmp test.tmp *.enc *.dec 

test: tests

tests:  build_tests
	@echo Tests pass if diffs are silent.
	@echo Enc/Dec test:
	@$(ENCTEST); $(ENCTEST2)
	@diff sample.txt sample.dec
	@$(ENCTEST3); $(ENCTEST4)
	@diff blocksample.txt blocksample.dec
	@echo $(HELLO) > test2.tmp
	@$(ENCTEST5) > test.tmp
	@diff -w test2.tmp test.tmp
	@echo Keytest:
	@$(KEYTEST) > test2.tmp; $(KEYTEST2) > test2.tmp
	@cat test2.tmp | grep OK > test.tmp
	@diff test.tmp keytest.org 
	@echo Sigtest:
	@$(SIGTEST); $(SIGTEST2) > test.tmp
	@diff  test.tmp sigtest.org
	@-rm -f test2.tmp test.tmp *.enc *.dec bb.*
    
build_tests: dibaencrypt.exe dibadecrypt.exe \
             dibasign.exe dibacheck.exe 

enctest.org:
	$(ENCTEST) > enctest.org

sigtest.org:
	@$(SIGTEST); $(SIGTEST2) > sigtest.org
	      
prep_tests:  build_tests enctest.org sigtest.org
	@$(KEYTEST) > test.tmp; $(KEYTEST2) > test.tmp
	@cat test.tmp | grep OK > keytest.org 
	@$(SIGTEST) > test.tmp; $(KEYTEST2) > test.tmp
	@cat test.tmp | grep OK > keytest.org 
	@rm test.tmp
	             
algos.exe: $(OBJS) algos.c  $(TOOLS) $(OBJS) $(CRYPTER)
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

test_sexp.exe: $(OBJS) test_sexp.c  $(TOOLS) $(OBJS) $(CRYPTER)
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

dibakeygen.exe:  dibakeygen.c $(TOOLS) $(OBJS) $(CRYPTER)
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

dibakeyinfo.exe: $(OBJS) dibakeyinfo.c $(TOOLS) $(OBJS) $(CRYPTER) 
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

dibasign.exe: $(OBJS) dibasign.c $(TOOLS) $(OBJS) $(CRYPTER) 
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

dibacheck.exe: $(OBJS) dibacheck.c $(TOOLS) $(OBJS) $(CRYPTER) 
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

dibaencrypt.exe: $(OBJS) dibaencrypt.c $(TOOLS) $(OBJS) $(CRYPTER) 
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

dibadecrypt.exe: $(OBJS) dibadecrypt.c $(TOOLS) $(OBJS) $(CRYPTER) 
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

dibadump.exe:  $(OBJS) dibadump.c $(TOOLS) ../bluepoint/bluepoint3.c  
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS)  -o $@

clean:
	@-rm -f aa.* bb.* cc.*  
	@-rm -f *.o  *.enc *.dec
	@-rm -f test2.tmp test.tmp 
	
allclean:  clean
	@-rm -f *.exe  
	
distclean:    clean allclean
	@-rm -f *.key *.pub  

	












