# ------------------------------------------------------------------------

# what flags you want to pass to the C compiler & linker
AM_CFLAGS = -std=c99 -O2 -I$(top_srcdir)/common \
    -I$(top_srcdir)/common -I$(top_srcdir)/bluepoint -I$(top_srcdir)/tools

AM_LDFLAGS = -L$(top_srcdir)/common -L$(top_srcdir)/tools -l z -l gcrypt \
      -l gpg-error 

#AUTOMAKE_OPTIONS = subdir-objects

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile

bin_PROGRAMS = test_base64 test_zmalloc \
 test_base64 test_base64a test_base64b \
         test_comline test_zstr test_misc \
            test_chunk test_keys test_zip test_getpass \
                test_dibabuffa test_dibafile test_buffkeys

test_zmalloc_SOURCES = test_zmalloc.c zmalloc.c
test_base64_SOURCES = test_base64.c base64.c zmalloc.c
test_base64a_SOURCES = test_base64a.c base64.c zmalloc.c
test_base64b_SOURCES = test_base64b.c base64.c zmalloc.c
test_comline_SOURCES = test_comline.c base64.c zmalloc.c misc.c cmdline.c zstr.c
test_zstr_SOURCES = test_zstr.c base64.c zmalloc.c misc.c cmdline.c zstr.c
test_misc_SOURCES = test_misc.c base64.c zmalloc.c misc.c cmdline.c zstr.c
test_getpass_SOURCES = test_getpass.c base64.c zmalloc.c misc.c cmdline.c zstr.c getpass.c

test_keys_SOURCES = test_keys.c base64.c dibafcom.c zmalloc.c misc.c cmdline.c zstr.c dibafile.c
test_zip_SOURCES = test_zip.c base64.c dibafcom.c zmalloc.c misc.c cmdline.c zstr.c  dibafile.c
test_chunk_SOURCES = test_chunk.c base64.c dibafcom.c zmalloc.c misc.c cmdline.c zstr.c dibafile.c
test_dibabuffa_SOURCES = test_dibabuffa.c dibafcom.c base64.c zmalloc.c misc.c cmdline.c zstr.c dibabuff.c
test_dibafile_SOURCES = test_dibabuffa.c dibafcom.c base64.c zmalloc.c misc.c cmdline.c zstr.c dibabuff.c
test_buffkeys_SOURCES = test_buffkeys.c dibafcom.c base64.c zmalloc.c misc.c cmdline.c zstr.c dibabuff.c

test:
	@echo Tests pass if diffs are silent.
	@./test_one.sh ./test_base64$(EXEEXT)
	@./test_one.sh ./test_base64a$(EXEEXT)
	@./test_one.sh ./test_comline$(EXEEXT)
	@./test_one.sh ./test_zstr$(EXEEXT)
	@./test_one.sh ./test_keys$(EXEEXT)
	@./test_one.sh ./test_chunk$(EXEEXT)
	@./test_one.sh ./test_dibabuffa$(EXEEXT)
	@./test_one.sh ./test_zip$(EXEEXT)
	@./test_two.sh ./test_misc$(EXEEXT) "$(FILTER2)"  
	@./test_two.sh ./test_zmalloc$(EXEEXT) "$(FILTER)"
	@-rm -f test.tmp 
    
prep_tests:  
	@./test_prep2.sh ./test_zmalloc$(EXEEXT) "$(FILTER)"
	@./test_prep2.sh ./test_misc$(EXEEXT) "$(FILTER2)"
	@./test_prep.sh ./test_base64$(EXE$(EXEEXT)
	@./test_prep.sh ./test_base64a$(EXEEXT)
	@./test_prep.sh ./test_comline$(EXEEXT)
	@./test_prep.sh ./test_zstr$(EXEE$(EXEEXT)
	@./test_prep.sh ./test_dibabuffa$(EXEEXT)
	@./test_prep.sh ./test_zip$(EXEEXT)
	@./test_prep.sh ./test_chunk$(EXEEXT)
	@./test_prep.sh ./test_keys$(EXEEXT)
	@echo Please press ENTER key for getpass  
	@./test_prep.sh ./test_getpass$(EXEEXT)

test_PROGRAMS:  ./test_base64$(EXEEXT)









