# ----------------------------------------------------------------------------------
# Makefile for digibank 
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

# Breaking with minimalism on include ...
include ../dibamac.inc

# Exclude building server ... it is just a stub for the worker
all: 	dibaserv.exe dibaclient.exe dibaworker.exe dibaquery.exe \
            dibacli_hello.exe dibacli_key.exe dibacli_sess.exe \
               dibacli_ping.exe 

dibaserv.exe: dibaserv.c $(TOOLS) $(OBJS) $(CRYPTER) dibascom.c
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -lws2_32 -o $@

dibaclient.exe: dibaclient.c $(TOOLS) $(OBJS) $(CRYPTER) dibascom.c
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -lws2_32 -o $@

dibacli_hello.exe: dibacli_hello.c $(TOOLS) $(OBJS) $(CRYPTER) dibascom.c
	$(CC)  $^ $(ALL_OPTS)$(ALL_LIBS) -lws2_32   -o $@

dibacli_ping.exe: dibacli_ping.c $(TOOLS) $(OBJS) $(CRYPTER) dibascom.c
	$(CC)  $^ $(ALL_OPTS)$(ALL_LIBS) -lws2_32   -o $@

dibacli_key.exe: dibacli_key.c $(TOOLS) $(OBJS) $(CRYPTER) dibascom.c
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -lws2_32 -o $@

dibacli_sess.exe: dibacli_sess.c $(TOOLS) $(OBJS) $(CRYPTER) dibascom.c
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -lws2_32 -o $@

dibaworker.exe: dibaworker.c $(TOOLS) $(OBJS) $(CRYPTER) dibascom.c
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -lws2_32 -o $@

dibaquery.exe: dibaquery.c $(TOOLS) $(OBJS) $(CRYPTER)  dibascom.c
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -lws2_32 -o $@

# Notice the plural on tests in subdirs.
tests:
	@echo No tests here

test:  tests

clean:
	-@rm -f *.o *.obj *.log
	-@rm -f a.out
	-@rm -f aa*
	-@rm -f *.exe

distclean: clean





















