# ----------------------------------------------------------------------------------
# Makefile for digibank chest subsystem.
# ----------------------------------------------------------------------------------

# These macros point to already built sub parts. Edit here if you move
# the files to a different directory. This is done, so one can use 
# these sub parts without installation.

include ../dibamac.inc

all:  dibachest.exe dibachestinfo.exe

sqlite3.o:  $(SQLSRC)
	gcc -std=c99  $(OPT4) $(SQLSRC) -c

dibachest.exe:  dibachest.c  $(TOOLS) $(OBJS) $(CRYPTER)
	$(CC)  $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

dibachestinfo.exe:  dibachestinfo.c    $(TOOLS) $(OBJS) $(CRYPTER)
	$(CC) $^ $(ALL_OPTS) $(ALL_LIBS) -o $@

tests: test

test: 

clean:
	-@rm -f *.o *.obj
	-@rm -f a.out
	-@rm -f *.exe

distclean: clean

dataclean:
	-@rm -f ../data/customers/data.mysql
	-@rm -f ../data/customers/keys/*
 

