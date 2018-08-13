# ------------------------------------------------------------------------

# what flags you want to pass to the C compiler & linker
AM_CFLAGS = -std=c99 -O2 -I$(top_srcdir)/common \
    -I$(top_srcdir)/common -I$(top_srcdir)/bluepoint -I$(top_srcdir)/tools

AM_LDFLAGS = -L$(top_srcdir)/common -L$(top_srcdir)/tools -l z -l gcrypt \
      -l gpg-error 

#AUTOMAKE_OPTIONS = subdir-objects

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile

bin_PROGRAMS = test_base64 test_zmalloc

test_zmalloc_SOURCES = test_zmalloc.c zmalloc.c
test_base64_SOURCES = test_base64.c base64.c zmalloc.c
           


