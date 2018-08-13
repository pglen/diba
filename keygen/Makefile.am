# ------------------------------------------------------------------------
# 

# Flags to pass to the C compiler & linker
AM_CFLAGS = -std=c99 -I../common -I../bluepoint -I../tools

AM_LDFLAGS = -L../bluepoint -L../common -L../tools \
            -l z -l gcrypt -l gpg-error 

#AUTOMAKE_OPTIONS = subdir-objects

# List the binaries to produce, 

bin_PROGRAMS = dibakeygen #dibakeyinfo

dibakeygen_SOURCES = dibakeygen.c ../tools/zmalloc.c ../tools/gcry.c \
   ../tools/base64.c ../tools/cmdline.c ../tools/zstr.c ../tools/getpass.c \
   ../tools/dibafile.c ../tools/misc.c ../tools/gsexp.c \
   ../common/dibastr.c ../common/dibautils.c \
   ../bluepoint/bluepoint3.c
   
dibakeyinfo_SOURCES = dibakeyinfo.c ../tools/zmalloc.c ../tools/gcry.c \
   ../tools/base64.c ../tools/cmdline.c ../tools/zstr.c ../tools/getpass.c \
   ../tools/dibafile.c ../tools/misc.c ../tools/gsexp.c \
   ../common/dibastr.c ../common/dibautils.c \
   ../bluepoint/bluepoint3.c

                                                  


