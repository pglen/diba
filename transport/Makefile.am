# ------------------------------------------------------------------------
# 

AM_CFLAGS = -std=c99 -I../common -I../bluepoint -I../tools 

AM_LDFLAGS = -L../bluepoint -L../common -L../tools \
            -l z -l gcrypt -l gpg-error 

#AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS =  dibaencrypt  dibadecrypt

dibaencrypt_SOURCES = dibaencrypt.c \
    ../tools/zmalloc.c ../tools/gcry.c \
   ../tools/base64.c ../tools/cmdline.c ../tools/zstr.c ../tools/getpass.c \
   ../tools/dibafile.c ../tools/misc.c ../tools/gsexp.c \
   ../common/dibastr.c ../common/dibautils.c \
   ../bluepoint/bluepoint3.c
   
dibadecrypt_SOURCES = dibadecrypt.c  \
   ../tools/zmalloc.c ../tools/gcry.c \
   ../tools/base64.c ../tools/cmdline.c ../tools/zstr.c ../tools/getpass.c \
   ../tools/dibafile.c ../tools/misc.c ../tools/gsexp.c \
   ../common/dibastr.c ../common/dibautils.c \
   ../bluepoint/bluepoint3.c

