# MAKEFILE for linux GCC
#
# Tom St Denis
# Modified by Clay Culver
#
# NOTE: This should later be replaced by autoconf/automake scripts, but for
# the time being this is actually pretty clean. The only ugly part is
# handling CFLAGS so that the x86 specific optimizations don't break
# a build. This is easy to remedy though, for those that have problems.

# The version
VERSION=0.79

#ch1-01-1
# Compiler and Linker Names
CC=gcc
LD=ld

# Archiver [makes .a files]
AR=ar
ARFLAGS=r
#ch1-01-1

#ch1-01-2
# here you can set the malloc/calloc/free functions you want
XMALLOC=malloc
XCALLOC=calloc
XREALLOC=realloc
XFREE=free

# you can redefine the clock
XCLOCK=clock
XCLOCKS_PER_SEC=CLOCKS_PER_SEC
#ch1-01-2

#ch1-01-3
# Compilation flags. Note the += does not write over the user's CFLAGS!
CFLAGS += -c -I./ -Wall -Wsign-compare -W -Wno-unused -Werror  \
   -DXMALLOC=$(XMALLOC) -DXCALLOC=$(XCALLOC) -DXFREE=$(XFREE) \
   -DXREALLOC=$(XREALLOC) -DXCLOCK=$(XCLOCK) \
   -DXCLOCKS_PER_SEC=$(XCLOCKS_PER_SEC)

# optimize for SPEED
#CFLAGS += -O3 -funroll-loops

# optimize for SIZE 
CFLAGS += -Os 

# compile for DEBUGGING 
#CFLAGS += -g3
#ch1-01-3

#These flags control how the library gets built.

#ch1-01-4
# Use small code variants of functions when possible?  
CFLAGS += -DSMALL_CODE

# no file support, when defined the library will not 
# have any functions that can read/write files 
# (comment out to have file support)
#CFLAGS += -DNO_FILE

# Support the UNIX /dev/random or /dev/urandom
CFLAGS += -DDEVRANDOM

# Use /dev/urandom first on devices where 
# /dev/random is too slow 
#CFLAGS += -DTRY_URANDOM_FIRST

# Clean the stack after sensitive functions.  Not 
# always required... With this defined most of 
# the ciphers and hashes will clean their stack area
# after usage with a (sometimes) huge penalty in speed.
# Normally this is not required if you simply lock your 
# stack and wipe it when your program is done.
#
#CFLAGS += -DCLEAN_STACK
#ch1-01-4

#ch1-01-5
# What algorithms to include? comment out and rebuild to remove them
CFLAGS += -DBLOWFISH
CFLAGS += -DRC2
CFLAGS += -DRC5
CFLAGS += -DRC6
CFLAGS += -DSERPENT
CFLAGS += -DSAFERP
CFLAGS += -DSAFER
CFLAGS += -DRIJNDAEL
CFLAGS += -DXTEA
CFLAGS += -DTWOFISH
CFLAGS += -DDES
CFLAGS += -DCAST5
CFLAGS += -DNOEKEON
#ch1-01-5

#You can also customize the Twofish code.  All four combinations 
#of the flags are possible but only three of them make sense.
#
#Both undefined:  Very fast, requires ~4.2KB of ram per scheduled key
#Both defined  :  Slow, requires only ~100 bytes of ram per scheduled key
#
#If defined on their own
#_SMALL defined:  Very Slow, small code only ~100 bytes of ram
#_TABLES defined: Very fast, not faster than if both were undefined.  Code is ~1KB bigger
#                 faster keysetup though...

#ch1-01-6
# Small Ram Variant of Twofish.  For this you must have TWOFISH 
# defined.  This variant requires about 4kb less memory but 
# is considerably slower.  It is ideal when high throughput is 
# less important than conserving memory. By default it is not 
# defined which means the larger ram (about 4.2Kb used) variant 
# is built.
#CFLAGS += -DTWOFISH_SMALL

# Tell Twofish to use precomputed tables.  If you want to use 
# the small table variant of Twofish you may want to turn 
# this on.  Essentially it tells Twofish to use precomputed 
# S-boxes (Q0 and Q1) as well as precomputed GF 
# multiplications [in the MDS].  This speeds up the cipher 
# somewhat.
#CFLAGS += -DTWOFISH_TABLES 
#ch1-01-6

#Use fast PK routines.  Basically this limits the size of the private key in the
#DH system to 256 bits.  The group order remains unchanged so the best
#attacks are still GNFS (for DH upto 2560-bits)
#
#This will only speed up the key generation and encryption routines.  It lowers the
#security so its by default not turned on.  USE AT YOUR RISK!
#CFLAGS += -DFAST_PK

#ch1-01-7
# Chaining modes
CFLAGS += -DCFB
CFLAGS += -DOFB
CFLAGS += -DECB
CFLAGS += -DCBC
CFLAGS += -DCTR
#ch1-01-7

#ch1-01-8
#One-way hashes
CFLAGS += -DSHA512
CFLAGS += -DSHA384
CFLAGS += -DSHA256
CFLAGS += -DTIGER
CFLAGS += -DSHA1
CFLAGS += -DMD5
CFLAGS += -DMD4
CFLAGS += -DMD2
#ch1-01-8

#ch1-01-9
# prngs 
CFLAGS += -DYARROW
CFLAGS += -DSPRNG
CFLAGS += -DRC4
#ch1-01-9

#ch1-01-10
# PK code 
CFLAGS += -DMRSA
CFLAGS += -DMDH
CFLAGS += -DMECC
#CFLAGS += -DMDSA
CFLAGS += -DKR
#ch1-01-10

#ch1-01-12
# Control which built in DH or ECC key paramaters
# are to be allowed
CFLAGS += -DDH768
CFLAGS += -DDH1024
CFLAGS += -DDH1280
CFLAGS += -DDH1536
CFLAGS += -DDH1792
CFLAGS += -DDH2048
CFLAGS += -DDH2560
CFLAGS += -DDH3072
CFLAGS += -DDH4096

CFLAGS += -DECC160
CFLAGS += -DECC192
CFLAGS += -DECC224
CFLAGS += -DECC256
CFLAGS += -DECC384
CFLAGS += -DECC521

CFLAGS += -DDSA1024
CFLAGS += -DDSA2048
CFLAGS += -DDSA4096
#ch1-01-12

#ch1-01-11
# base64 
CFLAGS += -DBASE64

# include GF math routines?
# (not currently used by anything internally)
#CFLAGS += -DGF

# include large integer math routines? (required by the PK code)
CFLAGS += -DMPI

# use the fast exptmod operation (used in dsa/rsa/dh and is_prime)
# This uses slightly more heap than the old code [only during the function call]
# this is also fairly faster than the previous code
CFLAGS += -DMPI_FASTEXPT

# use a "low" mem variant of the fast exptmod.  It is still always 
# faster then the old exptmod but its savings drops off after 
# 1024 to 2048-bits 
#CFLAGS += -DMPI_FASTEXPT_LOWMEM

# include HMAC support
CFLAGS += -DHMAC
#ch1-01-11

#Output filenames for various targets.
LIBNAME=libtomcrypt.a
TEST=test
HASH=hashsum
CRYPT=encrypt
SMALL=small

#LIBPATH-The directory for libtomcrypt to be installed to.
#INCPATH-The directory to install the header files for libtomcrypt.
LIBPATH=/usr/lib
INCPATH=/usr/include

#List of objects to compile.
OBJECTS=keyring.o gf.o mem.o sprng.o dsa.o ecc.o base64.o dh.o rsa.o \
bits.o yarrow.o cfb.o ofb.o ecb.o ctr.o cbc.o hash.o tiger.o sha1.o \
md5.o md4.o md2.o sha256.o sha512.o xtea.o aes.o serpent.o des.o \
safer_tab.o safer.o safer+.o rc4.o rc2.o rc6.o rc5.o cast5.o noekeon.o blowfish.o crypt.o \
ampi.o mpi.o prime.o twofish.o packet.o hmac.o strings.o

TESTOBJECTS=demos/test.o
HASHOBJECTS=demos/hashsum.o
CRYPTOBJECTS=demos/encrypt.o
SMALLOBJECTS=demos/small.o

#Files left over from making the crypt.pdf.
LEFTOVERS=*.dvi *.log *.aux *.toc *.idx *.ilg *.ind

#Compressed filenames
COMPRESSED=crypt.tar.bz2 crypt.zip crypt.tar.gz

#Header files used by libtomcrypt.
HEADERS=mpi-types.h mpi-config.h mpi.h \
mycrypt_cfg.h mycrypt_gf.h mycrypt_kr.h \
mycrypt_misc.h  mycrypt_prng.h mycrypt_cipher.h  mycrypt_hash.h \
mycrypt_macros.h  mycrypt_pk.h mycrypt.h mycrypt_argchk.h

#The default rule for make builds the libtomcrypt library.
default:library mycrypt.h mycrypt_cfg.h

#These are the rules to make certain object files.
rsa.o: rsa.c rsa_sys.c
ecc.o: ecc.c ecc_sys.c
dh.o: dh.c dh_sys.c
aes.o: aes.c aes_tab.c
sha512.o: sha512.c sha384.c

#This rule makes the libtomcrypt library.
library: $(OBJECTS) 
	$(AR) $(ARFLAGS) $(LIBNAME) $(OBJECTS)
	ranlib $(LIBNAME)

#This rule makes the test program included with libtomcrypt
test: library $(TESTOBJECTS)
	$(CC) $(TESTOBJECTS) $(LIBNAME) -o $(TEST) $(WARN)

#This rule makes the hash program included with libtomcrypt
hashsum: library $(HASHOBJECTS)
	$(CC) $(HASHOBJECTS) $(LIBNAME) -o $(HASH) $(WARN)

#makes the crypt program
crypt: library $(CRYPTOBJECTS)
	$(CC) $(CRYPTOBJECTS) $(LIBNAME) -o $(CRYPT) $(WARN)

#makes the small program
small: library $(SMALLOBJECTS)
	$(CC) $(SMALLOBJECTS) $(LIBNAME) -o $(SMALL) $(WARN)

#This rule installs the library and the header files. This must be run
#as root in order to have a high enough permission to write to the correct
#directories and to set the owner and group to root.
install: library docs
	install -g root -o root $(LIBNAME) $(LIBPATH)
	install -g root -o root $(HEADERS) $(INCPATH)
	mkdir -p /usr/doc/libtomcrypt/pdf
	cp crypt.pdf /usr/doc/libtomcrypt/pdf/

#This rule cleans the source tree of all compiled code, not including the pdf
#documentation.
clean:
	rm -f $(OBJECTS) $(TESTOBJECTS) $(HASHOBJECTS) $(CRYPTOBJECTS) $(SMALLOBJECTS) $(LEFTOVERS) $(LIBNAME)
	rm -f $(TEST) $(HASH) $(COMPRESSED)
	rm -f *stackdump *.lib *.exe *.obj demos/*.obj zlib/*.obj *.bat

#This builds the crypt.pdf file. Note that the rm -f *.pdf has been removed
#from the clean command! This is because most people would like to keep the
#nice pre-compiled crypt.pdf that comes with libtomcrypt! We only need to
#delete it if we are rebuilding it.
docs: crypt.tex
	rm -f crypt.pdf
	rm -f $(LEFTOVERS)
	latex crypt > /dev/null
	makeindex crypt > /dev/null
	pdflatex crypt > /dev/null
	rm -f $(LEFTOVERS)
       
#zipup the project (take that!)
zipup: clean docs
	chdir .. ; rm -rf crypt* libtomcrypt-$(VERSION) ; mkdir libtomcrypt-$(VERSION) ; \
	cp -R ./libtomcrypt/* ./libtomcrypt-$(VERSION)/ ; tar -c libtomcrypt-$(VERSION)/* > crypt-$(VERSION).tar ; \
	bzip2 -9vv crypt-$(VERSION).tar ; zip -9 -r crypt-$(VERSION).zip libtomcrypt-$(VERSION)/*