# MAKEFILE for linux GCC
#
# Tom St Denis
# Modified by Clay Culver

# The version
VERSION=1.17

PLATFORM := $(shell uname | sed -e 's/_.*//')

# Compiler and Linker Names
#CC=gcc
#LD=ld

# Archiver [makes .a files]
#AR=ar
#ARFLAGS=r

ifndef MAKE
  MAKE=make
endif

# ranlib tools
ifndef RANLIB
ifeq ($(PLATFORM), Darwin)
RANLIB=ranlib -c
else
RANLIB=ranlib
endif
endif

# Compilation flags. Note the += does not write over the user's CFLAGS!
CFLAGS += -c -I./testprof/ -I./src/headers/ -Wall -Wsign-compare -W -Wshadow -Wno-unused-parameter -DLTC_SOURCE

# additional warnings (newer GCC 3.4 and higher)
ifdef GCC_34
CFLAGS += -Wsystem-headers -Wdeclaration-after-statement -Wbad-function-cast -Wcast-align -Wstrict-prototypes -Wmissing-prototypes \
		  -Wmissing-declarations -Wpointer-arith 
endif

ifndef IGNORE_SPEED

# optimize for SPEED
CFLAGS += -O3 -funroll-loops

# add -fomit-frame-pointer.  hinders debugging!
CFLAGS += -fomit-frame-pointer

# optimize for SIZE
#CFLAGS += -Os -DLTC_SMALL_CODE

endif

# older GCCs can't handle the "rotate with immediate" ROLc/RORc/etc macros
# define this to help
#CFLAGS += -DLTC_NO_ROLC

# compile for DEBUGING (required for ccmalloc checking!!!)
#CFLAGS += -g3 -DLTC_NO_ASM

#Output filenames for various targets.
ifndef LIBNAME
   LIBNAME=libtomcrypt.a
endif
ifndef LIBTEST
   LIBTEST=libtomcrypt_prof.a
endif
LIBTEST_S=$(LIBTEST)

HASH=hashsum
CRYPT=encrypt
SMALL=small
PROF=x86_prof
TV=tv_gen
MULTI=multi
TIMING=timing
TEST=test

#LIBPATH-The directory for libtomcrypt to be installed to.
#INCPATH-The directory to install the header files for libtomcrypt.
#DATAPATH-The directory to install the pdf docs.
ifndef DESTDIR
   DESTDIR=
endif

ifndef LIBPATH
   LIBPATH=/usr/lib
endif
ifndef INCPATH
   INCPATH=/usr/include
endif
ifndef DATAPATH
   DATAPATH=/usr/share/doc/libtomcrypt/pdf
endif

#Who do we install as?
ifdef INSTALL_USER
USER=$(INSTALL_USER)
else
USER=root
endif

ifdef INSTALL_GROUP
GROUP=$(INSTALL_GROUP)
else
GROUP=wheel
endif

#List of objects to compile.
#START_INS
OBJECTS=src/ciphers/aes/aes_enc.o src/ciphers/aes/aes.o src/ciphers/anubis.o src/ciphers/blowfish.o \
src/ciphers/camellia.o src/ciphers/cast5.o src/ciphers/des.o src/ciphers/kasumi.o src/ciphers/khazad.o \
src/ciphers/kseed.o src/ciphers/multi2.o src/ciphers/noekeon.o src/ciphers/rc2.o src/ciphers/rc5.o \
src/ciphers/rc6.o src/ciphers/safer/safer.o src/ciphers/safer/saferp.o src/ciphers/safer/safer_tab.o \
src/ciphers/skipjack.o src/ciphers/twofish/twofish.o src/ciphers/xtea.o src/encauth/ccm/ccm_memory.o \
src/encauth/ccm/ccm_memory_ex.o src/encauth/ccm/ccm_test.o src/encauth/eax/eax_addheader.o \
src/encauth/eax/eax_decrypt.o src/encauth/eax/eax_decrypt_verify_memory.o src/encauth/eax/eax_done.o \
src/encauth/eax/eax_encrypt_authenticate_memory.o src/encauth/eax/eax_encrypt.o \
src/encauth/eax/eax_init.o src/encauth/eax/eax_test.o src/encauth/gcm/gcm_add_aad.o \
src/encauth/gcm/gcm_add_iv.o src/encauth/gcm/gcm_done.o src/encauth/gcm/gcm_gf_mult.o \
src/encauth/gcm/gcm_init.o src/encauth/gcm/gcm_memory.o src/encauth/gcm/gcm_mult_h.o \
src/encauth/gcm/gcm_process.o src/encauth/gcm/gcm_reset.o src/encauth/gcm/gcm_test.o \
src/encauth/ocb/ocb_decrypt.o src/encauth/ocb/ocb_decrypt_verify_memory.o \
src/encauth/ocb/ocb_done_decrypt.o src/encauth/ocb/ocb_done_encrypt.o \
src/encauth/ocb/ocb_encrypt_authenticate_memory.o src/encauth/ocb/ocb_encrypt.o \
src/encauth/ocb/ocb_init.o src/encauth/ocb/ocb_ntz.o src/encauth/ocb/ocb_shift_xor.o \
src/encauth/ocb/ocb_test.o src/encauth/ocb/s_ocb_done.o src/hashes/chc/chc.o \
src/hashes/helper/hash_file.o src/hashes/helper/hash_filehandle.o src/hashes/helper/hash_memory.o \
src/hashes/helper/hash_memory_multi.o src/hashes/md2.o src/hashes/md4.o src/hashes/md5.o \
src/hashes/rmd128.o src/hashes/rmd160.o src/hashes/rmd256.o src/hashes/rmd320.o src/hashes/sha1.o \
src/hashes/sha2/sha256.o src/hashes/sha2/sha512.o src/hashes/tiger.o src/hashes/whirl/whirl.o \
src/mac/f9/f9_done.o src/mac/f9/f9_file.o src/mac/f9/f9_init.o src/mac/f9/f9_memory.o \
src/mac/f9/f9_memory_multi.o src/mac/f9/f9_process.o src/mac/f9/f9_test.o src/mac/hmac/hmac_done.o \
src/mac/hmac/hmac_file.o src/mac/hmac/hmac_init.o src/mac/hmac/hmac_memory.o \
src/mac/hmac/hmac_memory_multi.o src/mac/hmac/hmac_process.o src/mac/hmac/hmac_test.o \
src/mac/omac/omac_done.o src/mac/omac/omac_file.o src/mac/omac/omac_init.o src/mac/omac/omac_memory.o \
src/mac/omac/omac_memory_multi.o src/mac/omac/omac_process.o src/mac/omac/omac_test.o \
src/mac/pelican/pelican.o src/mac/pelican/pelican_memory.o src/mac/pelican/pelican_test.o \
src/mac/pmac/pmac_done.o src/mac/pmac/pmac_file.o src/mac/pmac/pmac_init.o src/mac/pmac/pmac_memory.o \
src/mac/pmac/pmac_memory_multi.o src/mac/pmac/pmac_ntz.o src/mac/pmac/pmac_process.o \
src/mac/pmac/pmac_shift_xor.o src/mac/pmac/pmac_test.o src/mac/xcbc/xcbc_done.o \
src/mac/xcbc/xcbc_file.o src/mac/xcbc/xcbc_init.o src/mac/xcbc/xcbc_memory.o \
src/mac/xcbc/xcbc_memory_multi.o src/mac/xcbc/xcbc_process.o src/mac/xcbc/xcbc_test.o \
src/math/fp/ltc_ecc_fp_mulmod.o src/math/gmp_desc.o src/math/ltm_desc.o src/math/multi.o \
src/math/rand_prime.o src/math/tfm_desc.o src/misc/base64/base64_decode.o \
src/misc/pk_get_oid.o \
src/misc/base64/base64_encode.o src/misc/burn_stack.o src/misc/crypt/crypt_argchk.o \
src/misc/crypt/crypt.o src/misc/crypt/crypt_cipher_descriptor.o src/misc/crypt/crypt_cipher_is_valid.o \
src/misc/crypt/crypt_find_cipher_any.o src/misc/crypt/crypt_find_cipher.o \
src/misc/crypt/crypt_find_cipher_id.o src/misc/crypt/crypt_find_hash_any.o \
src/misc/crypt/crypt_find_hash.o src/misc/crypt/crypt_find_hash_id.o \
src/misc/crypt/crypt_find_hash_oid.o src/misc/crypt/crypt_find_prng.o src/misc/crypt/crypt_fsa.o \
src/misc/crypt/crypt_hash_descriptor.o src/misc/crypt/crypt_hash_is_valid.o \
src/misc/crypt/crypt_ltc_mp_descriptor.o src/misc/crypt/crypt_prng_descriptor.o \
src/misc/crypt/crypt_prng_is_valid.o src/misc/crypt/crypt_register_cipher.o \
src/misc/crypt/crypt_register_hash.o src/misc/crypt/crypt_register_prng.o \
src/misc/crypt/crypt_unregister_cipher.o src/misc/crypt/crypt_unregister_hash.o \
src/misc/crypt/crypt_unregister_prng.o src/misc/error_to_string.o src/misc/pkcs5/pkcs_5_1.o \
src/misc/pkcs5/pkcs_5_2.o src/misc/zeromem.o src/modes/cbc/cbc_decrypt.o src/modes/cbc/cbc_done.o \
src/modes/cbc/cbc_encrypt.o src/modes/cbc/cbc_getiv.o src/modes/cbc/cbc_setiv.o \
src/modes/cbc/cbc_start.o src/modes/cfb/cfb_decrypt.o src/modes/cfb/cfb_done.o \
src/modes/cfb/cfb_encrypt.o src/modes/cfb/cfb_getiv.o src/modes/cfb/cfb_setiv.o \
src/modes/cfb/cfb_start.o src/modes/ctr/ctr_decrypt.o src/modes/ctr/ctr_done.o \
src/modes/ctr/ctr_encrypt.o src/modes/ctr/ctr_getiv.o src/modes/ctr/ctr_setiv.o \
src/modes/ctr/ctr_start.o src/modes/ctr/ctr_test.o src/modes/ecb/ecb_decrypt.o src/modes/ecb/ecb_done.o \
src/modes/ecb/ecb_encrypt.o src/modes/ecb/ecb_start.o src/modes/f8/f8_decrypt.o src/modes/f8/f8_done.o \
src/modes/f8/f8_encrypt.o src/modes/f8/f8_getiv.o src/modes/f8/f8_setiv.o src/modes/f8/f8_start.o \
src/modes/f8/f8_test_mode.o src/modes/lrw/lrw_decrypt.o src/modes/lrw/lrw_done.o \
src/modes/lrw/lrw_encrypt.o src/modes/lrw/lrw_getiv.o src/modes/lrw/lrw_process.o \
src/modes/lrw/lrw_setiv.o src/modes/lrw/lrw_start.o src/modes/lrw/lrw_test.o \
src/modes/ofb/ofb_decrypt.o src/modes/ofb/ofb_done.o src/modes/ofb/ofb_encrypt.o \
src/modes/ofb/ofb_getiv.o src/modes/ofb/ofb_setiv.o src/modes/ofb/ofb_start.o \
src/modes/xts/xts_decrypt.o src/modes/xts/xts_done.o src/modes/xts/xts_encrypt.o \
src/modes/xts/xts_init.o src/modes/xts/xts_mult_x.o src/modes/xts/xts_test.o \
src/pk/asn1/der/bit/der_decode_bit_string.o src/pk/asn1/der/bit/der_encode_bit_string.o \
src/pk/asn1/der/bit/der_length_bit_string.o src/pk/asn1/der/boolean/der_decode_boolean.o \
src/pk/asn1/der/bit/der_decode_raw_bit_string.o src/pk/asn1/der/bit/der_encode_raw_bit_string.o \
src/pk/asn1/der/boolean/der_encode_boolean.o src/pk/asn1/der/boolean/der_length_boolean.o \
src/pk/asn1/der/choice/der_decode_choice.o src/pk/asn1/der/ia5/der_decode_ia5_string.o \
src/pk/asn1/der/ia5/der_encode_ia5_string.o src/pk/asn1/der/ia5/der_length_ia5_string.o \
src/pk/asn1/der/integer/der_decode_integer.o src/pk/asn1/der/integer/der_encode_integer.o \
src/pk/asn1/der/integer/der_length_integer.o \
src/pk/asn1/der/object_identifier/der_decode_object_identifier.o \
src/pk/asn1/der/object_identifier/der_encode_object_identifier.o \
src/pk/asn1/der/object_identifier/der_length_object_identifier.o \
src/pk/asn1/der/octet/der_decode_octet_string.o src/pk/asn1/der/octet/der_encode_octet_string.o \
src/pk/asn1/der/octet/der_length_octet_string.o \
src/pk/asn1/der/teletex_string/der_decode_teletex_string.o \
src/pk/asn1/der/teletex_string/der_length_teletex_string.o \
src/pk/asn1/der/printable_string/der_decode_printable_string.o \
src/pk/asn1/der/printable_string/der_encode_printable_string.o \
src/pk/asn1/der/printable_string/der_length_printable_string.o \
src/pk/asn1/der/sequence/der_encode_subject_public_key_info.o \
src/pk/asn1/der/sequence/der_decode_subject_public_key_info.o \
src/pk/asn1/der/sequence/der_decode_sequence_ex.o \
src/pk/asn1/der/sequence/der_decode_sequence_flexi.o \
src/pk/asn1/der/sequence/der_decode_sequence_multi.o \
src/pk/asn1/der/sequence/der_encode_sequence_ex.o \
src/pk/asn1/der/sequence/der_encode_sequence_multi.o src/pk/asn1/der/sequence/der_length_sequence.o \
src/pk/asn1/der/sequence/der_sequence_free.o src/pk/asn1/der/set/der_encode_set.o \
src/pk/asn1/der/set/der_encode_setof.o src/pk/asn1/der/short_integer/der_decode_short_integer.o \
src/pk/asn1/der/short_integer/der_encode_short_integer.o \
src/pk/asn1/der/short_integer/der_length_short_integer.o src/pk/asn1/der/utctime/der_decode_utctime.o \
src/pk/asn1/der/utctime/der_encode_utctime.o src/pk/asn1/der/utctime/der_length_utctime.o \
src/pk/asn1/der/utf8/der_decode_utf8_string.o src/pk/asn1/der/utf8/der_encode_utf8_string.o \
src/pk/asn1/der/utf8/der_length_utf8_string.o src/pk/dsa/dsa_decrypt_key.o \
src/pk/dsa/dsa_encrypt_key.o src/pk/dsa/dsa_export.o src/pk/dsa/dsa_free.o src/pk/dsa/dsa_import.o \
src/pk/dsa/dsa_make_key.o src/pk/dsa/dsa_shared_secret.o src/pk/dsa/dsa_sign_hash.o \
src/pk/dsa/dsa_verify_hash.o src/pk/dsa/dsa_verify_key.o src/pk/ecc/ecc_ansi_x963_export.o \
src/pk/ecc/ecc_ansi_x963_import.o src/pk/ecc/ecc.o src/pk/ecc/ecc_decrypt_key.o \
src/pk/ecc/ecc_encrypt_key.o src/pk/ecc/ecc_export.o src/pk/ecc/ecc_free.o src/pk/ecc/ecc_get_size.o \
src/pk/ecc/ecc_import.o src/pk/ecc/ecc_make_key.o src/pk/ecc/ecc_shared_secret.o \
src/pk/ecc/ecc_sign_hash.o src/pk/ecc/ecc_sizes.o src/pk/ecc/ecc_test.o src/pk/ecc/ecc_verify_hash.o \
src/pk/ecc/ltc_ecc_is_valid_idx.o src/pk/ecc/ltc_ecc_map.o src/pk/ecc/ltc_ecc_mul2add.o \
src/pk/ecc/ltc_ecc_mulmod.o src/pk/ecc/ltc_ecc_mulmod_timing.o src/pk/ecc/ltc_ecc_points.o \
src/pk/ecc/ltc_ecc_projective_add_point.o src/pk/ecc/ltc_ecc_projective_dbl_point.o \
src/pk/dh/dh.o \
src/pk/katja/katja_decrypt_key.o src/pk/katja/katja_encrypt_key.o src/pk/katja/katja_export.o \
src/pk/katja/katja_exptmod.o src/pk/katja/katja_free.o src/pk/katja/katja_import.o \
src/pk/katja/katja_make_key.o src/pk/pkcs1/pkcs_1_i2osp.o src/pk/pkcs1/pkcs_1_mgf1.o \
src/pk/pkcs1/pkcs_1_oaep_decode.o src/pk/pkcs1/pkcs_1_oaep_encode.o src/pk/pkcs1/pkcs_1_os2ip.o \
src/pk/pkcs1/pkcs_1_pss_decode.o src/pk/pkcs1/pkcs_1_pss_encode.o src/pk/pkcs1/pkcs_1_v1_5_decode.o \
src/pk/pkcs1/pkcs_1_v1_5_encode.o src/pk/rsa/rsa_decrypt_key.o src/pk/rsa/rsa_encrypt_key.o \
src/pk/rsa/rsa_export.o src/pk/rsa/rsa_exptmod.o src/pk/rsa/rsa_free.o src/pk/rsa/rsa_import.o \
src/pk/rsa/rsa_make_key.o src/pk/rsa/rsa_sign_hash.o src/pk/rsa/rsa_verify_hash.o src/prngs/fortuna.o \
src/prngs/rc4.o src/prngs/rng_get_bytes.o src/prngs/rng_make_prng.o src/prngs/sober128.o \
src/prngs/sprng.o src/prngs/yarrow.o 

HEADERS=src/headers/tomcrypt_cfg.h src/headers/tomcrypt_mac.h src/headers/tomcrypt_macros.h \
src/headers/tomcrypt_custom.h src/headers/tomcrypt_argchk.h src/headers/tomcrypt_cipher.h \
src/headers/tomcrypt_pk.h src/headers/tomcrypt_hash.h src/headers/tomcrypt_math.h \
src/headers/tomcrypt_misc.h src/headers/tomcrypt.h src/headers/tomcrypt_pkcs.h \
src/headers/tomcrypt_prng.h testprof/tomcrypt_test.h

#END_INS

TESTOBJECTS=demos/test.o
HASHOBJECTS=demos/hashsum.o
CRYPTOBJECTS=demos/encrypt.o
SMALLOBJECTS=demos/small.o
TVS=demos/tv_gen.o
MULTIS=demos/multi.o
TIMINGS=demos/timing.o
TESTS=demos/test.o

#Files left over from making the crypt.pdf.
LEFTOVERS=*.dvi *.log *.aux *.toc *.idx *.ilg *.ind *.out

#Compressed filenames
COMPRESSED=crypt-$(VERSION).tar.bz2 crypt-$(VERSION).zip

#The default rule for make builds the libtomcrypt library.
default:library

#ciphers come in two flavours... enc+dec and enc 
src/ciphers/aes/aes_enc.o: src/ciphers/aes/aes.c src/ciphers/aes/aes_tab.c
	$(CC) $(CFLAGS) -DENCRYPT_ONLY -c src/ciphers/aes/aes.c -o src/ciphers/aes/aes_enc.o

#These are the rules to make certain object files.
src/ciphers/aes/aes.o: src/ciphers/aes/aes.c src/ciphers/aes/aes_tab.c
src/ciphers/twofish/twofish.o: src/ciphers/twofish/twofish.c src/ciphers/twofish/twofish_tab.c
src/hashes/whirl/whirl.o: src/hashes/whirl/whirl.c src/hashes/whirl/whirltab.c
src/hashes/sha2/sha512.o: src/hashes/sha2/sha512.c src/hashes/sha2/sha384.c
src/hashes/sha2/sha256.o: src/hashes/sha2/sha256.c src/hashes/sha2/sha224.c

#This rule makes the libtomcrypt library.
library: $(LIBNAME)

$(OBJECTS): $(HEADERS)

testprof/$(LIBTEST): 
	cd testprof ; CFLAGS="$(CFLAGS)" LIBTEST_S=$(LIBTEST_S) $(MAKE) 

$(LIBNAME): $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $(OBJECTS) 
	$(RANLIB) $@

#This rule makes the hash program included with libtomcrypt
hashsum: library $(HASHOBJECTS)
	$(CC) $(HASHOBJECTS) $(LIBNAME) $(EXTRALIBS) -o $(HASH) $(WARN)

#makes the crypt program
crypt: library $(CRYPTOBJECTS)
	$(CC) $(CRYPTOBJECTS) $(LIBNAME) $(EXTRALIBS) -o $(CRYPT) $(WARN)

#makes the small program
small: library $(SMALLOBJECTS)
	$(CC) $(SMALLOBJECTS) $(LIBNAME) $(EXTRALIBS) -o $(SMALL) $(WARN)

tv_gen: library $(TVS)
	$(CC) $(LDFLAGS) $(TVS) $(LIBNAME) $(EXTRALIBS) -o $(TV)

multi: library $(MULTIS)
	$(CC) $(MULTIS) $(LIBNAME) $(EXTRALIBS) -o $(MULTI)

timing: library testprof/$(LIBTEST) $(TIMINGS)
	$(CC) $(LDFLAGS) $(TIMINGS) testprof/$(LIBTEST) $(LIBNAME) $(EXTRALIBS) -o $(TIMING)

test: library testprof/$(LIBTEST) $(TESTS)
	$(CC) $(LDFLAGS) $(TESTS) testprof/$(LIBTEST) $(LIBNAME) $(EXTRALIBS) -o $(TEST)

#This rule installs the library and the header files. This must be run
#as root in order to have a high enough permission to write to the correct
#directories and to set the owner and group to root.
ifndef NODOCS
install: library docs
else
install: library
endif
	install -d -g $(GROUP) -o $(USER) $(DESTDIR)$(LIBPATH)
	install -d -g $(GROUP) -o $(USER) $(DESTDIR)$(INCPATH)
	install -d -g $(GROUP) -o $(USER) $(DESTDIR)$(DATAPATH)
	install -g $(GROUP) -o $(USER) $(LIBNAME) $(DESTDIR)$(LIBPATH)
	install -g $(GROUP) -o $(USER) $(HEADERS) $(DESTDIR)$(INCPATH)
ifndef NODOCS
	install -g $(GROUP) -o $(USER) doc/crypt.pdf $(DESTDIR)$(DATAPATH)
endif

install_test: testprof/$(LIBTEST)
	install -d -g $(GROUP) -o $(USER) $(DESTDIR)$(LIBPATH)
	install -d -g $(GROUP) -o $(USER) $(DESTDIR)$(INCPATH)
	install -g $(GROUP) -o $(USER) testprof/$(LIBTEST) $(DESTDIR)$(LIBPATH)

profile:
	CFLAGS="$(CFLAGS) -fprofile-generate" $(MAKE) timing EXTRALIBS="$(EXTRALIBS) -lgcov"
	./timing
	rm -f timing `find . -type f | grep [.][ao] | xargs`
	CFLAGS="$(CFLAGS) -fprofile-use" $(MAKE) timing EXTRALIBS="$(EXTRALIBS) -lgcov"


#This rule cleans the source tree of all compiled code, not including the pdf
#documentation.
clean:
	rm -f `find . -type f | grep "[.]o" | xargs`
	rm -f `find . -type f | grep "[.]lo"  | xargs`
	rm -f `find . -type f | grep "[.]a" | xargs`
	rm -f `find . -type f | grep "[.]la"  | xargs`
	rm -f `find . -type f | grep "[.]obj" | xargs`
	rm -f `find . -type f | grep "[.]lib" | xargs`
	rm -f `find . -type f | grep "[.]exe" | xargs`
	rm -f `find . -type f | grep "[.]gcda" | xargs`
	rm -f `find . -type f | grep "[.]gcno" | xargs`
	rm -f `find . -type f | grep "[.]il" | xargs`
	rm -f `find . -type f | grep "[.]dyn" | xargs`
	rm -f `find . -type f | grep "[.]dpi" | xargs`
	rm -rf `find . -type d | grep "[.]libs" | xargs`
	rm -f crypt.aux  crypt.dvi  crypt.idx  crypt.ilg  crypt.ind  crypt.log crypt.toc
	rm -f $(TV) $(PROF) $(SMALL) $(CRYPT) $(HASHSUM) $(MULTI) $(TIMING) $(TEST)
	rm -rf doc/doxygen
	rm -f doc/*.pdf
	rm -f *.txt

#build the doxy files (requires Doxygen, tetex and patience)
doxy:
	doxygen
	cd doc/doxygen/latex ; ${MAKE} ; mv -f refman.pdf ../../.
	echo The huge doxygen PDF should be available as doc/refman.pdf

#This builds the crypt.pdf file. Note that the rm -f *.pdf has been removed
#from the clean command! This is because most people would like to keep the
#nice pre-compiled crypt.pdf that comes with libtomcrypt! We only need to
#delete it if we are rebuilding it.
docs: crypt.tex
	rm -f doc/crypt.pdf $(LEFTOVERS)
	echo "hello" > crypt.ind
	latex crypt > /dev/null
	latex crypt > /dev/null
	makeindex crypt.idx > /dev/null
	perl fixupind.pl
	latex crypt > /dev/null
	dvipdf crypt
	mv -ivf crypt.pdf doc/crypt.pdf
	rm -f $(LEFTOVERS)

docdvi: crypt.tex
	echo hello > crypt.ind
	latex crypt > /dev/null
	latex crypt > /dev/null
	makeindex crypt.idx
	perl fixupind.pl
	latex crypt > /dev/null
	latex crypt > /dev/null

#zipup the project (take that!)
no_oops: clean
	cd .. ; cvs commit 
	echo Scanning for scratch/dirty files
	find . -type f | grep -v CVS | xargs -n 1 bash mess.sh

zipup: no_oops docs
	cd .. ; rm -rf crypt* libtomcrypt-$(VERSION) ; mkdir libtomcrypt-$(VERSION) ; \
	cp -R ./libtomcrypt/* ./libtomcrypt-$(VERSION)/ ; \
	cd libtomcrypt-$(VERSION) ; rm -rf `find . -type d | grep CVS | xargs` ; cd .. ; \
	tar -cjvf crypt-$(VERSION).tar.bz2 libtomcrypt-$(VERSION) ; \
	zip -9r crypt-$(VERSION).zip libtomcrypt-$(VERSION) ; \
	gpg -b -a crypt-$(VERSION).tar.bz2 ; gpg -b -a crypt-$(VERSION).zip ; \
	mv -fv crypt* ~ ; rm -rf libtomcrypt-$(VERSION)


# $Source: /cvs/libtom/libtomcrypt/makefile,v $ 
# $Revision: 1.151 $ 
# $Date: 2007/06/20 13:14:31 $ 
