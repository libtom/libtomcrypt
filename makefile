# MAKEFILE for linux GCC
#
# Tom St Denis
# Modified by Clay Culver

include makefile.include

# The version
VERSION=1.17

PLATFORM := $(shell uname | sed -e 's/_.*//')

ifeq ($V,1)
silent=
else
silent=@
endif

%.o: %.c
ifneq ($V,1)
	@echo "   * ${CC} $@"
endif
	${silent} ${CC} ${CFLAGS} -c $< -o $@

# ranlib tools
ifndef RANLIB
ifeq ($(PLATFORM), Darwin)
RANLIB:=$(PREFIX)ranlib -c
else
RANLIB:=$(PREFIX)ranlib
endif
endif

#Output filenames for various targets.
ifndef LIBNAME
   LIBNAME=libtomcrypt.a
endif
ifndef LIBTEST
   LIBTEST=libtomcrypt_prof.a
endif
LIBTEST_S=$(LIBTEST)

#List of objects to compile.
#START_INS
OBJECTS=src/ciphers/aes/aes_enc.o src/ciphers/aes/aes.o src/ciphers/anubis.o src/ciphers/blowfish.o \
src/ciphers/camellia.o src/ciphers/cast5.o src/ciphers/des.o src/ciphers/kasumi.o src/ciphers/khazad.o \
src/ciphers/kseed.o src/ciphers/multi2.o src/ciphers/noekeon.o src/ciphers/rc2.o src/ciphers/rc5.o \
src/ciphers/rc6.o src/ciphers/safer/safer.o src/ciphers/safer/saferp.o src/ciphers/skipjack.o \
src/ciphers/twofish/twofish.o src/ciphers/xtea.o src/encauth/ccm/ccm_add_aad.o \
src/encauth/ccm/ccm_add_nonce.o src/encauth/ccm/ccm_done.o src/encauth/ccm/ccm_init.o \
src/encauth/ccm/ccm_memory.o src/encauth/ccm/ccm_memory_ex.o src/encauth/ccm/ccm_process.o \
src/encauth/ccm/ccm_reset.o src/encauth/ccm/ccm_test.o src/encauth/eax/eax_addheader.o \
src/encauth/eax/eax_decrypt.o src/encauth/eax/eax_decrypt_verify_memory.o src/encauth/eax/eax_done.o \
src/encauth/eax/eax_encrypt_authenticate_memory.o src/encauth/eax/eax_encrypt.o \
src/encauth/eax/eax_init.o src/encauth/eax/eax_test.o src/encauth/gcm/gcm_add_aad.o \
src/encauth/gcm/gcm_add_iv.o src/encauth/gcm/gcm_done.o src/encauth/gcm/gcm_gf_mult.o \
src/encauth/gcm/gcm_init.o src/encauth/gcm/gcm_memory.o src/encauth/gcm/gcm_mult_h.o \
src/encauth/gcm/gcm_process.o src/encauth/gcm/gcm_reset.o src/encauth/gcm/gcm_test.o \
src/encauth/ocb3/ocb3_add_aad.o src/encauth/ocb3/ocb3_decrypt.o src/encauth/ocb3/ocb3_decrypt_last.o \
src/encauth/ocb3/ocb3_decrypt_verify_memory.o src/encauth/ocb3/ocb3_done.o \
src/encauth/ocb3/ocb3_encrypt_authenticate_memory.o src/encauth/ocb3/ocb3_encrypt.o \
src/encauth/ocb3/ocb3_encrypt_last.o src/encauth/ocb3/ocb3_init.o \
src/encauth/ocb3/ocb3_int_aad_add_block.o src/encauth/ocb3/ocb3_int_calc_offset_zero.o \
src/encauth/ocb3/ocb3_int_ntz.o src/encauth/ocb3/ocb3_int_xor_blocks.o src/encauth/ocb3/ocb3_test.o \
src/encauth/ocb/ocb_decrypt.o src/encauth/ocb/ocb_decrypt_verify_memory.o \
src/encauth/ocb/ocb_done_decrypt.o src/encauth/ocb/ocb_done_encrypt.o \
src/encauth/ocb/ocb_encrypt_authenticate_memory.o src/encauth/ocb/ocb_encrypt.o \
src/encauth/ocb/ocb_init.o src/encauth/ocb/ocb_ntz.o src/encauth/ocb/ocb_shift_xor.o \
src/encauth/ocb/ocb_test.o src/encauth/ocb/s_ocb_done.o src/hashes/chc/chc.o \
src/hashes/helper/hash_file.o src/hashes/helper/hash_filehandle.o src/hashes/helper/hash_memory.o \
src/hashes/helper/hash_memory_multi.o src/hashes/md2.o src/hashes/md4.o src/hashes/md5.o \
src/hashes/rmd128.o src/hashes/rmd160.o src/hashes/rmd256.o src/hashes/rmd320.o src/hashes/sha1.o \
src/hashes/sha2/sha224.o src/hashes/sha2/sha256.o src/hashes/sha2/sha384.o src/hashes/sha2/sha512_224.o \
src/hashes/sha2/sha512_256.o src/hashes/sha2/sha512.o src/hashes/tiger.o src/hashes/whirl/whirl.o \
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
src/math/rand_bn.o src/math/rand_prime.o src/math/tfm_desc.o src/misc/adler32.o \
src/misc/base64/base64_decode.o src/misc/base64/base64_encode.o src/misc/burn_stack.o src/misc/crc32.o \
src/misc/crypt/crypt_argchk.o src/misc/crypt/crypt.o src/misc/crypt/crypt_cipher_descriptor.o \
src/misc/crypt/crypt_cipher_is_valid.o src/misc/crypt/crypt_constants.o \
src/misc/crypt/crypt_find_cipher_any.o src/misc/crypt/crypt_find_cipher.o \
src/misc/crypt/crypt_find_cipher_id.o src/misc/crypt/crypt_find_hash_any.o \
src/misc/crypt/crypt_find_hash.o src/misc/crypt/crypt_find_hash_id.o \
src/misc/crypt/crypt_find_hash_oid.o src/misc/crypt/crypt_find_prng.o src/misc/crypt/crypt_fsa.o \
src/misc/crypt/crypt_hash_descriptor.o src/misc/crypt/crypt_hash_is_valid.o \
src/misc/crypt/crypt_inits.o src/misc/crypt/crypt_ltc_mp_descriptor.o \
src/misc/crypt/crypt_prng_descriptor.o src/misc/crypt/crypt_prng_is_valid.o \
src/misc/crypt/crypt_register_cipher.o src/misc/crypt/crypt_register_hash.o \
src/misc/crypt/crypt_register_prng.o src/misc/crypt/crypt_sizes.o \
src/misc/crypt/crypt_unregister_cipher.o src/misc/crypt/crypt_unregister_hash.o \
src/misc/crypt/crypt_unregister_prng.o src/misc/error_to_string.o src/misc/hkdf/hkdf.o \
src/misc/hkdf/hkdf_test.o src/misc/mem_neq.o src/misc/pkcs5/pkcs_5_1.o src/misc/pkcs5/pkcs_5_2.o \
src/misc/pkcs5/pkcs_5_test.o src/misc/pk_get_oid.o src/misc/zeromem.o src/modes/cbc/cbc_decrypt.o \
src/modes/cbc/cbc_done.o src/modes/cbc/cbc_encrypt.o src/modes/cbc/cbc_getiv.o \
src/modes/cbc/cbc_setiv.o src/modes/cbc/cbc_start.o src/modes/cfb/cfb_decrypt.o \
src/modes/cfb/cfb_done.o src/modes/cfb/cfb_encrypt.o src/modes/cfb/cfb_getiv.o \
src/modes/cfb/cfb_setiv.o src/modes/cfb/cfb_start.o src/modes/ctr/ctr_decrypt.o \
src/modes/ctr/ctr_done.o src/modes/ctr/ctr_encrypt.o src/modes/ctr/ctr_getiv.o \
src/modes/ctr/ctr_setiv.o src/modes/ctr/ctr_start.o src/modes/ctr/ctr_test.o \
src/modes/ecb/ecb_decrypt.o src/modes/ecb/ecb_done.o src/modes/ecb/ecb_encrypt.o \
src/modes/ecb/ecb_start.o src/modes/f8/f8_decrypt.o src/modes/f8/f8_done.o src/modes/f8/f8_encrypt.o \
src/modes/f8/f8_getiv.o src/modes/f8/f8_setiv.o src/modes/f8/f8_start.o src/modes/f8/f8_test_mode.o \
src/modes/lrw/lrw_decrypt.o src/modes/lrw/lrw_done.o src/modes/lrw/lrw_encrypt.o \
src/modes/lrw/lrw_getiv.o src/modes/lrw/lrw_process.o src/modes/lrw/lrw_setiv.o \
src/modes/lrw/lrw_start.o src/modes/lrw/lrw_test.o src/modes/ofb/ofb_decrypt.o src/modes/ofb/ofb_done.o \
src/modes/ofb/ofb_encrypt.o src/modes/ofb/ofb_getiv.o src/modes/ofb/ofb_setiv.o \
src/modes/ofb/ofb_start.o src/modes/xts/xts_decrypt.o src/modes/xts/xts_done.o \
src/modes/xts/xts_encrypt.o src/modes/xts/xts_init.o src/modes/xts/xts_mult_x.o \
src/modes/xts/xts_test.o src/pk/asn1/der/bit/der_decode_bit_string.o \
src/pk/asn1/der/bit/der_decode_raw_bit_string.o src/pk/asn1/der/bit/der_encode_bit_string.o \
src/pk/asn1/der/bit/der_encode_raw_bit_string.o src/pk/asn1/der/bit/der_length_bit_string.o \
src/pk/asn1/der/boolean/der_decode_boolean.o src/pk/asn1/der/boolean/der_encode_boolean.o \
src/pk/asn1/der/boolean/der_length_boolean.o src/pk/asn1/der/choice/der_decode_choice.o \
src/pk/asn1/der/ia5/der_decode_ia5_string.o src/pk/asn1/der/ia5/der_encode_ia5_string.o \
src/pk/asn1/der/ia5/der_length_ia5_string.o src/pk/asn1/der/integer/der_decode_integer.o \
src/pk/asn1/der/integer/der_encode_integer.o src/pk/asn1/der/integer/der_length_integer.o \
src/pk/asn1/der/object_identifier/der_decode_object_identifier.o \
src/pk/asn1/der/object_identifier/der_encode_object_identifier.o \
src/pk/asn1/der/object_identifier/der_length_object_identifier.o \
src/pk/asn1/der/octet/der_decode_octet_string.o src/pk/asn1/der/octet/der_encode_octet_string.o \
src/pk/asn1/der/octet/der_length_octet_string.o \
src/pk/asn1/der/printable_string/der_decode_printable_string.o \
src/pk/asn1/der/printable_string/der_encode_printable_string.o \
src/pk/asn1/der/printable_string/der_length_printable_string.o \
src/pk/asn1/der/sequence/der_decode_sequence_ex.o \
src/pk/asn1/der/sequence/der_decode_sequence_flexi.o \
src/pk/asn1/der/sequence/der_decode_sequence_multi.o \
src/pk/asn1/der/sequence/der_decode_subject_public_key_info.o \
src/pk/asn1/der/sequence/der_encode_sequence_ex.o \
src/pk/asn1/der/sequence/der_encode_sequence_multi.o \
src/pk/asn1/der/sequence/der_encode_subject_public_key_info.o \
src/pk/asn1/der/sequence/der_length_sequence.o src/pk/asn1/der/sequence/der_sequence_free.o \
src/pk/asn1/der/set/der_encode_set.o src/pk/asn1/der/set/der_encode_setof.o \
src/pk/asn1/der/short_integer/der_decode_short_integer.o \
src/pk/asn1/der/short_integer/der_encode_short_integer.o \
src/pk/asn1/der/short_integer/der_length_short_integer.o \
src/pk/asn1/der/teletex_string/der_decode_teletex_string.o \
src/pk/asn1/der/teletex_string/der_length_teletex_string.o \
src/pk/asn1/der/utctime/der_decode_utctime.o src/pk/asn1/der/utctime/der_encode_utctime.o \
src/pk/asn1/der/utctime/der_length_utctime.o src/pk/asn1/der/utf8/der_decode_utf8_string.o \
src/pk/asn1/der/utf8/der_encode_utf8_string.o src/pk/asn1/der/utf8/der_length_utf8_string.o \
src/pk/dh/dh.o src/pk/dh/dh_static.o src/pk/dh/dh_sys.o src/pk/dsa/dsa_decrypt_key.o \
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
src/pk/katja/katja_decrypt_key.o src/pk/katja/katja_encrypt_key.o src/pk/katja/katja_export.o \
src/pk/katja/katja_exptmod.o src/pk/katja/katja_free.o src/pk/katja/katja_import.o \
src/pk/katja/katja_make_key.o src/pk/pkcs1/pkcs_1_i2osp.o src/pk/pkcs1/pkcs_1_mgf1.o \
src/pk/pkcs1/pkcs_1_oaep_decode.o src/pk/pkcs1/pkcs_1_oaep_encode.o src/pk/pkcs1/pkcs_1_os2ip.o \
src/pk/pkcs1/pkcs_1_pss_decode.o src/pk/pkcs1/pkcs_1_pss_encode.o src/pk/pkcs1/pkcs_1_v1_5_decode.o \
src/pk/pkcs1/pkcs_1_v1_5_encode.o src/pk/rsa/rsa_decrypt_key.o src/pk/rsa/rsa_encrypt_key.o \
src/pk/rsa/rsa_export.o src/pk/rsa/rsa_exptmod.o src/pk/rsa/rsa_free.o src/pk/rsa/rsa_get_size.o \
src/pk/rsa/rsa_import.o src/pk/rsa/rsa_make_key.o src/pk/rsa/rsa_sign_hash.o \
src/pk/rsa/rsa_sign_saltlen_get.o src/pk/rsa/rsa_verify_hash.o src/prngs/fortuna.o src/prngs/rc4.o \
src/prngs/rng_get_bytes.o src/prngs/rng_make_prng.o src/prngs/sober128.o src/prngs/sprng.o \
src/prngs/yarrow.o

HEADERS=src/headers/tomcrypt_argchk.h src/headers/tomcrypt_cfg.h src/headers/tomcrypt_cipher.h \
src/headers/tomcrypt_custom.h src/headers/tomcrypt.h src/headers/tomcrypt_hash.h \
src/headers/tomcrypt_mac.h src/headers/tomcrypt_macros.h src/headers/tomcrypt_math.h \
src/headers/tomcrypt_misc.h src/headers/tomcrypt_pkcs.h src/headers/tomcrypt_pk.h \
src/headers/tomcrypt_prng.h testprof/tomcrypt_test.h

#END_INS

DEMOS=hashsum crypt small tv_gen multi sizes constants

TIMINGS=demos/timing.o
TESTS=demos/test.o

#Files left over from making the crypt.pdf.
LEFTOVERS=*.dvi *.log *.aux *.toc *.idx *.ilg *.ind *.out *.lof

#Compressed filenames
COMPRESSED=crypt-$(VERSION).tar.bz2 crypt-$(VERSION).zip

#The default rule for make builds the libtomcrypt library.
default:library

#AES comes in two flavours... enc+dec and enc
src/ciphers/aes/aes_enc.o: src/ciphers/aes/aes.c src/ciphers/aes/aes_tab.c
	${silent} ${CC} ${CFLAGS} -DENCRYPT_ONLY -c $< -o $@

#These are the rules to make certain object files.
src/ciphers/aes/aes.o: src/ciphers/aes/aes.c src/ciphers/aes/aes_tab.c
src/ciphers/twofish/twofish.o: src/ciphers/twofish/twofish.c src/ciphers/twofish/twofish_tab.c
src/hashes/whirl/whirl.o: src/hashes/whirl/whirl.c src/hashes/whirl/whirltab.c
src/hashes/sha2/sha512.o: src/hashes/sha2/sha512.c src/hashes/sha2/sha384.c
src/hashes/sha2/sha512_224.o: src/hashes/sha2/sha512.c src/hashes/sha2/sha512_224.c
src/hashes/sha2/sha512_256.o: src/hashes/sha2/sha512.c src/hashes/sha2/sha512_256.c
src/hashes/sha2/sha256.o: src/hashes/sha2/sha256.c src/hashes/sha2/sha224.c

#This rule makes the libtomcrypt library.
library: $(LIBNAME)

$(OBJECTS): $(HEADERS)

$(LIBNAME): $(OBJECTS)
ifneq ($V,1)
	@echo "   * ${AR} $@"
endif
	${silent} $(AR) $(ARFLAGS) $@ $(OBJECTS)
ifneq ($V,1)
	@echo "   * ${RANLIB} $@"
endif
	${silent} $(RANLIB) $@

.PHONY: testprof/$(LIBTEST)
testprof/$(LIBTEST):
	${silent} CFLAGS="$(CFLAGS)" LIBTEST_S=$(LIBTEST_S) CC="$(CC)" LD="$(LD)" AR="$(AR)" ARFLAGS="$(ARFLAGS)" RANLIB="$(RANLIB)" V="$(V)" $(MAKE) -C testprof

timing: library testprof/$(LIBTEST) $(TIMINGS)
ifneq ($V,1)
	@echo "   * ${CC} $@"
endif
	${silent} $(CC) $(LDFLAGS) $(TIMINGS) testprof/$(LIBTEST) $(LIB_PRE) $(LIBNAME) $(LIB_POST) $(EXTRALIBS) -o $(TIMING)

.PHONY: test
test: library testprof/$(LIBTEST) $(TESTS)
ifneq ($V,1)
	@echo "   * ${CC} $@"
endif
	${silent} $(CC) $(LDFLAGS) $(TESTS) testprof/$(LIBTEST) $(LIB_PRE) $(LIBNAME) $(LIB_POST) $(EXTRALIBS) -o $(TEST)

# build the demos from a template
define DEMO_template
$(1): demos/$(1).o library
ifneq ($V,1)
	@echo "   * $${CC} $$@"
endif
	$${silent} $$(CC) $$< $$(LIB_PRE) $$(LIBNAME) $$(LIB_POST) $$(EXTRALIBS) -o $(1)
endef

$(foreach demo, $(strip $(DEMOS)), $(eval $(call DEMO_template,$(demo))))

all_test: test tv_gen $(DEMOS)
ifeq ($(COVERAGE),1)
all_test: LIB_PRE = -Wl,--whole-archive
all_test: LIB_POST = -Wl,--no-whole-archive
endif

#This rule installs the library and the header files. This must be run
#as root in order to have a high enough permission to write to the correct
#directories and to set the owner and group to root.
ifndef NODOCS
install: library docs
else
install: library
endif
	install -d $(DESTDIR)$(LIBPATH)
	install -d $(DESTDIR)$(INCPATH)
	install -d $(DESTDIR)$(DATAPATH)
	install -m 644 $(LIBNAME) $(DESTDIR)$(LIBPATH)
	install -m 644 $(HEADERS) $(DESTDIR)$(INCPATH)
ifndef NODOCS
	install -m 644 doc/crypt.pdf $(DESTDIR)$(DATAPATH)
endif

install_test: testprof/$(LIBTEST)
	install -d $(DESTDIR)$(LIBPATH)
	install -d $(DESTDIR)$(INCPATH)
	install -m 644 testprof/$(LIBTEST) $(DESTDIR)$(LIBPATH)

profile:
	CFLAGS="$(CFLAGS) -fprofile-generate" $(MAKE) timing EXTRALIBS="$(EXTRALIBS) -lgcov"
	./timing
	rm -f timing `find . -type f | grep [.][ao] | xargs`
	CFLAGS="$(CFLAGS) -fprofile-use" $(MAKE) timing EXTRALIBS="$(EXTRALIBS) -lgcov"

# target that pre-processes all coverage data
lcov-single-create:
	lcov --capture --no-external --directory src -q --output-file coverage_std.info

# target that removes all coverage output
cleancov-clean:
	rm -f `find . -type f -name "*.info" | xargs`
	rm -rf coverage/

# generates html output from all coverage_*.info files
lcov:
	lcov `find -name 'coverage_*.info' -exec echo -n " -a {}" \;` -o coverage.info -q 2>/dev/null
	genhtml coverage.info --output-directory coverage -q

# combines all necessary steps to create the coverage from a single testrun with e.g.
# CFLAGS="-DUSE_LTM -DLTM_DESC -I../libtommath" EXTRALIBS="../libtommath/libtommath.a" make coverage -j9
lcov-single: | cleancov-clean lcov-single-create lcov


#make the code coverage of the library
coverage: CFLAGS += -fprofile-arcs -ftest-coverage
coverage: EXTRALIBS += -lgcov
coverage: LIB_PRE = -Wl,--whole-archive
coverage: LIB_POST = -Wl,--no-whole-archive

coverage: test
	./test


# cleans everything - coverage output and standard 'clean'
cleancov: cleancov-clean clean

#This rule cleans the source tree of all compiled code, not including the pdf
#documentation.
clean:
	rm -f `find . -type f -name "*.o" | xargs`
	rm -f `find . -type f -name "*.lo"  | xargs`
	rm -f `find . -type f -name "*.a" | xargs`
	rm -f `find . -type f -name "*.la"  | xargs`
	rm -f `find . -type f -name "*.obj" | xargs`
	rm -f `find . -type f -name "*.lib" | xargs`
	rm -f `find . -type f -name "*.exe" | xargs`
	rm -f `find . -type f -name "*.gcov" | xargs`
	rm -f `find . -type f -name "*.gcda" | xargs`
	rm -f `find . -type f -name "*.gcno" | xargs`
	rm -f `find . -type f -name "*.il" | xargs`
	rm -f `find . -type f -name "*.dyn" | xargs`
	rm -f `find . -type f -name "*.dpi" | xargs`
	rm -rf `find . -type d -name "*.libs" | xargs`
	rm -f crypt.aux  crypt.dvi  crypt.idx  crypt.ilg  crypt.ind  crypt.log crypt.toc
	rm -f $(TV) $(SMALL) $(CRYPT) $(HASH) $(MULTI) $(TIMING) $(TEST)
	rm -f $(SIZES) $(CONSTANTS)
	rm -rf doc/doxygen
	rm -f `find . -type f -name "*.pdf" | grep -FL crypt.pdf | xargs`
	rm -f *.txt
	cd testprof ; $(MAKE) clean

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
	cp crypt.tex crypt.bak
	touch --reference=crypt.tex crypt.bak
	(echo "\\def\\fixedpdfdate{"; date +'D:%Y%m%d%H%M%S%:z' -d @$$(stat --format=%Y crypt.tex) | sed "s/:\([0-9][0-9]\)$$/'\1'}/g") > crypt-deterministic.tex
	echo "\\pdfinfo{" >> crypt-deterministic.tex
	echo "/CreationDate (\fixedpdfdate)" >> crypt-deterministic.tex
	echo "/ModDate (\fixedpdfdate) }" >> crypt-deterministic.tex
	cat crypt.tex >> crypt-deterministic.tex
	mv crypt-deterministic.tex crypt.tex
	touch --reference=crypt.bak crypt.tex
	echo "hello" > crypt.ind
	latex crypt 
	latex crypt 
	makeindex crypt.idx 
	perl fixupind.pl
	pdflatex crypt
	sed -b -i 's,^/ID \[.*\]$$,/ID [<0> <0>],g' crypt.pdf
	mv -ivf crypt.pdf doc/crypt.pdf
	mv crypt.bak crypt.tex
	rm -f $(LEFTOVERS)

docdvi: crypt.tex
	echo hello > crypt.ind
	latex crypt 
	latex crypt 
	makeindex crypt.idx
	perl fixupind.pl
	latex crypt 
	latex crypt 

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


check_defines:
	${silent} cat src/headers/tomcrypt_custom.h | grep '\#define[ \t]*LTC_' | sed -e 's@/\*@@g' -e 's@\*/@@g' -e 's@^[ \t]*@@g' \
	| cut -d' ' -f 2 | sed -e 's@(x)@@g' | sort | uniq \
	| grep -v -e 'LTC_ECC[0-9]*' -e 'LTC_DH[0-9]*' -e 'LTC_NO_' -e 'LTC_MUTEX' -e 'LTC_MPI' \
	| xargs -I '{}' sh -c 'grep -q -m 1 -o {} src/misc/crypt/crypt.c || echo {} not found'

# $Source$
# $Revision$
# $Date$
