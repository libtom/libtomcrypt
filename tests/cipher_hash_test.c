/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/* test the ciphers and hashes using their built-in self-tests */

#include <tomcrypt_test.h>

int cipher_hash_test(void)
{
   int           x;

   /* test block ciphers */
   for (x = 0; cipher_descriptor[x].name != NULL; x++) {
      DOX(cipher_descriptor[x].test(), cipher_descriptor[x].name);
   }

   /* explicit AES-NI test */
#if defined(LTC_AES_NI)
   if (aesni_is_supported()) {
      DO(aesni_test());
   }
   DO(rijndael_test());
#endif
#if defined(LTC_RIJNDAEL)
#ifndef ENCRYPT_ONLY
   DO(aes_test());
#else
   DO(aes_enc_test());
#endif
#endif

   /* test stream ciphers */
#ifdef LTC_CHACHA
   DO(chacha_test());
#endif
#ifdef LTC_XCHACHA20
   DO(xchacha20_test());
#endif
#ifdef LTC_SALSA20
   DO(salsa20_test());
#endif
#ifdef LTC_XSALSA20
   DO(xsalsa20_test());
#endif
#ifdef LTC_SOSEMANUK
   DO(sosemanuk_test());
#endif
#ifdef LTC_RABBIT
   DO(rabbit_test());
#endif
#ifdef LTC_RC4_STREAM
   DO(rc4_stream_test());
#endif
#ifdef LTC_SOBER128_STREAM
   DO(sober128_stream_test());
#endif

   /* test hashes */
   for (x = 0; hash_descriptor[x].name != NULL; x++) {
      DOX(hash_descriptor[x].test(), hash_descriptor[x].name);
   }

   /* explicit SHA-NI + portable implementations tests */
   if (sha512ni_is_supported()) {
#if defined(LTC_SHA512) && defined(LTC_SHA512_X86)
      DO(sha512_x86_test());
#endif
#if defined(LTC_SHA384) && defined(LTC_SHA384_X86)
      DO(sha384_x86_test());
#endif
#if defined(LTC_SHA512_256) && defined(LTC_SHA512_256_X86)
      DO(sha512_256_x86_test());
#endif
#if defined(LTC_SHA512_224) && defined(LTC_SHA512_224_X86)
      DO(sha512_224_x86_test());
#endif
   }
   if (shani_is_supported()) {
#if defined(LTC_SHA256) && defined(LTC_SHA256_X86)
      DO(sha256_x86_test());
#endif
#if defined(LTC_SHA224) && defined(LTC_SHA224_X86)
      DO(sha224_x86_test());
#endif
#if defined(LTC_SHA1) && defined(LTC_SHA1_X86)
      DO(sha1_x86_test());
#endif
   }
#if defined(LTC_SHA256)
   DO(sha256_c_test());
#endif
#if defined(LTC_SHA224)
   DO(sha224_c_test());
#endif
#if defined(LTC_SHA1)
   DO(sha1_c_test());
#endif
#ifdef LTC_SHA3
   /* SHAKE128 + SHAKE256 tests are a bit special */
   DOX(sha3_shake_test(), "sha3_shake");
#endif
#ifdef LTC_TURBO_SHAKE
   DO(turbo_shake_test());
#endif
#ifdef LTC_KANGAROO_TWELVE
   DO(kangaroo_twelve_test());
#endif

   return 0;
}
