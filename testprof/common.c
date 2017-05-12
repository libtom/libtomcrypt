/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "common.h"

/**
  @file common.c

  Steffen Jaeckel
*/


void print_hex(const char* what, const void* v, const unsigned long l)
{
  const unsigned char* p = v;
  unsigned long x, y = 0, z;
  fprintf(stderr, "%s contents: \n", what);
  for (x = 0; x < l; ) {
      fprintf(stderr, "%02X ", p[x]);
      if (!(++x % 16) || x == l) {
         if((x % 16) != 0) {
            z = 16 - (x % 16);
            if(z >= 8)
               fprintf(stderr, " ");
            for (; z != 0; --z) {
               fprintf(stderr, "   ");
            }
         }
         fprintf(stderr, " | ");
         for(; y < x; y++) {
            if((y % 8) == 0)
               fprintf(stderr, " ");
            if(isgraph(p[y]))
               fprintf(stderr, "%c", p[y]);
            else
               fprintf(stderr, ".");
         }
         fprintf(stderr, "\n");
      }
      else if((x % 8) == 0) {
         fprintf(stderr, " ");
      }
  }
}

#ifndef compare_testvector
int compare_testvector(const void* is, const unsigned long is_len, const void* should, const unsigned long should_len, const char* what, int which)
{
   int res = 0;
   if(is_len != should_len)
      res = is_len > should_len ? -1 : 1;
   else
      res = XMEMCMP(is, should, MAX(is_len, should_len));

   if (res != 0) {
      fprintf(stderr, "Testvector #%i of %s failed:\n", which, what);
      print_hex("SHOULD", should, should_len);
      print_hex("IS    ", is, is_len);
   }

   return res;
}
#endif

prng_state yarrow_prng;

/*
 * unregister ciphers, hashes & prngs
 */
static void _unregister_all(void)
{
#ifdef LTC_RIJNDAEL
  unregister_cipher(&aes_desc);
#endif
#ifdef LTC_BLOWFISH
  unregister_cipher(&blowfish_desc);
#endif
#ifdef LTC_XTEA
  unregister_cipher(&xtea_desc);
#endif
#ifdef LTC_RC5
  unregister_cipher(&rc5_desc);
#endif
#ifdef LTC_RC6
  unregister_cipher(&rc6_desc);
#endif
#ifdef LTC_SAFERP
  unregister_cipher(&saferp_desc);
#endif
#ifdef LTC_TWOFISH
  unregister_cipher(&twofish_desc);
#endif
#ifdef LTC_SAFER
  unregister_cipher(&safer_k64_desc);
  unregister_cipher(&safer_sk64_desc);
  unregister_cipher(&safer_k128_desc);
  unregister_cipher(&safer_sk128_desc);
#endif
#ifdef LTC_RC2
  unregister_cipher(&rc2_desc);
#endif
#ifdef LTC_DES
  unregister_cipher(&des_desc);
  unregister_cipher(&des3_desc);
#endif
#ifdef LTC_CAST5
  unregister_cipher(&cast5_desc);
#endif
#ifdef LTC_NOEKEON
  unregister_cipher(&noekeon_desc);
#endif
#ifdef LTC_SKIPJACK
  unregister_cipher(&skipjack_desc);
#endif
#ifdef LTC_KHAZAD
  unregister_cipher(&khazad_desc);
#endif
#ifdef LTC_ANUBIS
  unregister_cipher(&anubis_desc);
#endif
#ifdef LTC_KSEED
  unregister_cipher(&kseed_desc);
#endif
#ifdef LTC_KASUMI
  unregister_cipher(&kasumi_desc);
#endif
#ifdef LTC_MULTI2
  unregister_cipher(&multi2_desc);
#endif
#ifdef LTC_CAMELLIA
  unregister_cipher(&camellia_desc);
#endif

#ifdef LTC_TIGER
  unregister_hash(&tiger_desc);
#endif
#ifdef LTC_MD2
  unregister_hash(&md2_desc);
#endif
#ifdef LTC_MD4
  unregister_hash(&md4_desc);
#endif
#ifdef LTC_MD5
  unregister_hash(&md5_desc);
#endif
#ifdef LTC_SHA1
  unregister_hash(&sha1_desc);
#endif
#ifdef LTC_SHA224
  unregister_hash(&sha224_desc);
#endif
#ifdef LTC_SHA256
  unregister_hash(&sha256_desc);
#endif
#ifdef LTC_SHA384
  unregister_hash(&sha384_desc);
#endif
#ifdef LTC_SHA512
  unregister_hash(&sha512_desc);
#endif
#ifdef LTC_SHA512_224
  unregister_hash(&sha512_224_desc);
#endif
#ifdef LTC_SHA512_256
  unregister_hash(&sha512_256_desc);
#endif
#ifdef LTC_SHA3
  unregister_hash(&sha3_224_desc);
  unregister_hash(&sha3_256_desc);
  unregister_hash(&sha3_384_desc);
  unregister_hash(&sha3_512_desc);
#endif
#ifdef LTC_RIPEMD128
  unregister_hash(&rmd128_desc);
#endif
#ifdef LTC_RIPEMD160
  unregister_hash(&rmd160_desc);
#endif
#ifdef LTC_RIPEMD256
  unregister_hash(&rmd256_desc);
#endif
#ifdef LTC_RIPEMD320
  unregister_hash(&rmd320_desc);
#endif
#ifdef LTC_WHIRLPOOL
  unregister_hash(&whirlpool_desc);
#endif
#ifdef LTC_BLAKE2S
  unregister_hash(&blake2s_128_desc);
  unregister_hash(&blake2s_160_desc);
  unregister_hash(&blake2s_224_desc);
  unregister_hash(&blake2s_256_desc);
#endif
#ifdef LTC_BLAKE2B
  unregister_hash(&blake2b_160_desc);
  unregister_hash(&blake2b_256_desc);
  unregister_hash(&blake2b_384_desc);
  unregister_hash(&blake2b_512_desc);
#endif
#ifdef LTC_CHC_HASH
  unregister_hash(&chc_desc);
#endif

  unregister_prng(&yarrow_desc);
#ifdef LTC_FORTUNA
  unregister_prng(&fortuna_desc);
#endif
#ifdef LTC_RC4
  unregister_prng(&rc4_desc);
#endif
#ifdef LTC_CHACHA20_PRNG
  unregister_prng(&chacha20_prng_desc);
#endif
#ifdef LTC_SOBER128
  unregister_prng(&sober128_desc);
#endif
} /* _cleanup() */

#ifdef LTC_PRNG_ENABLE_LTC_RNG

static unsigned long my_test_rng_read;

static unsigned long my_test_rng(unsigned char *buf, unsigned long len,
                             void (*callback)(void))
{
   unsigned long n;
   LTC_UNUSED_PARAM(callback);
   for (n = 0; n < len; ++n) {
      buf[n] = 4;
   }
   my_test_rng_read += n;
   return n;
}

#endif

void register_algs(void)
{
#ifdef LTC_PRNG_ENABLE_LTC_RNG
  unsigned long before;
#endif
  int err;

  atexit(_unregister_all);

#ifdef LTC_RIJNDAEL
  register_cipher (&aes_desc);
#endif
#ifdef LTC_BLOWFISH
  register_cipher (&blowfish_desc);
#endif
#ifdef LTC_XTEA
  register_cipher (&xtea_desc);
#endif
#ifdef LTC_RC5
  register_cipher (&rc5_desc);
#endif
#ifdef LTC_RC6
  register_cipher (&rc6_desc);
#endif
#ifdef LTC_SAFERP
  register_cipher (&saferp_desc);
#endif
#ifdef LTC_TWOFISH
  register_cipher (&twofish_desc);
#endif
#ifdef LTC_SAFER
  register_cipher (&safer_k64_desc);
  register_cipher (&safer_sk64_desc);
  register_cipher (&safer_k128_desc);
  register_cipher (&safer_sk128_desc);
#endif
#ifdef LTC_RC2
  register_cipher (&rc2_desc);
#endif
#ifdef LTC_DES
  register_cipher (&des_desc);
  register_cipher (&des3_desc);
#endif
#ifdef LTC_CAST5
  register_cipher (&cast5_desc);
#endif
#ifdef LTC_NOEKEON
  register_cipher (&noekeon_desc);
#endif
#ifdef LTC_SKIPJACK
  register_cipher (&skipjack_desc);
#endif
#ifdef LTC_ANUBIS
  register_cipher (&anubis_desc);
#endif
#ifdef LTC_KHAZAD
  register_cipher (&khazad_desc);
#endif
#ifdef LTC_KSEED
  register_cipher (&kseed_desc);
#endif
#ifdef LTC_KASUMI
  register_cipher (&kasumi_desc);
#endif
#ifdef LTC_MULTI2
  register_cipher (&multi2_desc);
#endif
#ifdef LTC_CAMELLIA
  register_cipher (&camellia_desc);
#endif

#ifdef LTC_TIGER
  register_hash (&tiger_desc);
#endif
#ifdef LTC_MD2
  register_hash (&md2_desc);
#endif
#ifdef LTC_MD4
  register_hash (&md4_desc);
#endif
#ifdef LTC_MD5
  register_hash (&md5_desc);
#endif
#ifdef LTC_SHA1
  register_hash (&sha1_desc);
#endif
#ifdef LTC_SHA224
  register_hash (&sha224_desc);
#endif
#ifdef LTC_SHA256
  register_hash (&sha256_desc);
#endif
#ifdef LTC_SHA384
  register_hash (&sha384_desc);
#endif
#ifdef LTC_SHA512
  register_hash (&sha512_desc);
#endif
#ifdef LTC_SHA512_224
  register_hash (&sha512_224_desc);
#endif
#ifdef LTC_SHA512_256
  register_hash (&sha512_256_desc);
#endif
#ifdef LTC_SHA3
  register_hash (&sha3_224_desc);
  register_hash (&sha3_256_desc);
  register_hash (&sha3_384_desc);
  register_hash (&sha3_512_desc);
#endif
#ifdef LTC_RIPEMD128
  register_hash (&rmd128_desc);
#endif
#ifdef LTC_RIPEMD160
  register_hash (&rmd160_desc);
#endif
#ifdef LTC_RIPEMD256
  register_hash (&rmd256_desc);
#endif
#ifdef LTC_RIPEMD320
  register_hash (&rmd320_desc);
#endif
#ifdef LTC_WHIRLPOOL
  register_hash (&whirlpool_desc);
#endif
#ifdef LTC_BLAKE2S
  register_hash(&blake2s_128_desc);
  register_hash(&blake2s_160_desc);
  register_hash(&blake2s_224_desc);
  register_hash(&blake2s_256_desc);
#endif
#ifdef LTC_BLAKE2S
  register_hash(&blake2b_160_desc);
  register_hash(&blake2b_256_desc);
  register_hash(&blake2b_384_desc);
  register_hash(&blake2b_512_desc);
#endif
#ifdef LTC_CHC_HASH
  register_hash(&chc_desc);
  if ((err = chc_register(register_cipher(&aes_desc))) != CRYPT_OK) {
     fprintf(stderr, "chc_register error: %s\n", error_to_string(err));
     exit(EXIT_FAILURE);
  }
#endif


#ifndef LTC_YARROW
   #error This demo requires Yarrow.
#endif
register_prng(&yarrow_desc);
#ifdef LTC_FORTUNA
register_prng(&fortuna_desc);
#endif
#ifdef LTC_RC4
register_prng(&rc4_desc);
#endif
#ifdef LTC_CHACHA20_PRNG
register_prng(&chacha20_prng_desc);
#endif
#ifdef LTC_SOBER128
register_prng(&sober128_desc);
#endif
#ifdef LTC_SPRNG
register_prng(&sprng_desc);
#endif

#ifdef LTC_PRNG_ENABLE_LTC_RNG
   ltc_rng = my_test_rng;

   before = my_test_rng_read;
   if ((err = rng_make_prng(128, find_prng("yarrow"), &yarrow_prng, NULL)) != CRYPT_OK) {
      fprintf(stderr, "rng_make_prng with 'my_test_rng' failed: %s\n", error_to_string(err));
      exit(EXIT_FAILURE);
   }

   if (before == my_test_rng_read) {
      fprintf(stderr, "somehow there was no read from the ltc_rng! %lu == %lu\n", before, my_test_rng_read);
      exit(EXIT_FAILURE);
   }

   ltc_rng = NULL;
#endif

   if ((err = rng_make_prng(128, find_prng("yarrow"), &yarrow_prng, NULL)) != CRYPT_OK) {
      fprintf(stderr, "rng_make_prng failed: %s\n", error_to_string(err));
      exit(EXIT_FAILURE);
   }

   if (strcmp("CRYPT_OK", error_to_string(err))) {
       exit(EXIT_FAILURE);
   }

}

void setup_math(void)
{
#ifdef USE_LTM
   ltc_mp = ltm_desc;
#elif defined(USE_TFM)
   ltc_mp = tfm_desc;
#elif defined(USE_GMP)
   ltc_mp = gmp_desc;
#elif defined(EXT_MATH_LIB)
   extern ltc_math_descriptor EXT_MATH_LIB;
   ltc_mp = EXT_MATH_LIB;
#else
   fprintf(stderr, "No MPI provider available\n");
   exit(EXIT_FAILURE);
#endif
}
