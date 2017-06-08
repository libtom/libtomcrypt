#include <tomcrypt_test.h>

#ifndef GIT_VERSION
#define GIT_VERSION "Undefined version"
#endif

#define LTC_TEST_FN(f)  { f, #f }

static const struct {
   int (*fn)(void);
   const char* name;
} test_functions[] =
{
      LTC_TEST_FN(store_test),
      LTC_TEST_FN(rotate_test),
      LTC_TEST_FN(misc_test),
      LTC_TEST_FN(cipher_hash_test),
      LTC_TEST_FN(mac_test),
      LTC_TEST_FN(modes_test),
      LTC_TEST_FN(der_tests),
      LTC_TEST_FN(pkcs_1_test),
      LTC_TEST_FN(pkcs_1_pss_test),
      LTC_TEST_FN(pkcs_1_oaep_test),
      LTC_TEST_FN(pkcs_1_emsa_test),
      LTC_TEST_FN(pkcs_1_eme_test),
      LTC_TEST_FN(rsa_test),
      LTC_TEST_FN(dh_test),
      LTC_TEST_FN(ecc_tests),
      LTC_TEST_FN(dsa_test),
      LTC_TEST_FN(katja_test),
      LTC_TEST_FN(file_test),
      LTC_TEST_FN(multi_test),
      LTC_TEST_FN(prng_test),
};

#if defined(_WIN32)
  #include <windows.h> /* GetSystemTimeAsFileTime */
#else
  #include <sys/time.h>
#endif

/* microseconds since 1970 (UNIX epoch) */
static ulong64 epoch_usec(void)
{
#if defined(LTC_NO_TEST_TIMING)
  return 0;
#elif defined(_WIN32)
  FILETIME CurrentTime;
  ulong64 cur_time;
  ULARGE_INTEGER ul;
  GetSystemTimeAsFileTime(&CurrentTime);
  ul.LowPart  = CurrentTime.dwLowDateTime;
  ul.HighPart = CurrentTime.dwHighDateTime;
  cur_time = ul.QuadPart;
  cur_time -= CONST64(116444736000000000); /* subtract epoch in microseconds */
  cur_time /= 10; /* nanoseconds > microseconds */
  return cur_time;
#else
  struct timeval tv;
  struct timezone tz;
  gettimeofday(&tv, &tz);
  return (ulong64)(tv.tv_sec) * 1000000 + (ulong64)(tv.tv_usec); /* get microseconds */
#endif
}


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

static void register_algs(void)
{
  int err;

  atexit(_unregister_all);

#ifndef LTC_YARROW
   #error This demo requires Yarrow.
#endif
  register_all_ciphers();
  register_all_hashes();
  register_all_prngs();

   if ((err = rng_make_prng(128, find_prng("yarrow"), &yarrow_prng, NULL)) != CRYPT_OK) {
      fprintf(stderr, "rng_make_prng failed: %s\n", error_to_string(err));
      exit(EXIT_FAILURE);
   }

   if (strcmp("CRYPT_OK", error_to_string(err))) {
       exit(EXIT_FAILURE);
   }
}

int main(int argc, char **argv)
{
   int x, pass = 0, fail = 0, nop = 0;
   size_t fn_len, i, dots;
   char *single_test = NULL;
   ulong64 ts;
   long delta, dur = 0;
   register_algs();

   printf("build == %s\n%s\n", GIT_VERSION, crypt_build_settings);

#ifdef USE_LTM
   ltc_mp = ltm_desc;
   printf("math provider = libtommath\n");
#elif defined(USE_TFM)
   ltc_mp = tfm_desc;
   printf("math provider = tomsfastmath\n");
#elif defined(USE_GMP)
   ltc_mp = gmp_desc;
   printf("math provider = gnump\n");
#else
   extern ltc_math_descriptor EXT_MATH_LIB;
   ltc_mp = EXT_MATH_LIB;
   printf("math provider = EXT_MATH_LIB\n");
#endif
   printf("MP_DIGIT_BIT = %d\n", MP_DIGIT_BIT);

   fn_len = 0;
   for (i = 0; i < sizeof(test_functions)/sizeof(test_functions[0]); ++i) {
      size_t len = strlen(test_functions[i].name);
      if (fn_len < len) fn_len = len;
   }

   fn_len = fn_len + (4 - (fn_len % 4));

   /* single test name from commandline */
   if (argc > 1) single_test = argv[1];

   for (i = 0; i < sizeof(test_functions)/sizeof(test_functions[0]); ++i) {
      if (single_test && strcmp(test_functions[i].name, single_test)) {
        continue;
      }
      dots = fn_len - strlen(test_functions[i].name);

      printf("\n%s", test_functions[i].name);
      while(dots--) printf(".");
      fflush(stdout);

      ts = epoch_usec();
      x = test_functions[i].fn();
      delta = (long)(epoch_usec() - ts);
      dur += delta;

      if (x == CRYPT_OK) {
         printf("passed %10.3fms", (double)(delta)/1000);
         pass++;
      }
      else if (x == CRYPT_NOP) {
         printf("nop");
         nop++;
      }
      else {
         printf("failed %10.3fms", (double)(delta)/1000);
         fail++;
      }
   }

   if (fail > 0 || fail+pass+nop == 0) {
      printf("\n\nFAILURE: passed=%d failed=%d nop=%d duration=%.1fsec\n", pass, fail, nop, (double)(dur)/(1000*1000));
      return EXIT_FAILURE;
   }
   else {
      printf("\n\nSUCCESS: passed=%d failed=%d nop=%d duration=%.1fsec\n", pass, fail, nop, (double)(dur)/(1000*1000));
      return EXIT_SUCCESS;
   }
}

/* $Source$ */
/* $Revision$ */
/* $Date$ */
