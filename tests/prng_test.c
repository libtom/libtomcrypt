#include <tomcrypt_test.h>

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

int prng_test(void)
{
   int err = CRYPT_NOP;
#ifdef LTC_PRNG_ENABLE_LTC_RNG
   unsigned long before;

   unsigned long (*previous)(unsigned char *, unsigned long , void (*)(void)) = ltc_rng;
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

   ltc_rng = previous;
#endif
   return err;
}
