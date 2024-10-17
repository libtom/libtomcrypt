/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
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
   int           err = CRYPT_NOP;
   int           x;
   unsigned char buf[4096] = { 0 };
   unsigned long n, one;
   prng_state    nprng;

   typedef int (*fp_prng_start)(prng_state*);
   char name[2] = { 0 };

   fp_prng_start prng_start[] = {
#ifdef LTC_YARROW
      yarrow_start,
#endif
#ifdef LTC_FORTUNA
      fortuna_start,
#endif
#ifdef LTC_RC4
      rc4_start,
#endif
#ifdef LTC_CHACHA20_PRNG
      chacha20_prng_start,
#endif
#ifdef LTC_SOBER128
      sober128_start,
#endif
#ifdef LTC_SPRNG
      sprng_start,
#endif
      NULL
   };

#ifdef LTC_PRNG_ENABLE_LTC_RNG
   unsigned long before;

   unsigned long (*previous)(unsigned char *, unsigned long , void (*)(void)) = ltc_rng;
   ltc_rng = my_test_rng;

   before = my_test_rng_read;

   if ((err = rng_make_prng(128, find_prng("yarrow"), &nprng, NULL)) != CRYPT_OK) {
      fprintf(stderr, "rng_make_prng with 'my_test_rng' failed: %s\n", error_to_string(err));
      exit(EXIT_FAILURE);
   }
   DO(yarrow_done(&nprng));

   if (before == my_test_rng_read) {
      fprintf(stderr, "somehow there was no read from the ltc_rng! %lu == %lu\n", before, my_test_rng_read);
      exit(EXIT_FAILURE);
   }

   ltc_rng = previous;
#endif

   /* test prngs (test, import/export) */
   for (x = 0; prng_start[x] != NULL; x++) {
      name[0] = '0' + (unsigned)x;
      DOX(prng_start[x](&nprng), name);
      DOX(nprng.desc.test(), nprng.desc.name);
      DOX(nprng.desc.add_entropy((unsigned char *)"helloworld12", 12, &nprng), nprng.desc.name);
      DOX(nprng.desc.ready(&nprng), nprng.desc.name);
      n = sizeof(buf);
      if (strcmp(nprng.desc.name, "sprng")) {
         one = 1;
         if (nprng.desc.pexport(buf, &one, &nprng) != CRYPT_BUFFER_OVERFLOW) {
            fprintf(stderr, "Error testing pexport with a short buffer (%s)\n", nprng.desc.name);
            return CRYPT_ERROR;
         }
      }
      DOX(nprng.desc.pexport(buf, &n, &nprng), nprng.desc.name);
      nprng.desc.done(&nprng);
      DOX(nprng.desc.pimport(buf, n, &nprng), nprng.desc.name);
      DOX(nprng.desc.pimport(buf, sizeof(buf), &nprng), nprng.desc.name); /* try to import larger data */
      DOX(nprng.desc.ready(&nprng), nprng.desc.name);
      if (nprng.desc.read(buf, 100, &nprng) != 100) {
         fprintf(stderr, "Error reading from imported PRNG (%s)!\n", nprng.desc.name);
         return CRYPT_ERROR;
      }
      nprng.desc.done(&nprng);
   }

   DO(yarrow_start(&nprng));
   if ((err = rng_make_prng(-1, &nprng, NULL)) != CRYPT_OK) {
      fprintf(stderr, "rng_make_prng(-1,..) with 'yarrow' failed: %s\n", error_to_string(err));
   }
   DO(yarrow_done(&nprng));

#ifdef LTC_FORTUNA
   DO(fortuna_start(&nprng));
   DO(fortuna_add_entropy(buf, 32, &nprng));
   DO(fortuna_ready(&nprng));
   if (fortuna_read(buf + 32, 32, &nprng) != 32) {
      fprintf(stderr, "Error reading from Fortuna after fortuna_add_entropy()!\n");
      return CRYPT_ERROR;
   }
   DO(fortuna_done(&nprng));

   DO(fortuna_start(&nprng));
   DO(fortuna_add_random_event(0, 0, buf, 32, &nprng));
   DO(fortuna_ready(&nprng));
   if (fortuna_read(buf + 64, 32, &nprng) != 32) {
      fprintf(stderr, "Error reading from Fortuna after fortuna_add_random_event()!\n");
      return CRYPT_ERROR;
   }
   DO(fortuna_done(&nprng));

   if (compare_testvector(buf + 64, 32, buf + 32, 32, "fortuna_add_entropy() vs. fortuna_add_random_event()", 0) != 0) {
      err = CRYPT_FAIL_TESTVECTOR;
   }
#endif
   return err;
}
