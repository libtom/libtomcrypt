/* test the ciphers and hashes using their built-in self-tests */

#include <tomcrypt_test.h>

int cipher_hash_test(void)
{
   int           x, fails = 0;
   unsigned char buf[4096];
   unsigned long n;
   prng_state    nprng;

   /* test ciphers */
   for (x = 0; cipher_descriptor[x].name != NULL; x++) {
      DOX(cipher_descriptor[x].test(), cipher_descriptor[x].name);
   }

#ifdef LTC_CHACHA
   /* ChaCha is a special case (stream cipher) */
   DO(chacha_test());
#endif

   /* test hashes */
   for (x = 0; hash_descriptor[x].name != NULL; x++) {
      DOX(hash_descriptor[x].test(), hash_descriptor[x].name);
   }

   /* SHAKE128 + SHAKE256 tests are a bit special */
   DOX(sha3_shake_test(), "sha3_shake");

   /* test prngs (test, import/export */
   for (x = 0; prng_descriptor[x].name != NULL; x++) {
      unsigned char buf1[100], buf2[100];

      DOX(prng_descriptor[x].test(), prng_descriptor[x].name);
      DOX(prng_descriptor[x].start(&nprng), prng_descriptor[x].name);
      DOX(prng_descriptor[x].add_entropy((unsigned char *)"helloworld12", 12, &nprng), prng_descriptor[x].name);
      DOX(prng_descriptor[x].ready(&nprng), prng_descriptor[x].name);
      n = sizeof(buf);
      DOX(prng_descriptor[x].pexport(buf, &n, &nprng), prng_descriptor[x].name);
      if (prng_descriptor[x].read(buf1, 100, &nprng) != 100) exit(EXIT_FAILURE); /* skip 100 bytes */
      if (prng_descriptor[x].read(buf1, 10, &nprng) != 10) exit(EXIT_FAILURE);   /* 10 bytes for comparison */
      prng_descriptor[x].done(&nprng);

      DOX(prng_descriptor[x].pimport(buf, n, &nprng), prng_descriptor[x].name);
      /*DOX(prng_descriptor[x].ready(&nprng), prng_descriptor[x].name);*/ /* it fails both with/without this line */
      if (prng_descriptor[x].read(buf2, 100, &nprng) != 100) exit(EXIT_FAILURE); /* skip 100 bytes */
      if (prng_descriptor[x].read(buf2, 10, &nprng) != 10) exit(EXIT_FAILURE);   /* 10 bytes for comparison */
      prng_descriptor[x].done(&nprng);

      if (XMEMCMP(buf1, buf2, 10) != 0) {
         int i;
         fprintf(stderr, "%s export/import FAILED\n", prng_descriptor[x].name);
         fprintf(stderr, "%s buf1: ", prng_descriptor[x].name);
         for(i = 1; i < 10; i++) fprintf(stderr, "%02x ", buf1[i]);
         fprintf(stderr, "\n%s buf2: ", prng_descriptor[x].name);
         for(i = 1; i < 10; i++) fprintf(stderr, "%02x ", buf2[i]);
         fprintf(stderr, "\n");
         fails++;
      }
      else {
         fprintf(stderr, "%s export/import OK\n", prng_descriptor[x].name);
      }
   }
   if (fails > 0) return CRYPT_FAIL_TESTVECTOR;

   return 0;
}

/* $Source$ */
/* $Revision$ */
/* $Date$ */
