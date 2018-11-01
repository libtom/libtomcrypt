/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include  <tomcrypt_test.h>

#ifdef LTC_BASE16

int base16_test(void)
{
   unsigned char in[100], tmp[100];
   char out[201];
   unsigned char testin[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
   const char *testout[2] = {
      "0123456789abcdef",
      "0123456789ABCDEF",
   };
   const char *failing_decode = "test";
   unsigned long x, l1, l2;
   int idx;

   for (idx = 0; idx < 2; idx++) {
      for (x = 0; x < 100; x++) {
         yarrow_read(in, x, &yarrow_prng);
         l1 = sizeof(out);
         DO(base16_encode(in, x, out, &l1, idx));
         l2 = sizeof(tmp);
         DO(base16_decode(out, l1, tmp, &l2));
         DO(do_compare_testvector(tmp, l2, in, x, "random base16", idx * 100 + x));
      }
   }

   for (idx = 0; idx < 2; idx++) {
      l1 = sizeof(out);
      DO(base16_encode(testin, sizeof(testin), out, &l1, idx));
      DO(do_compare_testvector(out, strlen(out), testout[idx], strlen(testout[idx]), "testout base16", idx));
      l2 = sizeof(tmp);
      DO(base16_decode(out, l1, tmp, &l2));
      DO(do_compare_testvector(tmp, l2, testin, sizeof(testin), "testin base16", idx));
   }

   l1 = 4;
   l2 = sizeof(tmp);
   DO(base16_decode(failing_decode, l1, tmp, &l2) == CRYPT_OK ? CRYPT_FAIL_TESTVECTOR : CRYPT_OK);

   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
