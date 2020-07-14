/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include  <tomcrypt_test.h>

#ifdef LTC_BASE32

int base32_test(void)
{
   unsigned char in[100], tmp[100];
   char out[160];
   unsigned char testin[] = { 0x61,0xc2,0xcb,0xbc,0x5e,0x6d,0x2a,0x7a,0x1a,0x19,0x1a,0xae,0xc9,0x02,0xd4,0xbf,0x7d };
   const int testid[4] = {
      BASE32_RFC4648,
      BASE32_BASE32HEX,
      BASE32_ZBASE32,
      BASE32_CROCKFORD
   };
   const char *testout[4] = {
      "MHBMXPC6NUVHUGQZDKXMSAWUX56Q",
      "C71CNF2UDKL7K6GP3ANCI0MKNTUG",
      "c8bczxn6pwi8wgo3dkzc1yswz76o",
      "C71CQF2YDMN7M6GS3AQCJ0PMQXYG"
   };
   unsigned long x, l1, l2;
   int idx;

   for (idx = 0; idx < 4; idx++) {
      for (x = 0; x < 100; x++) {
         yarrow_read(in, x, &yarrow_prng);
         l1 = sizeof(out);
         DO(base32_encode(in, x, out, &l1, testid[idx]));
         l2 = sizeof(tmp);
         DO(base32_decode(out, l1, tmp, &l2, testid[idx]));
         DO(do_compare_testvector(tmp, l2, in, x, "random base32", idx * 100 + x));
      }
   }

   for (idx = 0; idx < 4; idx++) {
      l1 = sizeof(out);
      DO(base32_encode(testin, sizeof(testin), out, &l1, testid[idx]));
      DO(do_compare_testvector(out, l1, testout[idx], XSTRLEN(testout[idx]), "testout base32", idx));
      l2 = sizeof(tmp);
      DO(base32_decode(out, l1, tmp, &l2, testid[idx]));
      DO(do_compare_testvector(tmp, l2, testin, sizeof(testin), "testin base32", idx));
   }

   return CRYPT_OK;
}

#endif
