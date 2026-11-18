/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include <tomcrypt_test.h>

#ifdef LTC_MRSA

#ifdef LTC_TEST_REAL_RAND
#define LTC_TEST_RAND_SEED  time(NULL)
#else
#define LTC_TEST_RAND_SEED  23
#endif

int pkcs_1_test(void)
{
   unsigned char buf[3][128];
   int res1, res2, res3;
   unsigned long x, y, l1, l2, l3, i1, modlen;
   static const unsigned char lparam[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
   ltc_rsa_op_parameters rsa_params = {
                                       .wprng = find_prng("yarrow"),
                                       .prng = &yarrow_prng,
                                       .params.hash_idx = -1,
                                       .params.mgf1_hash_idx = -1,
   };
   rsa_params.params.hash_idx = find_hash("sha1");
   rsa_params.params.mgf1_hash_idx = rsa_params.params.hash_idx;

   srand(LTC_TEST_RAND_SEED);
   /* do many tests */
   for (x = 0; x < 100; x++) {
      zeromem(buf, sizeof(buf));

      /* make a dummy message (of random length) */
      l3 = (rand() & 31) + 8;
      for (y = 0; y < l3; y++) buf[0][y] = rand() & 255;

      /* pick a random lparam len [0..16] */
      rsa_params.u.crypt.lparamlen = abs(rand()) % 17;

      /* pick a random saltlen 0..16 */
      rsa_params.params.saltlen = abs(rand()) % 17;

      /* PKCS #1 v2.0 supports modlens not multiple of 8 */
      modlen = 800 + (abs(rand()) % 224);

      /* encode it */
      l1 = sizeof(buf[1]);
      rsa_params.padding = LTC_PKCS_1_OAEP;
      rsa_params.u.crypt.lparam = lparam;
      DO(ltc_pkcs_1_oaep_encode(buf[0], l3, &rsa_params, modlen, buf[1], &l1));

      /* decode it */
      l2 = sizeof(buf[2]);
      DO(ltc_pkcs_1_oaep_decode(buf[1], l1, &rsa_params, modlen, buf[2], &l2, &res1));

      ENSURE(res1 == 1);
      COMPARE_TESTVECTOR(buf[0], l3, buf[2], l2, "PKCS#1 OAEP", x);

      /* test PSS */
      l1 = sizeof(buf[1]);
      rsa_params.padding = LTC_PKCS_1_PSS;
      rsa_params.u.crypt.lparam = NULL;
      rsa_params.u.crypt.lparamlen = 0;
      DO(ltc_pkcs_1_pss_encode_mgf1(buf[0], l3, &rsa_params, modlen, buf[1], &l1));
      DO(ltc_pkcs_1_pss_decode_mgf1(buf[0], l3, buf[1], l1, &rsa_params, modlen, &res1));

      buf[0][i1 = abs(rand()) % l3] ^= 1;
      DO(ltc_pkcs_1_pss_decode_mgf1(buf[0], l3, buf[1], l1, &rsa_params, modlen, &res2));

      buf[0][i1] ^= 1;
      buf[1][abs(rand()) % (l1 - 1)] ^= 1;
      ltc_pkcs_1_pss_decode_mgf1(buf[0], l3, buf[1], l1, &rsa_params, modlen, &res3);
      if (!(res1 == 1 && res2 == 0 && res3 == 0)) {
         fprintf(stderr, "PSS failed: %d, %d, %d, %lu, %lu\n", res1, res2, res3, l3, rsa_params.params.saltlen);
         return 1;
      }
   }

   /* the PSS encoded message has to be exactly as long as the decoder expects */
   SHOULD_FAIL_WITH(ltc_pkcs_1_pss_decode_mgf1(buf[0], l3, buf[1], l1 - 1, &rsa_params, modlen, &res1), CRYPT_PK_INVALID_SIZE);
   SHOULD_FAIL_WITH(ltc_pkcs_1_pss_decode_mgf1(buf[0], l3, buf[1], 0, &rsa_params, modlen, &res1), CRYPT_PK_INVALID_SIZE);
   return 0;
}

#else
LTC_NOP_TEST(pkcs_1_test)
#endif

