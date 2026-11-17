/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_test.h"

#ifdef LTC_CURVE448

/* RFC 7748 Section 5.2 - X448 scalar multiplication test vectors */
static int s_x448_rfc7748_scalarmult_test(void)
{
   /* First test vector */
   static const unsigned char k1[56] = {
      0x3d, 0x26, 0x2f, 0xdd, 0xf9, 0xec, 0x8e, 0x88,
      0x49, 0x52, 0x66, 0xfe, 0xa1, 0x9a, 0x34, 0xd2,
      0x88, 0x82, 0xac, 0xef, 0x04, 0x51, 0x04, 0xd0,
      0xd1, 0xaa, 0xe1, 0x21, 0x70, 0x0a, 0x77, 0x9c,
      0x98, 0x4c, 0x24, 0xf8, 0xcd, 0xd7, 0x8f, 0xbf,
      0xf4, 0x49, 0x43, 0xeb, 0xa3, 0x68, 0xf5, 0x4b,
      0x29, 0x25, 0x9a, 0x4f, 0x1c, 0x60, 0x0a, 0xd3
   };
   static const unsigned char u1[56] = {
      0x06, 0xfc, 0xe6, 0x40, 0xfa, 0x34, 0x87, 0xbf,
      0xda, 0x5f, 0x6c, 0xf2, 0xd5, 0x26, 0x3f, 0x8a,
      0xad, 0x88, 0x33, 0x4c, 0xbd, 0x07, 0x43, 0x7f,
      0x02, 0x0f, 0x08, 0xf9, 0x81, 0x4d, 0xc0, 0x31,
      0xdd, 0xbd, 0xc3, 0x8c, 0x19, 0xc6, 0xda, 0x25,
      0x83, 0xfa, 0x54, 0x29, 0xdb, 0x94, 0xad, 0xa1,
      0x8a, 0xa7, 0xa7, 0xfb, 0x4e, 0xf8, 0xa0, 0x86
   };
   static const unsigned char expected1[56] = {
      0xce, 0x3e, 0x4f, 0xf9, 0x5a, 0x60, 0xdc, 0x66,
      0x97, 0xda, 0x1d, 0xb1, 0xd8, 0x5e, 0x6a, 0xfb,
      0xdf, 0x79, 0xb5, 0x0a, 0x24, 0x12, 0xd7, 0x54,
      0x6d, 0x5f, 0x23, 0x9f, 0xe1, 0x4f, 0xba, 0xad,
      0xeb, 0x44, 0x5f, 0xc6, 0x6a, 0x01, 0xb0, 0x77,
      0x9d, 0x98, 0x22, 0x39, 0x61, 0x11, 0x1e, 0x21,
      0x76, 0x62, 0x82, 0xf7, 0x3d, 0xd9, 0x6b, 0x6f
   };

   /* Second test vector */
   static const unsigned char k2[56] = {
      0x20, 0x3d, 0x49, 0x44, 0x28, 0xb8, 0x39, 0x93,
      0x52, 0x66, 0x5d, 0xdc, 0xa4, 0x2f, 0x9d, 0xe8,
      0xfe, 0xf6, 0x00, 0x90, 0x8e, 0x0d, 0x46, 0x1c,
      0xb0, 0x21, 0xf8, 0xc5, 0x38, 0x34, 0x5d, 0xd7,
      0x7c, 0x3e, 0x48, 0x06, 0xe2, 0x5f, 0x46, 0xd3,
      0x31, 0x5c, 0x44, 0xe0, 0xa5, 0xb4, 0x37, 0x12,
      0x82, 0xdd, 0x2c, 0x8d, 0x5b, 0xe3, 0x09, 0x5b
   };
   static const unsigned char u2[56] = {
      0x0f, 0xbc, 0xc2, 0xf9, 0x93, 0xcd, 0x56, 0xd3,
      0x30, 0x5b, 0x0b, 0x7d, 0x9e, 0x55, 0xd4, 0xc1,
      0xa8, 0xfb, 0x5d, 0xbb, 0x52, 0xf8, 0xe9, 0xa1,
      0xe9, 0xb6, 0x20, 0x1b, 0x16, 0x5d, 0x01, 0x58,
      0x94, 0xe5, 0x6c, 0x4d, 0x35, 0x70, 0xbe, 0xe5,
      0x2f, 0xe2, 0x05, 0xe2, 0x8a, 0x78, 0xb9, 0x1c,
      0xdf, 0xbd, 0xe7, 0x1c, 0xe8, 0xd1, 0x57, 0xdb
   };
   static const unsigned char expected2[56] = {
      0xe4, 0x3a, 0x6e, 0x84, 0xc5, 0x41, 0x24, 0x19,
      0x69, 0xe1, 0xbc, 0x13, 0xaf, 0xae, 0xba, 0x34,
      0xe8, 0xe0, 0x91, 0x22, 0xaf, 0x0f, 0xaf, 0x6a,
      0x45, 0xf8, 0xd2, 0x51, 0x38, 0xb4, 0x80, 0x0f,
      0x07, 0xc8, 0x62, 0xd8, 0x04, 0xac, 0xaf, 0x18,
      0xd2, 0xc5, 0xf5, 0x02, 0x76, 0xcd, 0xf0, 0xbd,
      0x06, 0x8e, 0x95, 0x73, 0x73, 0xd3, 0x52, 0x97
   };

   unsigned char out[56];

   ec448_scalarmult_internal(out, k1, u1);
   COMPARE_TESTVECTOR(out, 56, expected1, 56, "X448 RFC7748 5.2 #1", 0);

   ec448_scalarmult_internal(out, k2, u2);
   COMPARE_TESTVECTOR(out, 56, expected2, 56, "X448 RFC7748 5.2 #2", 1);

   return CRYPT_OK;
}

/* RFC 7748 Section 5.2 - X448 iterative scalar multiplication test
 *
 * Start with k = u = 5 (as 56-byte little-endian).
 * Each iteration: out = X448(k, u), then u = old_k, k = out.
 */
static int s_x448_rfc7748_iter_test(void)
{
   /* Expected result after 1 iteration */
   static const unsigned char expected_1[56] = {
      0x3f, 0x48, 0x2c, 0x8a, 0x9f, 0x19, 0xb0, 0x1e,
      0x6c, 0x46, 0xee, 0x97, 0x11, 0xd9, 0xdc, 0x14,
      0xfd, 0x4b, 0xf6, 0x7a, 0xf3, 0x07, 0x65, 0xc2,
      0xae, 0x2b, 0x84, 0x6a, 0x4d, 0x23, 0xa8, 0xcd,
      0x0d, 0xb8, 0x97, 0x08, 0x62, 0x39, 0x49, 0x2c,
      0xaf, 0x35, 0x0b, 0x51, 0xf8, 0x33, 0x86, 0x8b,
      0x9b, 0xc2, 0xb3, 0xbc, 0xa9, 0xcf, 0x41, 0x13
   };

   /* Expected result after 1000 iterations */
   static const unsigned char expected_1000[56] = {
      0xaa, 0x3b, 0x47, 0x49, 0xd5, 0x5b, 0x9d, 0xaf,
      0x1e, 0x5b, 0x00, 0x28, 0x88, 0x26, 0xc4, 0x67,
      0x27, 0x4c, 0xe3, 0xeb, 0xbd, 0xd5, 0xc1, 0x7b,
      0x97, 0x5e, 0x09, 0xd4, 0xaf, 0x6c, 0x67, 0xcf,
      0x10, 0xd0, 0x87, 0x20, 0x2d, 0xb8, 0x82, 0x86,
      0xe2, 0xb7, 0x9f, 0xce, 0xea, 0x3e, 0xc3, 0x53,
      0xef, 0x54, 0xfa, 0xa2, 0x6e, 0x21, 0x9f, 0x38
   };

   unsigned char k[56], u[56], out[56], tmp[56];
   unsigned long i;

   /* k = u = 5 (little-endian) */
   XMEMSET(k, 0, 56);
   XMEMSET(u, 0, 56);
   k[0] = 5;
   u[0] = 5;

   /* 1 iteration */
   ec448_scalarmult_internal(out, k, u);
   XMEMCPY(u, k, 56);
   XMEMCPY(k, out, 56);
   COMPARE_TESTVECTOR(k, 56, expected_1, 56, "X448 RFC7748 iter=1", 0);

   /* Continue to 1000 iterations (we already did 1) */
   for (i = 1; i < 1000; i++) {
      ec448_scalarmult_internal(out, k, u);
      XMEMCPY(tmp, k, 56);
      XMEMCPY(k, out, 56);
      XMEMCPY(u, tmp, 56);
   }
   COMPARE_TESTVECTOR(k, 56, expected_1000, 56, "X448 RFC7748 iter=1000", 1);

   return CRYPT_OK;
}

static int s_x448_keygen_dh_test(void)
{
   curve448_key alice, bob;
   unsigned char ss_a[56], ss_b[56];
   unsigned long sslen;
   int prng_idx;

   prng_idx = find_prng("yarrow");

   /* Generate two key pairs */
   DO(x448_make_key(&yarrow_prng, prng_idx, &alice));
   DO(x448_make_key(&yarrow_prng, prng_idx, &bob));
   ENSURE(alice.type == PK_PRIVATE);
   ENSURE(alice.pka == LTC_PKA_X448);

   /* DH: both sides compute the same shared secret */
   sslen = sizeof(ss_a);
   DO(x448_shared_secret(&alice, &bob, ss_a, &sslen));
   ENSURE(sslen == 56);

   sslen = sizeof(ss_b);
   DO(x448_shared_secret(&bob, &alice, ss_b, &sslen));
   ENSURE(sslen == 56);

   COMPARE_TESTVECTOR(ss_a, 56, ss_b, 56, "X448 DH shared secret", 0);

   /* Export/import raw round-trip */
   {
      curve448_key imported;
      unsigned char buf[56];
      unsigned long buflen = sizeof(buf);

      DO(x448_export(buf, &buflen, PK_PUBLIC, &alice));
      ENSURE(buflen == 56);
      DO(x448_import_raw(buf, buflen, PK_PUBLIC, &imported));
      ENSURE(imported.type == PK_PUBLIC);
      ENSURE(imported.pka == LTC_PKA_X448);
      COMPARE_TESTVECTOR(imported.pub, 56, alice.pub, 56, "X448 import_raw pub", 0);
   }

   return CRYPT_OK;
}

/* Wycheproof x448_test.json tcId=22 (Twist + SpecialPublicKey) */
static int s_x448_wycheproof_special_test(void)
{
   const char *priv_hex = "8c37fb35eac1dbda6a3b5bf492c1f642c761be3adf0ab7617a66002576c45bba8202970bae6c5e05f645f5439ca2f42b89dacace1a5d0e82";
   const char *pub_hex  = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040";
   const char *exp_hex  = "60c468df97e2e4427f27420cc6bc9eebaa2bceb827eb55a187fc5c29555e72a663243f6af4095641d72caeacb369720ea18cadd6efdbece6";
   unsigned char priv[56], pub[56], expected[56], out[56];
   unsigned long len;

   len = sizeof(priv);     DO(base16_decode(priv_hex, XSTRLEN(priv_hex), priv, &len));
   len = sizeof(pub);      DO(base16_decode(pub_hex,  XSTRLEN(pub_hex),  pub,  &len));
   len = sizeof(expected); DO(base16_decode(exp_hex,  XSTRLEN(exp_hex),  expected, &len));
   ec448_scalarmult_internal(out, priv, pub);
   COMPARE_TESTVECTOR(out, 56, expected, 56, "X448 Wycheproof tcId=22", 22);
   return CRYPT_OK;
}

/* Export/import round-trip (requires MPI for DER/PKCS8) */
static int s_x448_compat_test(void)
{
   curve448_key priv, pub, imported;
   unsigned char buf[1024];
   unsigned long buflen;
   int prng_idx = find_prng("yarrow");

   XMEMSET(&priv, 0, sizeof(priv));
   XMEMSET(&pub, 0, sizeof(pub));
   XMEMSET(&imported, 0, sizeof(imported));

   DO(x448_make_key(&yarrow_prng, prng_idx, &priv));

   /* private PKCS#8 export -> import */
   buflen = sizeof(buf);
   DO(x448_export(buf, &buflen, PK_PRIVATE | PK_STD, &priv));
   DO(x448_import_pkcs8(buf, buflen, NULL, &imported));
   COMPARE_TESTVECTOR(&priv, sizeof(priv), &imported, sizeof(imported), "X448 priv pkcs8 round-trip", __LINE__);
   XMEMSET(&imported, 0, sizeof(imported));

   /* public raw export -> import */
   buflen = sizeof(buf);
   DO(x448_export(buf, &buflen, PK_PUBLIC, &priv));
   DO(x448_import_raw(buf, buflen, PK_PUBLIC, &pub));

   /* public DER export -> import */
   buflen = sizeof(buf);
   DO(x448_export(buf, &buflen, PK_PUBLIC | PK_STD, &priv));
   DO(x448_import(buf, buflen, &imported));
   COMPARE_TESTVECTOR(&pub, sizeof(pub), &imported, sizeof(imported), "X448 pub DER round-trip", __LINE__);

   return CRYPT_OK;
}

static int s_x448_zero_shared_secret_test(void)
{
   curve448_key alice, bob, zero_pub;
   unsigned char shared[56], zeros[56];
   unsigned long len;
   int prng_idx = find_prng("yarrow");

   zeromem(zeros, sizeof(zeros));

   DO(x448_make_key(&yarrow_prng, prng_idx, &alice));
   DO(x448_make_key(&yarrow_prng, prng_idx, &bob));

   len = sizeof(shared);
   DO(x448_shared_secret(&alice, &bob, shared, &len));
   ENSURE(len == sizeof(shared));

   DO(x448_import_raw(zeros, sizeof(zeros), PK_PUBLIC, &zero_pub));

   len = sizeof(shared);
   SHOULD_FAIL_WITH(x448_shared_secret(&alice, &zero_pub, shared, &len), CRYPT_INVALID_PACKET);

   return CRYPT_OK;
}

int x448_test(void)
{
   DO(s_x448_rfc7748_scalarmult_test());
   DO(s_x448_rfc7748_iter_test());
   DO(s_x448_keygen_dh_test());
   DO(s_x448_wycheproof_special_test());
   DO(s_x448_zero_shared_secret_test());
   return CRYPT_OK;
}

static int s_x448_short_key_test(void)
{
   /* PrivateKeyInfo and SubjectPublicKeyInfo with a 1 byte key */
   const unsigned char p8[] = { 0x30, 0x0f, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f,
                                0x04, 0x03, 0x04, 0x01, 0x01 };
   const unsigned char spki[] = { 0x30, 0x0b, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x03, 0x02, 0x00, 0x01 };
   unsigned char buf[57] = { 0 };
   curve448_key key;

   SHOULD_FAIL_WITH(x448_import_pkcs8(p8, sizeof(p8), NULL, &key), CRYPT_PK_INVALID_SIZE);
   SHOULD_FAIL_WITH(x448_import(spki, sizeof(spki), &key), CRYPT_PK_INVALID_SIZE);
   SHOULD_FAIL_WITH(x448_import_raw(buf, 55, PK_PUBLIC, &key), CRYPT_PK_INVALID_SIZE);
   SHOULD_FAIL_WITH(x448_import_raw(buf, 57, PK_PRIVATE, &key), CRYPT_PK_INVALID_SIZE);
   return CRYPT_OK;
}

int x448_mpi_test(void)
{
   if (ltc_mp.name == NULL) return CRYPT_NOP;
   DO(s_x448_short_key_test());
   DO(s_x448_compat_test());
   return CRYPT_OK;
}

#else
LTC_NOP_TEST(x448_test)
LTC_NOP_TEST(x448_mpi_test)
#endif
