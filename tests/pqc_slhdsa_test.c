/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_test.h"

#ifdef LTC_SLHDSA

/* OpenSSL 4.0.0 test vectors from test/slh_dsa.inc */
static const char slh_dsa_sha2_128s_0_keygen_priv_hex[] =
   "aa9cc7dca491fc86bcb15a709a15e9b3905c800b6e2fb9b54b6b050ee5e4de9afa5464d1c661fed38b2a51ca3eae71bacae3d1865215e3d3850e8c1b8292bf42";

static const char slh_dsa_sha2_128f_0_keygen_priv_hex[] =
   "e2bdaa37c8cffe5e8d5676c23267890c31441758f573285881cdc82ab911dd8472dc8d26df6ef708f4c41af9fd04b65a8927927229891d47a60d67ecef3d2c17";

static const char slh_dsa_sha2_192s_0_keygen_priv_hex[] =
   "442e446e73330afb98704656328f4dd7334f8a9ab4d92cbe790f91c2e92a81afee0a7ec45a3d609346276f5a328755a17dd41608f59e492668d81d03441394fe"
   "7a8e7e58705d7632ba8bc66d04c99ee5c721e4ff4bbe7815ccf923e81e10c475";

static const char slh_dsa_sha2_192f_0_keygen_priv_hex[] =
   "942dd588b0e0636060b1023baf1df36002b9d3c7256904f948596f0f2f17505585f022423433b3a3ef50977b98b01e8e3e1d7dcf880c2ea3c8872122a996d5d6"
   "233bdfbd57fa641fad3c81bbe6778b1f788195131b3fca91854ff3b075bf0009";

static const char slh_dsa_sha2_256s_0_keygen_priv_hex[] =
   "ae6ca8664ec0b9179d4e33c4defe01fcd589f60ba4502fe7416f2acd96e139f13fda2069147f44eabd5bbf29c74a20cb0f0cc2a12bab5834b773530af504900a"
   "134d5ed3c60b46344a84a45d4683b1ac55fb22886ba9478ea9ca93f27b9aa2c27c5c9908f086e57956f85de84b438ef1f082cd176dff3c5b8be710bc8699a143";

static const char slh_dsa_sha2_256f_0_keygen_priv_hex[] =
   "37d1806dd090353064a982276aebd20e7318f36b17ec5209d4006651760ca043896630d51c45a8f7c1da31192f41204deb71bbc4fb47700a91ec47bb4acf3a38"
   "dabbd00112520e60061da23f4c83a5c475a0ad3ab75f59e5c7b8ce2430deb480c07849dd9f8d993dce5685d0840134bd11592055f74cde3aa9e7d25b33c31067";

static const char slh_dsa_shake_128s_0_keygen_priv_hex[] =
   "ecd0a05696c2ec6bfe85b8b1b2022486bfd8732b1a42cea236e9822aa9e724e637d664792198176c12e8121ccf69e684fcf6ffe2a04243dc3e8ed3ee6e44cdef";

static const char slh_dsa_shake_128f_0_keygen_priv_hex[] =
   "bbc74306f75dc2daf7372b3c9841a4d6852c17b459f1692b8e9a1a0dace5ba26380c99304a0ddd32f344b95144e1fdef60bbc2340e08770fb41a80a76cb08e34";

static const char slh_dsa_shake_192s_0_keygen_priv_hex[] =
   "2d5748b1acda8299e2e905545d2e66dfcec02461bc3673dd9d830416b1b82a665dd435a3f3a8e2124df59a0e2bc2ec73633ff65c724ae17045c094617549081c"
   "940f2ef4d4a10e7559c7503fe1e96fb67b0e32acdcf712fbef610f8d21daac86";

static const char slh_dsa_shake_192f_0_keygen_priv_hex[] =
   "3b7889d254f5ad87882dacbf3c58495667401601ec4739797e935cbc27f3d7cd627b611cbef7546c7f27751e18155cc4266b6fb56bd0d922e0482700a4280cc1"
   "f07052804a8f46fded3954ba0a9da45d0d18867437777f60211bb9cd03a60d4b";

static const char slh_dsa_shake_256s_0_keygen_priv_hex[] =
   "a653918fa557b5250d11e96a74f5d8c62b5ff67152acf227aaf4bf5211aa600e961b4e679ceb9d4e24df86ed22f405d8ede5623672f4737fc2fb65f8bf3b556c"
   "315a5e795b701676e6b8309c89cc6ad0c3d69ff4f7f432dc61329fbb1be6069f0887b1a8f1b3a8b9770a0871630e46dd0479c5bd123e8eeb6be70f2999c466a1";

static const char slh_dsa_shake_256f_0_keygen_priv_hex[] =
   "d50f77713cf59193fe5f10b8aaf1876b0d3e7e4181ed3fae346876269801758436c22b81940403157446d44f04c09fd28df72c6d4021b271544055783081b7c0"
   "46d2ac50751a0c71ec850bb7d16a679a66901eee05389d4615940efd89c0182fdebcfbf3527cc768c5ec6cb5b6cc10a674390745d8612d0920187df658d3b7ef";

#define SPX_TEST_N_MAX 32 /* largest SLH-DSA n, the size of opt_rand */

static int s_decode_hex(const char *hex, unsigned char *buf, unsigned long *len)
{
   return base16_decode(hex, XSTRLEN(hex), buf, len);
}

static int s_slhdsa_sign_verify(int alg)
{
   slhdsa_key key, pubkey, imported_priv, imported_pub;
   const unsigned char msg[] = "test message for SLH-DSA";
   unsigned char *sig, *pk_buf, *sk_buf, *std_buf, *cmp_buf;
   unsigned long siglen, sig_sz, pklen, pk_sz, sklen, sk_sz, stdlen, std_sz, cmplen;
   int stat, prng_idx;

   prng_idx = find_prng("yarrow");

   DO(slhdsa_get_sizes(alg, &pk_sz, &sk_sz, &sig_sz, NULL, NULL));

   sig = XMALLOC(sig_sz);
   pk_buf = XMALLOC(pk_sz);
   sk_buf = XMALLOC(sk_sz);
   std_sz = sk_sz + 128uL;
   std_buf = XMALLOC(std_sz);
   cmp_buf = XMALLOC(sk_sz);
   ENSURE(sig != NULL && pk_buf != NULL && sk_buf != NULL && std_buf != NULL && cmp_buf != NULL);
   XMEMSET(&key, 0, sizeof(key));
   XMEMSET(&pubkey, 0, sizeof(pubkey));
   XMEMSET(&imported_priv, 0, sizeof(imported_priv));
   XMEMSET(&imported_pub, 0, sizeof(imported_pub));

   /* keygen */
   DO(slhdsa_make_key(&yarrow_prng, prng_idx, alg, &key));
   ENSURE(key.type == PK_PRIVATE);

   /* export/import private key in PKCS#8 format */
   stdlen = std_sz;
   DO(slhdsa_export(std_buf, &stdlen, PK_PRIVATE | PK_STD, &key));
   DO(slhdsa_import_pkcs8(std_buf, stdlen, NULL, &imported_priv));

   /* sign */
   siglen = sig_sz;
   DO(slhdsa_sign(msg, sizeof(msg), sig, &siglen, NULL, 0,
                  &yarrow_prng, prng_idx, &key));
   ENSURE(siglen == sig_sz);

   sklen = sk_sz;
   DO(slhdsa_export_raw(sk_buf, &sklen, PK_PRIVATE, &key));
   cmplen = sk_sz;
   DO(slhdsa_export_raw(cmp_buf, &cmplen, PK_PRIVATE, &imported_priv));
   COMPARE_TESTVECTOR(cmp_buf, cmplen, sk_buf, sklen, "SLH-DSA private std round-trip", alg);

   /* export/import public key */
   pklen = pk_sz;
   DO(slhdsa_export_raw(pk_buf, &pklen, PK_PUBLIC, &key));
   DO(slhdsa_import_raw(pk_buf, pklen, PK_PUBLIC, alg, &pubkey));

   cmplen = pk_sz;
   DO(slhdsa_export_raw(cmp_buf, &cmplen, PK_PUBLIC, &imported_priv));
   COMPARE_TESTVECTOR(cmp_buf, cmplen, pk_buf, pklen, "SLH-DSA public from imported private", alg);

   /* export/import public key in SubjectPublicKeyInfo format */
   stdlen = std_sz;
   DO(slhdsa_export(std_buf, &stdlen, PK_PUBLIC | PK_STD, &key));
   DO(slhdsa_import(std_buf, stdlen, &imported_pub));
   cmplen = pk_sz;
   DO(slhdsa_export_raw(cmp_buf, &cmplen, PK_PUBLIC, &imported_pub));
   COMPARE_TESTVECTOR(cmp_buf, cmplen, pk_buf, pklen, "SLH-DSA public std round-trip", alg);

   /* sign/verify with exported/imported std keys */
   siglen = sig_sz;
   DO(slhdsa_sign(msg, sizeof(msg), sig, &siglen, NULL, 0,
                  &yarrow_prng, prng_idx, &imported_priv));
   stat = 0;
   DO(slhdsa_verify(sig, siglen, msg, sizeof(msg), NULL, 0, &stat, &imported_pub));
   ENSURE(stat == 1);

   /* verify */
   stat = 0;
   DO(slhdsa_verify(sig, siglen, msg, sizeof(msg), NULL, 0, &stat, &pubkey));
   ENSURE(stat == 1);

   /* corrupted sig must fail */
   sig[0] ^= 1;
   stat = 1;
   DO(slhdsa_verify(sig, siglen, msg, sizeof(msg), NULL, 0, &stat, &pubkey));
   ENSURE(stat == 0);

   /* export/import private key round-trip */
   sklen = sk_sz;
   DO(slhdsa_export_raw(sk_buf, &sklen, PK_PRIVATE, &key));
   slhdsa_free(&key);
   DO(slhdsa_import_raw(sk_buf, sklen, PK_PRIVATE, alg, &key));

   /* sign again after reimport */
   sig[0] ^= 1;
   siglen = sig_sz;
   DO(slhdsa_sign(msg, sizeof(msg), sig, &siglen, NULL, 0,
                  &yarrow_prng, prng_idx, &key));
   stat = 0;
   DO(slhdsa_verify(sig, siglen, msg, sizeof(msg), NULL, 0, &stat, &pubkey));
   ENSURE(stat == 1);

   slhdsa_free(&key);
   slhdsa_free(&pubkey);
   slhdsa_free(&imported_priv);
   slhdsa_free(&imported_pub);
   XFREE(sig);
   XFREE(pk_buf);
   XFREE(sk_buf);
   XFREE(std_buf);
   XFREE(cmp_buf);
   return CRYPT_OK;
}

static int s_slhdsa_sizes_test(void)
{
   unsigned long pk, sk, sig, opt, seed;

   /* SHA-2 variants */
   DO(slhdsa_get_sizes(LTC_SLHDSA_SHA2_128S, &pk, &sk, &sig, &opt, &seed));
   ENSURE(pk == 32 && sk == 64 && sig == 7856 && opt == 16 && seed == 48);
   DO(slhdsa_get_sizes(LTC_SLHDSA_SHA2_128F, &pk, &sk, &sig, &opt, &seed));
   ENSURE(pk == 32 && sk == 64 && sig == 17088 && opt == 16 && seed == 48);
   DO(slhdsa_get_sizes(LTC_SLHDSA_SHA2_192S, &pk, &sk, &sig, &opt, &seed));
   ENSURE(pk == 48 && sk == 96 && sig == 16224 && opt == 24 && seed == 72);
   DO(slhdsa_get_sizes(LTC_SLHDSA_SHA2_192F, &pk, &sk, &sig, &opt, &seed));
   ENSURE(pk == 48 && sk == 96 && sig == 35664 && opt == 24 && seed == 72);
   DO(slhdsa_get_sizes(LTC_SLHDSA_SHA2_256S, &pk, &sk, &sig, &opt, &seed));
   ENSURE(pk == 64 && sk == 128 && sig == 29792 && opt == 32 && seed == 96);
   DO(slhdsa_get_sizes(LTC_SLHDSA_SHA2_256F, &pk, &sk, &sig, &opt, &seed));
   ENSURE(pk == 64 && sk == 128 && sig == 49856 && opt == 32 && seed == 96);

   /* SHAKE variants */
   DO(slhdsa_get_sizes(LTC_SLHDSA_SHAKE_128S, &pk, &sk, &sig, &opt, &seed));
   ENSURE(pk == 32 && sk == 64 && sig == 7856 && opt == 16 && seed == 48);
   DO(slhdsa_get_sizes(LTC_SLHDSA_SHAKE_128F, &pk, &sk, &sig, &opt, &seed));
   ENSURE(pk == 32 && sk == 64 && sig == 17088 && opt == 16 && seed == 48);
   DO(slhdsa_get_sizes(LTC_SLHDSA_SHAKE_192S, &pk, &sk, &sig, &opt, &seed));
   ENSURE(pk == 48 && sk == 96 && sig == 16224 && opt == 24 && seed == 72);
   DO(slhdsa_get_sizes(LTC_SLHDSA_SHAKE_192F, &pk, &sk, &sig, &opt, &seed));
   ENSURE(pk == 48 && sk == 96 && sig == 35664 && opt == 24 && seed == 72);
   DO(slhdsa_get_sizes(LTC_SLHDSA_SHAKE_256S, &pk, &sk, &sig, &opt, &seed));
   ENSURE(pk == 64 && sk == 128 && sig == 29792 && opt == 32 && seed == 96);
   DO(slhdsa_get_sizes(LTC_SLHDSA_SHAKE_256F, &pk, &sk, &sig, &opt, &seed));
   ENSURE(pk == 64 && sk == 128 && sig == 49856 && opt == 32 && seed == 96);

   SHOULD_FAIL(slhdsa_get_sizes(99, &pk, &sk, &sig, &opt, &seed));

   return CRYPT_OK;
}

static int s_slhdsa_openssl_keygen_test(void)
{
   static const struct {
      int alg;
      const char *priv_hex;
   } vectors[] = {
      { LTC_SLHDSA_SHA2_128S,  slh_dsa_sha2_128s_0_keygen_priv_hex  },
      { LTC_SLHDSA_SHA2_128F,  slh_dsa_sha2_128f_0_keygen_priv_hex  },
      { LTC_SLHDSA_SHA2_192S,  slh_dsa_sha2_192s_0_keygen_priv_hex  },
      { LTC_SLHDSA_SHA2_192F,  slh_dsa_sha2_192f_0_keygen_priv_hex  },
      { LTC_SLHDSA_SHA2_256S,  slh_dsa_sha2_256s_0_keygen_priv_hex  },
      { LTC_SLHDSA_SHA2_256F,  slh_dsa_sha2_256f_0_keygen_priv_hex  },
      { LTC_SLHDSA_SHAKE_128S, slh_dsa_shake_128s_0_keygen_priv_hex },
      { LTC_SLHDSA_SHAKE_128F, slh_dsa_shake_128f_0_keygen_priv_hex },
      { LTC_SLHDSA_SHAKE_192S, slh_dsa_shake_192s_0_keygen_priv_hex },
      { LTC_SLHDSA_SHAKE_192F, slh_dsa_shake_192f_0_keygen_priv_hex },
      { LTC_SLHDSA_SHAKE_256S, slh_dsa_shake_256s_0_keygen_priv_hex },
      { LTC_SLHDSA_SHAKE_256F, slh_dsa_shake_256f_0_keygen_priv_hex }
   };
   unsigned char sk[128], pk[64], expected[128];
   unsigned long sklen, pklen, explen;
   unsigned long n;

   for (n = 0; n < sizeof(vectors) / sizeof(vectors[0]); n++) {
      slhdsa_key key;
      XMEMSET(&key, 0, sizeof(key));

      explen = sizeof(expected);
      DO(s_decode_hex(vectors[n].priv_hex, expected, &explen));

      DO(slhdsa_import_raw(expected, explen, PK_PRIVATE, vectors[n].alg, &key));

      sklen = sizeof(sk);
      DO(slhdsa_export_raw(sk, &sklen, PK_PRIVATE, &key));
      COMPARE_TESTVECTOR(sk, sklen, expected, explen, "SLH-DSA OpenSSL private key", vectors[n].alg);

      pklen = sizeof(pk);
      DO(slhdsa_export_raw(pk, &pklen, PK_PUBLIC, &key));
      COMPARE_TESTVECTOR(pk, pklen, expected + explen / 2, explen / 2, "SLH-DSA OpenSSL public key", vectors[n].alg);

      slhdsa_free(&key);
   }

   return CRYPT_OK;
}

#if defined(LTC_TEST_READDIR) && defined(LTC_BASE64)
/* Verify the self-signature of the OpenSSL generated certificates in tests/pem. The sign/verify round-trips below pass
   for any self-consistent scheme, these signatures come from another implementation and pin the module to FIPS 205. */
static int s_slhdsa_x509_selfsig(const void *in, unsigned long inlen, void *ctx)
{
   slhdsa_key key;
   const unsigned char *tbs, *sig;
   unsigned char *der;
   unsigned long derlen = inlen, tbslen, siglen;
   int stat, err;

   der = XMALLOC(inlen);
   if (der == NULL) return CRYPT_MEM;

   err = test_pem_to_der(in, inlen, "CERTIFICATE", der, &derlen);
   if (err != CRYPT_OK || slhdsa_import_x509(der, derlen, &key) != CRYPT_OK) {
      /* not a certificate, or not an SLH-DSA one */
      XFREE(der);
      return CRYPT_NOP;
   }

#ifdef LTC_PEM
   /* the generic PEM path has to recognize the certificate as well */
   {
      ltc_pka_key pka;
      XMEMSET(&pka, 0, sizeof(pka));
      ENSURE(pem_decode(in, inlen, &pka, NULL) == CRYPT_OK);
      ENSURE(pka.id == LTC_PKA_SLHDSA);
      pka_key_free(&pka);
   }
#endif

   DO(test_x509_split(der, derlen, &tbs, &tbslen, &sig, &siglen));

   stat = 0;
   DO(slhdsa_verify(sig, siglen, tbs, tbslen, NULL, 0, &stat, &key));
   ENSURE(stat == 1);

   /* the same signature must not verify over modified data or with a context string */
   stat = 1;
   DO(slhdsa_verify(sig, siglen, tbs, tbslen, (const unsigned char *)"x", 1, &stat, &key));
   ENSURE(stat == 0);

   der[(tbs - der) + tbslen / 2] ^= 0x01;
   stat = 1;
   DO(slhdsa_verify(sig, siglen, tbs, tbslen, NULL, 0, &stat, &key));
   ENSURE(stat == 0);

   (*((int *)ctx))++;
   slhdsa_free(&key);
   XFREE(der);
   return CRYPT_OK;
}

static int s_slhdsa_x509_test(void)
{
   int count = 0;
   DO(test_process_dir("tests/pem", &count, s_slhdsa_x509_selfsig, NULL, NULL, "pqc_slhdsa_x509"));
   /* one certificate per parameter set, SHA-2 and SHAKE at all three security levels */
   ENSURE(count == 12);
   return CRYPT_OK;
}
#endif

#if ARGTYPE == 4
/* ctx may only be NULL when ctxlen is 0, see FIPS 205 10.2 for the M' encoding */
static int s_slhdsa_ctx_argchk_test(void)
{
   slhdsa_key key;
   unsigned char seed[96], optrand[32], sig[20000];
   unsigned long pks, sks, sigs, orr, ks, siglen, i;
   int stat;

   DO(slhdsa_get_sizes(LTC_SLHDSA_SHAKE_128F, &pks, &sks, &sigs, &orr, &ks));
   for (i = 0; i < ks; i++) seed[i] = (unsigned char)i;
   for (i = 0; i < orr; i++) optrand[i] = (unsigned char)i;
   DO(slhdsa_make_key_from_seed(LTC_SLHDSA_SHAKE_128F, seed, ks, &key));

   siglen = sizeof(sig);
   SHOULD_FAIL_WITH(slhdsa_sign_ex((const unsigned char *)"m", 1, sig, &siglen, NULL, 4,
                                   optrand, orr, &key), CRYPT_INVALID_ARG);
   siglen = sizeof(sig);
   DO(slhdsa_sign_ex((const unsigned char *)"m", 1, sig, &siglen, NULL, 0, optrand, orr, &key));
   SHOULD_FAIL_WITH(slhdsa_verify(sig, siglen, (const unsigned char *)"m", 1, NULL, 4, &stat, &key),
                    CRYPT_INVALID_ARG);

   slhdsa_free(&key);
   return CRYPT_OK;
}
#endif


/* FIPS 205 10.2 - M' is 0x00 || ctxlen || ctx || M, hashed in two parts instead of being copied. The signature digests below were
   produced by the implementation that built M' in one contiguous buffer and were checked to be byte-identical, they pin the framing
   for a non-empty context and for messages far larger than the prefix. Regenerate them only together with a KAT that says why. */
static int s_slhdsa_message_framing_test(void)
{
   static const struct {
      unsigned long msglen;
      int with_ctx;
      const char *sig_sha256;
   } vectors[] = {
      {      0, 1, "74a7567060ceac545f608e8424eddb4b347b9ee4e7eb2f20e0e9a251dea971af" },
      {      1, 0, "761e43661b61a67a0ae406123694ef9d399b94501d918044d5da658b9aaa47dd" },
      { 100000, 1, "3d3fa5955d45c3e0896ae42d7f362a67f40cb23d007231d609b0b18cb1b404c3" },
   };
   static const unsigned char ctx[] = "libtomcrypt-ctx";
   slhdsa_key key;
   unsigned char seed[96], optrand[SPX_TEST_N_MAX], md[32], expected[32];
   unsigned char *msg, *sig;
   unsigned long i, n, siglen, sig_sz, orr, ks, mdlen, explen;
   int stat, hash_idx;

   hash_idx = find_hash("sha256");
   ENSURE(hash_idx != -1);

   DO(slhdsa_get_sizes(LTC_SLHDSA_SHAKE_128F, NULL, NULL, &sig_sz, &orr, &ks));
   ENSURE(ks <= sizeof(seed) && orr <= sizeof(optrand));

   msg = XMALLOC(100000);
   sig = XMALLOC(sig_sz);
   ENSURE(msg != NULL && sig != NULL);
   for (i = 0; i < 100000; i++) msg[i] = (unsigned char)(i * 7 + (i >> 5));
   for (i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)(0xA0 + i);
   for (i = 0; i < sizeof(optrand); i++) optrand[i] = (unsigned char)(0x5A + i);

   DO(slhdsa_make_key_from_seed(LTC_SLHDSA_SHAKE_128F, seed, ks, &key));

   for (n = 0; n < LTC_ARRAY_SIZE(vectors); n++) {
      const unsigned char *c = vectors[n].with_ctx ? ctx : NULL;
      unsigned long clen = vectors[n].with_ctx ? sizeof(ctx) - 1 : 0;

      siglen = sig_sz;
      DO(slhdsa_sign_ex(vectors[n].msglen ? msg : NULL, vectors[n].msglen,
                        sig, &siglen, c, clen, optrand, orr, &key));
      mdlen = sizeof(md);
      DO(hash_memory(hash_idx, sig, siglen, md, &mdlen));
      explen = sizeof(expected);
      DO(s_decode_hex(vectors[n].sig_sha256, expected, &explen));
      COMPARE_TESTVECTOR(md, mdlen, expected, explen, "SLH-DSA M' framing", (int)n);

      stat = 0;
      DO(slhdsa_verify(sig, siglen, vectors[n].msglen ? msg : NULL, vectors[n].msglen,
                       c, clen, &stat, &key));
      ENSURE(stat == 1);

      /* the context is part of M', so verifying with the other context must fail */
      stat = 1;
      DO(slhdsa_verify(sig, siglen, vectors[n].msglen ? msg : NULL, vectors[n].msglen,
                       vectors[n].with_ctx ? NULL : ctx, vectors[n].with_ctx ? 0 : sizeof(ctx) - 1,
                       &stat, &key));
      ENSURE(stat == 0);
   }

   /* a single flipped byte deep inside the large message must break the signature */
   siglen = sig_sz;
   DO(slhdsa_sign_ex(msg, 100000, sig, &siglen, ctx, sizeof(ctx) - 1, optrand, orr, &key));
   msg[99999] ^= 0x01;
   stat = 1;
   DO(slhdsa_verify(sig, siglen, msg, 100000, ctx, sizeof(ctx) - 1, &stat, &key));
   ENSURE(stat == 0);
   msg[99999] ^= 0x01;

   /* ctx and the message are only kept apart by the ctxlen byte: ("AB","C") and ("A","BC")
      concatenate to the same octets, so a signature over one must not verify the other */
   siglen = sig_sz;
   DO(slhdsa_sign_ex((const unsigned char *)"C", 1, sig, &siglen,
                     (const unsigned char *)"AB", 2, optrand, orr, &key));
   stat = 1;
   DO(slhdsa_verify(sig, siglen, (const unsigned char *)"BC", 2,
                    (const unsigned char *)"A", 1, &stat, &key));
   ENSURE(stat == 0);

   slhdsa_free(&key);
   XFREE(sig);
   XFREE(msg);
   return CRYPT_OK;
}


/* slhdsa_check_key() has to detect a key struct that a caller changed */
static int s_slhdsa_check_key_test(void)
{
   slhdsa_key key, pub;
   unsigned char pk[64];
   unsigned long pklen, n;
   int prng_idx = find_prng("yarrow");

   XMEMSET(&key, 0, sizeof(key));
   XMEMSET(&pub, 0, sizeof(pub));

   DO(slhdsa_make_key(&yarrow_prng, prng_idx, LTC_SLHDSA_SHAKE_128F, &key));
   DO(slhdsa_check_key(&key));
   n = key.pklen / 2;

   pklen = sizeof(pk);
   DO(slhdsa_export_raw(pk, &pklen, PK_PUBLIC, &key));
   DO(slhdsa_import_raw(pk, pklen, PK_PUBLIC, LTC_SLHDSA_SHAKE_128F, &pub));
   DO(slhdsa_check_key(&pub));

   key.sklen -= 1;
   SHOULD_FAIL_WITH(slhdsa_check_key(&key), CRYPT_PK_INVALID_TYPE);
   key.sklen += 1;
   key.type = PK_PUBLIC;
   SHOULD_FAIL_WITH(slhdsa_check_key(&key), CRYPT_PK_INVALID_TYPE);
   key.type = PK_PRIVATE;

   /* PK.seed || PK.root is stored twice, in sk and in pk */
   key.pk[0] ^= 1;
   SHOULD_FAIL_WITH(slhdsa_check_key(&key), CRYPT_INVALID_PACKET);
   key.pk[0] ^= 1;

   /* every WOTS+ key comes from SK.seed, so PK.root changes as well */
   key.sk[0] ^= 1;
   SHOULD_FAIL_WITH(slhdsa_check_key(&key), CRYPT_INVALID_PACKET);
   key.sk[0] ^= 1;

   /* PK.root as stored in the private key */
   key.sk[3 * n] ^= 1;
   key.pk[n] ^= 1;
   SHOULD_FAIL_WITH(slhdsa_check_key(&key), CRYPT_INVALID_PACKET);
   key.sk[3 * n] ^= 1;
   key.pk[n] ^= 1;
   DO(slhdsa_check_key(&key));

   slhdsa_free(&pub);
   slhdsa_free(&key);
   return CRYPT_OK;
}


static void s_slhdsa_try_import(const unsigned char *in, unsigned long inlen, int kind, int alg)
{
   slhdsa_key key;
   int err;

   XMEMSET(&key, 0, sizeof(key));
   switch (kind) {
      case 0:  err = slhdsa_import_raw(in, inlen, PK_PUBLIC, alg, &key); break;
      case 1:  err = slhdsa_import_raw(in, inlen, PK_PRIVATE, alg, &key); break;
      case 2:  err = slhdsa_import(in, inlen, &key); break;
      default: err = slhdsa_import_pkcs8(in, inlen, NULL, &key); break;
   }
   /* anything an importer accepts has to pass the key check as well */
   if (err == CRYPT_OK) DO(slhdsa_check_key(&key));
   slhdsa_free(&key);
}

/* A deterministic replacement for fuzzing: every encoding a key can be read from is
   truncated, extended and bit flipped. Run it under ASan/UBSan to get the most out of it. */
static int s_slhdsa_import_mutation_test(int alg)
{
   slhdsa_key key;
   unsigned char enc[4][512], buf[600];
   static const int kinds[4] = { 0, 1, 2, 3 };
   unsigned long lens[4], n, pos, step;
   int prng_idx = find_prng("yarrow");

   XMEMSET(&key, 0, sizeof(key));
   DO(slhdsa_make_key(&yarrow_prng, prng_idx, alg, &key));

   lens[0] = sizeof(enc[0]);
   DO(slhdsa_export_raw(enc[0], &lens[0], PK_PUBLIC, &key));
   lens[1] = sizeof(enc[1]);
   DO(slhdsa_export_raw(enc[1], &lens[1], PK_PRIVATE, &key));
   lens[2] = sizeof(enc[2]);
   DO(slhdsa_export(enc[2], &lens[2], PK_PUBLIC | PK_STD, &key));
   lens[3] = sizeof(enc[3]);
   DO(slhdsa_export(enc[3], &lens[3], PK_PRIVATE | PK_STD, &key));

   for (n = 0; n < LTC_ARRAY_SIZE(kinds); n++) {
      XMEMCPY(buf, enc[n], lens[n]);
      s_slhdsa_try_import(buf, lens[n], kinds[n], alg);

      /* truncation and extension */
      s_slhdsa_try_import(buf, 0, kinds[n], alg);
      s_slhdsa_try_import(buf, 1, kinds[n], alg);
      s_slhdsa_try_import(buf, lens[n] / 2, kinds[n], alg);
      s_slhdsa_try_import(buf, lens[n] - 1, kinds[n], alg);
      buf[lens[n]] = 0x00;
      s_slhdsa_try_import(buf, lens[n] + 1, kinds[n], alg);

      /* one flipped byte at a time, spread over the whole encoding */
      step = lens[n] / 32 ? lens[n] / 32 : 1;
      for (pos = 0; pos < lens[n]; pos += step) {
         buf[pos] ^= 0x80;
         s_slhdsa_try_import(buf, lens[n], kinds[n], alg);
         buf[pos] ^= 0x80;
      }
   }

   slhdsa_free(&key);
   return CRYPT_OK;
}


#if defined(LTC_SHA256) && defined(LTC_SHA512) && !defined(LTC_PTHREAD)
/* The SHA-2 parameter sets use the sha256 and sha512 descriptors directly, so they have to
   keep working with no hash registered. Unregistering is not thread safe, hence the guard. */
static int s_slhdsa_no_registration_test(void)
{
   static const unsigned char msg[] = "hashes are resolved at compile time";
   slhdsa_key key;
   unsigned char seed[3 * SPX_TEST_N_MAX];
   unsigned char *sig;
   unsigned long siglen, sig_sz, orr, ks;
   int stat;

   XMEMSET(&key, 0, sizeof(key));
   XMEMSET(seed, 0x33, sizeof(seed));
   DO(slhdsa_get_sizes(LTC_SLHDSA_HASH_SHA2_192F_WITH_SHA512, NULL, NULL, &sig_sz, &orr, &ks));
   sig = XMALLOC(sig_sz);
   ENSURE(sig != NULL);

   DO(unregister_hash(&sha256_desc));
   DO(unregister_hash(&sha512_desc));

   /* the pre-hash, PRF_msg, thash and the Merkle root all run without a registered hash */
   DO(slhdsa_make_key_from_seed(LTC_SLHDSA_HASH_SHA2_192F_WITH_SHA512, seed, ks, &key));
   siglen = sig_sz;
   DO(slhdsa_sign_ex(msg, sizeof(msg), sig, &siglen, NULL, 0, seed, orr, &key));
   stat = 0;
   DO(slhdsa_verify(sig, siglen, msg, sizeof(msg), NULL, 0, &stat, &key));
   ENSURE(stat == 1);
   DO(slhdsa_check_key(&key));
   slhdsa_free(&key);
   XFREE(sig);

   ENSURE(register_hash(&sha256_desc) != -1);
   ENSURE(register_hash(&sha512_desc) != -1);
   return CRYPT_OK;
}
#endif

int pqc_slhdsa_test(void)
{
   if (ltc_mp.name == NULL) return CRYPT_NOP;

#if ARGTYPE == 4
   DO(s_slhdsa_ctx_argchk_test());
#endif
   DO(s_slhdsa_sizes_test());
   DO(s_slhdsa_openssl_keygen_test());
   DO(s_slhdsa_message_framing_test());
   DO(s_slhdsa_check_key_test());
   DO(s_slhdsa_import_mutation_test(LTC_SLHDSA_SHAKE_128F));
   DO(s_slhdsa_import_mutation_test(LTC_SLHDSA_SHA2_128F));
#if defined(LTC_SHA256) && defined(LTC_SHA512) && !defined(LTC_PTHREAD)
   DO(s_slhdsa_no_registration_test());
#endif
#if defined(LTC_TEST_READDIR) && defined(LTC_BASE64)
   DO(s_slhdsa_x509_test());
#endif
   /* All 6 fast variants (covers both SHA-2 and SHAKE at all security levels) */
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_SHA2_128F));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_SHA2_192F));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_SHA2_256F));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_SHAKE_128F));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_SHAKE_192F));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_SHAKE_256F));
   /* One small variant to verify S-parameter code paths */
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_SHAKE_128S));
   /* HashSLH-DSA fast variants cover SHA-256, SHA-512, SHAKE128, and SHAKE256 pre-hash paths */
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_HASH_SHA2_128F_WITH_SHA256));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_HASH_SHA2_192F_WITH_SHA512));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_HASH_SHA2_256F_WITH_SHA512));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_HASH_SHAKE_128F_WITH_SHAKE128));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_HASH_SHAKE_192F_WITH_SHAKE256));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_HASH_SHAKE_256F_WITH_SHAKE256));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_HASH_SHAKE_128S_WITH_SHAKE128));
#ifdef LTC_SLHDSA_TEST_SLOW
   /* Remaining small variants (very slow) */
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_SHA2_128S));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_SHA2_192S));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_SHA2_256S));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_SHAKE_192S));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_SHAKE_256S));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_HASH_SHA2_128S_WITH_SHA256));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_HASH_SHA2_192S_WITH_SHA512));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_HASH_SHA2_256S_WITH_SHA512));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_HASH_SHAKE_192S_WITH_SHAKE256));
   DO(s_slhdsa_sign_verify(LTC_SLHDSA_HASH_SHAKE_256S_WITH_SHAKE256));
#endif
   return CRYPT_OK;
}

#else

int pqc_slhdsa_test(void)
{
   return CRYPT_NOP;
}

#endif
