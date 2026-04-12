/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_test.h"

#ifdef LTC_MLKEM

/* OpenSSL 4.0.0 test vectors from test/evp_extra_test.c */
static const char ml_kem_seed_hex[] =
   "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f";

static const char ml_kem_512_pubkey_hex[] =
   "400865ed10b619aa5811139bc086825782b2b7124f757c83ae794444bc78a47896acf1262c81351077893bfc56f90449c2fa5f6e586dd37c0b9b581992638cb7"
   "e7bcbbb99afe4781d80a50e69463fbd988722c3635423e27466c71dcc674527ccd728968cbcdc00c5c9035bb0af2c9922c7881a41dd2875273925131230f6ca5"
   "9e9136b39f956c93b3b2d14c641b089e07d0a840c893ecd76bbf92c805456668d07c621491c5c054991a656f511619556eb97782e27a3c785124c70b0daba6c6"
   "24d18e0f9793f96ba9e1599b17b30dccc0b4f3766a07b23b257309cd76aba072c2b9c9744394c6ab9cb6c54a97b5c57861a58dc0a03519832ee32a07654a070c"
   "0c8c4e8648addc355f274fc6b92a087b3f9751923e44274f858c49caba72b65851b3adc48936955097cad9553f5a263f1844b52a020ff7ca89e881a01b95d957"
   "a3153c0a5e0a1ccd66b1821a2b8632546e24c7cbbc4cb08808cac37f7da6b16f8aced052cdb2564948f1ab0f768a0d3286ccc7c3749c63c781530fa1ae670542"
   "855004a645b522881ec1412bdae342085a9dd5f8126af96bbdb0c1af69a15562cb2a155a100309d1b641d08b2d4ed17bfbf0bc04265f9b10c108f850309504d7"
   "72811bba8e2be16249aa737d879fc7fb255ee7a6a0a753bd93741c61658ec074f6e002b019345769113cc013ff7494ba8378b11a172260aaa53421bde03a3558"
   "9d57e322fefa4100a4743926ab7d62258b87b31ccbb5e6b89cb10b271aa05d994bb5708b23ab327ecb93c0f3156869f0883da2064f795e0e2ab7d3c64d61d230"
   "3fc3a29e1619923ca801e59fd752ca6e7649d303c9d20788e1214651b06995eb260c929a1344a849b25ca0a01f1eb52913686bba619e23714464031a78439287"
   "fca78f4c0476223eea61b7f25a7ce42cca901b2aea129817894ba3470823854f3e5b28d86ba979e54671862d90470b1e7838972a81a48107d6ac0611406b21fb"
   "cce1db7702ea9dd6ba6e40527b9dc663f3c93bad056dc28511f66c3e0b928db8879d22c592685cc775a6cd574ac3bce3b27591c821929076358a2200b377365f"
   "7efb9e40c3bf0ff0432986ae4bc1a242ce9921aa9e22448819585dea308eb039";

static const char ml_kem_768_pubkey_hex[] =
   "a8e651a1e685f22478a8954f007bc7711b930772c78f092e82878e3e937f367967532913a8d53dfdf4bfb1f8846746596705cf345142b972a3f16325c40c2952"
   "a37b25897e5ef35fbaeb73a4acbeb6a0b89942ceb195531cfc0a07993954483e6cbc87c06aa74ff0cac5207e535b260aa98d1198c07da605c4d11020f6c9f7bb"
   "68bb3456c73a01b710bc99d17739a51716aa01660c8b628b2f5602ba65f07ea993336e896e83f2c5731bbf03460c5b6c8afecb748ee391e98934a2c57d4d069f"
   "50d88b30d6966f38c37bc649b82634ce7722645ccd625063364646d6d699db57b45eb67465e16de4d406a818b9eae1ca916a2594489708a43cea88b02a4c03d0"
   "9b44815c97101caf5048bbcb247ae2366cdc254ba22129f45b3b0eb399ca91a303402830ec01db7b2ca480cf350409b216094b7b0c3ae33ce10a9124e89651ab"
   "901ea253c8415bd7825f02bb229369af972028f22875ea55af16d3bc69f70c2ee8b75f28b47dd391f989ade314729c331fa04c1917b278c3eb602868512821ad"
   "c825c64577ce1e63b1d9644a612948a3483c7f1b9a258000e30196944a403627609c76c7ea6b5de01764d24379117b9ea29848dc555c454bceae1ba5cc72c74a"
   "b96b9c91b910d26b88b25639d4778ae26c7c6151a19c6cd7938454372465e4c5ec29245acb3db5379de3dabfa629a7c04a8353a8530c95acb732bb4bb81932bb"
   "2ca7a848cd366801444abe23c83b366a87d6a3cf360924c002bae90af65c48060b3752f2badf1ab2722072554a5059753594e6a702761fc97684c8c4a7540a6b"
   "07fbc9de87c974aa8809d928c7f4cbbf8045aea5bc667825fd05a521f1a4bf539210c7113bc37b3e58b0cbfc53c841cbb0371de2e511b989cb7c70c023366d78"
   "f9c37ef047f8720be1c759a8d96b93f65a94114ffaf60d9a81795e995c71152a4691a5a602a9e1f3599e37c768c7bc108994c0669f3adc957d46b4b6256968e2"
   "90d7892ea85464ee7a750f39c5e3152c2dfc56d8b0c924ba8a959a68096547f66423c838982a5794b9e1533771331a9a656c28828beb9126a60e95e8c5d90683"
   "2c7710705576b1fb9507269ddaf8c95ce9719b2ca8dd112be10bcc9f4a37bd1b1eeeb33ecda76ae9f69a5d4b2923a86957671d619335be1c4c2c77ce87c41f98"
   "a8cc466460fa300aaf5b301f0a1d09c88e65da4d8ee64f68c02189bbb3584baff716c85db654048a004333489393a07427cd3e217e6a345f6c2c2b13c27b3372"
   "71c0b27b2dbaa00d237600b5b594e8cf2dd625ea76cf0ed899122c9796b4b0187004258049a477cd11d68c49b9a0e7b00bce8cac7864cbb375140084744c9306"
   "2694ca795c4f40e7acc9c5a1884072d8c38dafb501ee4184dd5a819ec24ec1651261f962b17a7215aa4a748c15836c389137678204838d7195a85b4f98a1b574"
   "c4cd7909cd1f833effd1485543229d3748d9b5cd6c17b9b3b84aef8bce13e683733659c79542d615782a71cdeee792bab51bdc4bbfe8308e663144ede8491830"
   "ad98b4634f64aba8b9c042272653920f380c1a17ca87ced7aac41c82888793181a6f76e197b7b90ef90943bb3844912911d8551e5466c5767ab0bc61a1a3f736"
   "162ec098a900b12dd8fabbfb3fe8cb1dc4e8315f2af0d32f0017ae136e19f028";

static const char ml_kem_1024_pubkey_hex[] =
   "537911957c125148a87f41589cb222d0d19229e2cb55e1a044791e7ca61192a46460c3183d2bcd6de08a5e7651603acc349ca16cba18abb23a3e8c330d742159"
   "8a6278ec7ebfabca0ef488b2290554753499c0452e453815309955b8150fa1a1e393386dc12fdb27b38c6745f2944016ec457f39b18d604a07a1abe07bc84405"
   "0ffa8a06fa154a49d88fac775452d6a7c0e589bfb5c370c2c4b6201dda80c9ab2076ecc08b44522fda3326f033806dd2693f319739f40c4f42b24aca7098fb8f"
   "f5f9ac20292d02b56ac746801acccc84863dee32878497b69438bf991776286650482c8d9d9587bc6a55b85c4d7fa74d02656b421c9e23e03a48d4b74425c26e"
   "4a20dd9562a4da0793f3a352ccc0f18217d868c7f5002abe768b1fc73f05744e7cc28f10344062c10e08eccced3c1f7d392c01d979dd718d8398374665a16a98"
   "70585c39d5589a50e133389c9b9a276c024260d9fc7711c81b6337b57da3c376d0cd74e14c73727b276656b9d8a4eb71896ff589d4b893e7110f3bb948ece291"
   "dd86c0b7468a678c746980c12aa6b95e2b0cbe4331bb24a33a270153aa472c47312382ca365c5f35259d025746fc6595fe636c767510a69c1e8a176b7949958f"
   "2697399497a2fc7364a12c8198295239c826cb5082086077282ed628651fc04c639b438522a9de309b14b086d6e923c551623bd72a733cb0dabc54a9416a99e7"
   "2c9fda1cb3fb9ba06b8adb2422d68cadc553c98202a17656478ac044ef3456378abce9991e0141ba79094fa8f77a300805d2d32ffc62bf0ca4554c330c2bb704"
   "2db35102f68b1a0062583865381c74dd913af70b26cf0923d0c4cb971692222552a8f4b788b4afd1341a9df415cf203900f5ccf7f65988949a75580d04963985"
   "3100854b21f4018003502bb1ba95f556a5d67c7eb52410eba288a6d0635ca8a4f6d696d0a020c826938d34943c3808c79cc007768533216bc1b29da6c812eff3"
   "340baa8d2e65344f09bd47894f5a3a4118715b3c5020679327f9189f7e10856b238bb9b0ab4ca85abf4b21f5c76bccd71850b22e045928276a0f2e951db0707c"
   "6a116dc19113fa762dc5f20bd5d2ab5be71744dc9cbdb51ea757963aac56a90a0d8023bed1f5cae8a64da047279b353a096a835b0b2b023b6aa048989233079a"
   "eb467e522fa27a5822921e5c551b4f537536e46f3a6a97e72c3b063104e09a040598940d872f6d871f5ef9b4355073b54769e45454e6a0819599408621ab4413"
   "b35507b0df578ce2d511d52058d5749df38b29d6cc58870caf92f69a75161406e71c5ff92451a77522b8b2967a2d58a49a81661aa65ac09b08c9fe45abc3851f"
   "99c730c45003aca2bf0f8424a19b7408a537d541c16f5682bfe3a7faea564f1298611a7f5f60922ba19de73b1917f1853273555199a649318b50773345c99746"
   "0856972acb43fc81ab6321b1c33c2bb5098bd489d696a0f70679c1213873d08bdad42844927216047205633212310ee9a06cb10016c805503c341a36d87e5607"
   "2eabe23731e34af7e2328f85cdb370ccaf00515b64c9c54bc837578447aacfaed5969aa351e7da4efa7b115c4c51f4a699779850295ca72d781ad41bc680532b"
   "89e710e2189eb3c50817ba255c7474c95ca9110cc43b8ba8e682c7fb7b0fdc265c0483a65ca4514ee4b832aac5800c3b08e74f563951c1fbb210353efa1aa866"
   "856bc1e034733b0485dab1d020c6bf765ff60b3b801984a90c2fe970bf1de97004a6cf44b4984ab58258b4af71221cd17530a700c32959c9436344b5316f09cc"
   "ca7029a230d639dcb022d8ba79ba91cd6ab12ae1579c50c7bb10e30301a65cae3101d40c7ba927bb553148d1647024d4a06c8166d0b0b81269b7d5f4b34fb022"
   "f69152f514004a7c685368552343bb60360fbb9945edf446d345bdcaa7455c74ba0a551e184620fef97688773d50b6433ca7a7ac5cb6b7f671a15376e5a6747a"
   "623fa7bc6630373f5b1b512690a661377870a60a7a189683f9b0cf0466e1f750762631c4ab09f505c42dd28633569472735442851e321616d4009810777b6bd4"
   "6fa7224461a5cc27405dfbac0d39b002cab33433f2a86eb8ce91c134a6386f860a1994eb4b6875a46d195581d173854b53d2293df3e9a822756cd8f212b325ca"
   "29b4f9f8cfbadf2e41869abfbad10738ad04cc752bc20c394746850e0c4847db";

static int s_decode_hex(const char *hex, unsigned char *buf, unsigned long *len)
{
   return base16_decode(hex, XSTRLEN(hex), buf, len);
}

static int s_mlkem_keygen_encaps_decaps(int alg)
{
   mlkem_key key, pubkey, imported_priv, imported_pub;
   unsigned char ct[1600], ss1[32], ss2[32];
   unsigned char der_buf[4096], pk_buf[1600], sk_buf[3200], cmp_buf[3200];
   unsigned long ctlen, derlen, sslen, pklen, sklen, cmplen;
   int prng_idx;

   prng_idx = find_prng("yarrow");
   XMEMSET(&key, 0, sizeof(key));
   XMEMSET(&pubkey, 0, sizeof(pubkey));
   XMEMSET(&imported_priv, 0, sizeof(imported_priv));
   XMEMSET(&imported_pub, 0, sizeof(imported_pub));

   /* keygen */
   DO(mlkem_make_key(&yarrow_prng, prng_idx, alg, &key));
   ENSURE(key.type == PK_PRIVATE);

   /* export/import private key in PKCS#8 format */
   derlen = sizeof(der_buf);
   DO(mlkem_export(der_buf, &derlen, PK_PRIVATE | PK_STD, &key));
   DO(mlkem_import_pkcs8(der_buf, derlen, NULL, &imported_priv));

   sklen = sizeof(sk_buf);
   DO(mlkem_export_raw(sk_buf, &sklen, PK_PRIVATE, &key));
   cmplen = sizeof(cmp_buf);
   DO(mlkem_export_raw(cmp_buf, &cmplen, PK_PRIVATE, &imported_priv));
   COMPARE_TESTVECTOR(cmp_buf, cmplen, sk_buf, sklen, "ML-KEM private std round-trip", alg);

   /* export/import public key */
   pklen = sizeof(pk_buf);
   DO(mlkem_export_raw(pk_buf, &pklen, PK_PUBLIC, &key));
   DO(mlkem_import_raw(pk_buf, pklen, PK_PUBLIC, alg, &pubkey));
   ENSURE(pubkey.type == PK_PUBLIC);

   cmplen = sizeof(cmp_buf);
   DO(mlkem_export_raw(cmp_buf, &cmplen, PK_PUBLIC, &imported_priv));
   COMPARE_TESTVECTOR(cmp_buf, cmplen, pk_buf, pklen, "ML-KEM public from imported private", alg);

   /* export/import public key in SubjectPublicKeyInfo format */
   derlen = sizeof(der_buf);
   DO(mlkem_export(der_buf, &derlen, PK_PUBLIC | PK_STD, &key));
   DO(mlkem_import(der_buf, derlen, &imported_pub));
   cmplen = sizeof(cmp_buf);
   DO(mlkem_export_raw(cmp_buf, &cmplen, PK_PUBLIC, &imported_pub));
   COMPARE_TESTVECTOR(cmp_buf, cmplen, pk_buf, pklen, "ML-KEM public std round-trip", alg);

   /* encaps/decaps with exported/imported std keys */
   ctlen = sizeof(ct);
   sslen = sizeof(ss1);
   DO(mlkem_encaps(ct, &ctlen, ss1, &sslen, &yarrow_prng, prng_idx, &imported_pub));
   ENSURE(sslen == 32);
   sslen = sizeof(ss2);
   DO(mlkem_decaps(ss2, &sslen, ct, ctlen, &imported_priv));
   COMPARE_TESTVECTOR(ss1, 32, ss2, 32, "ML-KEM std export/import", alg);

   /* encaps with public key */
   ctlen = sizeof(ct);
   sslen = sizeof(ss1);
   DO(mlkem_encaps(ct, &ctlen, ss1, &sslen, &yarrow_prng, prng_idx, &pubkey));
   ENSURE(sslen == 32);

   /* decaps with private key */
   sslen = sizeof(ss2);
   DO(mlkem_decaps(ss2, &sslen, ct, ctlen, &key));
   ENSURE(sslen == 32);

   /* shared secrets must match */
   COMPARE_TESTVECTOR(ss1, 32, ss2, 32, "ML-KEM shared secret", alg);

   /* decaps with corrupted ciphertext must produce different ss (implicit rejection) */
   ct[0] ^= 1;
   sslen = sizeof(ss2);
   DO(mlkem_decaps(ss2, &sslen, ct, ctlen, &key));
   ENSURE(XMEMCMP(ss1, ss2, 32) != 0);

   /* export/import private key round-trip */
   sklen = sizeof(sk_buf);
   DO(mlkem_export_raw(sk_buf, &sklen, PK_PRIVATE, &key));
   mlkem_free(&key);
   DO(mlkem_import_raw(sk_buf, sklen, PK_PRIVATE, alg, &key));
   ENSURE(key.type == PK_PRIVATE);

   /* decaps still works after import (undo corruption) */
   ct[0] ^= 1;
   sslen = sizeof(ss2);
   DO(mlkem_decaps(ss2, &sslen, ct, ctlen, &key));
   COMPARE_TESTVECTOR(ss1, 32, ss2, 32, "ML-KEM decaps after reimport", alg);

   mlkem_free(&key);
   mlkem_free(&pubkey);
   mlkem_free(&imported_priv);
   mlkem_free(&imported_pub);
   return CRYPT_OK;
}

static int s_mlkem_sizes_test(void)
{
   static const struct { int alg; unsigned long pk, sk, ct; } sizes[] = {
      { LTC_MLKEM_512,   800, 1632,  768 },
      { LTC_MLKEM_768,  1184, 2400, 1088 },
      { LTC_MLKEM_1024, 1568, 3168, 1568 },
   };
   unsigned long pk, sk, ct, ss, seed, m, one;
   unsigned i;

   for (i = 0; i < LTC_ARRAY_SIZE(sizes); ++i) {
      DO(mlkem_get_sizes(sizes[i].alg, &pk, &sk, &ct, &ss, &seed, &m));
      ENSURE(pk == sizes[i].pk && sk == sizes[i].sk && ct == sizes[i].ct);
      ENSURE(ss == LTC_MLKEM_SHARED_SECRET_BYTES);
      ENSURE(seed == LTC_MLKEM_KEYGEN_SEED_BYTES);
      ENSURE(m == LTC_MLKEM_M_BYTES);

      /* the output pointers are optional, all of them at once and one on its own */
      DO(mlkem_get_sizes(sizes[i].alg, NULL, NULL, NULL, NULL, NULL, NULL));
      one = 0;
      DO(mlkem_get_sizes(sizes[i].alg, NULL, NULL, NULL, NULL, NULL, &one));
      ENSURE(one == m);
   }

   SHOULD_FAIL(mlkem_get_sizes(99, &pk, &sk, &ct, &ss, &seed, &m));

   return CRYPT_OK;
}

static int s_mlkem_from_seed_test(void)
{
   static const unsigned char seed[64] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
      0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
   };
   mlkem_key key1, key2;
   unsigned char pk1[1600], pk2[1600], sk1[3200], sk2[3200];
   unsigned long pk1len, pk2len, sk1len, sk2len;

   XMEMSET(&key1, 0, sizeof(key1));
   XMEMSET(&key2, 0, sizeof(key2));

   DO(mlkem_make_key_from_seed(LTC_MLKEM_512, seed, sizeof(seed), &key1));
   DO(mlkem_make_key_from_seed(LTC_MLKEM_512, seed, sizeof(seed), &key2));

   pk1len = sizeof(pk1);
   pk2len = sizeof(pk2);
   sk1len = sizeof(sk1);
   sk2len = sizeof(sk2);
   DO(mlkem_export_raw(pk1, &pk1len, PK_PUBLIC, &key1));
   DO(mlkem_export_raw(pk2, &pk2len, PK_PUBLIC, &key2));
   DO(mlkem_export_raw(sk1, &sk1len, PK_PRIVATE, &key1));
   DO(mlkem_export_raw(sk2, &sk2len, PK_PRIVATE, &key2));

   COMPARE_TESTVECTOR(pk1, pk1len, pk2, pk2len, "ML-KEM deterministic public key", 0);
   COMPARE_TESTVECTOR(sk1, sk1len, sk2, sk2len, "ML-KEM deterministic private key", 0);

   SHOULD_FAIL(mlkem_make_key_from_seed(LTC_MLKEM_512, seed, sizeof(seed) - 1, &key2));

   mlkem_free(&key1);
   mlkem_free(&key2);
   return CRYPT_OK;
}

static int s_mlkem_openssl_seed_test(void)
{
   static const struct {
      int alg;
      const char *pubkey_hex;
   } vectors[] = {
      { LTC_MLKEM_512,  ml_kem_512_pubkey_hex  },
      { LTC_MLKEM_768,  ml_kem_768_pubkey_hex  },
      { LTC_MLKEM_1024, ml_kem_1024_pubkey_hex }
   };
   unsigned char seed[64], pubkey[1600], expected[1600];
   unsigned long seedlen, pklen, explen;
   unsigned long n;

   seedlen = sizeof(seed);
   DO(s_decode_hex(ml_kem_seed_hex, seed, &seedlen));
   ENSURE(seedlen == sizeof(seed));

   for (n = 0; n < sizeof(vectors) / sizeof(vectors[0]); n++) {
      mlkem_key key;
      XMEMSET(&key, 0, sizeof(key));

      DO(mlkem_make_key_from_seed(vectors[n].alg, seed, seedlen, &key));

      pklen = sizeof(pubkey);
      DO(mlkem_export_raw(pubkey, &pklen, PK_PUBLIC, &key));

      explen = sizeof(expected);
      DO(s_decode_hex(vectors[n].pubkey_hex, expected, &explen));
      COMPARE_TESTVECTOR(pubkey, pklen, expected, explen, "ML-KEM OpenSSL seed public key", vectors[n].alg);

      mlkem_free(&key);
   }

   return CRYPT_OK;
}

static int s_mlkem_error_test(void)
{
   mlkem_key key;
   unsigned char ct[1600], ss[32];
   unsigned long ctlen, sslen;
   int prng_idx;

   prng_idx = find_prng("yarrow");

   /* invalid alg */
   SHOULD_FAIL(mlkem_make_key(&yarrow_prng, prng_idx, 99, &key));

   /* encaps with private key is OK (uses embedded pk) */
   DO(mlkem_make_key(&yarrow_prng, prng_idx, LTC_MLKEM_512, &key));
   ctlen = sizeof(ct);
   sslen = sizeof(ss);
   DO(mlkem_encaps(ct, &ctlen, ss, &sslen, &yarrow_prng, prng_idx, &key));

   /* decaps with public-only key must fail */
   {
      mlkem_key pubkey;
      unsigned char pk_buf[1600];
      unsigned long pklen = sizeof(pk_buf);
      DO(mlkem_export_raw(pk_buf, &pklen, PK_PUBLIC, &key));
      DO(mlkem_import_raw(pk_buf, pklen, PK_PUBLIC, LTC_MLKEM_512, &pubkey));
      sslen = sizeof(ss);
      SHOULD_FAIL(mlkem_decaps(ss, &sslen, ct, ctlen, &pubkey));
      mlkem_free(&pubkey);
   }

   /* wrong ciphertext length */
   sslen = sizeof(ss);
   SHOULD_FAIL(mlkem_decaps(ss, &sslen, ct, ctlen - 1, &key));

   /* buffer too small */
   ctlen = 1;
   sslen = sizeof(ss);
   SHOULD_FAIL_WITH(mlkem_encaps(ct, &ctlen, ss, &sslen, &yarrow_prng, prng_idx, &key),
                    CRYPT_BUFFER_OVERFLOW);

   mlkem_free(&key);
   return CRYPT_OK;
}

/* FIPS 203 7.2 modulus check - an encapsulation key holding a coefficient that is not
   reduced mod q has to be rejected, otherwise two encodings describe the same key. */
static int s_mlkem_modulus_check_test(void)
{
   static const int algs[] = { LTC_MLKEM_512, LTC_MLKEM_768, LTC_MLKEM_1024 };
   unsigned char pk[1600];
   unsigned long n, pklen;

   for (n = 0; n < LTC_ARRAY_SIZE(algs); n++) {
      mlkem_key key, imported;
      int prng_idx = find_prng("yarrow");

      DO(mlkem_make_key(&yarrow_prng, prng_idx, algs[n], &key));
      pklen = sizeof(pk);
      DO(mlkem_export_raw(pk, &pklen, PK_PUBLIC, &key));
      mlkem_free(&key);

      /* a generated key is always reduced */
      DO(mlkem_import_raw(pk, pklen, PK_PUBLIC, algs[n], &imported));
      mlkem_free(&imported);

      /* both coefficients of the first three bytes become 0xFFF, which is >= q */
      pk[0] = pk[1] = pk[2] = 0xFF;
      SHOULD_FAIL_WITH(mlkem_import_raw(pk, pklen, PK_PUBLIC, algs[n], &imported), CRYPT_INVALID_PACKET);
   }

   return CRYPT_OK;
}


static int s_mlkem_key_is(const mlkem_key *key,
                          const unsigned char *sk, unsigned long sklen,
                          const unsigned char *pk, unsigned long pklen,
                          const char *what, int alg)
{
   unsigned char buf[3200];
   unsigned long buflen;

   buflen = sizeof(buf);
   DO(mlkem_export_raw(buf, &buflen, PK_PRIVATE, key));
   COMPARE_TESTVECTOR(buf, buflen, sk, sklen, what, alg);
   buflen = sizeof(buf);
   DO(mlkem_export_raw(buf, &buflen, PK_PUBLIC, key));
   COMPARE_TESTVECTOR(buf, buflen, pk, pklen, what, alg);
   return CRYPT_OK;
}

/* RFC 9935 - the PKCS#8 private key is a CHOICE of seed, expandedKey or both. A seed cannot be
   computed back from the expanded key, so only a key that has one can write seed and both. */
static int s_mlkem_privkey_format_test(int alg)
{
   static const enum ltc_oid_id oids[] = { LTC_OID_MLKEM_512, LTC_OID_MLKEM_768, LTC_OID_MLKEM_1024 };
   mlkem_key key, other, imported;
   unsigned char seed[LTC_MLKEM_KEYGEN_SEED_BYTES], buf[LTC_MLKEM_KEYGEN_SEED_BYTES];
   unsigned char sk[3200], other_sk[3200], pk[1600];
   unsigned char der[4096], der2[4096];
   unsigned long seedlen, buflen, sklen, other_sklen, pklen, derlen, der2len;
   int prng_idx = find_prng("yarrow");

   XMEMSET(&key, 0, sizeof(key));
   XMEMSET(&other, 0, sizeof(other));
   XMEMSET(&imported, 0, sizeof(imported));

   DO(mlkem_make_key(&yarrow_prng, prng_idx, alg, &key));
   ENSURE(mlkem_has_seed(&key) == 1);
   ENSURE(mlkem_has_seed(NULL) == 0);

   seedlen = sizeof(seed);
   DO(mlkem_export_seed(seed, &seedlen, &key));
   ENSURE(seedlen == LTC_MLKEM_KEYGEN_SEED_BYTES);
   buflen = 1;
   SHOULD_FAIL_WITH(mlkem_export_seed(buf, &buflen, &key), CRYPT_BUFFER_OVERFLOW);
   ENSURE(buflen == LTC_MLKEM_KEYGEN_SEED_BYTES);

   sklen = sizeof(sk);
   DO(mlkem_export_raw(sk, &sklen, PK_PRIVATE, &key));
   pklen = sizeof(pk);
   DO(mlkem_export_raw(pk, &pklen, PK_PUBLIC, &key));

   /* expanding the exported seed gives back the same key and the same seed */
   DO(mlkem_make_key_from_seed(alg, seed, seedlen, &imported));
   ENSURE(mlkem_has_seed(&imported) == 1);
   buflen = sizeof(buf);
   DO(mlkem_export_seed(buf, &buflen, &imported));
   COMPARE_TESTVECTOR(buf, buflen, seed, seedlen, "ML-KEM seed round-trip", alg);
   DO(s_mlkem_key_is(&imported, sk, sklen, pk, pklen, "ML-KEM seed expansion", alg));
   mlkem_free(&imported);

   /* a raw expanded private key has no seed */
   DO(mlkem_import_raw(sk, sklen, PK_PRIVATE, alg, &imported));
   ENSURE(mlkem_has_seed(&imported) == 0);
   mlkem_free(&imported);

   /* a public key never has a seed */
   DO(mlkem_import_raw(pk, pklen, PK_PUBLIC, alg, &imported));
   ENSURE(mlkem_has_seed(&imported) == 0);
   buflen = sizeof(buf);
   SHOULD_FAIL_WITH(mlkem_export_seed(buf, &buflen, &imported), CRYPT_PK_NOT_PRIVATE);
   mlkem_free(&imported);

   /* the raw private export is the expanded key, whatever the key object holds */
   der2len = sizeof(der2);
   DO(mlkem_export(der2, &der2len, PK_PRIVATE, &key));
   COMPARE_TESTVECTOR(der2, der2len, sk, sklen, "ML-KEM raw private export", alg);
   der2len = sizeof(der2);
   DO(mlkem_export_ex(der2, &der2len, PK_PRIVATE, LTC_PQC_PRIVKEY_EXPANDED, &key));
   COMPARE_TESTVECTOR(der2, der2len, sk, sklen, "ML-KEM raw private export expanded", alg);
   der2len = sizeof(der2);
   SHOULD_FAIL_WITH(mlkem_export_ex(der2, &der2len, PK_PRIVATE, LTC_PQC_PRIVKEY_SEED, &key), CRYPT_INVALID_ARG);
   der2len = sizeof(der2);
   SHOULD_FAIL_WITH(mlkem_export_ex(der2, &der2len, PK_PRIVATE, LTC_PQC_PRIVKEY_BOTH, &key), CRYPT_INVALID_ARG);
   der2len = sizeof(der2);
   SHOULD_FAIL_WITH(mlkem_export_ex(der2, &der2len, PK_PUBLIC | PK_STD, LTC_PQC_PRIVKEY_SEED, &key), CRYPT_INVALID_ARG);

   /* seed: AUTO uses it whenever the key has one */
   derlen = sizeof(der);
   DO(mlkem_export_ex(der, &derlen, PK_PRIVATE | PK_STD, LTC_PQC_PRIVKEY_SEED, &key));
   der2len = sizeof(der2);
   DO(mlkem_export(der2, &der2len, PK_PRIVATE | PK_STD, &key));
   COMPARE_TESTVECTOR(der2, der2len, der, derlen, "ML-KEM PKCS#8 AUTO is seed", alg);
   DO(mlkem_import_pkcs8(der, derlen, NULL, &imported));
   ENSURE(mlkem_has_seed(&imported) == 1);
   DO(s_mlkem_key_is(&imported, sk, sklen, pk, pklen, "ML-KEM PKCS#8 seed", alg));
   mlkem_free(&imported);

   /* expandedKey: the imported key cannot get the seed back */
   derlen = sizeof(der);
   DO(mlkem_export_ex(der, &derlen, PK_PRIVATE | PK_STD, LTC_PQC_PRIVKEY_EXPANDED, &key));
   DO(mlkem_import_pkcs8(der, derlen, NULL, &imported));
   ENSURE(mlkem_has_seed(&imported) == 0);
   DO(s_mlkem_key_is(&imported, sk, sklen, pk, pklen, "ML-KEM PKCS#8 expandedKey", alg));
   buflen = sizeof(buf);
   SHOULD_FAIL_WITH(mlkem_export_seed(buf, &buflen, &imported), CRYPT_PK_INVALID_TYPE);
   der2len = sizeof(der2);
   SHOULD_FAIL_WITH(mlkem_export_ex(der2, &der2len, PK_PRIVATE | PK_STD, LTC_PQC_PRIVKEY_SEED, &imported), CRYPT_PK_INVALID_TYPE);
   der2len = sizeof(der2);
   SHOULD_FAIL_WITH(mlkem_export_ex(der2, &der2len, PK_PRIVATE | PK_STD, LTC_PQC_PRIVKEY_BOTH, &imported), CRYPT_PK_INVALID_TYPE);
   der2len = sizeof(der2);
   DO(mlkem_export(der2, &der2len, PK_PRIVATE | PK_STD, &imported));
   COMPARE_TESTVECTOR(der2, der2len, der, derlen, "ML-KEM PKCS#8 AUTO falls back", alg);
   mlkem_free(&imported);

   /* both */
   derlen = sizeof(der);
   DO(mlkem_export_ex(der, &derlen, PK_PRIVATE | PK_STD, LTC_PQC_PRIVKEY_BOTH, &key));
   DO(mlkem_import_pkcs8(der, derlen, NULL, &imported));
   ENSURE(mlkem_has_seed(&imported) == 1);
   DO(s_mlkem_key_is(&imported, sk, sklen, pk, pklen, "ML-KEM PKCS#8 both", alg));
   mlkem_free(&imported);

   /* a both encoding whose seed and expandedKey do not match must be rejected, in
      either direction, so build the two mismatched halves straight from a second key */
   DO(mlkem_make_key(&yarrow_prng, prng_idx, alg, &other));
   other_sklen = sizeof(other_sk);
   DO(mlkem_export_raw(other_sk, &other_sklen, PK_PRIVATE, &other));
   buflen = sizeof(buf);
   DO(mlkem_export_seed(buf, &buflen, &other));

   der2len = sizeof(der2);
   DO(pqc_export_privkey(der2, &der2len, oids[alg], seed, seedlen, other_sk, other_sklen));
   SHOULD_FAIL_WITH(mlkem_import_pkcs8(der2, der2len, NULL, &imported), CRYPT_INVALID_PACKET);

   der2len = sizeof(der2);
   DO(pqc_export_privkey(der2, &der2len, oids[alg], buf, buflen, sk, sklen));
   SHOULD_FAIL_WITH(mlkem_import_pkcs8(der2, der2len, NULL, &imported), CRYPT_INVALID_PACKET);

   mlkem_free(&other);

   mlkem_free(&key);
   return CRYPT_OK;
}


#if defined(LTC_TEST_READDIR) && defined(LTC_BASE64)
/* RFC 9935 interop - the OpenSSL keys in tests/pem use the both encoding, so encoding an imported key again has to give back the same file, byte for byte. */
static int s_mlkem_openssl_pkcs8(const void *in, unsigned long inlen, void *ctx)
{
   mlkem_key key, imported;
   unsigned char *der, *out;
   unsigned char sk[3200], pk[1600];
   unsigned long derlen = inlen, outlen, sklen, pklen;
   int err;

   der = XMALLOC(inlen);
   out = XMALLOC(inlen);
   if (der == NULL || out == NULL) {
      XFREE(out);
      XFREE(der);
      return CRYPT_MEM;
   }

   err = test_pem_to_der(in, inlen, "PRIVATE KEY", der, &derlen);
   if (err != CRYPT_OK || mlkem_import_pkcs8(der, derlen, NULL, &key) != CRYPT_OK) {
      /* not a private key, or not an ML-KEM one */
      XFREE(out);
      XFREE(der);
      return CRYPT_NOP;
   }

   ENSURE(mlkem_has_seed(&key) == 1);
   sklen = sizeof(sk);
   DO(mlkem_export_raw(sk, &sklen, PK_PRIVATE, &key));
   pklen = sizeof(pk);
   DO(mlkem_export_raw(pk, &pklen, PK_PUBLIC, &key));

   outlen = inlen;
   DO(mlkem_export_ex(out, &outlen, PK_PRIVATE | PK_STD, LTC_PQC_PRIVKEY_BOTH, &key));
   COMPARE_TESTVECTOR(out, outlen, der, derlen, "ML-KEM OpenSSL PKCS#8 both", key.alg);

   /* the seed and expandedKey alternatives describe the same key pair */
   outlen = inlen;
   DO(mlkem_export_ex(out, &outlen, PK_PRIVATE | PK_STD, LTC_PQC_PRIVKEY_SEED, &key));
   DO(mlkem_import_pkcs8(out, outlen, NULL, &imported));
   ENSURE(mlkem_has_seed(&imported) == 1);
   DO(s_mlkem_key_is(&imported, sk, sklen, pk, pklen, "ML-KEM OpenSSL PKCS#8 seed", key.alg));
   mlkem_free(&imported);

   outlen = inlen;
   DO(mlkem_export_ex(out, &outlen, PK_PRIVATE | PK_STD, LTC_PQC_PRIVKEY_EXPANDED, &key));
   DO(mlkem_import_pkcs8(out, outlen, NULL, &imported));
   ENSURE(mlkem_has_seed(&imported) == 0);
   DO(s_mlkem_key_is(&imported, sk, sklen, pk, pklen, "ML-KEM OpenSSL PKCS#8 expandedKey", key.alg));
   mlkem_free(&imported);

   (*((int *)ctx))++;
   mlkem_free(&key);
   XFREE(out);
   XFREE(der);
   return CRYPT_OK;
}

static int s_mlkem_openssl_pkcs8_test(void)
{
   int count = 0;
   DO(test_process_dir("tests/pem", &count, s_mlkem_openssl_pkcs8, NULL, NULL, "pqc_mlkem_pkcs8"));
   /* one private key per parameter set */
   ENSURE(count == 3);
   return CRYPT_OK;
}
#endif


/* mlkem_check_key() has to detect a key struct that a caller changed */
static int s_mlkem_check_key_test(int alg)
{
   mlkem_key key, pub;
   unsigned char pk[1600], der[4096];
   unsigned long pklen, derlen;
   int prng_idx = find_prng("yarrow");

   XMEMSET(&key, 0, sizeof(key));
   XMEMSET(&pub, 0, sizeof(pub));

   DO(mlkem_make_key(&yarrow_prng, prng_idx, alg, &key));
   DO(mlkem_check_key(&key));

   pklen = sizeof(pk);
   DO(mlkem_export_raw(pk, &pklen, PK_PUBLIC, &key));
   DO(mlkem_import_raw(pk, pklen, PK_PUBLIC, alg, &pub));
   DO(mlkem_check_key(&pub));

   /* a wrong key field is reported before any key material is hashed */
   key.sklen -= 1;
   SHOULD_FAIL_WITH(mlkem_check_key(&key), CRYPT_PK_INVALID_TYPE);
   key.sklen += 1;
   key.type = PK_PUBLIC;
   SHOULD_FAIL_WITH(mlkem_check_key(&key), CRYPT_PK_INVALID_TYPE);
   key.type = PK_PRIVATE;

   /* the copy of the encapsulation key inside the decapsulation key */
   key.pk[0] ^= 1;
   SHOULD_FAIL_WITH(mlkem_check_key(&key), CRYPT_INVALID_PACKET);
   key.pk[0] ^= 1;

   /* the H(ek) at the end of the decapsulation key */
   key.sk[key.sklen - 64] ^= 1;
   SHOULD_FAIL_WITH(mlkem_check_key(&key), CRYPT_INVALID_PACKET);
   key.sk[key.sklen - 64] ^= 1;

   /* a seed that no longer expands to this key, the both export has to fail too */
   key.seed[0] ^= 1;
   SHOULD_FAIL_WITH(mlkem_check_key(&key), CRYPT_INVALID_PACKET);
   derlen = sizeof(der);
   SHOULD_FAIL_WITH(mlkem_export_ex(der, &derlen, PK_PRIVATE | PK_STD, LTC_PQC_PRIVKEY_BOTH, &key),
                    CRYPT_INVALID_PACKET);
   key.seed[0] ^= 1;
   DO(mlkem_check_key(&key));

   mlkem_free(&pub);
   mlkem_free(&key);
   return CRYPT_OK;
}


static void s_mlkem_try_import(const unsigned char *in, unsigned long inlen, int kind, int alg)
{
   mlkem_key key;
   int err;

   XMEMSET(&key, 0, sizeof(key));
   switch (kind) {
      case 0:  err = mlkem_import_raw(in, inlen, PK_PUBLIC, alg, &key); break;
      case 1:  err = mlkem_import_raw(in, inlen, PK_PRIVATE, alg, &key); break;
      case 2:  err = mlkem_import(in, inlen, &key); break;
      default: err = mlkem_import_pkcs8(in, inlen, NULL, &key); break;
   }
   /* anything an importer accepts has to pass the key check as well */
   if (err == CRYPT_OK) DO(mlkem_check_key(&key));
   mlkem_free(&key);
}

/* A deterministic replacement for fuzzing: every encoding a key can be read from is
   truncated, extended and bit flipped. Run it under ASan/UBSan to get the most out of it. */
static int s_mlkem_import_mutation_test(int alg)
{
   mlkem_key key;
   unsigned char enc[4][4096], buf[4200];
   static const int kinds[6] = { 0, 1, 2, 3, 3, 3 };
   const unsigned char *src[6];
   unsigned long lens[6], i, n, pos, step;
   int prng_idx = find_prng("yarrow");

   XMEMSET(&key, 0, sizeof(key));
   DO(mlkem_make_key(&yarrow_prng, prng_idx, alg, &key));

   lens[0] = sizeof(enc[0]);
   DO(mlkem_export_raw(enc[0], &lens[0], PK_PUBLIC, &key));
   lens[1] = sizeof(enc[1]);
   DO(mlkem_export_raw(enc[1], &lens[1], PK_PRIVATE, &key));
   lens[2] = sizeof(enc[2]);
   DO(mlkem_export(enc[2], &lens[2], PK_PUBLIC | PK_STD, &key));
   /* the three PKCS#8 private-key representations share one buffer, one at a time */
   for (i = 0; i < 3; i++) src[i] = enc[i];

   for (n = 0; n < 6; n++) {
      if (n >= 3) {
         static const enum ltc_pqc_privkey_format formats[3] = {
            LTC_PQC_PRIVKEY_SEED, LTC_PQC_PRIVKEY_EXPANDED, LTC_PQC_PRIVKEY_BOTH
         };
         lens[n] = sizeof(enc[3]);
         DO(mlkem_export_ex(enc[3], &lens[n], PK_PRIVATE | PK_STD, formats[n - 3], &key));
         src[n] = enc[3];
      }

      XMEMCPY(buf, src[n], lens[n]);
      s_mlkem_try_import(buf, lens[n], kinds[n], alg);

      /* truncation and extension */
      s_mlkem_try_import(buf, 0, kinds[n], alg);
      s_mlkem_try_import(buf, 1, kinds[n], alg);
      s_mlkem_try_import(buf, lens[n] / 2, kinds[n], alg);
      s_mlkem_try_import(buf, lens[n] - 1, kinds[n], alg);
      buf[lens[n]] = 0x00;
      s_mlkem_try_import(buf, lens[n] + 1, kinds[n], alg);

      /* one flipped byte at a time, spread over the whole encoding */
      step = lens[n] / 64 ? lens[n] / 64 : 1;
      for (pos = 0; pos < lens[n]; pos += step) {
         buf[pos] ^= 0x80;
         s_mlkem_try_import(buf, lens[n], kinds[n], alg);
         buf[pos] ^= 0x80;
      }
   }

   mlkem_free(&key);
   return CRYPT_OK;
}

int pqc_mlkem_test(void)
{
   if (ltc_mp.name == NULL) return CRYPT_NOP;

   DO(s_mlkem_sizes_test());
   DO(s_mlkem_privkey_format_test(LTC_MLKEM_512));
   DO(s_mlkem_privkey_format_test(LTC_MLKEM_768));
   DO(s_mlkem_privkey_format_test(LTC_MLKEM_1024));
   DO(s_mlkem_check_key_test(LTC_MLKEM_512));
   DO(s_mlkem_check_key_test(LTC_MLKEM_768));
   DO(s_mlkem_check_key_test(LTC_MLKEM_1024));
   DO(s_mlkem_import_mutation_test(LTC_MLKEM_512));
   DO(s_mlkem_import_mutation_test(LTC_MLKEM_1024));
#if defined(LTC_TEST_READDIR) && defined(LTC_BASE64)
   DO(s_mlkem_openssl_pkcs8_test());
#endif
   DO(s_mlkem_from_seed_test());
   DO(s_mlkem_openssl_seed_test());
   DO(s_mlkem_error_test());
   DO(s_mlkem_modulus_check_test());
   DO(s_mlkem_keygen_encaps_decaps(LTC_MLKEM_512));
   DO(s_mlkem_keygen_encaps_decaps(LTC_MLKEM_768));
   DO(s_mlkem_keygen_encaps_decaps(LTC_MLKEM_1024));
   return CRYPT_OK;
}

#else

int pqc_mlkem_test(void)
{
   return CRYPT_NOP;
}

#endif
