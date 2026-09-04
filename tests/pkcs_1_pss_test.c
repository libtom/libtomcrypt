/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include <tomcrypt_test.h>

#if defined(LTC_MRSA)

#include "../notes/rsa-testvectors/pss-vect.c"


#ifdef LTC_SHA3
static int s_pss_shake_wycheproof_test(void)
{
  const struct {
    const char *name;
    const char *n, *e;
    unsigned long saltlen;
    struct {
      int tc_id, valid;
      const char *msg, *sig;
    } tests[2];
  } cases[] = {
    { /* Project Wycheproof: testvectors_v1/rsa_pss_2048_shake128_test.json */
      "shake128",
      "00ac7ae7bde0bc9067fff5d5b4229350f8f6a1b285cda38b86ab61a54b02350889de49ff3ae1e243d380d4349ee3df2505d6041938fc270f8dcc265c5d022e3610d5f06ea2247e634b08d7aa3e24a347f6d61c127813e0302a5727c10292afa8"
      "3b9775e5ba26d6b7ae217d05c469d193376d70ee92ff40f8424baaa4ded3814ac523016d8c7d7ccd1eec17459f3d2449f4cbfae3f2d51e506827282bde589a52e66320f54ca930a21f6aa7e3b0bc531ad1b568d7e32c0afed523ca6da62e5f22"
      "fed6f7ee722974b5f70aad710dcb14fa7a3c561b3d4c8696a455abe4cb9b351a6c0b6e478c60a81f02fb3a285245ebfe93221e36ad8787b3e7f3099d7c23225641",
      "010001",
      32,
      {
        {
          3, 1, /* valid */
          "54657374",
          "62f31cf2a408ddae7a46914951080377319f310df9930d41566926a7aaa8938fcf3e91852abd12897aef378a13ad670b93ec13d5ace695377f3cf83d95d10375a6c14ffaf1ae6459cd381da1be9571a1de6e8e32dd741cb10d692ef0caaaa477"
          "70b86ca05a2cf251d203aeaa048dbedc7d99e6e4c5a51e8b820d9df7b904834aef30190e9e36630794b687147a000167f599f902a22568fdb556518090f3e671734ec87874759e3efbf25b31582ef6b8cc687addea20c85917a941e59118b1e9"
          "d847129fc6c2e071a6ef1a282e7b99d991208c6c127b87cc263af8c4942ead189f30c446a48161c465e71714265b4058c4a7410a589c89fd8e1ef821528e18c2"
        },
        {
          87, 0, /* invalid */
          "313233343030",
          "98b3e4580c788c9a4e6a49bc2a409e2930319c8136ff41df308299ae8c9cea98d29825d5288528a95310a6c92ac2073dbc9b1719f5e2b875ca72dffa2f192dcfe4a04ac63798605c77e3f48893696363f17a94ef1f0ad1774ffb86a32fee18d4"
          "f975b44db75f24264143ebde795dbea887be4fba72ace4733e688ce1f44e2dd46ed9f703d8f6864c7bf899e13d4a6adefaebf9ac3c5aa901a2415f9f688765a80e41a6681e9d3762289d9bc54709fbd687b12104efe23413d3de97f880cd2e26"
          "fd29c6426792e7ff576caf3fc46ec2e139cbe00a7864ef5b3256908914fecd3c3712f2c70098ada0d62778dadb4e77256fc67ac158a4af661a15b00f25182515"
        }
      }
    },
    { /* Project Wycheproof: testvectors_v1/rsa_pss_2048_shake256_test.json */
      "shake256",
      "008a33fe25984e4d5e5ac821ebad6c13051c5b48ccd4f22a60ea82d4802cc56ef3441c19df897bb7a45c0baf22972a6b35cfa176007555b8312de42bfa224a3d1d8e7dee5c3a484b491f4db7a7d70c4504efbd717abbaf0b9a7191c9aadc48e9"
      "720a33ad578086321619a25b1da1d5c29949f69783e6e32b1d5d5875afb0f54786058dc970967e235e6eb6803f46b14be9f210fdbca164f7be0b5a3c486bc6f6971cfe9a5f1f08935a2559be01a058bb100715bb0d6c7745d08ab702d5ec9327"
      "f1db33bf3555dc2f8a93bea42a4a0cf566ba7a5c0d8b6a848c23b92112462288dae97b56923385d7a8acb0014d04ba715f797d2716b6c13c3342b80be6b3e490cf",
      "010001",
      64,
      {
        {
          3, 1, /* valid */
          "54657374",
          "0f9be5d84919e2b58bf9079be5783d7b7b8ce4ac6bb6ed3f7f4f9640f1e9135084b4dae0c7d7c950d49c62a9a2013dec7aaba2b6c5465a2d3c952d1a805dcc2fc594ce94c2ebaf5dafcd5e62154d4d5f8e2a3592b63a9c3dace20a1fb859181d"
          "895c02f64d0198c64514cc17315c99749617356cdcceacfb5ae87e01def90c6fb6d59cd4a9beb1c31fd8ee966c9c245795fd249c76b59f9f4c28614b9de3bd0ae04598794ba2864441efbe332cd68aa3107f7ec2e3b88dd3c063d57da1fc7cf1"
          "5ef39213e81d94dd4f555eda5d8a37ad5e303b1532e753b330ec913bda57f11725a2bffa6e16250955680d21c510b5bddf2b6ba78556158c991a859c7a029ed3"
        },
        {
          137, 0, /* invalid */
          "313233343030",
          "4ddb8c5f83ebdcc5c08486df729549c9732117b5fac42645e58c45f40410a39538409af0cdc75cc1c03f43c5787821c252f5ddf50ac9e584e65f50e811402d683e9a246cb4246ee7b1427819e63f74b6b90bf023e3aad406e66fc9782d1d71c6"
          "a70fa3787d08cb437106ad51cf7c78923b8b5df662788810e071645882955690c8b1a29a6a6fc54204fb1715b8d1a2bcbd739805e0dfaea734110ed719caf77143ba2863e2521127d4b7fc55488f1d26216b3e8a2861a6aabdff8732616d2f73"
          "e78c868772877443a05847fb99c4738728be884668058289547848167724f5ebe4b7f637618a5c3641fe687105a52a7b44e5fd060b165fdf831c80b2769c26bd"
        }
      }
    }
  };
  unsigned char n[257], e[8], msg[64], sig[512], hash[64];
  unsigned long nlen, elen, msglen, siglen, hashlen;
  unsigned int i, j;
  rsa_key key;
  ltc_rsa_op_parameters params = { .params.hash_idx = -1, .params.mgf1_hash_idx = -1, .padding = LTC_PKCS_1_PSS };

  for (i = 0; i < LTC_ARRAY_SIZE(cases); ++i) {
    int hash_idx = find_hash(cases[i].name);
    DO(hash_is_valid(hash_idx));

    DOX(rsa_init(&key), cases[i].name);
    nlen = sizeof(n);
    elen = sizeof(e);
    DOX(base16_decode(cases[i].n, XSTRLEN(cases[i].n), n, &nlen), cases[i].name);
    DOX(base16_decode(cases[i].e, XSTRLEN(cases[i].e), e, &elen), cases[i].name);
    DOX(ltc_mp_read_unsigned_bin(key.N, n, nlen), cases[i].name);
    DOX(ltc_mp_read_unsigned_bin(key.e, e, elen), cases[i].name);
    key.type = PK_PUBLIC;

    params.params.hash_idx = hash_idx;
    params.params.mgf1_hash_idx = hash_idx;
    params.params.saltlen = cases[i].saltlen;

    for (j = 0; j < LTC_ARRAY_SIZE(cases[i].tests); ++j) {
      int err, stat;
      char name[64];

      snprintf(name, sizeof(name), "Wycheproof %s/%d tcId=%d", cases[i].name, hash_idx, cases[i].tests[j].tc_id);
      msglen = sizeof(msg);
      siglen = sizeof(sig);
      DOX(base16_decode(cases[i].tests[j].msg, XSTRLEN(cases[i].tests[j].msg), msg, &msglen), name);
      DOX(base16_decode(cases[i].tests[j].sig, XSTRLEN(cases[i].tests[j].sig), sig, &siglen), name);

      hashlen = hash_descriptor[hash_idx].hashsize;
      DOX(hash_memory(hash_idx, msg, msglen, hash, &hashlen), name);

      stat = 0;
      err = rsa_verify_hash_v2(sig, siglen, hash, hashlen, &params, &stat, &key);
      if (cases[i].tests[j].valid) {
        DOX(err, name);
        ENSUREX(stat == 1, name);
      }
      else {
        ENSUREX(err != CRYPT_OK || stat == 0, name);
      }
    }
    rsa_free(&key);
  }
  return CRYPT_OK;
}
#endif

int pkcs_1_pss_test(void)
{
  struct ltc_prng_descriptor* no_prng_desc = no_prng_desc_get();
  ltc_rsa_op_parameters rsa_params = {
                                      .wprng = register_prng(no_prng_desc),
                                      .prng = (void*)no_prng_desc,
                                      .params.hash_idx = -1,
                                      .params.mgf1_hash_idx = -1,
                                      .padding = LTC_PKCS_1_PSS
  };
  int hash_idx = find_hash("sha1");
  unsigned int i, j;
  rsa_params.params.hash_idx = hash_idx;
  rsa_params.params.mgf1_hash_idx = hash_idx;

  if (ltc_mp.name == NULL) return CRYPT_NOP;

  DO(hash_is_valid(hash_idx));

  for (i = 0; i < LTC_ARRAY_SIZE(testcases_pss); ++i) {
    testcase_t* t = &testcases_pss[i];
    rsa_key k, *key = &k;
    DOX(rsa_init(key), t->name);

    DOX(ltc_mp_read_unsigned_bin(key->e, t->rsa.e, t->rsa.e_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->d, t->rsa.d, t->rsa.d_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->N, t->rsa.n, t->rsa.n_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->dQ, t->rsa.dQ, t->rsa.dQ_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->dP, t->rsa.dP, t->rsa.dP_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->qP, t->rsa.qInv, t->rsa.qInv_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->q, t->rsa.q, t->rsa.q_l), t->name);
    DOX(ltc_mp_read_unsigned_bin(key->p, t->rsa.p, t->rsa.p_l), t->name);
    key->type = PK_PRIVATE;

    for (j = 0; j < LTC_ARRAY_SIZE(t->data); ++j) {
        rsaData_t* s = &t->data[j];
        unsigned char buf[20], obuf[256];
        unsigned long buflen = sizeof(buf), obuflen = sizeof(obuf);
        int stat, err;
        prng_descriptor[rsa_params.wprng].add_entropy(s->o2, s->o2_l, rsa_params.prng);
        DOX(hash_memory(hash_idx, s->o1, s->o1_l, buf, &buflen), s->name);
        rsa_params.params.saltlen = s->o2_l;
        DOX(rsa_sign_hash_v2(buf, buflen, obuf, &obuflen, &rsa_params, key), s->name);
        COMPARE_TESTVECTOR(obuf, obuflen, s->o3, s->o3_l,s->name, j);
        DOX(rsa_verify_hash_v2(obuf, obuflen, buf, buflen, &rsa_params, &stat, key), s->name);
        ENSUREX(stat == 1, s->name);

        /* pkcs_1_pss_decode() (unlike rsa_verify_hash_v2()) forwards siglen
         * straight to ltc_pkcs_1_pss_decode_mgf1() with no check that it
         * matches modulus_len. That function copies modulus_len - 1 bytes
         * total out of `sig` based on modulus_len alone, so a caller
         * passing a genuinely truncated buffer used to walk past its end
         * instead of failing early.
         */
        {
          unsigned long modulus_bitlen = ltc_mp_count_bits(key->N);
          const unsigned char *em = obuf;
          unsigned long emlen = obuflen;
          if (modulus_bitlen % 8 == 1) {
            em++;
            emlen--;
          }
          stat = 1;
          err = pkcs_1_pss_decode(buf, buflen, em, emlen - 1, s->o2_l,
                                   hash_idx, modulus_bitlen, &stat);
          ENSUREX(err == CRYPT_PK_INVALID_SIZE, s->name);
          ENSUREX(stat == 0, s->name);
        }
    } /* for */

    ltc_mp_deinit_multi(key->d,  key->e, key->N, key->dQ, key->dP, key->qP, key->p, key->q, LTC_NULL);
  } /* for */

#ifdef LTC_SHA3
  DO(s_pss_shake_wycheproof_test());
#endif
  unregister_prng(no_prng_desc);
  no_prng_desc_free(no_prng_desc);

  return 0;
}

#else
LTC_NOP_TEST(pkcs_1_pss_test)
#endif

