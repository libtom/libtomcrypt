/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include <tomcrypt_test.h>

#if defined(LTC_MECC) && defined(LTC_DER) && defined(LTC_SM3) && defined(LTC_ECC_SM2P256V1)

static const unsigned char s_sm2_test_priv_der[] = {
   0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x63, 0xa0, 0x63, 0x0a, 0x53, 0x91, 0x57, 0x1c,
   0x8a, 0x57, 0x32, 0x8d, 0x72, 0x09, 0xa9, 0x40, 0x42, 0xaf, 0xf0, 0x77, 0x9b, 0xd3, 0x8a,
   0xf9, 0x00, 0x1a, 0x99, 0xc9, 0x9d, 0xb4, 0xda, 0xf6, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x81,
   0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x69, 0xe1, 0xa4,
   0x14, 0xe7, 0xcd, 0xe8, 0x0f, 0xa4, 0x06, 0xed, 0x10, 0x75, 0x88, 0x0e, 0x82, 0x74, 0x98,
   0x98, 0x70, 0xff, 0x3b, 0x8c, 0x97, 0xcb, 0x46, 0x30, 0x15, 0x56, 0xde, 0x37, 0x25, 0x7b,
   0xc2, 0x3a, 0xaf, 0x05, 0x14, 0x3d, 0x69, 0x2b, 0x9b, 0x93, 0x54, 0xf9, 0x95, 0x78, 0xe3,
   0xcb, 0xd2, 0x04, 0xc2, 0xd0, 0x20, 0x71, 0x6f, 0xad, 0x7a, 0x6f, 0x75, 0x6c, 0xca, 0x9d,
   0xd2
};

static const unsigned char s_sm2_test_pub[] = {
   0x04, 0x69, 0xe1, 0xa4, 0x14, 0xe7, 0xcd, 0xe8, 0x0f, 0xa4, 0x06, 0xed, 0x10, 0x75, 0x88,
   0x0e, 0x82, 0x74, 0x98, 0x98, 0x70, 0xff, 0x3b, 0x8c, 0x97, 0xcb, 0x46, 0x30, 0x15, 0x56,
   0xde, 0x37, 0x25, 0x7b, 0xc2, 0x3a, 0xaf, 0x05, 0x14, 0x3d, 0x69, 0x2b, 0x9b, 0x93, 0x54,
   0xf9, 0x95, 0x78, 0xe3, 0xcb, 0xd2, 0x04, 0xc2, 0xd0, 0x20, 0x71, 0x6f, 0xad, 0x7a, 0x6f,
   0x75, 0x6c, 0xca, 0x9d, 0xd2
};

static const unsigned char s_sm2_test_user_id[] = {
   0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
   0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

/* Source: draft-shen-sm2-ecdsa-02, Appendix A.2 "Digital Signature of over E(Fp)"
   and Appendix C.2 "Encryption and Decryption over E(Fp)".

   These are published example vectors for the draft's Fp-256 example curve,
   not for the built-in sm2p256v1/curveSM2 parameters.
*/
static const char s_sm2_draft_fp256_p[]     = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
static const char s_sm2_draft_fp256_a[]     = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
static const char s_sm2_draft_fp256_b[]     = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
static const char s_sm2_draft_fp256_n[]     = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
static const char s_sm2_draft_fp256_gx[]    = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
static const char s_sm2_draft_fp256_gy[]    = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";

/* Source: draft-shen-sm2-ecdsa-02, Appendix A.1/A.2 */
static const unsigned char s_sm2_draft_sig_id[] = "ALICE123@YAHOO.COM";
static const unsigned char s_sm2_draft_sig_msg[] = "message digest";
static const char s_sm2_draft_sig_pub_x[] = "0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A";
static const char s_sm2_draft_sig_pub_y[] = "7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857";
static const char s_sm2_draft_sig_r[]     = "40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1";
static const char s_sm2_draft_sig_s[]     = "6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7";

/* Source: draft-shen-sm2-ecdsa-02, Appendix C.2 */
static const char s_sm2_draft_enc_priv[]  = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
static const char s_sm2_draft_enc_c1_x[]  = "245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252E7";
static const char s_sm2_draft_enc_c1_y[]  = "76CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01B8";
static const char s_sm2_draft_enc_c2[]    = "650053A89B41C418B0C3AAD00D886C00286467";
static const char s_sm2_draft_enc_c3[]    = "9C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E07480653426D";

/* Source: generated with OpenSSL 3.0.13:
   openssl genpkey -algorithm SM2 -out key.pem
   printf %s "OpenSSL SM2 vector" > msg.bin
   openssl dgst -sm3 -sign key.pem -sigopt distid:OpenSSL-with-SM2 -out sig.bin msg.bin
   openssl pkey -in key.pem -pubout -outform DER -out pub.der
*/
static const unsigned char s_sm2_openssl_msg[] = "OpenSSL SM2 vector";
static const unsigned char s_sm2_openssl_id[] = "OpenSSL-with-SM2";
static const unsigned char s_sm2_openssl_pub_der[] = {
   0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
   0x01, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03,
   0x42, 0x00, 0x04, 0x1c, 0x44, 0x0a, 0xe5, 0x88, 0x20, 0x02, 0x36, 0x77,
   0xc9, 0x2a, 0x70, 0xbf, 0x4c, 0xc4, 0x9c, 0xe3, 0xb1, 0x03, 0xb6, 0x93,
   0x9a, 0x22, 0x52, 0x5b, 0x07, 0xbb, 0x09, 0xa2, 0xb2, 0x7e, 0x4d, 0x1f,
   0xda, 0x22, 0xdc, 0x08, 0xc0, 0xdf, 0x83, 0x1c, 0xeb, 0x53, 0x06, 0x2f,
   0x62, 0x81, 0xa0, 0x64, 0xe4, 0xed, 0xde, 0x24, 0x1c, 0xa4, 0x90, 0x28,
   0x58, 0x51, 0x49, 0xbf, 0x90, 0xf6, 0x80
};
static const unsigned char s_sm2_openssl_sig_der[] = {
   0x30, 0x45, 0x02, 0x20, 0x2c, 0xf8, 0x57, 0x9e, 0x14, 0x72, 0xb0, 0xf3,
   0x84, 0xd2, 0x97, 0xf1, 0x48, 0x02, 0x27, 0x46, 0xeb, 0xdc, 0x54, 0x9d,
   0xd3, 0x88, 0x9d, 0x71, 0x93, 0x75, 0x06, 0xa0, 0xa3, 0xc1, 0x55, 0x12,
   0x02, 0x21, 0x00, 0xc3, 0xec, 0x35, 0xc3, 0xec, 0xf1, 0x81, 0x94, 0xa7,
   0x02, 0xe4, 0xad, 0xe6, 0xc0, 0x53, 0x5b, 0x95, 0xe2, 0x9b, 0x44, 0x65,
   0xf0, 0x21, 0x20, 0x4a, 0x0c, 0x1d, 0x57, 0x84, 0xd9, 0xc1, 0x49
};

static int s_sm2_set_custom_curve(ecc_key *key)
{
   void *a = NULL, *b = NULL, *p = NULL, *n = NULL, *gx = NULL, *gy = NULL;
   int err;

   if ((err = ltc_mp_init_multi(&a, &b, &p, &n, &gx, &gy, LTC_NULL)) != CRYPT_OK) return err;
   if ((err = ltc_mp_read_radix(a,  s_sm2_draft_fp256_a,  16)) != CRYPT_OK) goto cleanup;
   if ((err = ltc_mp_read_radix(b,  s_sm2_draft_fp256_b,  16)) != CRYPT_OK) goto cleanup;
   if ((err = ltc_mp_read_radix(p,  s_sm2_draft_fp256_p,  16)) != CRYPT_OK) goto cleanup;
   if ((err = ltc_mp_read_radix(n,  s_sm2_draft_fp256_n,  16)) != CRYPT_OK) goto cleanup;
   if ((err = ltc_mp_read_radix(gx, s_sm2_draft_fp256_gx, 16)) != CRYPT_OK) goto cleanup;
   if ((err = ltc_mp_read_radix(gy, s_sm2_draft_fp256_gy, 16)) != CRYPT_OK) goto cleanup;
   err = ecc_set_curve_from_mpis(a, b, p, n, gx, gy, 1uL, key);

cleanup:
   ltc_mp_deinit_multi(a, b, p, n, gx, gy, LTC_NULL);
   return err;
}

static int s_sm2_set_public_point(ecc_key *key, const char *x, const char *y)
{
   int err;

   if ((err = ltc_mp_read_radix(key->pubkey.x, x, 16)) != CRYPT_OK) return err;
   if ((err = ltc_mp_read_radix(key->pubkey.y, y, 16)) != CRYPT_OK) return err;
   if ((err = ltc_mp_set(key->pubkey.z, 1)) != CRYPT_OK) return err;
   key->type = PK_PUBLIC;
   return CRYPT_OK;
}

static int s_sm2_set_private_scalar(ecc_key *key, const char *d)
{
   int err;

   if ((err = ltc_mp_read_radix(key->k, d, 16)) != CRYPT_OK) return err;
   key->type = PK_PRIVATE;
   return CRYPT_OK;
}

static int s_sm2_sig_der_from_hex(const char *r_hex, const char *s_hex, unsigned char *out, unsigned long *outlen)
{
   void *r = NULL, *s = NULL;
   int err;

   if ((err = ltc_mp_init_multi(&r, &s, LTC_NULL)) != CRYPT_OK) return err;
   if ((err = ltc_mp_read_radix(r, r_hex, 16)) != CRYPT_OK) goto cleanup;
   if ((err = ltc_mp_read_radix(s, s_hex, 16)) != CRYPT_OK) goto cleanup;
   err = der_encode_sequence_multi(out, outlen,
                                   LTC_ASN1_INTEGER, 1uL, r,
                                   LTC_ASN1_INTEGER, 1uL, s,
                                   LTC_ASN1_EOL, 0uL, LTC_NULL);

cleanup:
   ltc_mp_deinit_multi(r, s, LTC_NULL);
   return err;
}

int ecc_sm2_test(void)
{
   static const unsigned char msg[] = "encryption standard";
   unsigned char id_bad[sizeof(s_sm2_test_user_id)];
   unsigned char msg_bad[sizeof(msg)];
   unsigned char sig[256], ct[256], pt[sizeof(msg)], draft_sig[80], draft_ct[256];
   unsigned char pubbuf[sizeof(s_sm2_test_pub)];
   unsigned long len, siglen, ctlen, ptlen, draft_siglen, draft_ctlen, partlen;
   const ltc_ecc_curve *dp;
   ecc_key privkey = { 0 }, pubkey = { 0 }, draft_pubkey = { 0 }, draft_privkey = { 0 }, openssl_pubkey = { 0 };
   int err, stat, hash_idx, prng_idx;

   if (ltc_mp.name == NULL) return CRYPT_NOP;
   hash_idx = find_hash("sm3");
   if (hash_idx < 0) return CRYPT_NOP;
   prng_idx = find_prng("yarrow");

   DO(ecc_import_openssl(s_sm2_test_priv_der, sizeof(s_sm2_test_priv_der), &privkey));
   DO(ecc_find_curve("SM2", &dp));
   DO(ecc_set_curve(dp, &pubkey));
   DO(ecc_set_key(s_sm2_test_pub, sizeof(s_sm2_test_pub), PK_PUBLIC, &pubkey));

   len = sizeof(pubbuf);
   DO(ecc_ansi_x963_export(&privkey, pubbuf, &len));
   COMPARE_TESTVECTOR(pubbuf, len, s_sm2_test_pub, sizeof(s_sm2_test_pub), "SM2 public key import", 0);

   siglen = sizeof(sig);
   DO(ecc_sign_sm2(s_sm2_test_user_id, sizeof(s_sm2_test_user_id), msg, sizeof(msg) - 1uL,
                   sig, &siglen, &yarrow_prng, prng_idx, -1, &privkey));
   stat = 0;
   DO(ecc_verify_sm2(s_sm2_test_user_id, sizeof(s_sm2_test_user_id), msg, sizeof(msg) - 1uL,
                     sig, siglen, -1, &stat, &pubkey));
   if (stat != 1) {
      err = CRYPT_FAIL_TESTVECTOR;
      goto cleanup;
   }

   XMEMCPY(id_bad, s_sm2_test_user_id, sizeof(id_bad));
   id_bad[0] ^= 1;
   stat = 0;
   DO(ecc_verify_sm2(id_bad, sizeof(id_bad), msg, sizeof(msg) - 1uL, sig, siglen, -1, &stat, &pubkey));
   if (stat != 0) {
      err = CRYPT_FAIL_TESTVECTOR;
      goto cleanup;
   }

   XMEMCPY(msg_bad, msg, sizeof(msg));
   msg_bad[0] ^= 1;
   stat = 0;
   DO(ecc_verify_sm2(s_sm2_test_user_id, sizeof(s_sm2_test_user_id), msg_bad, sizeof(msg) - 1uL,
                     sig, siglen, -1, &stat, &pubkey));
   if (stat != 0) {
      err = CRYPT_FAIL_TESTVECTOR;
      goto cleanup;
   }

   ctlen = sizeof(ct);
   DO(ecc_encrypt_key_sm2(msg, sizeof(msg) - 1uL, ct, &ctlen,
                          &yarrow_prng, prng_idx, -1, &pubkey));
   ptlen = sizeof(pt);
   DO(ecc_decrypt_key_sm2(ct, ctlen, pt, &ptlen, -1, &privkey));
   COMPARE_TESTVECTOR(pt, ptlen, msg, sizeof(msg) - 1uL, "SM2 decrypt", 2);

   ct[ctlen - 1uL] ^= 1;
   ptlen = sizeof(pt);
   SHOULD_FAIL(ecc_decrypt_key_sm2(ct, ctlen, pt, &ptlen, -1, &privkey));

   DO(s_sm2_set_custom_curve(&draft_pubkey));
   DO(s_sm2_set_public_point(&draft_pubkey, s_sm2_draft_sig_pub_x, s_sm2_draft_sig_pub_y));

   /* Source: draft-shen-sm2-ecdsa-02, Appendix A.2. The draft publishes raw r,s values; the public API expects DER.
      The example uses a non-SM2 draft curve and is expected to be rejected by the public SM2 API. */
   draft_siglen = sizeof(draft_sig);
   DO(s_sm2_sig_der_from_hex(s_sm2_draft_sig_r, s_sm2_draft_sig_s, draft_sig, &draft_siglen));
   stat = 0;
   SHOULD_FAIL(ecc_verify_sm2(s_sm2_draft_sig_id, sizeof(s_sm2_draft_sig_id) - 1uL,
                              s_sm2_draft_sig_msg, sizeof(s_sm2_draft_sig_msg) - 1uL,
                              draft_sig, draft_siglen, hash_idx, &stat, &draft_pubkey));

   DO(s_sm2_set_custom_curve(&draft_privkey));
   DO(s_sm2_set_private_scalar(&draft_privkey, s_sm2_draft_enc_priv));

   /* Source: draft-shen-sm2-ecdsa-02, Appendix C.2 publishes C = C1 || C2 || C3.
      libtomcrypt's SM2 public API uses C1 || C3 || C2, so the test reorders the published pieces.
      The example uses a non-SM2 draft curve and is expected to be rejected by the public SM2 API. */
   draft_ctlen = 0;
   draft_ct[draft_ctlen++] = 0x04;
   partlen = sizeof(draft_ct) - draft_ctlen;
   DO(base16_decode(s_sm2_draft_enc_c1_x, XSTRLEN(s_sm2_draft_enc_c1_x), draft_ct + draft_ctlen, &partlen));
   draft_ctlen += partlen;
   partlen = sizeof(draft_ct) - draft_ctlen;
   DO(base16_decode(s_sm2_draft_enc_c1_y, XSTRLEN(s_sm2_draft_enc_c1_y), draft_ct + draft_ctlen, &partlen));
   draft_ctlen += partlen;
   partlen = sizeof(draft_ct) - draft_ctlen;
   DO(base16_decode(s_sm2_draft_enc_c3, XSTRLEN(s_sm2_draft_enc_c3), draft_ct + draft_ctlen, &partlen));
   draft_ctlen += partlen;
   partlen = sizeof(draft_ct) - draft_ctlen;
   DO(base16_decode(s_sm2_draft_enc_c2, XSTRLEN(s_sm2_draft_enc_c2), draft_ct + draft_ctlen, &partlen));
   draft_ctlen += partlen;

   ptlen = sizeof(pt);
   SHOULD_FAIL(ecc_decrypt_key_sm2(draft_ct, draft_ctlen, pt, &ptlen, hash_idx, &draft_privkey));

   DO(ecc_import_openssl(s_sm2_openssl_pub_der, sizeof(s_sm2_openssl_pub_der), &openssl_pubkey));
   stat = 0;
   DO(ecc_verify_sm2(s_sm2_openssl_id, sizeof(s_sm2_openssl_id) - 1uL,
                     s_sm2_openssl_msg, sizeof(s_sm2_openssl_msg) - 1uL,
                     s_sm2_openssl_sig_der, sizeof(s_sm2_openssl_sig_der), -1, &stat, &openssl_pubkey));
   if (stat != 1) {
      err = CRYPT_FAIL_TESTVECTOR;
      goto cleanup;
   }

   err = CRYPT_OK;
cleanup:
   ecc_free(&openssl_pubkey);
   ecc_free(&draft_privkey);
   ecc_free(&draft_pubkey);
   ecc_free(&pubkey);
   ecc_free(&privkey);
   return err;
}

#else

int ecc_sm2_test(void)
{
   return CRYPT_NOP;
}

#endif
