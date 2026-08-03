/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Based on serpent.cpp - originally written and placed in the public domain by Wei Dai
   https://github.com/weidai11/cryptopp/blob/master/serpent.cpp

   On 2017-10-16 wikipedia says:
   "The Serpent cipher algorithm is in the public domain and has not been patented."
   https://en.wikipedia.org/wiki/Serpent_(cipher)
 */

#include "tomcrypt_private.h"

#ifdef LTC_SERPENT

#define serpent_block_len 16

#define LTC_SERPENT_ACCEL_64_BIT /* todo move somewhere else */
#define LTC_SERPENT_ACCEL_128_BIT_X86_SSE2 /* todo move somewhere else */
#define LTC_SERPENT_ACCEL_256_BIT_X86_AVX2 /* todo move somewhere else */
#define LTC_SERPENT_ACCEL_512_BIT_X86_AVX512F /* todo move somewhere else */

#if \
  defined LTC_SERPENT_ACCEL_64_BIT || \
  defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2 || \
  defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2 || \
  defined LTC_SERPENT_ACCEL_512_BIT_X86_AVX512F || \
  0
#define LTC_SERPENT_ACCEL 1
#else
#define LTC_SERPENT_ACCEL 0
#endif

#if LTC_SERPENT_ACCEL
#define ltc_serpent_accel_ecb_encrypt &serpent_accel_ecb_encrypt
#define ltc_serpent_accel_ecb_decrypt &serpent_accel_ecb_decrypt
#define ltc_serpent_accel_cbc_decrypt &serpent_accel_cbc_decrypt
#define ltc_serpent_accel_ctr_encrypt &serpent_accel_ctr_encrypt
#else
#define ltc_serpent_accel_ecb_encrypt NULL
#define ltc_serpent_accel_ecb_decrypt NULL
#define ltc_serpent_accel_cbc_decrypt NULL
#define ltc_serpent_accel_ctr_encrypt NULL
#endif

const struct ltc_cipher_descriptor serpent_desc = {
   "serpent",
   25,                  /* cipher_ID */
   16, 32, serpent_block_len, 32,      /* min_key_len, max_key_len, block_len, default_rounds */
   &serpent_setup,
   &serpent_ecb_encrypt,
   &serpent_ecb_decrypt,
   &serpent_test,
   &serpent_done,
   &serpent_keysize,
   ltc_serpent_accel_ecb_encrypt,
   ltc_serpent_accel_ecb_decrypt,
   NULL,
   ltc_serpent_accel_cbc_decrypt,
   ltc_serpent_accel_ctr_encrypt,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};


#define s_apply_key(i, ra, rb, rc, rd, re) {                                               \
   s_do_xor(ra, s_do_broadcast(k[i * 4 + 0])); s_do_xor(rb, s_do_broadcast(k[i * 4 + 1])); \
   s_do_xor(rc, s_do_broadcast(k[i * 4 + 2])); s_do_xor(rd, s_do_broadcast(k[i * 4 + 3])); \
}
#define s_apply_lk(i, ra, rb, rc, rd, re) {                                                                                            \
   s_do_rol(ra, 13);                                                                                                                   \
   s_do_rol(rc, 3);                            s_do_xor(rb, ra);                           s_do_shl(re, ra, 3);                        \
   s_do_xor(rd, rc);                           s_do_xor(rb, rc);                                                                       \
   s_do_rol(rb, 1);                            s_do_xor(rd, re);                                                                       \
   s_do_rol(rd, 7);                            s_do_asgn(re, rb);                                                                      \
   s_do_xor(ra, rb);                           s_do_shl(re, re, 7);                        s_do_xor(rc, rd);                           \
   s_do_xor(ra, rd);                           s_do_xor(rc, re);                           s_do_xor(rd, s_do_broadcast(k[i * 4 + 3])); \
   s_do_xor(rb, s_do_broadcast(k[i * 4 + 1])); s_do_rol(ra, 5);                            s_do_rol(rc, 22);                           \
   s_do_xor(ra, s_do_broadcast(k[i * 4 + 0])); s_do_xor(rc, s_do_broadcast(k[i * 4 + 2]));                                             \
}
#define s_apply_kl(i, ra, rb, rc, rd, re) {                                                                                            \
   s_do_xor(ra, s_do_broadcast(k[4 * i + 0])); s_do_xor(rb, s_do_broadcast(k[4 * i + 1])); s_do_xor(rc, s_do_broadcast(k[4 * i + 2])); \
   s_do_xor(rd, s_do_broadcast(k[4 * i + 3])); s_do_ror(ra, 5);                            s_do_ror(rc, 22);                           \
   s_do_asgn(re, rb);                          s_do_xor(rc, rd);                           s_do_xor(ra, rd);                           \
   s_do_shl(re, re, 7);                        s_do_xor(ra, rb);                           s_do_ror(rb, 1);                            \
   s_do_xor(rc, re);                           s_do_ror(rd, 7);                            s_do_shl(re, ra, 3);                        \
   s_do_xor(rb, ra);                           s_do_xor(rd, re);                           s_do_ror(ra, 13);                           \
   s_do_xor(rb, rc);                           s_do_xor(rd, rc);                           s_do_ror(rc, 3);                            \
}
#define s_enc_0(i, ra, rb, rc, rd, re) {                  \
   s_do_asgn(re, rd);                                     \
   s_do_or  (rd, ra); s_do_xor(ra, re); s_do_xor(re, rc); \
   s_do_not (re, re); s_do_xor(rd, rb); s_do_and(rb, ra); \
   s_do_xor (rb, re); s_do_xor(rc, ra); s_do_xor(ra, rd); \
   s_do_or  (re, ra); s_do_xor(ra, rc); s_do_and(rc, rb); \
   s_do_xor (rd, rc); s_do_not(rb, rb); s_do_xor(rc, re); \
   s_do_xor (rb, rc);                                     \
}
#define s_enc_1(i, ra, rb, rc, rd, re) {                  \
   s_do_asgn(re, rb);                                     \
   s_do_xor (rb, ra); s_do_xor(ra, rd); s_do_not(rd, rd); \
   s_do_and (re, rb); s_do_or (ra, rb); s_do_xor(rd, rc); \
   s_do_xor (ra, rd); s_do_xor(rb, rd); s_do_xor(rd, re); \
   s_do_or  (rb, re); s_do_xor(re, rc); s_do_and(rc, ra); \
   s_do_xor (rc, rb); s_do_or (rb, ra); s_do_not(ra, ra); \
   s_do_xor (ra, rc); s_do_xor(re, rb);                   \
}
#define s_enc_2(i, ra, rb, rc, rd, re) {                  \
   s_do_not(rd, rd);                                      \
   s_do_xor(rb, ra); s_do_asgn(re, ra); s_do_and(ra, rc); \
   s_do_xor(ra, rd); s_do_or  (rd, re); s_do_xor(rc, rb); \
   s_do_xor(rd, rb); s_do_and (rb, ra); s_do_xor(ra, rc); \
   s_do_and(rc, rd); s_do_or  (rd, rb); s_do_not(ra, ra); \
   s_do_xor(rd, ra); s_do_xor (re, ra); s_do_xor(ra, rc); \
   s_do_or (rb, rc);                                      \
}
#define s_enc_3(i, ra, rb, rc, rd, re) {                  \
   s_do_asgn(re, rb);                                     \
   s_do_xor (rb, rd); s_do_or (rd, ra); s_do_and(re, ra); \
   s_do_xor (ra, rc); s_do_xor(rc, rb); s_do_and(rb, rd); \
   s_do_xor (rc, rd); s_do_or (ra, re); s_do_xor(re, rd); \
   s_do_xor (rb, ra); s_do_and(ra, rd); s_do_and(rd, re); \
   s_do_xor (rd, rc); s_do_or (re, rb); s_do_and(rc, rb); \
   s_do_xor (re, rd); s_do_xor(ra, rd); s_do_xor(rd, rc); \
}
#define s_enc_4(i, ra, rb, rc, rd, re) {                  \
   s_do_asgn(re, rd);                                     \
   s_do_and (rd, ra); s_do_xor(ra, re);                   \
   s_do_xor (rd, rc); s_do_or (rc, re); s_do_xor(ra, rb); \
   s_do_xor (re, rd); s_do_or (rc, ra);                   \
   s_do_xor (rc, rb); s_do_and(rb, ra);                   \
   s_do_xor (rb, re); s_do_and(re, rc); s_do_xor(rc, rd); \
   s_do_xor (re, ra); s_do_or (rd, rb); s_do_not(rb, rb); \
   s_do_xor (rd, ra);                                     \
}
#define s_enc_5(i, ra, rb, rc, rd, re) {                  \
   s_do_asgn(re, rb); s_do_or (rb, ra);                   \
   s_do_xor (rc, rb); s_do_not(rd, rd); s_do_xor(re, ra); \
   s_do_xor (ra, rc); s_do_and(rb, re); s_do_or (re, rd); \
   s_do_xor (re, ra); s_do_and(ra, rd); s_do_xor(rb, rd); \
   s_do_xor (rd, rc); s_do_xor(ra, rb); s_do_and(rc, re); \
   s_do_xor (rb, rc); s_do_and(rc, ra);                   \
   s_do_xor (rd, rc);                                     \
}
#define s_enc_6(i, ra, rb, rc, rd, re) {                  \
   s_do_asgn(re, rb);                                     \
   s_do_xor (rd, ra); s_do_xor(rb, rc); s_do_xor(rc, ra); \
   s_do_and (ra, rd); s_do_or (rb, rd); s_do_not(re, re); \
   s_do_xor (ra, rb); s_do_xor(rb, rc);                   \
   s_do_xor (rd, re); s_do_xor(re, ra); s_do_and(rc, ra); \
   s_do_xor (re, rb); s_do_xor(rc, rd); s_do_and(rd, rb); \
   s_do_xor (rd, ra); s_do_xor(rb, rc);                   \
}
#define s_enc_7(i, ra, rb, rc, rd, re) {                  \
   s_do_not (rb, rb);                                     \
   s_do_asgn(re, rb); s_do_not(ra, ra); s_do_and(rb, rc); \
   s_do_xor (rb, rd); s_do_or (rd, re); s_do_xor(re, rc); \
   s_do_xor (rc, rd); s_do_xor(rd, ra); s_do_or (ra, rb); \
   s_do_and (rc, ra); s_do_xor(ra, re); s_do_xor(re, rd); \
   s_do_and (rd, ra); s_do_xor(re, rb);                   \
   s_do_xor (rc, re); s_do_xor(rd, rb); s_do_or (re, ra); \
   s_do_xor (re, rb);                                     \
}
#define s_dec_0(i, ra, rb, rc, rd, re) {                  \
   s_do_asgn(re, rd); s_do_xor(rb, ra);                   \
   s_do_or  (rd, rb); s_do_xor(re, rb); s_do_not(ra, ra); \
   s_do_xor (rc, rd); s_do_xor(rd, ra); s_do_and(ra, rb); \
   s_do_xor (ra, rc); s_do_and(rc, rd); s_do_xor(rd, re); \
   s_do_xor (rc, rd); s_do_xor(rb, rd); s_do_and(rd, ra); \
   s_do_xor (rb, ra); s_do_xor(ra, rc); s_do_xor(re, rd); \
}
#define s_dec_1(i, ra, rb, rc, rd, re) {                  \
   s_do_xor(rb, rd); s_do_asgn(re, ra);                   \
   s_do_xor(ra, rc); s_do_not (rc, rc); s_do_or (re, rb); \
   s_do_xor(re, rd); s_do_and (rd, rb); s_do_xor(rb, rc); \
   s_do_and(rc, re); s_do_xor (re, rb); s_do_or (rb, rd); \
   s_do_xor(rd, ra); s_do_xor (rc, ra); s_do_or (ra, re); \
   s_do_xor(rc, re); s_do_xor (rb, ra);                   \
   s_do_xor(re, rb);                                      \
}
#define s_dec_2(i, ra, rb, rc, rd, re) {                  \
   s_do_xor(rc, rb); s_do_asgn(re, rd); s_do_not(rd, rd); \
   s_do_or (rd, rc); s_do_xor (rc, re); s_do_xor(re, ra); \
   s_do_xor(rd, rb); s_do_or  (rb, rc); s_do_xor(rc, ra); \
   s_do_xor(rb, re); s_do_or  (re, rd); s_do_xor(rc, rd); \
   s_do_xor(re, rc); s_do_and (rc, rb);                   \
   s_do_xor(rc, rd); s_do_xor (rd, re); s_do_xor(re, ra); \
}
#define s_dec_3(i, ra, rb, rc, rd, re) {                  \
   s_do_xor (rc, rb);                                     \
   s_do_asgn(re, rb); s_do_and(rb, rc);                   \
   s_do_xor (rb, ra); s_do_or (ra, re); s_do_xor(re, rd); \
   s_do_xor (ra, rd); s_do_or (rd, rb); s_do_xor(rb, rc); \
   s_do_xor (rb, rd); s_do_xor(ra, rc); s_do_xor(rc, rd); \
   s_do_and (rd, rb); s_do_xor(rb, ra); s_do_and(ra, rc); \
   s_do_xor (re, rd); s_do_xor(rd, ra); s_do_xor(ra, rb); \
}
#define s_dec_4(i, ra, rb, rc, rd, re) {                  \
   s_do_xor(rc, rd); s_do_asgn(re, ra); s_do_and(ra, rb); \
   s_do_xor(ra, rc); s_do_or  (rc, rd); s_do_not(re, re); \
   s_do_xor(rb, ra); s_do_xor (ra, rc); s_do_and(rc, re); \
   s_do_xor(rc, ra); s_do_or  (ra, re);                   \
   s_do_xor(ra, rd); s_do_and (rd, rc);                   \
   s_do_xor(re, rd); s_do_xor (rd, rb); s_do_and(rb, ra); \
   s_do_xor(re, rb); s_do_xor (ra, rd);                   \
}
#define s_dec_5(i, ra, rb, rc, rd, re) {                  \
   s_do_asgn(re, rb); s_do_or (rb, rc);                   \
   s_do_xor (rc, re); s_do_xor(rb, rd); s_do_and(rd, re); \
   s_do_xor (rc, rd); s_do_or (rd, ra); s_do_not(ra, ra); \
   s_do_xor (rd, rc); s_do_or (rc, ra); s_do_xor(re, rb); \
   s_do_xor (rc, re); s_do_and(re, ra); s_do_xor(ra, rb); \
   s_do_xor (rb, rd); s_do_and(ra, rc); s_do_xor(rc, rd); \
   s_do_xor (ra, rc); s_do_xor(rc, re); s_do_xor(re, rd); \
}
#define s_dec_6(i, ra, rb, rc, rd, re) {                  \
   s_do_xor (ra, rc);                                     \
   s_do_asgn(re, ra); s_do_and(ra, rd); s_do_xor(rc, rd); \
   s_do_xor (ra, rc); s_do_xor(rd, rb); s_do_or (rc, re); \
   s_do_xor (rc, rd); s_do_and(rd, ra); s_do_not(ra, ra); \
   s_do_xor (rd, rb); s_do_and(rb, rc); s_do_xor(re, ra); \
   s_do_xor (rd, re); s_do_xor(re, rc); s_do_xor(ra, rb); \
   s_do_xor (rc, ra);                                     \
}
#define s_dec_7(i, ra, rb, rc, rd, re) {                  \
   s_do_asgn(re, rd); s_do_and(rd, ra); s_do_xor(ra, rc); \
   s_do_or  (rc, re); s_do_xor(re, rb); s_do_not(ra, ra); \
   s_do_or  (rb, rd); s_do_xor(re, ra); s_do_and(ra, rc); \
   s_do_xor (ra, rb); s_do_and(rb, rc); s_do_xor(rd, rc); \
   s_do_xor (re, rd); s_do_and(rc, rd); s_do_or (rd, ra); \
   s_do_xor (rb, re); s_do_xor(rd, re); s_do_and(re, ra); \
   s_do_xor (re, rc);                                     \
}
#define s_apply_order_enc_00(fnc) fnc( 0, a, b, c, d, e)
#define s_apply_order_enc_01(fnc) fnc( 1, c, b, d, a, e)
#define s_apply_order_enc_02(fnc) fnc( 2, e, d, a, c, b)
#define s_apply_order_enc_03(fnc) fnc( 3, b, d, e, c, a)
#define s_apply_order_enc_04(fnc) fnc( 4, c, a, d, b, e)
#define s_apply_order_enc_05(fnc) fnc( 5, a, d, b, e, c)
#define s_apply_order_enc_06(fnc) fnc( 6, c, a, d, e, b)
#define s_apply_order_enc_07(fnc) fnc( 7, d, b, a, e, c)
#define s_apply_order_enc_08(fnc) fnc( 8, c, a, e, d, b)
#define s_apply_order_enc_09(fnc) fnc( 9, e, a, d, c, b)
#define s_apply_order_enc_10(fnc) fnc(10, b, d, c, e, a)
#define s_apply_order_enc_11(fnc) fnc(11, a, d, b, e, c)
#define s_apply_order_enc_12(fnc) fnc(12, e, c, d, a, b)
#define s_apply_order_enc_13(fnc) fnc(13, c, d, a, b, e)
#define s_apply_order_enc_14(fnc) fnc(14, e, c, d, b, a)
#define s_apply_order_enc_15(fnc) fnc(15, d, a, c, b, e)
#define s_apply_order_enc_16(fnc) fnc(16, e, c, b, d, a)
#define s_apply_order_enc_17(fnc) fnc(17, b, c, d, e, a)
#define s_apply_order_enc_18(fnc) fnc(18, a, d, e, b, c)
#define s_apply_order_enc_19(fnc) fnc(19, c, d, a, b, e)
#define s_apply_order_enc_20(fnc) fnc(20, b, e, d, c, a)
#define s_apply_order_enc_21(fnc) fnc(21, e, d, c, a, b)
#define s_apply_order_enc_22(fnc) fnc(22, b, e, d, a, c)
#define s_apply_order_enc_23(fnc) fnc(23, d, c, e, a, b)
#define s_apply_order_enc_24(fnc) fnc(24, b, e, a, d, c)
#define s_apply_order_enc_25(fnc) fnc(25, a, e, d, b, c)
#define s_apply_order_enc_26(fnc) fnc(26, c, d, b, a, e)
#define s_apply_order_enc_27(fnc) fnc(27, e, d, c, a, b)
#define s_apply_order_enc_28(fnc) fnc(28, a, b, d, e, c)
#define s_apply_order_enc_29(fnc) fnc(29, b, d, e, c, a)
#define s_apply_order_enc_30(fnc) fnc(30, a, b, d, c, e)
#define s_apply_order_enc_31(fnc) fnc(31, d, e, b, c, a)
#define s_apply_order_enc_32(fnc) fnc(32, a, b, c, d, e)
#define s_apply_order_dec_32(fnc) fnc(32, a, b, c, d, e)
#define s_apply_order_dec_31(fnc) fnc(31, b, d, a, e, c)
#define s_apply_order_dec_30(fnc) fnc(30, a, c, e, b, d)
#define s_apply_order_dec_29(fnc) fnc(29, c, d, a, e, b)
#define s_apply_order_dec_28(fnc) fnc(28, c, a, b, e, d)
#define s_apply_order_dec_27(fnc) fnc(27, b, c, d, e, a)
#define s_apply_order_dec_26(fnc) fnc(26, c, a, e, d, b)
#define s_apply_order_dec_25(fnc) fnc(25, b, a, e, d, c)
#define s_apply_order_dec_24(fnc) fnc(24, e, c, a, b, d)
#define s_apply_order_dec_23(fnc) fnc(23, c, b, e, d, a)
#define s_apply_order_dec_22(fnc) fnc(22, e, a, d, c, b)
#define s_apply_order_dec_21(fnc) fnc(21, a, b, e, d, c)
#define s_apply_order_dec_20(fnc) fnc(20, a, e, c, d, b)
#define s_apply_order_dec_19(fnc) fnc(19, c, a, b, d, e)
#define s_apply_order_dec_18(fnc) fnc(18, a, e, d, b, c)
#define s_apply_order_dec_17(fnc) fnc(17, c, e, d, b, a)
#define s_apply_order_dec_16(fnc) fnc(16, d, a, e, c, b)
#define s_apply_order_dec_15(fnc) fnc(15, a, c, d, b, e)
#define s_apply_order_dec_14(fnc) fnc(14, d, e, b, a, c)
#define s_apply_order_dec_13(fnc) fnc(13, e, c, d, b, a)
#define s_apply_order_dec_12(fnc) fnc(12, e, d, a, b, c)
#define s_apply_order_dec_11(fnc) fnc(11, a, e, c, b, d)
#define s_apply_order_dec_10(fnc) fnc(10, e, d, b, c, a)
#define s_apply_order_dec_09(fnc) fnc( 9, a, d, b, c, e)
#define s_apply_order_dec_08(fnc) fnc( 8, b, e, d, a, c)
#define s_apply_order_dec_07(fnc) fnc( 7, e, a, b, c, d)
#define s_apply_order_dec_06(fnc) fnc( 6, b, d, c, e, a)
#define s_apply_order_dec_05(fnc) fnc( 5, d, a, b, c, e)
#define s_apply_order_dec_04(fnc) fnc( 4, d, b, e, c, a)
#define s_apply_order_dec_03(fnc) fnc( 3, e, d, a, c, b)
#define s_apply_order_dec_02(fnc) fnc( 2, d, b, c, a, e)
#define s_apply_order_dec_01(fnc) fnc( 1, e, b, c, a, d)
#define s_apply_order_dec_00(fnc) fnc( 0, c, d, b, e, a)


/* linear transformation */
#define s_lt(i,a,b,c,d,e)  {                                 \
                            a = ROLc(a, 13);                \
                            c = ROLc(c, 3);                 \
                            d = ROLc(d ^ c ^ (a << 3), 7);  \
                            b = ROLc(b ^ a ^ c, 1);         \
                            a = ROLc(a ^ b ^ d, 5);         \
                            c = ROLc(c ^ d ^ (b << 7), 22); \
                          }

/* inverse linear transformation */
#define s_ilt(i,a,b,c,d,e) {                                 \
                            c = RORc(c, 22);                \
                            a = RORc(a, 5);                 \
                            c ^= d ^ (b << 7);              \
                            a ^= b ^ d;                     \
                            b = RORc(b, 1);                 \
                            d = RORc(d, 7) ^ c ^ (a << 3);  \
                            b ^= a ^ c;                     \
                            c = RORc(c, 3);                 \
                            a = RORc(a, 13);                \
                          }

/* order of output from S-box functions */
#define s_beforeS0(f) f(0,a,b,c,d,e)
#define s_afterS0(f)  f(1,b,e,c,a,d)
#define s_afterS1(f)  f(2,c,b,a,e,d)
#define s_afterS2(f)  f(3,a,e,b,d,c)
#define s_afterS3(f)  f(4,e,b,d,c,a)
#define s_afterS4(f)  f(5,b,a,e,c,d)
#define s_afterS5(f)  f(6,a,c,b,e,d)
#define s_afterS6(f)  f(7,a,c,d,b,e)
#define s_afterS7(f)  f(8,d,e,b,a,c)

/* order of output from inverse S-box functions */
#define s_beforeI7(f) f(8,a,b,c,d,e)
#define s_afterI7(f)  f(7,d,a,b,e,c)
#define s_afterI6(f)  f(6,a,b,c,e,d)
#define s_afterI5(f)  f(5,b,d,e,c,a)
#define s_afterI4(f)  f(4,b,c,e,a,d)
#define s_afterI3(f)  f(3,a,b,e,c,d)
#define s_afterI2(f)  f(2,b,d,e,c,a)
#define s_afterI1(f)  f(1,a,b,c,e,d)
#define s_afterI0(f)  f(0,a,d,b,e,c)

/* The instruction sequences for the S-box functions
 * come from Dag Arne Osvik's paper "Speeding up Serpent".
 */

#define s_s0(i, r0, r1, r2, r3, r4) { \
   r3 ^= r0;   \
   r4 = r1;    \
   r1 &= r3;   \
   r4 ^= r2;   \
   r1 ^= r0;   \
   r0 |= r3;   \
   r0 ^= r4;   \
   r4 ^= r3;   \
   r3 ^= r2;   \
   r2 |= r1;   \
   r2 ^= r4;   \
   r4 = ~r4;   \
   r4 |= r1;   \
   r1 ^= r3;   \
   r1 ^= r4;   \
   r3 |= r0;   \
   r1 ^= r3;   \
   r4 ^= r3;   \
}

#define s_i0(i, r0, r1, r2, r3, r4) { \
   r2 = ~r2;   \
   r4 = r1;    \
   r1 |= r0;   \
   r4 = ~r4;   \
   r1 ^= r2;   \
   r2 |= r4;   \
   r1 ^= r3;   \
   r0 ^= r4;   \
   r2 ^= r0;   \
   r0 &= r3;   \
   r4 ^= r0;   \
   r0 |= r1;   \
   r0 ^= r2;   \
   r3 ^= r4;   \
   r2 ^= r1;   \
   r3 ^= r0;   \
   r3 ^= r1;   \
   r2 &= r3;   \
   r4 ^= r2;   \
}

#define s_s1(i, r0, r1, r2, r3, r4) { \
   r0 = ~r0;   \
   r2 = ~r2;   \
   r4 = r0;    \
   r0 &= r1;   \
   r2 ^= r0;   \
   r0 |= r3;   \
   r3 ^= r2;   \
   r1 ^= r0;   \
   r0 ^= r4;   \
   r4 |= r1;   \
   r1 ^= r3;   \
   r2 |= r0;   \
   r2 &= r4;   \
   r0 ^= r1;   \
   r1 &= r2;   \
   r1 ^= r0;   \
   r0 &= r2;   \
   r0 ^= r4;   \
}

#define s_i1(i, r0, r1, r2, r3, r4) { \
   r4 = r1;    \
   r1 ^= r3;   \
   r3 &= r1;   \
   r4 ^= r2;   \
   r3 ^= r0;   \
   r0 |= r1;   \
   r2 ^= r3;   \
   r0 ^= r4;   \
   r0 |= r2;   \
   r1 ^= r3;   \
   r0 ^= r1;   \
   r1 |= r3;   \
   r1 ^= r0;   \
   r4 = ~r4;   \
   r4 ^= r1;   \
   r1 |= r0;   \
   r1 ^= r0;   \
   r1 |= r4;   \
   r3 ^= r1;   \
}

#define s_s2(i, r0, r1, r2, r3, r4) { \
   r4 = r0;    \
   r0 &= r2;   \
   r0 ^= r3;   \
   r2 ^= r1;   \
   r2 ^= r0;   \
   r3 |= r4;   \
   r3 ^= r1;   \
   r4 ^= r2;   \
   r1 = r3;    \
   r3 |= r4;   \
   r3 ^= r0;   \
   r0 &= r1;   \
   r4 ^= r0;   \
   r1 ^= r3;   \
   r1 ^= r4;   \
   r4 = ~r4;   \
}

#define s_i2(i, r0, r1, r2, r3, r4) { \
   r2 ^= r3;   \
   r3 ^= r0;   \
   r4 = r3;    \
   r3 &= r2;   \
   r3 ^= r1;   \
   r1 |= r2;   \
   r1 ^= r4;   \
   r4 &= r3;   \
   r2 ^= r3;   \
   r4 &= r0;   \
   r4 ^= r2;   \
   r2 &= r1;   \
   r2 |= r0;   \
   r3 = ~r3;   \
   r2 ^= r3;   \
   r0 ^= r3;   \
   r0 &= r1;   \
   r3 ^= r4;   \
   r3 ^= r0;   \
}

#define s_s3(i, r0, r1, r2, r3, r4) { \
   r4 = r0;    \
   r0 |= r3;   \
   r3 ^= r1;   \
   r1 &= r4;   \
   r4 ^= r2;   \
   r2 ^= r3;   \
   r3 &= r0;   \
   r4 |= r1;   \
   r3 ^= r4;   \
   r0 ^= r1;   \
   r4 &= r0;   \
   r1 ^= r3;   \
   r4 ^= r2;   \
   r1 |= r0;   \
   r1 ^= r2;   \
   r0 ^= r3;   \
   r2 = r1;    \
   r1 |= r3;   \
   r1 ^= r0;   \
}

#define s_i3(i, r0, r1, r2, r3, r4) { \
   r4 = r2;    \
   r2 ^= r1;   \
   r1 &= r2;   \
   r1 ^= r0;   \
   r0 &= r4;   \
   r4 ^= r3;   \
   r3 |= r1;   \
   r3 ^= r2;   \
   r0 ^= r4;   \
   r2 ^= r0;   \
   r0 |= r3;   \
   r0 ^= r1;   \
   r4 ^= r2;   \
   r2 &= r3;   \
   r1 |= r3;   \
   r1 ^= r2;   \
   r4 ^= r0;   \
   r2 ^= r4;   \
}

#define s_s4(i, r0, r1, r2, r3, r4) { \
   r1 ^= r3;   \
   r3 = ~r3;   \
   r2 ^= r3;   \
   r3 ^= r0;   \
   r4 = r1;    \
   r1 &= r3;   \
   r1 ^= r2;   \
   r4 ^= r3;   \
   r0 ^= r4;   \
   r2 &= r4;   \
   r2 ^= r0;   \
   r0 &= r1;   \
   r3 ^= r0;   \
   r4 |= r1;   \
   r4 ^= r0;   \
   r0 |= r3;   \
   r0 ^= r2;   \
   r2 &= r3;   \
   r0 = ~r0;   \
   r4 ^= r2;   \
}

#define s_i4(i, r0, r1, r2, r3, r4) { \
   r4 = r2;    \
   r2 &= r3;   \
   r2 ^= r1;   \
   r1 |= r3;   \
   r1 &= r0;   \
   r4 ^= r2;   \
   r4 ^= r1;   \
   r1 &= r2;   \
   r0 = ~r0;   \
   r3 ^= r4;   \
   r1 ^= r3;   \
   r3 &= r0;   \
   r3 ^= r2;   \
   r0 ^= r1;   \
   r2 &= r0;   \
   r3 ^= r0;   \
   r2 ^= r4;   \
   r2 |= r3;   \
   r3 ^= r0;   \
   r2 ^= r1;   \
}

#define s_s5(i, r0, r1, r2, r3, r4) { \
   r0 ^= r1;   \
   r1 ^= r3;   \
   r3 = ~r3;   \
   r4 = r1;    \
   r1 &= r0;   \
   r2 ^= r3;   \
   r1 ^= r2;   \
   r2 |= r4;   \
   r4 ^= r3;   \
   r3 &= r1;   \
   r3 ^= r0;   \
   r4 ^= r1;   \
   r4 ^= r2;   \
   r2 ^= r0;   \
   r0 &= r3;   \
   r2 = ~r2;   \
   r0 ^= r4;   \
   r4 |= r3;   \
   r2 ^= r4;   \
}

#define s_i5(i, r0, r1, r2, r3, r4) { \
   r1 = ~r1;   \
   r4 = r3;    \
   r2 ^= r1;   \
   r3 |= r0;   \
   r3 ^= r2;   \
   r2 |= r1;   \
   r2 &= r0;   \
   r4 ^= r3;   \
   r2 ^= r4;   \
   r4 |= r0;   \
   r4 ^= r1;   \
   r1 &= r2;   \
   r1 ^= r3;   \
   r4 ^= r2;   \
   r3 &= r4;   \
   r4 ^= r1;   \
   r3 ^= r0;   \
   r3 ^= r4;   \
   r4 = ~r4;   \
}

#define s_s6(i, r0, r1, r2, r3, r4) { \
   r2 = ~r2;   \
   r4 = r3;    \
   r3 &= r0;   \
   r0 ^= r4;   \
   r3 ^= r2;   \
   r2 |= r4;   \
   r1 ^= r3;   \
   r2 ^= r0;   \
   r0 |= r1;   \
   r2 ^= r1;   \
   r4 ^= r0;   \
   r0 |= r3;   \
   r0 ^= r2;   \
   r4 ^= r3;   \
   r4 ^= r0;   \
   r3 = ~r3;   \
   r2 &= r4;   \
   r2 ^= r3;   \
}

#define s_i6(i, r0, r1, r2, r3, r4) { \
   r0 ^= r2;   \
   r4 = r2;    \
   r2 &= r0;   \
   r4 ^= r3;   \
   r2 = ~r2;   \
   r3 ^= r1;   \
   r2 ^= r3;   \
   r4 |= r0;   \
   r0 ^= r2;   \
   r3 ^= r4;   \
   r4 ^= r1;   \
   r1 &= r3;   \
   r1 ^= r0;   \
   r0 ^= r3;   \
   r0 |= r2;   \
   r3 ^= r1;   \
   r4 ^= r0;   \
}

#define s_s7(i, r0, r1, r2, r3, r4) { \
   r4 = r2;    \
   r2 &= r1;   \
   r2 ^= r3;   \
   r3 &= r1;   \
   r4 ^= r2;   \
   r2 ^= r1;   \
   r1 ^= r0;   \
   r0 |= r4;   \
   r0 ^= r2;   \
   r3 ^= r1;   \
   r2 ^= r3;   \
   r3 &= r0;   \
   r3 ^= r4;   \
   r4 ^= r2;   \
   r2 &= r0;   \
   r4 = ~r4;   \
   r2 ^= r4;   \
   r4 &= r0;   \
   r1 ^= r3;   \
   r4 ^= r1;   \
}

#define s_i7(i, r0, r1, r2, r3, r4) { \
   r4 = r2;    \
   r2 ^= r0;   \
   r0 &= r3;   \
   r2 = ~r2;   \
   r4 |= r3;   \
   r3 ^= r1;   \
   r1 |= r0;   \
   r0 ^= r2;   \
   r2 &= r4;   \
   r1 ^= r2;   \
   r2 ^= r0;   \
   r0 |= r2;   \
   r3 &= r4;   \
   r0 ^= r3;   \
   r4 ^= r1;   \
   r3 ^= r4;   \
   r4 |= r0;   \
   r3 ^= r2;   \
   r4 ^= r2;   \
}

/* key xor */
#define s_kx(r, a, b, c, d, e) { \
   a ^= k[4 * r + 0];   \
   b ^= k[4 * r + 1];   \
   c ^= k[4 * r + 2];   \
   d ^= k[4 * r + 3];   \
}

#define s_lk(r, a, b, c, d, e) { \
   a = k[(8-r)*4 + 0];  \
   b = k[(8-r)*4 + 1];  \
   c = k[(8-r)*4 + 2];  \
   d = k[(8-r)*4 + 3];  \
}

#define s_sk(r, a, b, c, d, e) { \
   k[(8-r)*4 + 4] = a;  \
   k[(8-r)*4 + 5] = b;  \
   k[(8-r)*4 + 6] = c;  \
   k[(8-r)*4 + 7] = d;  \
}

#define s_setup_key s_serpent_setup_key
static int s_setup_key(const unsigned char *key, int keylen, int rounds, ulong32 *k)
{
   int i;
   ulong32 t;
   ulong32 k0[8] = { 0 }; /* zero-initialize */
   ulong32 a, b, c, d, e;

   for (i = 0; i < 8 && i < keylen/4; ++i) {
      LOAD32L(k0[i], key + i * 4);
   }
   if (keylen < 32) {
      k0[keylen/4] |= (ulong32)1 << ((keylen%4)*8);
    }

   t = k0[7];
   for (i = 0; i < 8; ++i) {
      k[i] = k0[i] = t = ROLc(k0[i] ^ k0[(i+3)%8] ^ k0[(i+5)%8] ^ t ^ 0x9e3779b9 ^ i, 11);
   }
   for (i = 8; i < 4*(rounds+1); ++i) {
      k[i] = t = ROLc(k[i-8] ^ k[i-5] ^ k[i-3] ^ t ^ 0x9e3779b9 ^ i, 11);
   }
   k -= 20;

   for (i = 0; i < rounds/8; i++) {
      s_afterS2(s_lk);  s_afterS2(s_s3);  s_afterS3(s_sk);
      s_afterS1(s_lk);  s_afterS1(s_s2);  s_afterS2(s_sk);
      s_afterS0(s_lk);  s_afterS0(s_s1);  s_afterS1(s_sk);
      s_beforeS0(s_lk); s_beforeS0(s_s0); s_afterS0(s_sk);
      k += 8*4;
      s_afterS6(s_lk); s_afterS6(s_s7); s_afterS7(s_sk);
      s_afterS5(s_lk); s_afterS5(s_s6); s_afterS6(s_sk);
      s_afterS4(s_lk); s_afterS4(s_s5); s_afterS5(s_sk);
      s_afterS3(s_lk); s_afterS3(s_s4); s_afterS4(s_sk);
   }
   s_afterS2(s_lk); s_afterS2(s_s3); s_afterS3(s_sk);

   return CRYPT_OK;
}

int serpent_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
   int err;

   LTC_ARGCHK(key  != NULL);
   LTC_ARGCHK(skey != NULL);

   if (num_rounds != 0 && num_rounds != 32) return CRYPT_INVALID_ROUNDS;
   if (keylen != 16 && keylen != 24 && keylen != 32) return CRYPT_INVALID_KEYSIZE;

   err = s_setup_key(key, keylen, 32, skey->serpent.k);
#ifdef LTC_CLEAN_STACK
   burn_stack(sizeof(ulong32) * 14 + sizeof(int));
#endif
   return err;
}

static LTC_INLINE void s_serpent_accel_ecb_32_bit_load_one(ulong32 *x, const unsigned char *bytes)
{
   *x =
      ((ulong32)(((ulong32)(bytes[0])) << (0 * CHAR_BIT))) |
      ((ulong32)(((ulong32)(bytes[1])) << (1 * CHAR_BIT))) |
      ((ulong32)(((ulong32)(bytes[2])) << (2 * CHAR_BIT))) |
      ((ulong32)(((ulong32)(bytes[3])) << (3 * CHAR_BIT))) |
   0;
}

static LTC_INLINE void s_serpent_accel_ecb_32_bit_store_one(const ulong32 *x, unsigned char *bytes)
{
   bytes[0] = ((unsigned char)(((ulong32)((*x)) >> (0 * CHAR_BIT)) & 0xff));
   bytes[1] = ((unsigned char)(((ulong32)((*x)) >> (1 * CHAR_BIT)) & 0xff));
   bytes[2] = ((unsigned char)(((ulong32)((*x)) >> (2 * CHAR_BIT)) & 0xff));
   bytes[3] = ((unsigned char)(((ulong32)((*x)) >> (3 * CHAR_BIT)) & 0xff));
}

static LTC_INLINE void s_serpent_accel_ecb_32_bit_load_four(ulong32 *pa, ulong32 *pb, ulong32 *pc, ulong32 *pd, const unsigned char *bytes)
{
   s_serpent_accel_ecb_32_bit_load_one(pa, &bytes[0 * sizeof(ulong32)]);
   s_serpent_accel_ecb_32_bit_load_one(pb, &bytes[1 * sizeof(ulong32)]);
   s_serpent_accel_ecb_32_bit_load_one(pc, &bytes[2 * sizeof(ulong32)]);
   s_serpent_accel_ecb_32_bit_load_one(pd, &bytes[3 * sizeof(ulong32)]);
}

static LTC_INLINE void s_serpent_accel_ecb_32_bit_store_four(const ulong32 *pa, const ulong32 *pb, const ulong32 *pc, const ulong32 *pd, unsigned char *bytes)
{
   s_serpent_accel_ecb_32_bit_store_one(pa, &bytes[0 * sizeof(ulong32)]);
   s_serpent_accel_ecb_32_bit_store_one(pb, &bytes[1 * sizeof(ulong32)]);
   s_serpent_accel_ecb_32_bit_store_one(pc, &bytes[2 * sizeof(ulong32)]);
   s_serpent_accel_ecb_32_bit_store_one(pd, &bytes[3 * sizeof(ulong32)]);
}

static LTC_INLINE int s_serpent_accel_ecb_encrypt_32_bit(const unsigned char *pt, unsigned char *ct, unsigned long blocks, const symmetric_key *skey)
{
   #define blocks_at_a_time (32 / 32)
   #define s_do_broadcast(x) x
   #define s_do_asgn(a, b) a = b
   #define s_do_or(a, b) a |= b
   #define s_do_xor(a, b) a ^= b
   #define s_do_and(a, b) a &= b
   #define s_do_not(a, b) a =~ b
   #define s_do_rol(x, i) x = ROL(x, i)
   #define s_do_shl(a, b, c) a = b << c

   const unsigned char *in;
   unsigned char *out;
   const ulong32* k;
   unsigned long iblock;
   ulong32 a, b, c, d, e;

   LTC_ARGCHK(pt);
   LTC_ARGCHK(ct);
   LTC_ARGCHK(blocks % blocks_at_a_time == 0);
   LTC_ARGCHK(skey);

   in = pt;
   out = ct;
   k = &skey->serpent.k[0];
   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      s_serpent_accel_ecb_32_bit_load_four(&a, &b, &c, &d, in);
      s_apply_order_enc_00(s_apply_key);
      s_apply_order_enc_00(s_enc_0); s_apply_order_enc_01(s_apply_lk);
      s_apply_order_enc_01(s_enc_1); s_apply_order_enc_02(s_apply_lk);
      s_apply_order_enc_02(s_enc_2); s_apply_order_enc_03(s_apply_lk);
      s_apply_order_enc_03(s_enc_3); s_apply_order_enc_04(s_apply_lk);
      s_apply_order_enc_04(s_enc_4); s_apply_order_enc_05(s_apply_lk);
      s_apply_order_enc_05(s_enc_5); s_apply_order_enc_06(s_apply_lk);
      s_apply_order_enc_06(s_enc_6); s_apply_order_enc_07(s_apply_lk);
      s_apply_order_enc_07(s_enc_7); s_apply_order_enc_08(s_apply_lk);
      s_apply_order_enc_08(s_enc_0); s_apply_order_enc_09(s_apply_lk);
      s_apply_order_enc_09(s_enc_1); s_apply_order_enc_10(s_apply_lk);
      s_apply_order_enc_10(s_enc_2); s_apply_order_enc_11(s_apply_lk);
      s_apply_order_enc_11(s_enc_3); s_apply_order_enc_12(s_apply_lk);
      s_apply_order_enc_12(s_enc_4); s_apply_order_enc_13(s_apply_lk);
      s_apply_order_enc_13(s_enc_5); s_apply_order_enc_14(s_apply_lk);
      s_apply_order_enc_14(s_enc_6); s_apply_order_enc_15(s_apply_lk);
      s_apply_order_enc_15(s_enc_7); s_apply_order_enc_16(s_apply_lk);
      s_apply_order_enc_16(s_enc_0); s_apply_order_enc_17(s_apply_lk);
      s_apply_order_enc_17(s_enc_1); s_apply_order_enc_18(s_apply_lk);
      s_apply_order_enc_18(s_enc_2); s_apply_order_enc_19(s_apply_lk);
      s_apply_order_enc_19(s_enc_3); s_apply_order_enc_20(s_apply_lk);
      s_apply_order_enc_20(s_enc_4); s_apply_order_enc_21(s_apply_lk);
      s_apply_order_enc_21(s_enc_5); s_apply_order_enc_22(s_apply_lk);
      s_apply_order_enc_22(s_enc_6); s_apply_order_enc_23(s_apply_lk);
      s_apply_order_enc_23(s_enc_7); s_apply_order_enc_24(s_apply_lk);
      s_apply_order_enc_24(s_enc_0); s_apply_order_enc_25(s_apply_lk);
      s_apply_order_enc_25(s_enc_1); s_apply_order_enc_26(s_apply_lk);
      s_apply_order_enc_26(s_enc_2); s_apply_order_enc_27(s_apply_lk);
      s_apply_order_enc_27(s_enc_3); s_apply_order_enc_28(s_apply_lk);
      s_apply_order_enc_28(s_enc_4); s_apply_order_enc_29(s_apply_lk);
      s_apply_order_enc_29(s_enc_5); s_apply_order_enc_30(s_apply_lk);
      s_apply_order_enc_30(s_enc_6); s_apply_order_enc_31(s_apply_lk);
      s_apply_order_enc_31(s_enc_7); s_apply_order_enc_32(s_apply_key);
      s_serpent_accel_ecb_32_bit_store_four(&a, &b, &c, &d, out);
      in += blocks_at_a_time * serpent_block_len;
      out += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
   #undef s_do_broadcast
   #undef s_do_asgn
   #undef s_do_or
   #undef s_do_xor
   #undef s_do_and
   #undef s_do_not
   #undef s_do_rol
   #undef s_do_shl
}

static LTC_INLINE int s_serpent_accel_ecb_decrypt_32_bit(const unsigned char *ct, unsigned char *pt, unsigned long blocks, const symmetric_key *skey)
{
   #define blocks_at_a_time (32 / 32)
   #define s_do_broadcast(x) x
   #define s_do_asgn(a, b) a = b
   #define s_do_or(a, b) a |= b
   #define s_do_xor(a, b) a ^= b
   #define s_do_and(a, b) a &= b
   #define s_do_not(a, b) a =~ b
   #define s_do_rol(x, i) x = ROL(x, i)
   #define s_do_ror(x, i) x = ROR(x, i)
   #define s_do_shl(a, b, c) a = b << c

   const unsigned char *in;
   unsigned char *out;
   const ulong32* k;
   unsigned long iblock;
   ulong32 a, b, c, d, e;

   LTC_ARGCHK(ct);
   LTC_ARGCHK(pt);
   LTC_ARGCHK(blocks % blocks_at_a_time == 0);
   LTC_ARGCHK(skey);

   in = ct;
   out = pt;
   k = &skey->serpent.k[0];
   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      s_serpent_accel_ecb_32_bit_load_four(&a, &b, &c, &d, in);
      s_apply_order_dec_32(s_apply_key);
      s_apply_order_dec_32(s_dec_7); s_apply_order_dec_31(s_apply_kl);
      s_apply_order_dec_31(s_dec_6); s_apply_order_dec_30(s_apply_kl);
      s_apply_order_dec_30(s_dec_5); s_apply_order_dec_29(s_apply_kl);
      s_apply_order_dec_29(s_dec_4); s_apply_order_dec_28(s_apply_kl);
      s_apply_order_dec_28(s_dec_3); s_apply_order_dec_27(s_apply_kl);
      s_apply_order_dec_27(s_dec_2); s_apply_order_dec_26(s_apply_kl);
      s_apply_order_dec_26(s_dec_1); s_apply_order_dec_25(s_apply_kl);
      s_apply_order_dec_25(s_dec_0); s_apply_order_dec_24(s_apply_kl);
      s_apply_order_dec_24(s_dec_7); s_apply_order_dec_23(s_apply_kl);
      s_apply_order_dec_23(s_dec_6); s_apply_order_dec_22(s_apply_kl);
      s_apply_order_dec_22(s_dec_5); s_apply_order_dec_21(s_apply_kl);
      s_apply_order_dec_21(s_dec_4); s_apply_order_dec_20(s_apply_kl);
      s_apply_order_dec_20(s_dec_3); s_apply_order_dec_19(s_apply_kl);
      s_apply_order_dec_19(s_dec_2); s_apply_order_dec_18(s_apply_kl);
      s_apply_order_dec_18(s_dec_1); s_apply_order_dec_17(s_apply_kl);
      s_apply_order_dec_17(s_dec_0); s_apply_order_dec_16(s_apply_kl);
      s_apply_order_dec_16(s_dec_7); s_apply_order_dec_15(s_apply_kl);
      s_apply_order_dec_15(s_dec_6); s_apply_order_dec_14(s_apply_kl);
      s_apply_order_dec_14(s_dec_5); s_apply_order_dec_13(s_apply_kl);
      s_apply_order_dec_13(s_dec_4); s_apply_order_dec_12(s_apply_kl);
      s_apply_order_dec_12(s_dec_3); s_apply_order_dec_11(s_apply_kl);
      s_apply_order_dec_11(s_dec_2); s_apply_order_dec_10(s_apply_kl);
      s_apply_order_dec_10(s_dec_1); s_apply_order_dec_09(s_apply_kl);
      s_apply_order_dec_09(s_dec_0); s_apply_order_dec_08(s_apply_kl);
      s_apply_order_dec_08(s_dec_7); s_apply_order_dec_07(s_apply_kl);
      s_apply_order_dec_07(s_dec_6); s_apply_order_dec_06(s_apply_kl);
      s_apply_order_dec_06(s_dec_5); s_apply_order_dec_05(s_apply_kl);
      s_apply_order_dec_05(s_dec_4); s_apply_order_dec_04(s_apply_kl);
      s_apply_order_dec_04(s_dec_3); s_apply_order_dec_03(s_apply_kl);
      s_apply_order_dec_03(s_dec_2); s_apply_order_dec_02(s_apply_kl);
      s_apply_order_dec_02(s_dec_1); s_apply_order_dec_01(s_apply_kl);
      s_apply_order_dec_01(s_dec_0); s_apply_order_dec_00(s_apply_key);
      s_serpent_accel_ecb_32_bit_store_four(&c, &d, &b, &e, out);
      in += blocks_at_a_time * serpent_block_len;
      out += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
   #undef s_do_broadcast
   #undef s_do_asgn
   #undef s_do_or
   #undef s_do_xor
   #undef s_do_and
   #undef s_do_not
   #undef s_do_rol
   #undef s_do_ror
   #undef s_do_shl
}

#if defined LTC_SERPENT_ACCEL_64_BIT

static LTC_INLINE void s_serpent_accel_ecb_64_bit_load_one(ulong64 *x, const unsigned char *bytes)
{
   *x =
      ((ulong64)(((ulong64)(bytes[0])) << (0 * CHAR_BIT))) |
      ((ulong64)(((ulong64)(bytes[1])) << (1 * CHAR_BIT))) |
      ((ulong64)(((ulong64)(bytes[2])) << (2 * CHAR_BIT))) |
      ((ulong64)(((ulong64)(bytes[3])) << (3 * CHAR_BIT))) |
      ((ulong64)(((ulong64)(bytes[4])) << (4 * CHAR_BIT))) |
      ((ulong64)(((ulong64)(bytes[5])) << (5 * CHAR_BIT))) |
      ((ulong64)(((ulong64)(bytes[6])) << (6 * CHAR_BIT))) |
      ((ulong64)(((ulong64)(bytes[7])) << (7 * CHAR_BIT))) |
   0;
}

static LTC_INLINE void s_serpent_accel_ecb_64_bit_store_one(const ulong64 *x, unsigned char *bytes)
{
   bytes[0] = ((unsigned char)(((ulong64)((*x)) >> (0 * CHAR_BIT)) & 0xff));
   bytes[1] = ((unsigned char)(((ulong64)((*x)) >> (1 * CHAR_BIT)) & 0xff));
   bytes[2] = ((unsigned char)(((ulong64)((*x)) >> (2 * CHAR_BIT)) & 0xff));
   bytes[3] = ((unsigned char)(((ulong64)((*x)) >> (3 * CHAR_BIT)) & 0xff));
   bytes[4] = ((unsigned char)(((ulong64)((*x)) >> (4 * CHAR_BIT)) & 0xff));
   bytes[5] = ((unsigned char)(((ulong64)((*x)) >> (5 * CHAR_BIT)) & 0xff));
   bytes[6] = ((unsigned char)(((ulong64)((*x)) >> (6 * CHAR_BIT)) & 0xff));
   bytes[7] = ((unsigned char)(((ulong64)((*x)) >> (7 * CHAR_BIT)) & 0xff));
}

static LTC_INLINE void s_serpent_accel_ecb_64_bit_load_four(ulong64 *pa, ulong64 *pb, ulong64 *pc, ulong64 *pd, const unsigned char *bytes)
{
   ulong64 ta, tb, tc, td;
   ulong64 ra, rb, rc, rd;
   ulong64 xa, xb;

   s_serpent_accel_ecb_64_bit_load_one(&ta, &bytes[0 * sizeof(ulong64)]);
   s_serpent_accel_ecb_64_bit_load_one(&tb, &bytes[1 * sizeof(ulong64)]);
   s_serpent_accel_ecb_64_bit_load_one(&tc, &bytes[2 * sizeof(ulong64)]);
   s_serpent_accel_ecb_64_bit_load_one(&td, &bytes[3 * sizeof(ulong64)]);
   xa = ta << 32;
   xa >>= 32;
   xb = tc << 32;
   ra = xa | xb;
   xa = ta >> 32;
   xb = tc >> 32;
   xb <<= 32;
   rb = xa | xb;
   xa = tb << 32;
   xa >>= 32;
   xb = td << 32;
   rc = xa | xb;
   xa = tb >> 32;
   xb = td >> 32;
   xb <<= 32;
   rd = xa | xb;
   *pa = ra;
   *pb = rb;
   *pc = rc;
   *pd = rd;
}

static LTC_INLINE void s_serpent_accel_ecb_64_bit_store_four(const ulong64 *pa, const ulong64 *pb, const ulong64 *pc, const ulong64 *pd, unsigned char *bytes)
{
   ulong64 ta, tb, tc, td;
   ulong64 ra, rb, rc, rd;
   ulong64 xa, xb;

   ta = *pa;
   tb = *pb;
   tc = *pc;
   td = *pd;
   xa = ta << 32;
   xa >>= 32;
   xb = tb << 32;
   ra = xa | xb;
   xa = tc << 32;
   xa >>= 32;
   xb = td << 32;
   rb = xa | xb;
   xa = ta >> 32;
   xb = tb >> 32;
   xb <<= 32;
   rc = xa | xb;
   xa = tc >> 32;
   xb = td >> 32;
   xb <<= 32;
   rd = xa | xb;
   s_serpent_accel_ecb_64_bit_store_one(&ra, &bytes[0 * sizeof(ulong64)]);
   s_serpent_accel_ecb_64_bit_store_one(&rb, &bytes[1 * sizeof(ulong64)]);
   s_serpent_accel_ecb_64_bit_store_one(&rc, &bytes[2 * sizeof(ulong64)]);
   s_serpent_accel_ecb_64_bit_store_one(&rd, &bytes[3 * sizeof(ulong64)]);
}

static LTC_INLINE int s_serpent_accel_ecb_encrypt_64_bit(const unsigned char *pt, unsigned char *ct, unsigned long blocks, const symmetric_key *skey)
{
   #define blocks_at_a_time (64 / 32)
   #define s_do_split_general(x, i) ((ulong32)((x) >> ((i) * 32)))
   #define s_do_split_lo(x) s_do_split_general(x, 0)
   #define s_do_split_hi(x) s_do_split_general(x, 1)
   #define s_do_join(lo, hi) ((((ulong64)(hi)) << 32) | ((ulong64)(lo)))
   #define s_do_broadcast(x) s_do_join(x, x)
   #define s_do_asgn(a, b) a = b
   #define s_do_or(a, b) a |= b
   #define s_do_xor(a, b) a ^= b
   #define s_do_and(a, b) a &= b
   #define s_do_not(a, b) a =~ b
   #define s_do_rol(x, i) x = s_do_join( \
      ROL(s_do_split_lo(x), i),          \
      ROL(s_do_split_hi(x), i))
   #define s_do_ror(x, i) x = s_do_join( \
      ROR(s_do_split_lo(x), i),          \
      ROR(s_do_split_hi(x), i))
   #define s_do_shl(a, b, c) a = s_do_join( \
      (s_do_split_lo(b) << c),              \
      (s_do_split_hi(b) << c))

   const unsigned char *in;
   unsigned char *out;
   const ulong32* k;
   unsigned long iblock;
   ulong64 a, b, c, d, e;

   LTC_ARGCHK(pt);
   LTC_ARGCHK(ct);
   LTC_ARGCHK(blocks % blocks_at_a_time == 0);
   LTC_ARGCHK(skey);

   in = pt;
   out = ct;
   k = &skey->serpent.k[0];
   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      s_serpent_accel_ecb_64_bit_load_four(&a, &b, &c, &d, in);
      s_apply_order_enc_00(s_apply_key);
      s_apply_order_enc_00(s_enc_0); s_apply_order_enc_01(s_apply_lk);
      s_apply_order_enc_01(s_enc_1); s_apply_order_enc_02(s_apply_lk);
      s_apply_order_enc_02(s_enc_2); s_apply_order_enc_03(s_apply_lk);
      s_apply_order_enc_03(s_enc_3); s_apply_order_enc_04(s_apply_lk);
      s_apply_order_enc_04(s_enc_4); s_apply_order_enc_05(s_apply_lk);
      s_apply_order_enc_05(s_enc_5); s_apply_order_enc_06(s_apply_lk);
      s_apply_order_enc_06(s_enc_6); s_apply_order_enc_07(s_apply_lk);
      s_apply_order_enc_07(s_enc_7); s_apply_order_enc_08(s_apply_lk);
      s_apply_order_enc_08(s_enc_0); s_apply_order_enc_09(s_apply_lk);
      s_apply_order_enc_09(s_enc_1); s_apply_order_enc_10(s_apply_lk);
      s_apply_order_enc_10(s_enc_2); s_apply_order_enc_11(s_apply_lk);
      s_apply_order_enc_11(s_enc_3); s_apply_order_enc_12(s_apply_lk);
      s_apply_order_enc_12(s_enc_4); s_apply_order_enc_13(s_apply_lk);
      s_apply_order_enc_13(s_enc_5); s_apply_order_enc_14(s_apply_lk);
      s_apply_order_enc_14(s_enc_6); s_apply_order_enc_15(s_apply_lk);
      s_apply_order_enc_15(s_enc_7); s_apply_order_enc_16(s_apply_lk);
      s_apply_order_enc_16(s_enc_0); s_apply_order_enc_17(s_apply_lk);
      s_apply_order_enc_17(s_enc_1); s_apply_order_enc_18(s_apply_lk);
      s_apply_order_enc_18(s_enc_2); s_apply_order_enc_19(s_apply_lk);
      s_apply_order_enc_19(s_enc_3); s_apply_order_enc_20(s_apply_lk);
      s_apply_order_enc_20(s_enc_4); s_apply_order_enc_21(s_apply_lk);
      s_apply_order_enc_21(s_enc_5); s_apply_order_enc_22(s_apply_lk);
      s_apply_order_enc_22(s_enc_6); s_apply_order_enc_23(s_apply_lk);
      s_apply_order_enc_23(s_enc_7); s_apply_order_enc_24(s_apply_lk);
      s_apply_order_enc_24(s_enc_0); s_apply_order_enc_25(s_apply_lk);
      s_apply_order_enc_25(s_enc_1); s_apply_order_enc_26(s_apply_lk);
      s_apply_order_enc_26(s_enc_2); s_apply_order_enc_27(s_apply_lk);
      s_apply_order_enc_27(s_enc_3); s_apply_order_enc_28(s_apply_lk);
      s_apply_order_enc_28(s_enc_4); s_apply_order_enc_29(s_apply_lk);
      s_apply_order_enc_29(s_enc_5); s_apply_order_enc_30(s_apply_lk);
      s_apply_order_enc_30(s_enc_6); s_apply_order_enc_31(s_apply_lk);
      s_apply_order_enc_31(s_enc_7); s_apply_order_enc_32(s_apply_key);
      s_serpent_accel_ecb_64_bit_store_four(&a, &b, &c, &d, out);
      in += blocks_at_a_time * serpent_block_len;
      out += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
   #undef s_do_split_general
   #undef s_do_split_lo
   #undef s_do_split_hi
   #undef s_do_join
   #undef s_do_broadcast
   #undef s_do_asgn
   #undef s_do_or
   #undef s_do_xor
   #undef s_do_and
   #undef s_do_not
   #undef s_do_rol
   #undef s_do_ror
   #undef s_do_shl
}

static LTC_INLINE int s_serpent_accel_ecb_decrypt_64_bit(const unsigned char *ct, unsigned char *pt, unsigned long blocks, const symmetric_key *skey)
{
   #define blocks_at_a_time (64 / 32)
   #define s_do_split_general(x, i) ((ulong32)((x) >> ((i) * 32)))
   #define s_do_split_lo(x) s_do_split_general(x, 0)
   #define s_do_split_hi(x) s_do_split_general(x, 1)
   #define s_do_join(lo, hi) ((((ulong64)(hi)) << 32) | ((ulong64)(lo)))
   #define s_do_broadcast(x) s_do_join(x, x)
   #define s_do_asgn(a, b) a = b
   #define s_do_or(a, b) a |= b
   #define s_do_xor(a, b) a ^= b
   #define s_do_and(a, b) a &= b
   #define s_do_not(a, b) a =~ b
   #define s_do_rol(x, i) x = s_do_join( \
      ROL(s_do_split_lo(x), i),          \
      ROL(s_do_split_hi(x), i))
   #define s_do_ror(x, i) x = s_do_join( \
      ROR(s_do_split_lo(x), i),          \
      ROR(s_do_split_hi(x), i))
   #define s_do_shl(a, b, c) a = s_do_join( \
      (s_do_split_lo(b) << c),              \
      (s_do_split_hi(b) << c))

   const unsigned char *in;
   unsigned char *out;
   const ulong32* k;
   unsigned long iblock;
   ulong64 a, b, c, d, e;

   LTC_ARGCHK(ct);
   LTC_ARGCHK(pt);
   LTC_ARGCHK(blocks % blocks_at_a_time == 0);
   LTC_ARGCHK(skey);

   in = ct;
   out = pt;
   k = &skey->serpent.k[0];
   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      s_serpent_accel_ecb_64_bit_load_four(&a, &b, &c, &d, in);
      s_apply_order_dec_32(s_apply_key);
      s_apply_order_dec_32(s_dec_7); s_apply_order_dec_31(s_apply_kl);
      s_apply_order_dec_31(s_dec_6); s_apply_order_dec_30(s_apply_kl);
      s_apply_order_dec_30(s_dec_5); s_apply_order_dec_29(s_apply_kl);
      s_apply_order_dec_29(s_dec_4); s_apply_order_dec_28(s_apply_kl);
      s_apply_order_dec_28(s_dec_3); s_apply_order_dec_27(s_apply_kl);
      s_apply_order_dec_27(s_dec_2); s_apply_order_dec_26(s_apply_kl);
      s_apply_order_dec_26(s_dec_1); s_apply_order_dec_25(s_apply_kl);
      s_apply_order_dec_25(s_dec_0); s_apply_order_dec_24(s_apply_kl);
      s_apply_order_dec_24(s_dec_7); s_apply_order_dec_23(s_apply_kl);
      s_apply_order_dec_23(s_dec_6); s_apply_order_dec_22(s_apply_kl);
      s_apply_order_dec_22(s_dec_5); s_apply_order_dec_21(s_apply_kl);
      s_apply_order_dec_21(s_dec_4); s_apply_order_dec_20(s_apply_kl);
      s_apply_order_dec_20(s_dec_3); s_apply_order_dec_19(s_apply_kl);
      s_apply_order_dec_19(s_dec_2); s_apply_order_dec_18(s_apply_kl);
      s_apply_order_dec_18(s_dec_1); s_apply_order_dec_17(s_apply_kl);
      s_apply_order_dec_17(s_dec_0); s_apply_order_dec_16(s_apply_kl);
      s_apply_order_dec_16(s_dec_7); s_apply_order_dec_15(s_apply_kl);
      s_apply_order_dec_15(s_dec_6); s_apply_order_dec_14(s_apply_kl);
      s_apply_order_dec_14(s_dec_5); s_apply_order_dec_13(s_apply_kl);
      s_apply_order_dec_13(s_dec_4); s_apply_order_dec_12(s_apply_kl);
      s_apply_order_dec_12(s_dec_3); s_apply_order_dec_11(s_apply_kl);
      s_apply_order_dec_11(s_dec_2); s_apply_order_dec_10(s_apply_kl);
      s_apply_order_dec_10(s_dec_1); s_apply_order_dec_09(s_apply_kl);
      s_apply_order_dec_09(s_dec_0); s_apply_order_dec_08(s_apply_kl);
      s_apply_order_dec_08(s_dec_7); s_apply_order_dec_07(s_apply_kl);
      s_apply_order_dec_07(s_dec_6); s_apply_order_dec_06(s_apply_kl);
      s_apply_order_dec_06(s_dec_5); s_apply_order_dec_05(s_apply_kl);
      s_apply_order_dec_05(s_dec_4); s_apply_order_dec_04(s_apply_kl);
      s_apply_order_dec_04(s_dec_3); s_apply_order_dec_03(s_apply_kl);
      s_apply_order_dec_03(s_dec_2); s_apply_order_dec_02(s_apply_kl);
      s_apply_order_dec_02(s_dec_1); s_apply_order_dec_01(s_apply_kl);
      s_apply_order_dec_01(s_dec_0); s_apply_order_dec_00(s_apply_key);
      s_serpent_accel_ecb_64_bit_store_four(&c, &d, &b, &e, out);
      in += blocks_at_a_time * serpent_block_len;
      out += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
   #undef s_do_split_general
   #undef s_do_split_lo
   #undef s_do_split_hi
   #undef s_do_join
   #undef s_do_broadcast
   #undef s_do_asgn
   #undef s_do_or
   #undef s_do_xor
   #undef s_do_and
   #undef s_do_not
   #undef s_do_rol
   #undef s_do_ror
   #undef s_do_shl
}

#endif

#if defined LTC_ARCH_X86
#if !defined LTC_S_X86_CPUID
#define LTC_S_X86_CPUID
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif
#include <immintrin.h> /* _xgetbv */
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#if defined _MSC_VER
#include <intrin.h> /* __cpuid */
#endif /* _MSC_VER */
static LTC_INLINE ulong64 LTC_XSAVE_TARGET s_x86_xgetbv0(void)
{
   return _xgetbv(0);
}
static LTC_INLINE void s_x86_cpuid(int* regs, int leaf)
{
#if defined _MSC_VER
   __cpuid(regs, leaf);
#else /* _MSC_VER */
   int a, b, c, d;
   a = leaf;
   b = c = d = 0;
   __asm__ volatile ("cpuid"
      :"=a"(a), "=b"(b), "=c"(c), "=d"(d)
      :"a"(a), "c"(c)
   );
   regs[0] = a;
   regs[1] = b;
   regs[2] = c;
   regs[3] = d;
#endif /* _MSC_VER */
}
#endif /* LTC_S_X86_CPUID */
#endif /* LTC_ARCH_X86 */

#if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2

#include <emmintrin.h> /* SSE2 __m128i _mm_and_si128 _mm_cmpeq_epi32 _mm_loadu_si128 _mm_or_si128 _mm_set1_epi32 _mm_slli_epi32 _mm_srli_epi32 _mm_storeu_si128 _mm_unpackhi_epi32 _mm_unpackhi_epi64 _mm_unpacklo_epi32 _mm_unpacklo_epi64 _mm_xor_si128 */

static LTC_INLINE int s_x86_sse2_is_supported(void)
{
   static int is_initialized = 0;
   static int is_supported = 0;

   if (is_initialized == 0) {
      int regs[4];
      int sse2;

      s_x86_cpuid(regs, 1);
      sse2 = ((((unsigned int)(regs[3])) >> 26) & 1u) != 0; /* SSE2, leaf 1, edx, bit 26 */
      is_supported = sse2;
      is_initialized = 1;
   }
   return is_supported;
}

static LTC_INLINE void s_serpent_accel_ecb_128_bit_sse2_load_one(__m128i *x, const unsigned char *bytes)
{
   *x = _mm_loadu_si128(((const __m128i*)(bytes)));
}

static LTC_INLINE void s_serpent_accel_ecb_128_bit_sse2_store_one(const __m128i *x, unsigned char *bytes)
{
   _mm_storeu_si128(((__m128i*)(bytes)), *x);
}

static LTC_INLINE void s_serpent_accel_128_bit_sse2_load_four(__m128i *pa, __m128i *pb, __m128i *pc, __m128i *pd, const unsigned char *bytes)
{
   __m128i ia, ib, ic, id;
   __m128i ta, tb, tc, td;
   __m128i ra, rb, rc, rd;

   s_serpent_accel_ecb_128_bit_sse2_load_one(&ia, &bytes[0 * sizeof(__m128i)]);
   s_serpent_accel_ecb_128_bit_sse2_load_one(&ib, &bytes[1 * sizeof(__m128i)]);
   s_serpent_accel_ecb_128_bit_sse2_load_one(&ic, &bytes[2 * sizeof(__m128i)]);
   s_serpent_accel_ecb_128_bit_sse2_load_one(&id, &bytes[3 * sizeof(__m128i)]);
   ta = _mm_unpacklo_epi32(ia, ib);
   tb = _mm_unpacklo_epi32(ic, id);
   tc = _mm_unpackhi_epi32(ia, ib);
   td = _mm_unpackhi_epi32(ic, id);
   ra = _mm_unpacklo_epi64(ta, tb);
   rb = _mm_unpackhi_epi64(ta, tb);
   rc = _mm_unpacklo_epi64(tc, td);
   rd = _mm_unpackhi_epi64(tc, td);
   *pa = ra;
   *pb = rb;
   *pc = rc;
   *pd = rd;
}

static LTC_INLINE void s_serpent_accel_128_bit_sse2_store_four(const __m128i *pa, const __m128i *pb, const __m128i *pc, const __m128i *pd, unsigned char *bytes)
{
   __m128i ia, ib, ic, id;
   __m128i ta, tb, tc, td;
   __m128i ra, rb, rc, rd;

   ia = *pa;
   ib = *pb;
   ic = *pc;
   id = *pd;
   ta = _mm_unpacklo_epi32(ia, ib);
   tb = _mm_unpacklo_epi32(ic, id);
   tc = _mm_unpackhi_epi32(ia, ib);
   td = _mm_unpackhi_epi32(ic, id);
   ra = _mm_unpacklo_epi64(ta, tb);
   rb = _mm_unpackhi_epi64(ta, tb);
   rc = _mm_unpacklo_epi64(tc, td);
   rd = _mm_unpackhi_epi64(tc, td);
   s_serpent_accel_ecb_128_bit_sse2_store_one(&ra, &bytes[0 * sizeof(__m128i)]);
   s_serpent_accel_ecb_128_bit_sse2_store_one(&rb, &bytes[1 * sizeof(__m128i)]);
   s_serpent_accel_ecb_128_bit_sse2_store_one(&rc, &bytes[2 * sizeof(__m128i)]);
   s_serpent_accel_ecb_128_bit_sse2_store_one(&rd, &bytes[3 * sizeof(__m128i)]);
}

static LTC_INLINE int s_serpent_accel_ecb_encrypt_128_bit_sse2(const unsigned char *pt, unsigned char *ct, unsigned long blocks, const symmetric_key *skey)
{
   #define blocks_at_a_time (128 / 32)
   #define s_do_broadcast(x) _mm_set1_epi32(*((const int *)(&(x))))
   #define s_do_asgn(a, b) a = b
   #define s_do_or(a, b) a = _mm_or_si128(a, b)
   #define s_do_xor(a, b) a = _mm_xor_si128(a, b)
   #define s_do_and(a, b) a = _mm_and_si128(a, b)
   #define s_do_not(a, b) a = _mm_xor_si128(b, _mm_cmpeq_epi32(b, b))
   #define s_do_rol(x, i) x = _mm_xor_si128(_mm_slli_epi32(x, i), _mm_srli_epi32(x, 32 - i))
   #define s_do_ror(x, i) x = _mm_xor_si128(_mm_srli_epi32(x, i), _mm_slli_epi32(x, 32 - i))
   #define s_do_shl(a, b, c) a = _mm_slli_epi32(b, c)

   const unsigned char *in;
   unsigned char *out;
   const ulong32* k;
   unsigned long iblock;
   __m128i a, b, c, d, e;

   LTC_ARGCHK(pt);
   LTC_ARGCHK(ct);
   LTC_ARGCHK(blocks % blocks_at_a_time == 0);

   in = pt;
   out = ct;
   k = &skey->serpent.k[0];
   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      s_serpent_accel_128_bit_sse2_load_four(&a, &b, &c, &d, in);
      s_apply_order_enc_00(s_apply_key);
      s_apply_order_enc_00(s_enc_0); s_apply_order_enc_01(s_apply_lk);
      s_apply_order_enc_01(s_enc_1); s_apply_order_enc_02(s_apply_lk);
      s_apply_order_enc_02(s_enc_2); s_apply_order_enc_03(s_apply_lk);
      s_apply_order_enc_03(s_enc_3); s_apply_order_enc_04(s_apply_lk);
      s_apply_order_enc_04(s_enc_4); s_apply_order_enc_05(s_apply_lk);
      s_apply_order_enc_05(s_enc_5); s_apply_order_enc_06(s_apply_lk);
      s_apply_order_enc_06(s_enc_6); s_apply_order_enc_07(s_apply_lk);
      s_apply_order_enc_07(s_enc_7); s_apply_order_enc_08(s_apply_lk);
      s_apply_order_enc_08(s_enc_0); s_apply_order_enc_09(s_apply_lk);
      s_apply_order_enc_09(s_enc_1); s_apply_order_enc_10(s_apply_lk);
      s_apply_order_enc_10(s_enc_2); s_apply_order_enc_11(s_apply_lk);
      s_apply_order_enc_11(s_enc_3); s_apply_order_enc_12(s_apply_lk);
      s_apply_order_enc_12(s_enc_4); s_apply_order_enc_13(s_apply_lk);
      s_apply_order_enc_13(s_enc_5); s_apply_order_enc_14(s_apply_lk);
      s_apply_order_enc_14(s_enc_6); s_apply_order_enc_15(s_apply_lk);
      s_apply_order_enc_15(s_enc_7); s_apply_order_enc_16(s_apply_lk);
      s_apply_order_enc_16(s_enc_0); s_apply_order_enc_17(s_apply_lk);
      s_apply_order_enc_17(s_enc_1); s_apply_order_enc_18(s_apply_lk);
      s_apply_order_enc_18(s_enc_2); s_apply_order_enc_19(s_apply_lk);
      s_apply_order_enc_19(s_enc_3); s_apply_order_enc_20(s_apply_lk);
      s_apply_order_enc_20(s_enc_4); s_apply_order_enc_21(s_apply_lk);
      s_apply_order_enc_21(s_enc_5); s_apply_order_enc_22(s_apply_lk);
      s_apply_order_enc_22(s_enc_6); s_apply_order_enc_23(s_apply_lk);
      s_apply_order_enc_23(s_enc_7); s_apply_order_enc_24(s_apply_lk);
      s_apply_order_enc_24(s_enc_0); s_apply_order_enc_25(s_apply_lk);
      s_apply_order_enc_25(s_enc_1); s_apply_order_enc_26(s_apply_lk);
      s_apply_order_enc_26(s_enc_2); s_apply_order_enc_27(s_apply_lk);
      s_apply_order_enc_27(s_enc_3); s_apply_order_enc_28(s_apply_lk);
      s_apply_order_enc_28(s_enc_4); s_apply_order_enc_29(s_apply_lk);
      s_apply_order_enc_29(s_enc_5); s_apply_order_enc_30(s_apply_lk);
      s_apply_order_enc_30(s_enc_6); s_apply_order_enc_31(s_apply_lk);
      s_apply_order_enc_31(s_enc_7); s_apply_order_enc_32(s_apply_key);
      s_serpent_accel_128_bit_sse2_store_four(&a, &b, &c, &d, out);
      in += blocks_at_a_time * serpent_block_len;
      out += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
   #undef s_do_broadcast
   #undef s_do_asgn
   #undef s_do_or
   #undef s_do_xor
   #undef s_do_and
   #undef s_do_not
   #undef s_do_rol
   #undef s_do_ror
   #undef s_do_shl
}

static LTC_INLINE int s_serpent_accel_ecb_decrypt_128_bit_sse2(const unsigned char *ct, unsigned char *pt, unsigned long blocks, const symmetric_key *skey)
{
   #define blocks_at_a_time (128 / 32)
   #define s_do_broadcast(x) _mm_set1_epi32(*((const int *)(&(x))))
   #define s_do_asgn(a, b) a = b
   #define s_do_or(a, b) a = _mm_or_si128(a, b)
   #define s_do_xor(a, b) a = _mm_xor_si128(a, b)
   #define s_do_and(a, b) a = _mm_and_si128(a, b)
   #define s_do_not(a, b) a = _mm_xor_si128(b, _mm_cmpeq_epi32(b, b))
   #define s_do_rol(x, i) x = _mm_xor_si128(_mm_slli_epi32(x, i), _mm_srli_epi32(x, 32 - i))
   #define s_do_ror(x, i) x = _mm_xor_si128(_mm_srli_epi32(x, i), _mm_slli_epi32(x, 32 - i))
   #define s_do_shl(a, b, c) a = _mm_slli_epi32(b, c)

   const unsigned char *in;
   unsigned char *out;
   const ulong32* k;
   unsigned long iblock;
   __m128i a, b, c, d, e;

   LTC_ARGCHK(ct);
   LTC_ARGCHK(pt);
   LTC_ARGCHK(blocks % blocks_at_a_time == 0);

   in = ct;
   out = pt;
   k = &skey->serpent.k[0];
   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      s_serpent_accel_128_bit_sse2_load_four(&a, &b, &c, &d, in);
      s_apply_order_dec_32(s_apply_key);
      s_apply_order_dec_32(s_dec_7); s_apply_order_dec_31(s_apply_kl);
      s_apply_order_dec_31(s_dec_6); s_apply_order_dec_30(s_apply_kl);
      s_apply_order_dec_30(s_dec_5); s_apply_order_dec_29(s_apply_kl);
      s_apply_order_dec_29(s_dec_4); s_apply_order_dec_28(s_apply_kl);
      s_apply_order_dec_28(s_dec_3); s_apply_order_dec_27(s_apply_kl);
      s_apply_order_dec_27(s_dec_2); s_apply_order_dec_26(s_apply_kl);
      s_apply_order_dec_26(s_dec_1); s_apply_order_dec_25(s_apply_kl);
      s_apply_order_dec_25(s_dec_0); s_apply_order_dec_24(s_apply_kl);
      s_apply_order_dec_24(s_dec_7); s_apply_order_dec_23(s_apply_kl);
      s_apply_order_dec_23(s_dec_6); s_apply_order_dec_22(s_apply_kl);
      s_apply_order_dec_22(s_dec_5); s_apply_order_dec_21(s_apply_kl);
      s_apply_order_dec_21(s_dec_4); s_apply_order_dec_20(s_apply_kl);
      s_apply_order_dec_20(s_dec_3); s_apply_order_dec_19(s_apply_kl);
      s_apply_order_dec_19(s_dec_2); s_apply_order_dec_18(s_apply_kl);
      s_apply_order_dec_18(s_dec_1); s_apply_order_dec_17(s_apply_kl);
      s_apply_order_dec_17(s_dec_0); s_apply_order_dec_16(s_apply_kl);
      s_apply_order_dec_16(s_dec_7); s_apply_order_dec_15(s_apply_kl);
      s_apply_order_dec_15(s_dec_6); s_apply_order_dec_14(s_apply_kl);
      s_apply_order_dec_14(s_dec_5); s_apply_order_dec_13(s_apply_kl);
      s_apply_order_dec_13(s_dec_4); s_apply_order_dec_12(s_apply_kl);
      s_apply_order_dec_12(s_dec_3); s_apply_order_dec_11(s_apply_kl);
      s_apply_order_dec_11(s_dec_2); s_apply_order_dec_10(s_apply_kl);
      s_apply_order_dec_10(s_dec_1); s_apply_order_dec_09(s_apply_kl);
      s_apply_order_dec_09(s_dec_0); s_apply_order_dec_08(s_apply_kl);
      s_apply_order_dec_08(s_dec_7); s_apply_order_dec_07(s_apply_kl);
      s_apply_order_dec_07(s_dec_6); s_apply_order_dec_06(s_apply_kl);
      s_apply_order_dec_06(s_dec_5); s_apply_order_dec_05(s_apply_kl);
      s_apply_order_dec_05(s_dec_4); s_apply_order_dec_04(s_apply_kl);
      s_apply_order_dec_04(s_dec_3); s_apply_order_dec_03(s_apply_kl);
      s_apply_order_dec_03(s_dec_2); s_apply_order_dec_02(s_apply_kl);
      s_apply_order_dec_02(s_dec_1); s_apply_order_dec_01(s_apply_kl);
      s_apply_order_dec_01(s_dec_0); s_apply_order_dec_00(s_apply_key);
      s_serpent_accel_128_bit_sse2_store_four(&c, &d, &b, &e, out);
      in += blocks_at_a_time * serpent_block_len;
      out += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
   #undef s_do_broadcast
   #undef s_do_asgn
   #undef s_do_or
   #undef s_do_xor
   #undef s_do_and
   #undef s_do_not
   #undef s_do_rol
   #undef s_do_ror
   #undef s_do_shl
}

#endif

#if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif
#include <immintrin.h> /* AVX2 __m256i _mm256_and_si256 _mm256_cmpeq_epi32 _mm256_loadu_si256 _mm256_or_si256 _mm256_set1_epi32 _mm256_slli_epi32 _mm256_srli_epi32 _mm256_storeu_si256 _mm256_unpackhi_epi32 _mm256_unpackhi_epi64 _mm256_unpacklo_epi32 _mm256_unpacklo_epi64 _mm256_xor_si256 */
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

static LTC_INLINE int s_is_supported_256_bit_avx2(void)
{
   static int is_initialized = 0;
   static int is_supported = 0;

   if (is_initialized == 0) {
      int regs[4];
      int osxsave, avx2, ymm;
      ulong64 xcr0;

      is_initialized = 1;
      s_x86_cpuid(regs, 0);
      if (regs[0] >= 7) {
         s_x86_cpuid(regs, 1);
         osxsave = ((((unsigned int)(regs[2])) >> 27) & 1u) != 0; /* OSXSAVE, leaf 1, ecx, bit 27 */
         s_x86_cpuid(regs, 7);
         avx2 = ((((unsigned int)(regs[1])) >> 5) & 1u) != 0; /* AVX2, leaf 7, ebx, bit 5 */
         if (osxsave) {
            xcr0 = s_x86_xgetbv0();
            ymm = (xcr0 & 0x6) == 0x6; /* 128bit SSE xmm + 256bit AVX ymm */
            is_supported = osxsave && avx2 && ymm;
         }
      }
   }
   return is_supported;
}

static LTC_INLINE void LTC_AVX2_TARGET s_serpent_accel_ecb_256_bit_avx2_load_one(__m256i *x, const unsigned char *bytes)
{
   *x = _mm256_loadu_si256(((const __m256i*)(bytes)));
}

static LTC_INLINE void LTC_AVX2_TARGET s_serpent_accel_ecb_256_bit_avx2_store_one(const __m256i *x, unsigned char *bytes)
{
   _mm256_storeu_si256(((__m256i*)(bytes)), *x);
}

static LTC_INLINE void LTC_AVX2_TARGET s_serpent_accel_256_bit_avx2_load_four(__m256i *pa, __m256i *pb, __m256i *pc, __m256i *pd, const unsigned char *bytes)
{
   __m256i ia, ib, ic, id;
   __m256i ta, tb, tc, td;
   __m256i ra, rb, rc, rd;

   s_serpent_accel_ecb_256_bit_avx2_load_one(&ia, &bytes[0 * sizeof(__m256i)]);
   s_serpent_accel_ecb_256_bit_avx2_load_one(&ib, &bytes[1 * sizeof(__m256i)]);
   s_serpent_accel_ecb_256_bit_avx2_load_one(&ic, &bytes[2 * sizeof(__m256i)]);
   s_serpent_accel_ecb_256_bit_avx2_load_one(&id, &bytes[3 * sizeof(__m256i)]);
   ta = _mm256_unpacklo_epi32(ia, ib);
   tb = _mm256_unpacklo_epi32(ic, id);
   tc = _mm256_unpackhi_epi32(ia, ib);
   td = _mm256_unpackhi_epi32(ic, id);
   ra = _mm256_unpacklo_epi64(ta, tb);
   rb = _mm256_unpackhi_epi64(ta, tb);
   rc = _mm256_unpacklo_epi64(tc, td);
   rd = _mm256_unpackhi_epi64(tc, td);
   *pa = ra;
   *pb = rb;
   *pc = rc;
   *pd = rd;
}

static LTC_INLINE void LTC_AVX2_TARGET s_serpent_accel_256_bit_avx2_store_four(const __m256i *pa, const __m256i *pb, const __m256i *pc, const __m256i *pd, unsigned char *bytes)
{
   __m256i ia, ib, ic, id;
   __m256i ta, tb, tc, td;
   __m256i ra, rb, rc, rd;

   ia = *pa;
   ib = *pb;
   ic = *pc;
   id = *pd;
   ta = _mm256_unpacklo_epi32(ia, ib);
   tb = _mm256_unpacklo_epi32(ic, id);
   tc = _mm256_unpackhi_epi32(ia, ib);
   td = _mm256_unpackhi_epi32(ic, id);
   ra = _mm256_unpacklo_epi64(ta, tb);
   rb = _mm256_unpackhi_epi64(ta, tb);
   rc = _mm256_unpacklo_epi64(tc, td);
   rd = _mm256_unpackhi_epi64(tc, td);
   s_serpent_accel_ecb_256_bit_avx2_store_one(&ra, &bytes[0 * sizeof(__m256i)]);
   s_serpent_accel_ecb_256_bit_avx2_store_one(&rb, &bytes[1 * sizeof(__m256i)]);
   s_serpent_accel_ecb_256_bit_avx2_store_one(&rc, &bytes[2 * sizeof(__m256i)]);
   s_serpent_accel_ecb_256_bit_avx2_store_one(&rd, &bytes[3 * sizeof(__m256i)]);
}

static LTC_INLINE int LTC_AVX2_TARGET s_serpent_accel_ecb_encrypt_256_bit_avx2(const unsigned char *pt, unsigned char *ct, unsigned long blocks, const symmetric_key *skey)
{
   #define blocks_at_a_time (256 / 32)
   #define s_do_broadcast(x) _mm256_set1_epi32(*((const int *)(&(x))))
   #define s_do_asgn(a, b) a = b
   #define s_do_or(a, b) a = _mm256_or_si256(a, b)
   #define s_do_xor(a, b) a = _mm256_xor_si256(a, b)
   #define s_do_and(a, b) a = _mm256_and_si256(a, b)
   #define s_do_not(a, b) a = _mm256_xor_si256(b, _mm256_cmpeq_epi32(b, b))
   #define s_do_rol(x, i) x = _mm256_or_si256(_mm256_slli_epi32(x, i), _mm256_srli_epi32(x, 32 - i))
   #define s_do_ror(x, i) x = _mm256_or_si256(_mm256_srli_epi32(x, i), _mm256_slli_epi32(x, 32 - i))
   #define s_do_shl(a, b, c) a = _mm256_slli_epi32(b, c)

   const unsigned char *in;
   unsigned char *out;
   const ulong32* k;
   unsigned long iblock;
   __m256i a, b, c, d, e;

   LTC_ARGCHK(pt);
   LTC_ARGCHK(ct);
   LTC_ARGCHK(blocks % blocks_at_a_time == 0);

   in = pt;
   out = ct;
   k = &skey->serpent.k[0];
   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      s_serpent_accel_256_bit_avx2_load_four(&a, &b, &c, &d, in);
      s_apply_order_enc_00(s_apply_key);
      s_apply_order_enc_00(s_enc_0); s_apply_order_enc_01(s_apply_lk);
      s_apply_order_enc_01(s_enc_1); s_apply_order_enc_02(s_apply_lk);
      s_apply_order_enc_02(s_enc_2); s_apply_order_enc_03(s_apply_lk);
      s_apply_order_enc_03(s_enc_3); s_apply_order_enc_04(s_apply_lk);
      s_apply_order_enc_04(s_enc_4); s_apply_order_enc_05(s_apply_lk);
      s_apply_order_enc_05(s_enc_5); s_apply_order_enc_06(s_apply_lk);
      s_apply_order_enc_06(s_enc_6); s_apply_order_enc_07(s_apply_lk);
      s_apply_order_enc_07(s_enc_7); s_apply_order_enc_08(s_apply_lk);
      s_apply_order_enc_08(s_enc_0); s_apply_order_enc_09(s_apply_lk);
      s_apply_order_enc_09(s_enc_1); s_apply_order_enc_10(s_apply_lk);
      s_apply_order_enc_10(s_enc_2); s_apply_order_enc_11(s_apply_lk);
      s_apply_order_enc_11(s_enc_3); s_apply_order_enc_12(s_apply_lk);
      s_apply_order_enc_12(s_enc_4); s_apply_order_enc_13(s_apply_lk);
      s_apply_order_enc_13(s_enc_5); s_apply_order_enc_14(s_apply_lk);
      s_apply_order_enc_14(s_enc_6); s_apply_order_enc_15(s_apply_lk);
      s_apply_order_enc_15(s_enc_7); s_apply_order_enc_16(s_apply_lk);
      s_apply_order_enc_16(s_enc_0); s_apply_order_enc_17(s_apply_lk);
      s_apply_order_enc_17(s_enc_1); s_apply_order_enc_18(s_apply_lk);
      s_apply_order_enc_18(s_enc_2); s_apply_order_enc_19(s_apply_lk);
      s_apply_order_enc_19(s_enc_3); s_apply_order_enc_20(s_apply_lk);
      s_apply_order_enc_20(s_enc_4); s_apply_order_enc_21(s_apply_lk);
      s_apply_order_enc_21(s_enc_5); s_apply_order_enc_22(s_apply_lk);
      s_apply_order_enc_22(s_enc_6); s_apply_order_enc_23(s_apply_lk);
      s_apply_order_enc_23(s_enc_7); s_apply_order_enc_24(s_apply_lk);
      s_apply_order_enc_24(s_enc_0); s_apply_order_enc_25(s_apply_lk);
      s_apply_order_enc_25(s_enc_1); s_apply_order_enc_26(s_apply_lk);
      s_apply_order_enc_26(s_enc_2); s_apply_order_enc_27(s_apply_lk);
      s_apply_order_enc_27(s_enc_3); s_apply_order_enc_28(s_apply_lk);
      s_apply_order_enc_28(s_enc_4); s_apply_order_enc_29(s_apply_lk);
      s_apply_order_enc_29(s_enc_5); s_apply_order_enc_30(s_apply_lk);
      s_apply_order_enc_30(s_enc_6); s_apply_order_enc_31(s_apply_lk);
      s_apply_order_enc_31(s_enc_7); s_apply_order_enc_32(s_apply_key);
      s_serpent_accel_256_bit_avx2_store_four(&a, &b, &c, &d, out);
      in += blocks_at_a_time * serpent_block_len;
      out += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
   #undef s_do_broadcast
   #undef s_do_asgn
   #undef s_do_or
   #undef s_do_xor
   #undef s_do_and
   #undef s_do_not
   #undef s_do_rol
   #undef s_do_ror
   #undef s_do_shl
}

static LTC_INLINE int LTC_AVX2_TARGET s_serpent_accel_ecb_decrypt_256_bit_avx2(const unsigned char *ct, unsigned char *pt, unsigned long blocks, const symmetric_key *skey)
{
   #define blocks_at_a_time (256 / 32)
   #define s_do_broadcast(x) _mm256_set1_epi32(*((const int *)(&(x))))
   #define s_do_asgn(a, b) a = b
   #define s_do_or(a, b) a = _mm256_or_si256(a, b)
   #define s_do_xor(a, b) a = _mm256_xor_si256(a, b)
   #define s_do_and(a, b) a = _mm256_and_si256(a, b)
   #define s_do_not(a, b) a = _mm256_xor_si256(b, _mm256_cmpeq_epi32(b, b))
   #define s_do_rol(x, i) x = _mm256_or_si256(_mm256_slli_epi32(x, i), _mm256_srli_epi32(x, 32 - i))
   #define s_do_ror(x, i) x = _mm256_or_si256(_mm256_srli_epi32(x, i), _mm256_slli_epi32(x, 32 - i))
   #define s_do_shl(a, b, c) a = _mm256_slli_epi32(b, c)

   const unsigned char *in;
   unsigned char *out;
   const ulong32* k;
   unsigned long iblock;
   __m256i a, b, c, d, e;

   LTC_ARGCHK(ct);
   LTC_ARGCHK(pt);
   LTC_ARGCHK(blocks % blocks_at_a_time == 0);

   in = ct;
   out = pt;
   k = &skey->serpent.k[0];
   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      s_serpent_accel_256_bit_avx2_load_four(&a, &b, &c, &d, in);
      s_apply_order_dec_32(s_apply_key);
      s_apply_order_dec_32(s_dec_7); s_apply_order_dec_31(s_apply_kl);
      s_apply_order_dec_31(s_dec_6); s_apply_order_dec_30(s_apply_kl);
      s_apply_order_dec_30(s_dec_5); s_apply_order_dec_29(s_apply_kl);
      s_apply_order_dec_29(s_dec_4); s_apply_order_dec_28(s_apply_kl);
      s_apply_order_dec_28(s_dec_3); s_apply_order_dec_27(s_apply_kl);
      s_apply_order_dec_27(s_dec_2); s_apply_order_dec_26(s_apply_kl);
      s_apply_order_dec_26(s_dec_1); s_apply_order_dec_25(s_apply_kl);
      s_apply_order_dec_25(s_dec_0); s_apply_order_dec_24(s_apply_kl);
      s_apply_order_dec_24(s_dec_7); s_apply_order_dec_23(s_apply_kl);
      s_apply_order_dec_23(s_dec_6); s_apply_order_dec_22(s_apply_kl);
      s_apply_order_dec_22(s_dec_5); s_apply_order_dec_21(s_apply_kl);
      s_apply_order_dec_21(s_dec_4); s_apply_order_dec_20(s_apply_kl);
      s_apply_order_dec_20(s_dec_3); s_apply_order_dec_19(s_apply_kl);
      s_apply_order_dec_19(s_dec_2); s_apply_order_dec_18(s_apply_kl);
      s_apply_order_dec_18(s_dec_1); s_apply_order_dec_17(s_apply_kl);
      s_apply_order_dec_17(s_dec_0); s_apply_order_dec_16(s_apply_kl);
      s_apply_order_dec_16(s_dec_7); s_apply_order_dec_15(s_apply_kl);
      s_apply_order_dec_15(s_dec_6); s_apply_order_dec_14(s_apply_kl);
      s_apply_order_dec_14(s_dec_5); s_apply_order_dec_13(s_apply_kl);
      s_apply_order_dec_13(s_dec_4); s_apply_order_dec_12(s_apply_kl);
      s_apply_order_dec_12(s_dec_3); s_apply_order_dec_11(s_apply_kl);
      s_apply_order_dec_11(s_dec_2); s_apply_order_dec_10(s_apply_kl);
      s_apply_order_dec_10(s_dec_1); s_apply_order_dec_09(s_apply_kl);
      s_apply_order_dec_09(s_dec_0); s_apply_order_dec_08(s_apply_kl);
      s_apply_order_dec_08(s_dec_7); s_apply_order_dec_07(s_apply_kl);
      s_apply_order_dec_07(s_dec_6); s_apply_order_dec_06(s_apply_kl);
      s_apply_order_dec_06(s_dec_5); s_apply_order_dec_05(s_apply_kl);
      s_apply_order_dec_05(s_dec_4); s_apply_order_dec_04(s_apply_kl);
      s_apply_order_dec_04(s_dec_3); s_apply_order_dec_03(s_apply_kl);
      s_apply_order_dec_03(s_dec_2); s_apply_order_dec_02(s_apply_kl);
      s_apply_order_dec_02(s_dec_1); s_apply_order_dec_01(s_apply_kl);
      s_apply_order_dec_01(s_dec_0); s_apply_order_dec_00(s_apply_key);
      s_serpent_accel_256_bit_avx2_store_four(&c, &d, &b, &e, out);
      in += blocks_at_a_time * serpent_block_len;
      out += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
   #undef s_do_broadcast
   #undef s_do_asgn
   #undef s_do_or
   #undef s_do_xor
   #undef s_do_and
   #undef s_do_not
   #undef s_do_rol
   #undef s_do_ror
   #undef s_do_shl
}

#endif

#if defined LTC_SERPENT_ACCEL_512_BIT_X86_AVX512F

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif
#include <immintrin.h> /* AVX512F __m512i _mm512_and_si512 _mm512_cmpeq_epi32 _mm512_loadu_si512 _mm512_or_si512 _mm512_set1_epi32 _mm512_set1_epi8 _mm512_slli_epi32 _mm512_srli_epi32 _mm512_storeu_si512 _mm512_unpackhi_epi32 _mm512_unpackhi_epi64 _mm512_unpacklo_epi32 _mm512_unpacklo_epi64 _mm512_xor_si512 */
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

static LTC_INLINE int s_is_supported_512_bit_avx512f(void)
{
   static int is_initialized = 0;
   static int is_supported = 0;

   if (is_initialized == 0) {
      int regs[4];
      int osxsave, avx512f, zmm;
      ulong64 xcr0;

      is_initialized = 1;
      s_x86_cpuid(regs, 0);
      if (regs[0] >= 7) {
         s_x86_cpuid(regs, 1);
         osxsave = ((((unsigned int)(regs[2])) >> 27) & 1u) != 0; /* OSXSAVE, leaf 1, ecx, bit 27 */
         s_x86_cpuid(regs, 7);
         avx512f = ((((unsigned int)(regs[1])) >> 16) & 1u) != 0; /* AVX512F, leaf 7, ebx, bit 16 */
         if (osxsave) {
            xcr0 = s_x86_xgetbv0();
            zmm = (xcr0 & 0xe0) == 0xe0; /* 512bit AVX zmm */
            is_supported = osxsave && avx512f && zmm;
         }
      }
   }
   return is_supported;
}

static LTC_INLINE void LTC_AVX512F_TARGET s_serpent_accel_ecb_512_bit_avx512f_load_one(__m512i *x, const unsigned char *bytes)
{
   *x = _mm512_loadu_si512(((const __m512i*)(bytes)));
}

static LTC_INLINE void LTC_AVX512F_TARGET s_serpent_accel_ecb_512_bit_avx512f_store_one(const __m512i *x, unsigned char *bytes)
{
   _mm512_storeu_si512(((__m512i*)(bytes)), *x);
}

static LTC_INLINE void LTC_AVX512F_TARGET s_serpent_accel_512_bit_avx512f_load_four(__m512i *pa, __m512i *pb, __m512i *pc, __m512i *pd, const unsigned char *bytes)
{
   __m512i ia, ib, ic, id;
   __m512i ta, tb, tc, td;
   __m512i ra, rb, rc, rd;

   s_serpent_accel_ecb_512_bit_avx512f_load_one(&ia, &bytes[0 * sizeof(__m512i)]);
   s_serpent_accel_ecb_512_bit_avx512f_load_one(&ib, &bytes[1 * sizeof(__m512i)]);
   s_serpent_accel_ecb_512_bit_avx512f_load_one(&ic, &bytes[2 * sizeof(__m512i)]);
   s_serpent_accel_ecb_512_bit_avx512f_load_one(&id, &bytes[3 * sizeof(__m512i)]);
   ta = _mm512_unpacklo_epi32(ia, ib);
   tb = _mm512_unpacklo_epi32(ic, id);
   tc = _mm512_unpackhi_epi32(ia, ib);
   td = _mm512_unpackhi_epi32(ic, id);
   ra = _mm512_unpacklo_epi64(ta, tb);
   rb = _mm512_unpackhi_epi64(ta, tb);
   rc = _mm512_unpacklo_epi64(tc, td);
   rd = _mm512_unpackhi_epi64(tc, td);
   *pa = ra;
   *pb = rb;
   *pc = rc;
   *pd = rd;
}

static LTC_INLINE void LTC_AVX512F_TARGET s_serpent_accel_512_bit_avx512f_store_four(const __m512i *pa, const __m512i *pb, const __m512i *pc, const __m512i *pd, unsigned char *bytes)
{
   __m512i ia, ib, ic, id;
   __m512i ta, tb, tc, td;
   __m512i ra, rb, rc, rd;

   ia = *pa;
   ib = *pb;
   ic = *pc;
   id = *pd;
   ta = _mm512_unpacklo_epi32(ia, ib);
   tb = _mm512_unpacklo_epi32(ic, id);
   tc = _mm512_unpackhi_epi32(ia, ib);
   td = _mm512_unpackhi_epi32(ic, id);
   ra = _mm512_unpacklo_epi64(ta, tb);
   rb = _mm512_unpackhi_epi64(ta, tb);
   rc = _mm512_unpacklo_epi64(tc, td);
   rd = _mm512_unpackhi_epi64(tc, td);
   s_serpent_accel_ecb_512_bit_avx512f_store_one(&ra, &bytes[0 * sizeof(__m512i)]);
   s_serpent_accel_ecb_512_bit_avx512f_store_one(&rb, &bytes[1 * sizeof(__m512i)]);
   s_serpent_accel_ecb_512_bit_avx512f_store_one(&rc, &bytes[2 * sizeof(__m512i)]);
   s_serpent_accel_ecb_512_bit_avx512f_store_one(&rd, &bytes[3 * sizeof(__m512i)]);
}

static LTC_INLINE int LTC_AVX512F_TARGET s_serpent_accel_ecb_encrypt_512_bit_avx512f(const unsigned char *pt, unsigned char *ct, unsigned long blocks, const symmetric_key *skey)
{
   #define blocks_at_a_time (512 / 32)
   #define s_do_broadcast(x) _mm512_set1_epi32(*((const int *)(&(x))))
   #define s_do_asgn(a, b) a = b
   #define s_do_or(a, b) a = _mm512_or_si512(a, b)
   #define s_do_xor(a, b) a = _mm512_xor_si512(a, b)
   #define s_do_and(a, b) a = _mm512_and_si512(a, b)
   #define s_do_not(a, b) a = _mm512_xor_si512(b, _mm512_set1_epi8('\xff'))
   #define s_do_rol(x, i) x = _mm512_or_si512(_mm512_slli_epi32(x, i), _mm512_srli_epi32(x, 32 - i))
   #define s_do_ror(x, i) x = _mm512_or_si512(_mm512_srli_epi32(x, i), _mm512_slli_epi32(x, 32 - i))
   #define s_do_shl(a, b, c) a = _mm512_slli_epi32(b, c)

   const unsigned char *in;
   unsigned char *out;
   const ulong32* k;
   unsigned long iblock;
   __m512i a, b, c, d, e;

   LTC_ARGCHK(pt);
   LTC_ARGCHK(ct);
   LTC_ARGCHK(blocks % blocks_at_a_time == 0);

   in = pt;
   out = ct;
   k = &skey->serpent.k[0];
   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      s_serpent_accel_512_bit_avx512f_load_four(&a, &b, &c, &d, in);
      s_apply_order_enc_00(s_apply_key);
      s_apply_order_enc_00(s_enc_0); s_apply_order_enc_01(s_apply_lk);
      s_apply_order_enc_01(s_enc_1); s_apply_order_enc_02(s_apply_lk);
      s_apply_order_enc_02(s_enc_2); s_apply_order_enc_03(s_apply_lk);
      s_apply_order_enc_03(s_enc_3); s_apply_order_enc_04(s_apply_lk);
      s_apply_order_enc_04(s_enc_4); s_apply_order_enc_05(s_apply_lk);
      s_apply_order_enc_05(s_enc_5); s_apply_order_enc_06(s_apply_lk);
      s_apply_order_enc_06(s_enc_6); s_apply_order_enc_07(s_apply_lk);
      s_apply_order_enc_07(s_enc_7); s_apply_order_enc_08(s_apply_lk);
      s_apply_order_enc_08(s_enc_0); s_apply_order_enc_09(s_apply_lk);
      s_apply_order_enc_09(s_enc_1); s_apply_order_enc_10(s_apply_lk);
      s_apply_order_enc_10(s_enc_2); s_apply_order_enc_11(s_apply_lk);
      s_apply_order_enc_11(s_enc_3); s_apply_order_enc_12(s_apply_lk);
      s_apply_order_enc_12(s_enc_4); s_apply_order_enc_13(s_apply_lk);
      s_apply_order_enc_13(s_enc_5); s_apply_order_enc_14(s_apply_lk);
      s_apply_order_enc_14(s_enc_6); s_apply_order_enc_15(s_apply_lk);
      s_apply_order_enc_15(s_enc_7); s_apply_order_enc_16(s_apply_lk);
      s_apply_order_enc_16(s_enc_0); s_apply_order_enc_17(s_apply_lk);
      s_apply_order_enc_17(s_enc_1); s_apply_order_enc_18(s_apply_lk);
      s_apply_order_enc_18(s_enc_2); s_apply_order_enc_19(s_apply_lk);
      s_apply_order_enc_19(s_enc_3); s_apply_order_enc_20(s_apply_lk);
      s_apply_order_enc_20(s_enc_4); s_apply_order_enc_21(s_apply_lk);
      s_apply_order_enc_21(s_enc_5); s_apply_order_enc_22(s_apply_lk);
      s_apply_order_enc_22(s_enc_6); s_apply_order_enc_23(s_apply_lk);
      s_apply_order_enc_23(s_enc_7); s_apply_order_enc_24(s_apply_lk);
      s_apply_order_enc_24(s_enc_0); s_apply_order_enc_25(s_apply_lk);
      s_apply_order_enc_25(s_enc_1); s_apply_order_enc_26(s_apply_lk);
      s_apply_order_enc_26(s_enc_2); s_apply_order_enc_27(s_apply_lk);
      s_apply_order_enc_27(s_enc_3); s_apply_order_enc_28(s_apply_lk);
      s_apply_order_enc_28(s_enc_4); s_apply_order_enc_29(s_apply_lk);
      s_apply_order_enc_29(s_enc_5); s_apply_order_enc_30(s_apply_lk);
      s_apply_order_enc_30(s_enc_6); s_apply_order_enc_31(s_apply_lk);
      s_apply_order_enc_31(s_enc_7); s_apply_order_enc_32(s_apply_key);
      s_serpent_accel_512_bit_avx512f_store_four(&a, &b, &c, &d, out);
      in += blocks_at_a_time * serpent_block_len;
      out += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
   #undef s_do_broadcast
   #undef s_do_asgn
   #undef s_do_or
   #undef s_do_xor
   #undef s_do_and
   #undef s_do_not
   #undef s_do_rol
   #undef s_do_ror
   #undef s_do_shl
}

static LTC_INLINE int LTC_AVX512F_TARGET s_serpent_accel_ecb_decrypt_512_bit_avx512f(const unsigned char *ct, unsigned char *pt, unsigned long blocks, const symmetric_key *skey)
{
   #define blocks_at_a_time (512 / 32)
   #define s_do_broadcast(x) _mm512_set1_epi32(*((const int *)(&(x))))
   #define s_do_asgn(a, b) a = b
   #define s_do_or(a, b) a = _mm512_or_si512(a, b)
   #define s_do_xor(a, b) a = _mm512_xor_si512(a, b)
   #define s_do_and(a, b) a = _mm512_and_si512(a, b)
   #define s_do_not(a, b) a = _mm512_xor_si512(b, _mm512_set1_epi8('\xff'))
   #define s_do_rol(x, i) x = _mm512_or_si512(_mm512_slli_epi32(x, i), _mm512_srli_epi32(x, 32 - i))
   #define s_do_ror(x, i) x = _mm512_or_si512(_mm512_srli_epi32(x, i), _mm512_slli_epi32(x, 32 - i))
   #define s_do_shl(a, b, c) a = _mm512_slli_epi32(b, c)

   const unsigned char *in;
   unsigned char *out;
   const ulong32* k;
   unsigned long iblock;
   __m512i a, b, c, d, e;

   LTC_ARGCHK(ct);
   LTC_ARGCHK(pt);
   LTC_ARGCHK(blocks % blocks_at_a_time == 0);

   in = ct;
   out = pt;
   k = &skey->serpent.k[0];
   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      s_serpent_accel_512_bit_avx512f_load_four(&a, &b, &c, &d, in);
      s_apply_order_dec_32(s_apply_key);
      s_apply_order_dec_32(s_dec_7); s_apply_order_dec_31(s_apply_kl);
      s_apply_order_dec_31(s_dec_6); s_apply_order_dec_30(s_apply_kl);
      s_apply_order_dec_30(s_dec_5); s_apply_order_dec_29(s_apply_kl);
      s_apply_order_dec_29(s_dec_4); s_apply_order_dec_28(s_apply_kl);
      s_apply_order_dec_28(s_dec_3); s_apply_order_dec_27(s_apply_kl);
      s_apply_order_dec_27(s_dec_2); s_apply_order_dec_26(s_apply_kl);
      s_apply_order_dec_26(s_dec_1); s_apply_order_dec_25(s_apply_kl);
      s_apply_order_dec_25(s_dec_0); s_apply_order_dec_24(s_apply_kl);
      s_apply_order_dec_24(s_dec_7); s_apply_order_dec_23(s_apply_kl);
      s_apply_order_dec_23(s_dec_6); s_apply_order_dec_22(s_apply_kl);
      s_apply_order_dec_22(s_dec_5); s_apply_order_dec_21(s_apply_kl);
      s_apply_order_dec_21(s_dec_4); s_apply_order_dec_20(s_apply_kl);
      s_apply_order_dec_20(s_dec_3); s_apply_order_dec_19(s_apply_kl);
      s_apply_order_dec_19(s_dec_2); s_apply_order_dec_18(s_apply_kl);
      s_apply_order_dec_18(s_dec_1); s_apply_order_dec_17(s_apply_kl);
      s_apply_order_dec_17(s_dec_0); s_apply_order_dec_16(s_apply_kl);
      s_apply_order_dec_16(s_dec_7); s_apply_order_dec_15(s_apply_kl);
      s_apply_order_dec_15(s_dec_6); s_apply_order_dec_14(s_apply_kl);
      s_apply_order_dec_14(s_dec_5); s_apply_order_dec_13(s_apply_kl);
      s_apply_order_dec_13(s_dec_4); s_apply_order_dec_12(s_apply_kl);
      s_apply_order_dec_12(s_dec_3); s_apply_order_dec_11(s_apply_kl);
      s_apply_order_dec_11(s_dec_2); s_apply_order_dec_10(s_apply_kl);
      s_apply_order_dec_10(s_dec_1); s_apply_order_dec_09(s_apply_kl);
      s_apply_order_dec_09(s_dec_0); s_apply_order_dec_08(s_apply_kl);
      s_apply_order_dec_08(s_dec_7); s_apply_order_dec_07(s_apply_kl);
      s_apply_order_dec_07(s_dec_6); s_apply_order_dec_06(s_apply_kl);
      s_apply_order_dec_06(s_dec_5); s_apply_order_dec_05(s_apply_kl);
      s_apply_order_dec_05(s_dec_4); s_apply_order_dec_04(s_apply_kl);
      s_apply_order_dec_04(s_dec_3); s_apply_order_dec_03(s_apply_kl);
      s_apply_order_dec_03(s_dec_2); s_apply_order_dec_02(s_apply_kl);
      s_apply_order_dec_02(s_dec_1); s_apply_order_dec_01(s_apply_kl);
      s_apply_order_dec_01(s_dec_0); s_apply_order_dec_00(s_apply_key);
      s_serpent_accel_512_bit_avx512f_store_four(&c, &d, &b, &e, out);
      in += blocks_at_a_time * serpent_block_len;
      out += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
   #undef s_do_broadcast
   #undef s_do_asgn
   #undef s_do_or
   #undef s_do_xor
   #undef s_do_and
   #undef s_do_not
   #undef s_do_rol
   #undef s_do_ror
   #undef s_do_shl
}

#endif

int serpent_ecb_encrypt(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
{
   int err = s_serpent_accel_ecb_encrypt_32_bit(pt, ct, 1, skey);
#ifdef LTC_CLEAN_STACK
   burn_stack(sizeof(ulong32) * 5 + sizeof(int));
#endif
   return err;
}

int serpent_ecb_decrypt(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey)
{
   int err = s_serpent_accel_ecb_decrypt_32_bit(ct, pt, 1, skey);
#ifdef LTC_CLEAN_STACK
   burn_stack(sizeof(ulong32) * 5 + sizeof(int));
#endif
   return err;
}

void serpent_done(symmetric_key *skey)
{
   LTC_UNUSED_PARAM(skey);
}

int serpent_keysize(int *keysize)
{
   LTC_ARGCHK(keysize != NULL);

   if (*keysize >= 32) { *keysize = 32; }
   else if (*keysize >= 24) { *keysize = 24; }
   else if (*keysize >= 16) { *keysize = 16; }
   else return CRYPT_INVALID_KEYSIZE;
   return CRYPT_OK;
}

#if defined LTC_SERPENT_ACCEL

static LTC_INLINE void s_serpent_accel_ctr_increment_counter_be(unsigned char *counter)
{
   int i;
   int idx;

   for (i = 0; i != serpent_block_len; ++i) {
      idx = (serpent_block_len - 1) - i;
      ++counter[idx];
      if (counter[idx] != 0x00) {
         break;
      }
   }
}

static LTC_INLINE void s_serpent_accel_ctr_increment_counter_le(unsigned char *counter)
{
   int i;
   int idx;

   for (i = 0; i != serpent_block_len; ++i) {
      idx = i;
      ++counter[idx];
      if (counter[idx] != 0x00) {
         break;
      }
   }
}

static LTC_INLINE void s_serpent_accel_ctr_increment_counter_generic(unsigned char *counter, int mode)
{
   if (mode == CTR_COUNTER_LITTLE_ENDIAN) {
      s_serpent_accel_ctr_increment_counter_le(counter);
   } else {
      s_serpent_accel_ctr_increment_counter_be(counter);
   }
}

static LTC_INLINE int s_serpent_accel_cbc_decrypt_32_bit(const unsigned char *ct, unsigned char *pt, unsigned long blocks, unsigned char *IV, const symmetric_key *skey)
{
   #define blocks_at_a_time (32 / 32)

   unsigned long iblock;
   int err;
   LTC_ALIGN_MSVC(4) unsigned char pad1[blocks_at_a_time * serpent_block_len] LTC_ALIGN(4);
   int i;
   LTC_ALIGN_MSVC(4) unsigned char pad2[blocks_at_a_time * serpent_block_len] LTC_ALIGN(4);
   int j;

   LTC_ARGCHK(blocks % blocks_at_a_time == 0);
   LTC_ARGCHK(serpent_block_len % sizeof(LTC_FAST_TYPE) == 0);

   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      if ((err = s_serpent_accel_ecb_decrypt_32_bit(ct, pad1, blocks_at_a_time, skey)) != CRYPT_OK) {
         return err;
      }
      for (i = 0; i != serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
      LTC_FAST_XOR3(&pad2[i * sizeof(LTC_FAST_TYPE)], &IV[i * sizeof(LTC_FAST_TYPE)], &pad1[i * sizeof(LTC_FAST_TYPE)]);
      }
      for (j = 1; j != blocks_at_a_time; ++j) {
         for (i = 0; i != serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
            LTC_FAST_XOR3(&pad2[j * serpent_block_len + i * sizeof(LTC_FAST_TYPE)], &ct[(j - 1) * serpent_block_len + i * sizeof(LTC_FAST_TYPE)], &pad1[j * serpent_block_len + i * sizeof(LTC_FAST_TYPE)]);
         }
      }
      for (i = 0; i != serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_STORE(&IV[i * sizeof(LTC_FAST_TYPE)], LTC_FAST_LOAD(&ct[(j - 1) * serpent_block_len + i * sizeof(LTC_FAST_TYPE)]));
      }
      for (i = 0; i != blocks_at_a_time * serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_STORE(&pt[i * sizeof(LTC_FAST_TYPE)], LTC_FAST_LOAD(&pad2[i * sizeof(LTC_FAST_TYPE)]));
      }
      pt += blocks_at_a_time * serpent_block_len;
      ct += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
}

#if defined LTC_SERPENT_ACCEL_64_BIT

static LTC_INLINE int s_serpent_accel_cbc_decrypt_64_bit(const unsigned char *ct, unsigned char *pt, unsigned long blocks, unsigned char *IV, const symmetric_key *skey)
{
   #define blocks_at_a_time (64 / 32)

   unsigned long iblock;
   int err;
   LTC_ALIGN_MSVC(8) unsigned char pad1[blocks_at_a_time * serpent_block_len] LTC_ALIGN(8);
   int i;
   LTC_ALIGN_MSVC(8) unsigned char pad2[blocks_at_a_time * serpent_block_len] LTC_ALIGN(8);
   int j;

   LTC_ARGCHK(blocks % blocks_at_a_time == 0);
   LTC_ARGCHK(serpent_block_len % sizeof(LTC_FAST_TYPE) == 0);

   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      if ((err = s_serpent_accel_ecb_decrypt_64_bit(ct, pad1, blocks_at_a_time, skey)) != CRYPT_OK) {
         return err;
      }
      for (i = 0; i != serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_XOR3(&pad2[i * sizeof(LTC_FAST_TYPE)], &IV[i * sizeof(LTC_FAST_TYPE)], &pad1[i * sizeof(LTC_FAST_TYPE)]);
      }
      for (j = 1; j != blocks_at_a_time; ++j) {
         for (i = 0; i != serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
            LTC_FAST_XOR3(&pad2[j * serpent_block_len + i * sizeof(LTC_FAST_TYPE)], &ct[(j - 1) * serpent_block_len + i * sizeof(LTC_FAST_TYPE)], &pad1[j * serpent_block_len + i * sizeof(LTC_FAST_TYPE)]);
         }
      }
      for (i = 0; i != serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_STORE(&IV[i * sizeof(LTC_FAST_TYPE)], LTC_FAST_LOAD(&ct[(j - 1) * serpent_block_len + i * sizeof(LTC_FAST_TYPE)]));
      }
      for (i = 0; i != blocks_at_a_time * serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_STORE(&pt[i * sizeof(LTC_FAST_TYPE)], LTC_FAST_LOAD(&pad2[i * sizeof(LTC_FAST_TYPE)]));
      }
      pt += blocks_at_a_time * serpent_block_len;
      ct += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
}

#endif

#if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2

static LTC_INLINE int s_serpent_accel_cbc_decrypt_128_bit_sse2(const unsigned char *ct, unsigned char *pt, unsigned long blocks, unsigned char *IV, const symmetric_key *skey)
{
   #define blocks_at_a_time (128 / 32)

   unsigned long iblock;
   int err;
   LTC_ALIGN_MSVC(16) unsigned char pad1[blocks_at_a_time * serpent_block_len] LTC_ALIGN(16);
   int i;
   LTC_ALIGN_MSVC(16) unsigned char pad2[blocks_at_a_time * serpent_block_len] LTC_ALIGN(16);
   int j;

   LTC_ARGCHK(blocks % blocks_at_a_time == 0);
   LTC_ARGCHK(serpent_block_len % sizeof(LTC_FAST_TYPE) == 0);

   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      if ((err = s_serpent_accel_ecb_decrypt_128_bit_sse2(ct, pad1, blocks_at_a_time, skey)) != CRYPT_OK) {
         return err;
      }
      for (i = 0; i != serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_XOR3(&pad2[i * sizeof(LTC_FAST_TYPE)], &IV[i * sizeof(LTC_FAST_TYPE)], &pad1[i * sizeof(LTC_FAST_TYPE)]);
      }
      for (j = 1; j != blocks_at_a_time; ++j) {
         for (i = 0; i != serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
            LTC_FAST_XOR3(&pad2[j * serpent_block_len + i * sizeof(LTC_FAST_TYPE)], &ct[(j - 1) * serpent_block_len + i * sizeof(LTC_FAST_TYPE)], &pad1[j * serpent_block_len + i * sizeof(LTC_FAST_TYPE)]);
         }
      }
      for (i = 0; i != serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_STORE(&IV[i * sizeof(LTC_FAST_TYPE)], LTC_FAST_LOAD(&ct[(j - 1) * serpent_block_len + i * sizeof(LTC_FAST_TYPE)]));
      }
      for (i = 0; i != blocks_at_a_time * serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_STORE(&pt[i * sizeof(LTC_FAST_TYPE)], LTC_FAST_LOAD(&pad2[i * sizeof(LTC_FAST_TYPE)]));
      }
      pt += blocks_at_a_time * serpent_block_len;
      ct += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
}

#endif

#if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2

static LTC_INLINE int s_serpent_accel_cbc_decrypt_256_bit_avx2(const unsigned char *ct, unsigned char *pt, unsigned long blocks, unsigned char *IV, const symmetric_key *skey)
{
   #define blocks_at_a_time (256 / 32)

   unsigned long iblock;
   int err;
   LTC_ALIGN_MSVC(32) unsigned char pad1[blocks_at_a_time * serpent_block_len] LTC_ALIGN(32);
   int i;
   LTC_ALIGN_MSVC(32) unsigned char pad2[blocks_at_a_time * serpent_block_len] LTC_ALIGN(32);
   int j;

   LTC_ARGCHK(blocks % blocks_at_a_time == 0);
   LTC_ARGCHK(serpent_block_len % sizeof(LTC_FAST_TYPE) == 0);

   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      if ((err = s_serpent_accel_ecb_decrypt_256_bit_avx2(ct, pad1, blocks_at_a_time, skey)) != CRYPT_OK) {
         return err;
      }
      for (i = 0; i != serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_XOR3(&pad2[i * sizeof(LTC_FAST_TYPE)], &IV[i * sizeof(LTC_FAST_TYPE)], &pad1[i * sizeof(LTC_FAST_TYPE)]);
      }
      for (j = 1; j != blocks_at_a_time; ++j) {
         for (i = 0; i != serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
            LTC_FAST_XOR3(&pad2[j * serpent_block_len + i * sizeof(LTC_FAST_TYPE)], &ct[(j - 1) * serpent_block_len + i * sizeof(LTC_FAST_TYPE)], &pad1[j * serpent_block_len + i * sizeof(LTC_FAST_TYPE)]);
         }
      }
      for (i = 0; i != serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_STORE(&IV[i * sizeof(LTC_FAST_TYPE)], LTC_FAST_LOAD(&ct[(j - 1) * serpent_block_len + i * sizeof(LTC_FAST_TYPE)]));
      }
      for (i = 0; i != blocks_at_a_time * serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_STORE(&pt[i * sizeof(LTC_FAST_TYPE)], LTC_FAST_LOAD(&pad2[i * sizeof(LTC_FAST_TYPE)]));
      }
      pt += blocks_at_a_time * serpent_block_len;
      ct += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
}

#endif

static LTC_INLINE int s_serpent_accel_ctr_encrypt_32_bit(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, const symmetric_key *skey)
{
   #define blocks_at_a_time (32 / 32)

   unsigned long iblock;
   int i;
   LTC_ALIGN_MSVC(4) unsigned char pad[blocks_at_a_time * serpent_block_len] LTC_ALIGN(4);
   int err;

   LTC_ARGCHK(blocks % blocks_at_a_time == 0);
   LTC_ARGCHK(serpent_block_len % sizeof(LTC_FAST_TYPE) == 0);

   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      for (i = 0; i != blocks_at_a_time; ++i) {
         s_serpent_accel_ctr_increment_counter_generic(IV, mode);
         XMEMCPY(&pad[i * serpent_block_len], IV, serpent_block_len);
      }
      if ((err = s_serpent_accel_ecb_encrypt_32_bit(&pad[0], &pad[0], blocks_at_a_time, skey)) != CRYPT_OK) {
         return err;
      }
      for (i = 0; i != blocks_at_a_time * serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_XOR3(&ct[i * sizeof(LTC_FAST_TYPE)], &pt[i * sizeof(LTC_FAST_TYPE)], &pad[i * sizeof(LTC_FAST_TYPE)]);
      }
      pt += blocks_at_a_time * serpent_block_len;
      ct += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
}

#if defined LTC_SERPENT_ACCEL_64_BIT

static LTC_INLINE int s_serpent_accel_ctr_encrypt_64_bit(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, const symmetric_key *skey)
{
   #define blocks_at_a_time (64 / 32)

   unsigned long iblock;
   int i;
   LTC_ALIGN_MSVC(8) unsigned char pad[blocks_at_a_time * serpent_block_len] LTC_ALIGN(8);
   int err;

   LTC_ARGCHK(blocks % blocks_at_a_time == 0);
   LTC_ARGCHK(serpent_block_len % sizeof(LTC_FAST_TYPE) == 0);

   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      for (i = 0; i != blocks_at_a_time; ++i) {
         s_serpent_accel_ctr_increment_counter_generic(IV, mode);
         XMEMCPY(&pad[i * serpent_block_len], IV, serpent_block_len);
      }
      if ((err = s_serpent_accel_ecb_encrypt_64_bit(&pad[0], &pad[0], blocks_at_a_time, skey)) != CRYPT_OK) {
         return err;
      }
      for (i = 0; i != blocks_at_a_time * serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_XOR3(&ct[i * sizeof(LTC_FAST_TYPE)], &pt[i * sizeof(LTC_FAST_TYPE)], &pad[i * sizeof(LTC_FAST_TYPE)]);
      }
      pt += blocks_at_a_time * serpent_block_len;
      ct += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
}

#endif

#if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2

static LTC_INLINE int s_serpent_accel_ctr_encrypt_128_bit_sse2(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, const symmetric_key *skey)
{
   #define blocks_at_a_time (128 / 32)

   unsigned long iblock;
   int i;
   LTC_ALIGN_MSVC(16) unsigned char pad[blocks_at_a_time * serpent_block_len] LTC_ALIGN(16);
   int err;

   LTC_ARGCHK(blocks % blocks_at_a_time == 0);
   LTC_ARGCHK(serpent_block_len % sizeof(LTC_FAST_TYPE) == 0);

   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      for (i = 0; i != blocks_at_a_time; ++i) {
         s_serpent_accel_ctr_increment_counter_generic(IV, mode);
         XMEMCPY(&pad[i * serpent_block_len], IV, serpent_block_len);
      }
      if ((err = s_serpent_accel_ecb_encrypt_128_bit_sse2(&pad[0], &pad[0], blocks_at_a_time, skey)) != CRYPT_OK) {
         return err;
      }
      for (i = 0; i != blocks_at_a_time * serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_XOR3(&ct[i * sizeof(LTC_FAST_TYPE)], &pt[i * sizeof(LTC_FAST_TYPE)], &pad[i * sizeof(LTC_FAST_TYPE)]);
      }
      pt += blocks_at_a_time * serpent_block_len;
      ct += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
}

#endif

#if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2

static LTC_INLINE int s_serpent_accel_ctr_encrypt_256_bit_avx2(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, const symmetric_key *skey)
{
   #define blocks_at_a_time (256 / 32)

   unsigned long iblock;
   int i;
   LTC_ALIGN_MSVC(32) unsigned char pad[blocks_at_a_time * serpent_block_len] LTC_ALIGN(32);
   int err;

   LTC_ARGCHK(blocks % blocks_at_a_time == 0);
   LTC_ARGCHK(serpent_block_len % sizeof(LTC_FAST_TYPE) == 0);

   for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
      for (i = 0; i != blocks_at_a_time; ++i) {
         s_serpent_accel_ctr_increment_counter_generic(IV, mode);
         XMEMCPY(&pad[i * serpent_block_len], IV, serpent_block_len);
      }
      if ((err = s_serpent_accel_ecb_encrypt_256_bit_avx2(&pad[0], &pad[0], blocks_at_a_time, skey)) != CRYPT_OK) {
         return err;
      }
      for (i = 0; i != blocks_at_a_time * serpent_block_len / sizeof(LTC_FAST_TYPE); ++i) {
         LTC_FAST_XOR3(&ct[i * sizeof(LTC_FAST_TYPE)], &pt[i * sizeof(LTC_FAST_TYPE)], &pad[i * sizeof(LTC_FAST_TYPE)]);
      }
      pt += blocks_at_a_time * serpent_block_len;
      ct += blocks_at_a_time * serpent_block_len;
   }
   return CRYPT_OK;

   #undef blocks_at_a_time
}

#endif

int serpent_accel_ecb_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long blocks, const symmetric_key *skey)
{
   const unsigned char *in;
   unsigned char *out;
   unsigned long rem;
   unsigned long n;
   int err;

   in = pt;
   out = ct;
   rem = blocks;
   while (rem != 0) {
      #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
      if (rem >= (256 / 32) && s_is_supported_256_bit_avx2()) {
         n = (rem / (256 / 32)) * (256 / 32);
         err = s_serpent_accel_ecb_encrypt_256_bit_avx2(in, out, n, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      } else
      #endif
      #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
      if (rem >= (128 / 32) && s_x86_sse2_is_supported()) {
         #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
         n = 128 / 32;
         #else
         n = (rem / (128 / 32)) * (128 / 32);
         #endif
         err = s_serpent_accel_ecb_encrypt_128_bit_sse2(in, out, n, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      } else
      #endif
      #if defined LTC_SERPENT_ACCEL_64_BIT
      if (rem >= (64 / 32)) {
         #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
         n = 64 / 32;
         #else
         n = (rem / (64 / 32)) * (64 / 32);
         #endif
         err = s_serpent_accel_ecb_encrypt_64_bit(in, out, n, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      } else
      #endif
      {
         #if defined LTC_SERPENT_ACCEL_64_BIT
         n = 32 / 32;
         #else
         n = rem;
         #endif
         err = s_serpent_accel_ecb_encrypt_32_bit(in, out, n, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      }
   }
   return CRYPT_OK;
}

int serpent_accel_ecb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long blocks, const symmetric_key *skey)
{
   const unsigned char *in;
   unsigned char *out;
   unsigned long rem;
   unsigned long n;
   int err;

   in = ct;
   out = pt;
   rem = blocks;
   while (rem != 0) {
      #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
      if (rem >= (256 / 32) && s_is_supported_256_bit_avx2()) {
         n = (rem / (256 / 32)) * (256 / 32);
         err = s_serpent_accel_ecb_decrypt_256_bit_avx2(in, out, n, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      } else
      #endif
      #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
      if (rem >= (128 / 32) && s_x86_sse2_is_supported()) {
         #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
         n = 128 / 32;
         #else
         n = (rem / (128 / 32)) * (128 / 32);
         #endif
         err = s_serpent_accel_ecb_decrypt_128_bit_sse2(in, out, n, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      } else
      #endif
      #if defined LTC_SERPENT_ACCEL_64_BIT
      if (rem >= (64 / 32)) {
         #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
         n = 64 / 32;
         #else
         n = (rem / (64 / 32)) * (64 / 32);
         #endif
         err = s_serpent_accel_ecb_decrypt_64_bit(in, out, n, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      } else
      #endif
      {
         #if defined LTC_SERPENT_ACCEL_64_BIT
         n = 32 / 32;
         #else
         n = rem;
         #endif
         err = s_serpent_accel_ecb_decrypt_32_bit(in, out, n, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      }
   }
   return CRYPT_OK;
}

int serpent_accel_cbc_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long blocks, unsigned char *IV, const symmetric_key *skey)
{
   const unsigned char *in;
   unsigned char *out;
   unsigned long rem;
   unsigned long n;
   int err;

   in = ct;
   out = pt;
   rem = blocks;
   while (rem != 0) {
      #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
      if (rem >= (256 / 32) && s_is_supported_256_bit_avx2()) {
         n = (rem / (256 / 32)) * (256 / 32);
         err = s_serpent_accel_cbc_decrypt_256_bit_avx2(in, out, n, IV, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      } else
      #endif
      #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
      if (rem >= (128 / 32) && s_x86_sse2_is_supported()) {
         #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
         n = 128 / 32;
         #else
         n = (rem / (128 / 32)) * (128 / 32);
         #endif
         err = s_serpent_accel_cbc_decrypt_128_bit_sse2(in, out, n, IV, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      } else
      #endif
      #if defined LTC_SERPENT_ACCEL_64_BIT
      if (rem >= (64 / 32)) {
         #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
         n = 64 / 32;
         #else
         n = (rem / (64 / 32)) * (64 / 32);
         #endif
         err = s_serpent_accel_cbc_decrypt_64_bit(in, out, n, IV, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      } else
      #endif
      {
         #if defined LTC_SERPENT_ACCEL_64_BIT
         n = 32 / 32;
         #else
         n = rem;
         #endif
         err = s_serpent_accel_cbc_decrypt_32_bit(in, out, n, IV, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      }
   }
   return CRYPT_OK;
}

int serpent_accel_ctr_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, const symmetric_key *skey)
{
   const unsigned char *in;
   unsigned char *out;
   unsigned long rem;
   unsigned long n;
   int err;

   in = pt;
   out = ct;
   rem = blocks;
   while (rem != 0) {
      #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
      if (rem >= (256 / 32) && s_is_supported_256_bit_avx2()) {
         n = (rem / (256 / 32)) * (256 / 32);
         err = s_serpent_accel_ctr_encrypt_256_bit_avx2(in, out, n, IV, mode, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      } else
      #endif
      #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
      if (rem >= (128 / 32) && s_x86_sse2_is_supported()) {
         #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
         n = 128 / 32;
         #else
         n = (rem / (128 / 32)) * (128 / 32);
         #endif
         err = s_serpent_accel_ctr_encrypt_128_bit_sse2(in, out, n, IV, mode, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      } else
      #endif
      #if defined LTC_SERPENT_ACCEL_64_BIT
      if (rem >= (64 / 32)) {
         #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
         n = 64 / 32;
         #else
         n = (rem / (64 / 32)) * (64 / 32);
         #endif
         err = s_serpent_accel_ctr_encrypt_64_bit(in, out, n, IV, mode, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      } else
      #endif
      {
         #if defined LTC_SERPENT_ACCEL_64_BIT
         n = 32 / 32;
         #else
         n = rem;
         #endif
         err = s_serpent_accel_ctr_encrypt_32_bit(in, out, n, IV, mode, skey);
         if (err != CRYPT_OK) {
            return err;
         }
         out += n * serpent_block_len;
         in += n * serpent_block_len;
         rem -= n;
      }
   }
   return CRYPT_OK;
}

#endif

int serpent_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   static const struct {
      unsigned char key[32];
      int keylen;
      unsigned char pt[16], ct[16];
   } tests[] = {
      {
      /* key */    {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 32,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0xA2,0x23,0xAA,0x12,0x88,0x46,0x3C,0x0E,0x2B,0xE3,0x8E,0xBD,0x82,0x56,0x16,0xC0}
      },
      {
      /* key */    {0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 32,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0xEA,0xE1,0xD4,0x05,0x57,0x01,0x74,0xDF,0x7D,0xF2,0xF9,0x96,0x6D,0x50,0x91,0x59}
      },
      {
      /* key */    {0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 32,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x65,0xF3,0x76,0x84,0x47,0x1E,0x92,0x1D,0xC8,0xA3,0x0F,0x45,0xB4,0x3C,0x44,0x99}
      },
      {
      /* key */    {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 24,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x9E,0x27,0x4E,0xAD,0x9B,0x73,0x7B,0xB2,0x1E,0xFC,0xFC,0xA5,0x48,0x60,0x26,0x89}
      },
      {
      /* key */    {0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 24,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x92,0xFC,0x8E,0x51,0x03,0x99,0xE4,0x6A,0x04,0x1B,0xF3,0x65,0xE7,0xB3,0xAE,0x82}
      },
      {
      /* key */    {0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 24,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x5E,0x0D,0xA3,0x86,0xC4,0x6A,0xD4,0x93,0xDE,0xA2,0x03,0xFD,0xC6,0xF5,0x7D,0x70}
      },
      {
      /* key */    {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 16,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x26,0x4E,0x54,0x81,0xEF,0xF4,0x2A,0x46,0x06,0xAB,0xDA,0x06,0xC0,0xBF,0xDA,0x3D}
      },
      {
      /* key */    {0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 16,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x4A,0x23,0x1B,0x3B,0xC7,0x27,0x99,0x34,0x07,0xAC,0x6E,0xC8,0x35,0x0E,0x85,0x24}
      },
      {
      /* key */    {0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 16,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0xE0,0x32,0x69,0xF9,0xE9,0xFD,0x85,0x3C,0x7D,0x81,0x56,0xDF,0x14,0xB9,0x8D,0x56}
      }
   };

   unsigned char buf[2][16];
   symmetric_key key;
   int err, x;

   for (x = 0; x < (int)LTC_ARRAY_SIZE(tests); x++) {
      if ((err = serpent_setup(tests[x].key, tests[x].keylen, 0, &key)) != CRYPT_OK) {
        return err;
      }
      if ((err = serpent_ecb_encrypt(tests[x].pt, buf[0], &key)) != CRYPT_OK) {
        return err;
      }
      if (ltc_compare_testvector(buf[0], 16, tests[x].ct, 16, "SERPENT Encrypt", x)) {
        return CRYPT_FAIL_TESTVECTOR;
      }
      if ((err = serpent_ecb_decrypt(tests[x].ct, buf[1], &key)) != CRYPT_OK) {
        return err;
      }
      if (ltc_compare_testvector(buf[1], 16, tests[x].pt, 16, "SERPENT Decrypt", x)) {
        return CRYPT_FAIL_TESTVECTOR;
      }
   }

   return CRYPT_OK;
#endif
}

#undef s_lt
#undef s_ilt
#undef s_beforeS0
#undef s_afterS0
#undef s_afterS1
#undef s_afterS2
#undef s_afterS3
#undef s_afterS4
#undef s_afterS5
#undef s_afterS6
#undef s_afterS7
#undef s_beforeI7
#undef s_afterI7
#undef s_afterI6
#undef s_afterI5
#undef s_afterI4
#undef s_afterI3
#undef s_afterI2
#undef s_afterI1
#undef s_afterI0
#undef s_s0
#undef s_i0
#undef s_s1
#undef s_i1
#undef s_s2
#undef s_i2
#undef s_s3
#undef s_i3
#undef s_s4
#undef s_i4
#undef s_s5
#undef s_i5
#undef s_s6
#undef s_i6
#undef s_s7
#undef s_i7
#undef s_kx
#undef s_lk
#undef s_sk
#undef s_setup_key
#undef serpent_block_len

#endif
