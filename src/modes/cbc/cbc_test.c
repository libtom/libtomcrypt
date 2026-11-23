/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file cbc_test.c
  CBC implementation
*/

#ifdef LTC_CBC_MODE

static LTC_INLINE int s_cbc_test_1(void)
{
#ifdef LTC_NO_TEST
   return CRYPT_NOP;
#else
  #define LTC_ALIGN_BUF2(buf, align) ((void*)(((((ltc_uintptr)(buf)) + ((align) - 1)) / (align)) * (align)))
  #define buf_cap (4 * 1024) /* allocate big buffer, for example 4kB */
  #define buf_alg (1 * 1024) /* align the buffer to ridiculously strict alignment, for example 1kB */
  #define buf_len (buf_cap - buf_alg) /* in worst case, the buffer will be only 3kB big */

  unsigned char *ct;
  unsigned char ct1_storage[buf_cap];
  unsigned char *pt1;
  unsigned char pt_storage[buf_cap];
  unsigned char *pt2;
  unsigned char ct2_storage[buf_cap];
  int idx;
  int n;
  int i;
  unsigned char iv[MAXBLOCKSIZE];
  unsigned char key[4 * MAXBLOCKSIZE]; /* todo this is only guesstimate */
  int block_len;
  int err;
  symmetric_CBC cbc;

  ct = (unsigned char*)LTC_ALIGN_BUF2(ct1_storage, buf_alg);
  pt1 = (unsigned char*)LTC_ALIGN_BUF2(pt_storage, buf_alg);
  pt2 = (unsigned char*)LTC_ALIGN_BUF2(ct2_storage, buf_alg);
  idx = 0;
  for(;;) {
    if (cipher_is_valid(idx) != CRYPT_OK) {
      break;
    }
    n = buf_len;
    for (i = 0; i != n; ++i) {
      ct[i] = rand() & 0xff;
    }
    n = buf_len;
    for (i = 0; i != n; ++i) {
      pt1[i] = rand() & 0xff;
    }
    n = buf_len;
    for (i = 0; i != n; ++i) {
      pt2[i] = rand() & 0xff;
    }
    n = LTC_ARRAY_SIZE(iv);
    for (i = 0; i != n; ++i) {
      iv[i] = rand() & 0xff;
    }
    n = LTC_ARRAY_SIZE(key);
    for (i = 0; i != n; ++i) {
      key[i] = rand() & 0xff;
    }
    block_len = cipher_descriptor[idx].block_length;
    LTC_ARGCHK(block_len >= 2);
    LTC_ARGCHK(block_len % 2 == 0);
    LTC_ARGCHK((int)LTC_ARRAY_SIZE(key) >= cipher_descriptor[idx].max_key_length);
    LTC_ARGCHK(buf_len % block_len == 0);

    /* decrypt random data by random key, do it piece-wise, so any acceleration might be hindered */
    if ((err = cbc_start(idx, iv, key, cipher_descriptor[idx].max_key_length, 0, &cbc)) != CRYPT_OK) { return err; }
    n = buf_len / block_len;
    for (i = 0; i != n; ++i) {
      if ((err = cbc_decrypt(ct + i * block_len, pt1 + i * block_len, block_len, &cbc)) != CRYPT_OK) { return err; }
    }
    if ((err = cbc_done(&cbc)) != CRYPT_OK) { return err; }

    /* decrypt random data by random key, do it all at once, so any acceleration might be used */
    if ((err = cbc_start(idx, iv, key, cipher_descriptor[idx].max_key_length, 0, &cbc)) != CRYPT_OK) { return err; }
    if ((err = cbc_decrypt(ct, pt2, buf_len, &cbc)) != CRYPT_OK) { return err; }
    if ((err = cbc_done(&cbc)) != CRYPT_OK) { return err; }

    /* compare both non-accelerated and accelerated plain texts */
    if (ltc_compare_testvector(pt2, buf_len, pt1, buf_len, "CBC", idx)) { return CRYPT_FAIL_TESTVECTOR; }
    ++idx;
  }
  return CRYPT_OK;

  #undef LTC_ALIGN_BUF2
  #undef buf_cap
  #undef buf_alg
  #undef buf_len
#endif
}


int cbc_test(void)
{
  int err;

  err = s_cbc_test_1(); if (err != CRYPT_OK){ return err; }
  return CRYPT_OK;
}

#endif
