/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ctr_test.c
  CTR implementation, Tests again RFC 3686, Tom St Denis
*/

#ifdef LTC_CTR_MODE

static LTC_INLINE int s_ctr_test_1(void)
{
#ifdef LTC_NO_TEST
   return CRYPT_NOP;
#else
   static const struct {
      int keylen, msglen;
      unsigned char key[32], IV[16], pt[64], ct[64];
   } tests[] = {
/* 128-bit key, 16-byte pt */
{
   16, 16,
   {0xAE,0x68,0x52,0xF8,0x12,0x10,0x67,0xCC,0x4B,0xF7,0xA5,0x76,0x55,0x77,0xF3,0x9E },
   {0x00,0x00,0x00,0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
   {0x53,0x69,0x6E,0x67,0x6C,0x65,0x20,0x62,0x6C,0x6F,0x63,0x6B,0x20,0x6D,0x73,0x67 },
   {0xE4,0x09,0x5D,0x4F,0xB7,0xA7,0xB3,0x79,0x2D,0x61,0x75,0xA3,0x26,0x13,0x11,0xB8 },
},

/* 128-bit key, 36-byte pt */
{
   16, 36,
   {0x76,0x91,0xBE,0x03,0x5E,0x50,0x20,0xA8,0xAC,0x6E,0x61,0x85,0x29,0xF9,0xA0,0xDC },
   {0x00,0xE0,0x01,0x7B,0x27,0x77,0x7F,0x3F,0x4A,0x17,0x86,0xF0,0x00,0x00,0x00,0x00 },
   {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
    0x20,0x21,0x22,0x23},
   {0xC1,0xCF,0x48,0xA8,0x9F,0x2F,0xFD,0xD9,0xCF,0x46,0x52,0xE9,0xEF,0xDB,0x72,0xD7,
    0x45,0x40,0xA4,0x2B,0xDE,0x6D,0x78,0x36,0xD5,0x9A,0x5C,0xEA,0xAE,0xF3,0x10,0x53,
    0x25,0xB2,0x07,0x2F },
},
};
  int idx, err, x;
  unsigned char buf[64];
  symmetric_CTR ctr;

  /* AES can be under rijndael or aes... try to find it */
  if ((idx = find_cipher("aes")) == -1) {
     if ((idx = find_cipher("rijndael")) == -1) {
        return CRYPT_NOP;
     }
  }

  for (x = 0; x < (int)LTC_ARRAY_SIZE(tests); x++) {
     if ((err = ctr_start(idx, tests[x].IV, tests[x].key, tests[x].keylen, 0, CTR_COUNTER_BIG_ENDIAN|LTC_CTR_RFC3686, &ctr)) != CRYPT_OK) {
        return err;
     }
     if ((err = ctr_encrypt(tests[x].pt, buf, tests[x].msglen, &ctr)) != CRYPT_OK) {
        return err;
     }
     ctr_done(&ctr);
     if (ltc_compare_testvector(buf, tests[x].msglen, tests[x].ct, tests[x].msglen, "CTR", x)) {
        return CRYPT_FAIL_TESTVECTOR;
     }
  }
  return CRYPT_OK;
#endif
}

static LTC_INLINE int s_ctr_test_2(void)
{
#ifdef LTC_NO_TEST
   return CRYPT_NOP;
#else
  #define LTC_ALIGN_BUF2(buf, align) ((void*)(((((ltc_uintptr)(buf)) + ((align) - 1)) / (align)) * (align)))
  #define buf_cap (4 * 1024) /* allocate big buffer, for example 4kB */
  #define buf_alg (1 * 1024) /* align the buffer to ridiculously strict alignment, for example 1kB */
  #define buf_len (buf_cap - buf_alg) /* in worst case, the buffer will be only 3kB big */

  unsigned char *pt;
  unsigned char pt_storage[buf_cap];
  unsigned char *ct1;
  unsigned char ct1_storage[buf_cap];
  unsigned char *ct2;
  unsigned char ct2_storage[buf_cap];
  int idx;
  int n;
  int i;
  unsigned char iv[MAXBLOCKSIZE];
  unsigned char key[4 * MAXBLOCKSIZE]; /* todo this is only guesstimate */
  int block_len;
  int err;
  symmetric_CTR ctr;

  pt = (unsigned char*)LTC_ALIGN_BUF2(pt_storage, buf_alg);
  ct1 = (unsigned char*)LTC_ALIGN_BUF2(ct1_storage, buf_alg);
  ct2 = (unsigned char*)LTC_ALIGN_BUF2(ct2_storage, buf_alg);
  idx = 0;
  for(;;) {
    if (cipher_is_valid(idx) != CRYPT_OK) {
      break;
    }
    n = buf_len;
    for (i = 0; i != n; ++i) {
      pt[i] = rand() & 0xff;
    }
    n = buf_len;
    for (i = 0; i != n; ++i) {
      ct1[i] = rand() & 0xff;
    }
    n = buf_len;
    for (i = 0; i != n; ++i) {
      ct2[i] = rand() & 0xff;
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

    /* encrypt random data by random key, do it piece-wise, so any acceleration might be hindered */
    if ((err = ctr_start(idx, iv, key, cipher_descriptor[idx].max_key_length, 0, CTR_COUNTER_BIG_ENDIAN | LTC_CTR_RFC3686, &ctr)) != CRYPT_OK) { return err; }
    n = buf_len / block_len;
    for (i = 0; i != n; ++i) {
      if ((err = ctr_encrypt(pt + i * block_len + (block_len / 2) * 0, ct1 + i * block_len + (block_len / 2) * 0, block_len / 2, &ctr)) != CRYPT_OK) { return err; }
      if ((err = ctr_encrypt(pt + i * block_len + (block_len / 2) * 1, ct1 + i * block_len + (block_len / 2) * 1, block_len / 2, &ctr)) != CRYPT_OK) { return err; }
    }
    if ((err = ctr_done(&ctr)) != CRYPT_OK) { return err; }

    /* encrypt random data by random key, do it all at once, so any acceleration might be used */
    if ((err = ctr_start(idx, iv, key, cipher_descriptor[idx].max_key_length, 0, CTR_COUNTER_BIG_ENDIAN | LTC_CTR_RFC3686, &ctr)) != CRYPT_OK) { return err; }
    if ((err = ctr_encrypt(pt, ct2, buf_len, &ctr)) != CRYPT_OK) { return err; }
    if ((err = ctr_done(&ctr)) != CRYPT_OK) { return err; }

    /* compare both non-accelerated and accelerated cipher texts */
    if (ltc_compare_testvector(ct2, buf_len, ct1, buf_len, "CTR", idx)) { return CRYPT_FAIL_TESTVECTOR; }
    ++idx;
  }
  return CRYPT_OK;

  #undef LTC_ALIGN_BUF2
  #undef buf_cap
  #undef buf_alg
  #undef buf_len
#endif
}

static LTC_INLINE int s_ctr_test_3(void)
{
#ifdef LTC_NO_TEST
   return CRYPT_NOP;
#else
  #define LTC_ALIGN_BUF2(buf, align) ((void*)(((((ltc_uintptr)(buf)) + ((align) - 1)) / (align)) * (align)))
  #define buf_cap (4 * 1024) /* allocate big buffer, for example 4kB */
  #define buf_alg (1 * 1024) /* align the buffer to ridiculously strict alignment, for example 1kB */
  #define buf_len (buf_cap - buf_alg) /* in worst case, the buffer will be only 3kB big */

  unsigned char *pt1;
  unsigned char pt1_storage[buf_cap];
  unsigned char *ct;
  unsigned char ct_storage[buf_cap];
  unsigned char *pt2;
  unsigned char pt2_storage[buf_cap];
  int idx;
  int n;
  int i;
  unsigned char iv[MAXBLOCKSIZE];
  unsigned char key[4 * MAXBLOCKSIZE]; /* todo this is only guesstimate */
  int block_len;
  int err;
  symmetric_CTR ctr;

  pt1 = (unsigned char*)LTC_ALIGN_BUF2(pt1_storage, buf_alg);
  ct = (unsigned char*)LTC_ALIGN_BUF2(ct_storage, buf_alg);
  pt2 = (unsigned char*)LTC_ALIGN_BUF2(pt2_storage, buf_alg);
  idx = 0;
  for(;;) {
    if (cipher_is_valid(idx) != CRYPT_OK) {
      break;
    }
    n = buf_len;
    for (i = 0; i != n; ++i) {
      pt1[i] = rand() & 0xff;
    }
    n = buf_len;
    for (i = 0; i != n; ++i) {
      ct[i] = rand() & 0xff;
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

    if ((err = ctr_start(idx, iv, key, cipher_descriptor[idx].max_key_length, 0, CTR_COUNTER_BIG_ENDIAN | LTC_CTR_RFC3686, &ctr)) != CRYPT_OK) { return err; }
    n = buf_len / block_len;
    for (i = 0; i != n; ++i) {
      if ((err = ctr_encrypt(pt1 + i * block_len + (block_len / 2) * 0, ct + i * block_len + (block_len / 2) * 0, block_len / 2, &ctr)) != CRYPT_OK) { return err; }
      if ((err = ctr_encrypt(pt1 + i * block_len + (block_len / 2) * 1, ct + i * block_len + (block_len / 2) * 1, block_len / 2, &ctr)) != CRYPT_OK) { return err; }
    }
    if ((err = ctr_done(&ctr)) != CRYPT_OK) { return err; }

    if ((err = ctr_start(idx, iv, key, cipher_descriptor[idx].max_key_length, 0, CTR_COUNTER_BIG_ENDIAN | LTC_CTR_RFC3686, &ctr)) != CRYPT_OK) { return err; }
    if ((err = ctr_decrypt(ct, pt2, buf_len, &ctr)) != CRYPT_OK) { return err; }
    if ((err = ctr_done(&ctr)) != CRYPT_OK) { return err; }

    /* test (possibly) accelerated decryption */
    if (ltc_compare_testvector(pt2, buf_len, pt1, buf_len, "CTR", idx)) { return CRYPT_FAIL_TESTVECTOR; }
    ++idx;
  }
  return CRYPT_OK;

  #undef LTC_ALIGN_BUF2
  #undef buf_cap
  #undef buf_alg
  #undef buf_len
#endif
}


int ctr_test(void)
{
  int err;

  err = s_ctr_test_1(); if (err != CRYPT_OK){ return err; }
  err = s_ctr_test_2(); if (err != CRYPT_OK){ return err; }
  err = s_ctr_test_3(); if (err != CRYPT_OK){ return err; }
  return CRYPT_OK;
}

#endif
