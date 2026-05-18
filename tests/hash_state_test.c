/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include <tomcrypt_test.h>

#include <stdlib.h>


static int s_hash_state_test_sha1(void)
{
#ifdef LTC_SHA1
  struct ugly_struct
  {
    unsigned char uchar;
    struct sha1_state state;
  };
  typedef struct ugly_struct ugly_struct;

  const unsigned char digest_baseline[] = { 0xa4, 0x9b, 0x24, 0x46, 0xa0, 0x2c, 0x64, 0x5b, 0xf4, 0x19, 0xf9, 0x95, 0xb6, 0x70, 0x91, 0x25, 0x3a, 0x04, 0xa2, 0x59 };

  ugly_struct* md_a;
  int err;
  ugly_struct* md_b;
  unsigned char digest_computed[sizeof(digest_baseline)];
  int cmp;

  md_a = (ugly_struct*)malloc(sizeof(*md_a));
  err = sha1_init((hash_state*)&md_a->state); if(err != CRYPT_OK){ return err; }
  err = sha1_process((hash_state*)&md_a->state, (const unsigned char*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112); if(err != CRYPT_OK){ return err; }
  md_b = (ugly_struct*)malloc(sizeof(*md_b));
  *md_b = *md_a;
  XMEMSET(md_a, 0xff, sizeof(*md_a));
  free(md_a);
  err = sha1_done((hash_state*)&md_b->state, &digest_computed[0]); if(err != CRYPT_OK){ return err; }
  free(md_b);
  cmp = ltc_compare_testvector(&digest_computed[0], sizeof(digest_computed), &digest_baseline[0], sizeof(digest_baseline), "SHA-1", 0);
  if(cmp != 0)
  {
    return CRYPT_FAIL_TESTVECTOR;
  }
#endif
  return CRYPT_OK;
}

static int s_hash_state_test_sha224(void)
{
#ifdef LTC_SHA224
  struct ugly_struct
  {
    unsigned char uchar;
    struct sha256_state state;
  };
  typedef struct ugly_struct ugly_struct;

  const unsigned char digest_baseline[] = { 0xc9, 0x7c, 0xa9, 0xa5, 0x59, 0x85, 0x0c, 0xe9, 0x7a, 0x04, 0xa9, 0x6d, 0xef, 0x6d, 0x99, 0xa9, 0xe0, 0xe0, 0xe2, 0xab, 0x14, 0xe6, 0xb8, 0xdf, 0x26, 0x5f, 0xc0, 0xb3 };

  ugly_struct* md_a;
  int err;
  ugly_struct* md_b;
  unsigned char digest_computed[sizeof(digest_baseline)];
  int cmp;

  md_a = (ugly_struct*)malloc(sizeof(*md_a));
  err = sha224_init((hash_state*)&md_a->state); if(err != CRYPT_OK){ return err; }
  err = sha224_process((hash_state*)&md_a->state, (const unsigned char*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112); if(err != CRYPT_OK){ return err; }
  md_b = (ugly_struct*)malloc(sizeof(*md_b));
  *md_b = *md_a;
  XMEMSET(md_a, 0xff, sizeof(*md_a));
  free(md_a);
  err = sha224_done((hash_state*)&md_b->state, &digest_computed[0]); if(err != CRYPT_OK){ return err; }
  free(md_b);
  cmp = ltc_compare_testvector(&digest_computed[0], sizeof(digest_computed), &digest_baseline[0], sizeof(digest_baseline), "SHA-224", 0);
  if(cmp != 0)
  {
    return CRYPT_FAIL_TESTVECTOR;
  }
#endif
  return CRYPT_OK;
}

static int s_hash_state_test_sha256(void)
{
#ifdef LTC_SHA256
  struct ugly_struct
  {
    unsigned char uchar;
    struct sha256_state state;
  };
  typedef struct ugly_struct ugly_struct;

  const unsigned char digest_baseline[] = { 0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37, 0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1 };

  ugly_struct* md_a;
  int err;
  ugly_struct* md_b;
  unsigned char digest_computed[sizeof(digest_baseline)];
  int cmp;

  md_a = (ugly_struct*)malloc(sizeof(*md_a));
  err = sha256_init((hash_state*)&md_a->state); if(err != CRYPT_OK){ return err; }
  err = sha256_process((hash_state*)&md_a->state, (const unsigned char*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112); if(err != CRYPT_OK){ return err; }
  md_b = (ugly_struct*)malloc(sizeof(*md_b));
  *md_b = *md_a;
  XMEMSET(md_a, 0xff, sizeof(*md_a));
  free(md_a);
  err = sha256_done((hash_state*)&md_b->state, &digest_computed[0]); if(err != CRYPT_OK){ return err; }
  free(md_b);
  cmp = ltc_compare_testvector(&digest_computed[0], sizeof(digest_computed), &digest_baseline[0], sizeof(digest_baseline), "SHA-256", 0);
  if(cmp != 0)
  {
    return CRYPT_FAIL_TESTVECTOR;
  }
#endif
  return CRYPT_OK;
}


int hash_state_test(void)
{
  int err;

  err = s_hash_state_test_sha1(); if(err != CRYPT_OK){ return err; }
  err = s_hash_state_test_sha224(); if(err != CRYPT_OK){ return err; }
  err = s_hash_state_test_sha256(); if(err != CRYPT_OK){ return err; }
  return CRYPT_OK;
}
