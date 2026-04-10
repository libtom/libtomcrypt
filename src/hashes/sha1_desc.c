/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_SHA1

const struct ltc_hash_descriptor sha1_desc =
{
    "sha1",
    2,
    20,
    64,

    /* OID */
   { 1, 3, 14, 3, 2, 26,  },
   6,

    &sha1_init,
    &sha1_process,
    &sha1_done,
    &sha1_test,
    NULL
};

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha1_init(hash_state * md)
{
    int err;

    #if defined LTC_SHA1_X86
    ~~~todo~~~
    #else
    err = sha1_c_init(md); if(err != CRYPT_OK){ return err; }
    #endif
    return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
int sha1_process(hash_state * md, const unsigned char *in, unsigned long inlen)
{
    int err;

    #if defined LTC_SHA1_X86
    ~~~todo~~~
    #else
    err = sha1_c_process(md, in, inlen); if(err != CRYPT_OK){ return err; }
    #endif
    return CRYPT_OK;
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (20 bytes)
   @return CRYPT_OK if successful
*/
int sha1_done(hash_state * md, unsigned char *out)
{
    int err;

    #if defined LTC_SHA1_X86
    ~~~todo~~~
    #else
    err = sha1_c_done(md, out); if(err != CRYPT_OK){ return err; }
    #endif
    return CRYPT_OK;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int  sha1_test(void)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else
  static const struct {
      const char *msg;
      unsigned char hash[20];
  } tests[] = {
    { "abc",
      { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d }
    },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E,
        0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5,
        0xE5, 0x46, 0x70, 0xF1 }
    }
  };

  int i;
  unsigned char tmp[20];
  hash_state md;

  for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0]));  i++) {
      sha1_init(&md);
      sha1_process(&md, (unsigned char*)tests[i].msg, (unsigned long)XSTRLEN(tests[i].msg));
      sha1_done(&md, tmp);
      if (ltc_compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "SHA1", i)) {
         return CRYPT_FAIL_TESTVECTOR;
      }
  }
  return CRYPT_OK;
  #endif
}

#endif
