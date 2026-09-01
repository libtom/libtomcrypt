/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* The implementation is based on:
 * "Extending the Salsa20 nonce", https://cr.yp.to/snuffle/xsalsa-20081128.pdf
 * "Salsa20 specification", http://cr.yp.to/snuffle/spec.pdf
 * and salsa20-ref.c version 20051118
 * Public domain from D. J. Bernstein
 */

#include "tomcrypt_private.h"

#ifdef LTC_XSALSA20

#if defined(LTC_SHA256) && defined(LTC_TEST)
static int s_sha256(unsigned char *hash, const unsigned char *data, const int datalen) {
   hash_state md;
   sha256_init(&md);
   sha256_process(&md, data, datalen);
   sha256_done(&md, hash);
   return CRYPT_OK;
}
#endif

int xsalsa20_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else

   /***************************************************************************
    * TV0: HSalsa20 known-answer test
    * From the NaCl test suite / https://cr.yp.to/snuffle/xsalsa-20081128.pdf
    */
   {
      const unsigned char key[] = {
         0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7,
         0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
      };
      const unsigned char in[] = {
         0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6
      };
      const unsigned char expected[] = {
         0xdc,0x90,0x8d,0xda,0x0b,0x93,0x44,0xa9,0x53,0x62,0x9b,0x73,0x38,0x20,0x77,0x88,
         0x80,0xf3,0xce,0xb4,0x21,0xbb,0x61,0xb9,0x1c,0xbd,0x4c,0x3e,0x66,0x25,0x6c,0xe4
      };
      unsigned char out[32];
      int err;

      if ((err = xsalsa20_hsalsa20(out, 32, key, 32, in, 16, 20)) != CRYPT_OK) return err;
      if (ltc_compare_testvector(out, 32, expected, 32, "XSALSA20-TV0 (HSalsa20)", 0)) return CRYPT_FAIL_TESTVECTOR;
   }

    /***************************************************************************
     * verify a round trip:
     */
    {
        const unsigned char key[]   = {0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89};
        const unsigned char nonce[] = {0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37};
        const void *msg             = "Kilroy was here!";
        unsigned char msglen = 17;                  /* includes trailing NULL */
        int rounds = 20;
        unsigned char ciphertext[17];
        unsigned char msg2[17];
        salsa20_state st;
        int err;

        if ((err = xsalsa20_setup(&st, key, 32, nonce, 24, rounds)) != CRYPT_OK)  return err;
        if ((err = salsa20_crypt(&st, msg, msglen, ciphertext))     != CRYPT_OK)  return err;
        if ((err = salsa20_done(&st))                               != CRYPT_OK)  return err;

        if ((err = xsalsa20_setup(&st, key, 32, nonce, 24, rounds)) != CRYPT_OK)  return err;
        if ((err = salsa20_crypt(&st, ciphertext, msglen, msg2))    != CRYPT_OK)  return err;
        if ((err = salsa20_done(&st))                               != CRYPT_OK)  return err;

        if (ltc_compare_testvector(msg, msglen, msg2, msglen, "XSALSA20-TV1", 1))  return CRYPT_FAIL_TESTVECTOR;


        /* round trip with two single function calls */
        if ((err = xsalsa20_memory(key, sizeof(key), 20, nonce, sizeof(nonce), msg, msglen, ciphertext))  != CRYPT_OK)                return err;
        if ((err = xsalsa20_memory(key, sizeof(key), 20, nonce, sizeof(nonce), ciphertext, msglen, msg2)) != CRYPT_OK)                return err;
        if (ltc_compare_testvector(msg, msglen, msg2, msglen, "XSALSA20-TV2", 1))  return CRYPT_FAIL_TESTVECTOR;
    }

#ifdef LTC_SHA256
   /***************************************************************************
    * verify correct generation of a keystream
    */
   {
       const unsigned char key[]        = {0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89};
       const unsigned char nonce[]      = {0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37};
       const unsigned char expecthash[] = {0x6a,0x60,0x57,0x65,0x27,0xe0,0x00,0x51,0x6d,0xb0,0xda,0x60,0x46,0x20,0xf6,0xd0,0x95,0x65,0x45,0x39,0xf4,0x86,0x83,0x43,0x64,0xdf,0xd9,0x5a,0x6f,0x3f,0xbe,0xb7};
       int rounds = 20;
       unsigned char keystream[91101];
       unsigned long keystreamlen = 91101;
       unsigned char hash[32];
       salsa20_state st;
       int err;

       if ((err = xsalsa20_setup(&st, key, 32, nonce, 24, rounds))   != CRYPT_OK)  return err;
       if ((err = salsa20_keystream(&st, keystream, keystreamlen))   != CRYPT_OK)  return err;
       if ((err = salsa20_done(&st))                                 != CRYPT_OK)  return err;
       if ((err = s_sha256(hash, keystream, keystreamlen))            != CRYPT_OK)  return err;
       if (ltc_compare_testvector(hash, sizeof(hash), expecthash, sizeof(expecthash),   "XSALSA20-TV3", 1))  return CRYPT_FAIL_TESTVECTOR;
   }
#endif

   return CRYPT_OK;

#endif
}

#endif
