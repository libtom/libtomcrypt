/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/* The implementation is based on:
 * "Extending the Salsa20 nonce", https://cr.yp.to/snuffle/xsalsa-20081128.pdf
 * "Salsa20 specification", http://cr.yp.to/snuffle/spec.pdf
 * and salsa20-ref.c version 20051118
 * Public domain from D. J. Bernstein
 */

#include "tomcrypt.h"

#ifdef LTC_XSALSA20

int _sha256(unsigned char *hash, const unsigned char *data, const int datalen) {
   hash_state md;
   sha256_init(&md);
   sha256_process(&md, data, datalen);
   sha256_done(&md, hash);
   return CRYPT_OK;
}

int xsalsa20_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else

    /***************************************************************************
     * verify a round trip:
     */
    {
        unsigned char key[]   = {0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89};
        unsigned char nonce[] = {0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37};
        int rounds            = 20;
        const void *msg       = "Kilroy was here!";
        unsigned char msglen  = 17;                  /* includes trailing NULL */
        unsigned char ciphertext[17];
        unsigned char msg2[17];
        xsalsa20_state st;
        int err;

        if ((err = xsalsa20_setup(&st, key, 32, nonce, 24, rounds, NULL))   != CRYPT_OK)  return err;
        if ((err = xsalsa20_crypt(&st, msg, msglen, ciphertext))            != CRYPT_OK)  return err;
        if ((err = xsalsa20_done(&st))                                      != CRYPT_OK)  return err;

        if ((err = xsalsa20_setup(&st, key, 32, nonce, 24, rounds, NULL))   != CRYPT_OK)  return err;
        if ((err = xsalsa20_crypt(&st, ciphertext, msglen, msg2))           != CRYPT_OK)  return err;
        if ((err = xsalsa20_done(&st))                                      != CRYPT_OK)  return err;

        if (compare_testvector(msg, msglen, msg2, msglen, "XSALSA20-TV1", 1))  return CRYPT_FAIL_TESTVECTOR;
    }

   /***************************************************************************
      verify correct generation of subkey 
      ref: stream3.c/out in nacl-20110221/tests
   */
   {
       unsigned char key[]      = {0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89};
       unsigned char nonce[]    = {0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37};
       unsigned char subkey[32] = {0};
       unsigned char expect[]   = {0xdc,0x90,0x8d,0xda,0x0b,0x93,0x44,0xa9,0x53,0x62,0x9b,0x73,0x38,0x20,0x77,0x88,0x80,0xf3,0xce,0xb4,0x21,0xbb,0x61,0xb9,0x1c,0xbd,0x4c,0x3e,0x66,0x25,0x6c,0xe4};
       int rounds               = 20;
       xsalsa20_state st;
       int err;
       
       if ((err = xsalsa20_setup(&st, key, 32, nonce, 24, rounds, subkey)) != CRYPT_OK)  return err;
       if (compare_testvector(subkey, sizeof(subkey), expect, sizeof(expect), "XSALSA20-TV2", 1))               return CRYPT_FAIL_TESTVECTOR;
   }

   /***************************************************************************
      verify correct generation of very long keystream
      ref: stream.c/out in nacl-20110221/tests
   */
   {
       unsigned char key[]        = {0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89};
       unsigned char subkey[32]   = {0};
       unsigned char expectkey[]  = {0xdc,0x90,0x8d,0xda,0x0b,0x93,0x44,0xa9,0x53,0x62,0x9b,0x73,0x38,0x20,0x77,0x88,0x80,0xf3,0xce,0xb4,0x21,0xbb,0x61,0xb9,0x1c,0xbd,0x4c,0x3e,0x66,0x25,0x6c,0xe4};
       unsigned char nonce[]      = {0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37};
       unsigned char keystream[4194304];
       unsigned long keystreamlen = 4194304;
       unsigned char hash[32];
       unsigned char expecthash[] = {0x66,0x2b,0x9d,0x0e,0x34,0x63,0x02,0x91,0x56,0x06,0x9b,0x12,0xf9,0x18,0x69,0x1a,0x98,0xf7,0xdf,0xb2,0xca,0x03,0x93,0xc9,0x6b,0xbf,0xc6,0xb1,0xfb,0xd6,0x30,0xa2};
       int rounds                 = 20;
       xsalsa20_state st;
       int err;
       
       if ((err = xsalsa20_setup(&st, key, 32, nonce, 24, rounds, subkey)) != CRYPT_OK)  return err;
       if ((err = xsalsa20_keystream(&st, keystream, keystreamlen))        != CRYPT_OK)  return err;
       if ((err = xsalsa20_done(&st))                                      != CRYPT_OK)  return err;
       if ((err = _sha256(hash, keystream, keystreamlen))                  != CRYPT_OK)  return err;
       if (compare_testvector(subkey, sizeof(subkey), expectkey, sizeof(expectkey), "XSALSA20-TV2", 1))               return CRYPT_FAIL_TESTVECTOR;
       if (compare_testvector(hash, sizeof(hash), expecthash, sizeof(expecthash),   "XSALSA20-TV3", 1))               return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
#endif
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  af67321bf3cde1a470c679e459ebb8189e38c9bd */
/* commit time: 2018-04-13 09:42:47 +0200 */
