/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt.h"

/**
  @file siv.c
  RFC 5297  SIV - Synthetic Initialization Vector, Steffen Jaeckel
*/

#ifdef LTC_SIV_MODE

static void _siv_dbl(unsigned char *inout)
{
   int y, mask, msb, len;

   /* setup the system */
   mask = 0x87;
   len = 16;

   /* if msb(L * u^(x+1)) = 0 then just shift, otherwise shift and xor constant mask */
   msb = inout[0] >> 7;

   /* shift left */
   for (y = 0; y < (len - 1); y++) {
      inout[y] = ((inout[y] << 1) | (inout[y + 1] >> 7)) & 255;
   }
   inout[len - 1] = ((inout[len - 1] << 1) ^ (msb ? mask : 0)) & 255;
}

static int _siv_S2V(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char **ad,    unsigned long *adlen,
    const unsigned char *in,     unsigned long inlen,
          unsigned char *V,      unsigned long *Vlen)
{
   int err, n;
   unsigned long Dlen, TMPlen, Tlen, i, j;
   unsigned char D[16], TMP[16], *T;
   unsigned char zero_or_one[16] = {0};

   if(ad == NULL || adlen == NULL || ad[0] == NULL || adlen[0] == 0) {
      /* if n = 0 then
       *   return V = AES-CMAC(K, <one>)
       */
      zero_or_one[0] = 1;
      err = omac_memory(cipher, key, keylen, zero_or_one, sizeof(zero_or_one), V, Vlen);
   } else {
      /* D = AES-CMAC(K, <zero>) */
      Dlen = sizeof(D);
      if ((err = omac_memory(cipher, key, keylen, zero_or_one, sizeof(zero_or_one), D, &Dlen)) != CRYPT_OK) {
         return err;
      }
      /* for i = 1 to n-1 do
       *   D = dbl(D) xor AES-CMAC(K, Si)
       * done
       */
      n = 0;
      while(ad[n] != NULL && adlen[n] != 0) {
         _siv_dbl(D);
         TMPlen = sizeof(TMP);
         if ((err = omac_memory(cipher, key, keylen, ad[n], adlen[n], TMP, &TMPlen)) != CRYPT_OK) {
            return err;
         }
         for (i = 0; i < sizeof(D); ++i) {
            D[i] ^= TMP[i];
         }
         n++;
      }
      /* if len(Sn) >= 128 then
       *   T = Sn xorend D
       * else
       *   T = dbl(D) xor pad(Sn)
       * fi
       */
      Tlen = inlen >= 16 ? inlen : 16;
      T = XMALLOC(Tlen);
      if (T == NULL) {
         return CRYPT_MEM;
      }
      XMEMCPY(T, in, inlen);
      if (inlen >= 16) {
         for(i = inlen - 16, j = 0; i < inlen; ++i, ++j) {
            T[i] = D[j] ^ T[i];
         }
      } else {
         _siv_dbl(D);
         T[inlen] = 0x80;
         for (i = inlen + 1; i < 16; ++i) {
            T[i] = 0x0;
         }
         for(i = 0; i < Tlen; ++i) {
            T[i] ^= D[i];
         }
      }
      err = omac_memory(cipher, key, keylen, T, Tlen, V, Vlen);
#ifdef LTC_CLEAN_STACK
      zeromem(T, Tlen);
#endif
      XFREE(T);
   }

   return err;

}

static void _siv_bitand(const unsigned char* V, unsigned char* Q)
{
   int n;
   XMEMSET(Q, 0xff, 16);
   Q[8] = Q[12] = 0x7f;
   for (n = 0; n < 16; ++n) {
      Q[n] &= V[n];
   }
}


typedef struct {
   unsigned char V[16];
   symmetric_CTR ctr;
} siv_state;

/**
   SIV encrypt

   @param cipher     The index of the cipher desired
   @param key        The secret key to use
   @param keylen     The length of the secret key (octets)
   @param ad         An array of Associated Data pointers (must be NULL terminated)
   @param adlen      An array with the lengths of the Associated Data
   @param pt         The plaintext
   @param ptlen      The length of the plaintext
   @param ct         The ciphertext
   @param ctlen      [in/out] The length of the ciphertext
   @return CRYPT_OK if successful
*/
int siv_encrypt(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char **ad,    unsigned long *adlen,
    const unsigned char *pt,     unsigned long ptlen,
          unsigned char *ct,     unsigned long *ctlen)
{
   int err;
   unsigned char Q[16];
   const unsigned char *K1, *K2;
   unsigned long Vlen;
   siv_state siv;

   LTC_ARGCHK(key    != NULL);
   LTC_ARGCHK(ad     != NULL);
   LTC_ARGCHK(adlen  != NULL);
   LTC_ARGCHK(pt     != NULL);
   LTC_ARGCHK(ct     != NULL);
   LTC_ARGCHK(ctlen  != NULL);

   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }
   if (*ctlen < ptlen + 16) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   K1 = key;
   K2 = &key[keylen/2];

   Vlen = sizeof(siv.V);
   err = _siv_S2V(cipher, K1, keylen/2, ad, adlen, pt, ptlen, siv.V, &Vlen);
#ifdef LTC_CLEAN_STACK
   burn_stack(3 * 16 + 7 * sizeof(unsigned long) + 1 * sizeof(void*));
#endif
   if (err != CRYPT_OK) {
      return err;
   }
   _siv_bitand(siv.V, Q);
   err = ctr_start(cipher, Q, K2, keylen/2, 0, CTR_COUNTER_BIG_ENDIAN | 16, &siv.ctr);
   if (err != CRYPT_OK) {
      goto out;
   }
   XMEMCPY(ct, siv.V, 16);
   ct += 16;
   err = ctr_encrypt(pt, ct, ptlen, &siv.ctr);
   if (err != CRYPT_OK) {
      zeromem(ct, ptlen + 16);
   } else {
      *ctlen = ptlen + 16;
   }
   ctr_done(&siv.ctr);

out:
#ifdef LTC_CLEAN_STACK
   zeromem(Q, sizeof(Q));
   zeromem(&siv, sizeof(siv));
#endif

   return err;
}

/**
   SIV decrypt

   @param cipher     The index of the cipher desired
   @param key        The secret key to use
   @param keylen     The length of the secret key (octets)
   @param ad         An array of Associated Data pointers (must be NULL terminated)
   @param adlen      An array with the lengths of the Associated Data
   @param ct         The ciphertext
   @param ctlen      The length of the ciphertext
   @param pt         The plaintext
   @param ptlen      [in/out] The length of the plaintext
   @return CRYPT_OK if successful
*/
int siv_decrypt(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char **ad,    unsigned long *adlen,
    const unsigned char *ct,     unsigned long ctlen,
          unsigned char *pt,     unsigned long *ptlen)
{
   int err;
   unsigned char Q[16], *pt_work;
   const unsigned char *K1, *K2, *V;
   unsigned long Vlen;
   siv_state siv;

   LTC_ARGCHK(key    != NULL);
   LTC_ARGCHK(ad     != NULL);
   LTC_ARGCHK(adlen  != NULL);
   LTC_ARGCHK(ct     != NULL);
   LTC_ARGCHK(pt     != NULL);
   LTC_ARGCHK(ptlen  != NULL);

   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }
   if (*ptlen < ctlen || ctlen < 16) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   *ptlen = ctlen - 16;
   pt_work = XMALLOC(*ptlen);
   if (pt_work == NULL) {
      return CRYPT_MEM;
   }

   K1 = key;
   K2 = &key[keylen/2];

   V = ct;
   _siv_bitand(V, Q);
   ct += 16;

   err = ctr_start(cipher, Q, K2, keylen/2, 0, CTR_COUNTER_BIG_ENDIAN | 16, &siv.ctr);
   if (err != CRYPT_OK) {
      goto out;
   }
   err = ctr_decrypt(ct, pt_work, *ptlen, &siv.ctr);
   if (err != CRYPT_OK) {
      goto out;
   }
   Vlen = sizeof(siv.V);
   err = _siv_S2V(cipher, K1, keylen/2, ad, adlen, pt_work, *ptlen, siv.V, &Vlen);
#ifdef LTC_CLEAN_STACK
   burn_stack(3 * 16 + 7 * sizeof(unsigned long) + 1 * sizeof(void*));
#endif
   if (err != CRYPT_OK) {
      goto out;
   }

   err = XMEM_NEQ(siv.V, V, Vlen);
   copy_or_zeromem(pt_work, pt, *ptlen, err);
out:
#ifdef LTC_CLEAN_STACK
   zeromem(Q, sizeof(Q));
   zeromem(&siv, sizeof(siv));
   zeromem(pt_work, *ptlen);
#endif
   XFREE(pt_work);

   return err;
}

int siv_test(void)
{
   /*
    * RFC5297 - A.1.  Deterministic Authenticated Encryption Example
    */
   const unsigned char Key_A1[] =
      { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
   const unsigned char AD_A1[] =
      { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 };
   const unsigned char Plaintext_A1[] =
      { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
   const unsigned char output_A1[] =
      { 0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f,
        0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93,
        0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04,
        0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c };
   const unsigned char *ad_A1[] =
      { AD_A1, NULL };
   unsigned long adlen_A1[] =
      { sizeof(AD_A1), 0 };

   const unsigned char Key_A2[] =
      { 0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78,
        0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f };
   const unsigned char AD1_A2[] =
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xde, 0xad, 0xda, 0xda, 0xde, 0xad, 0xda, 0xda,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
   const unsigned char AD2_A2[] =
      { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0 };
   const unsigned char AD3_A2[] =
      { 0x09, 0xf9, 0x11, 0x02, 0x9d, 0x74, 0xe3, 0x5b,
        0xd8, 0x41, 0x56, 0xc5, 0x63, 0x56, 0x88, 0xc0 };
   const unsigned char Plaintext_A2[] =
      { 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x73, 0x6f, 0x6d, 0x65, 0x20, 0x70, 0x6c, 0x61,
        0x69, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x20, 0x74,
        0x6f, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70,
        0x74, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20,
        0x53, 0x49, 0x56, 0x2d, 0x41, 0x45, 0x53 };
   const unsigned char output_A2[] =
      { 0x7b, 0xdb, 0x6e, 0x3b, 0x43, 0x26, 0x67, 0xeb,
        0x06, 0xf4, 0xd1, 0x4b, 0xff, 0x2f, 0xbd, 0x0f,
        0xcb, 0x90, 0x0f, 0x2f, 0xdd, 0xbe, 0x40, 0x43,
        0x26, 0x60, 0x19, 0x65, 0xc8, 0x89, 0xbf, 0x17,
        0xdb, 0xa7, 0x7c, 0xeb, 0x09, 0x4f, 0xa6, 0x63,
        0xb7, 0xa3, 0xf7, 0x48, 0xba, 0x8a, 0xf8, 0x29,
        0xea, 0x64, 0xad, 0x54, 0x4a, 0x27, 0x2e, 0x9c,
        0x48, 0x5b, 0x62, 0xa3, 0xfd, 0x5c, 0x0d };
   const unsigned char *ad_A2[] =
      { AD1_A2, AD2_A2, AD3_A2, NULL };
   unsigned long adlen_A2[] =
      { sizeof(AD1_A2), sizeof(AD2_A2), sizeof(AD3_A2), 0 };

#define PL_PAIR(n) n, sizeof(n)
   struct {
      const unsigned char* Key;
            unsigned long  Keylen;
      const unsigned char* Plaintext;
            unsigned long  Plaintextlen;
      const          void* ADs;
                     void* ADlens;
      const unsigned char* output;
            unsigned long  outputlen;
      const          char* name;
   } siv_tests[] = {
     { PL_PAIR(Key_A1), PL_PAIR(Plaintext_A1), &ad_A1, &adlen_A1, PL_PAIR(output_A1), "RFC5297 - A.1.  Deterministic Authenticated Encryption Example" },
     { PL_PAIR(Key_A2), PL_PAIR(Plaintext_A2), &ad_A2, &adlen_A2, PL_PAIR(output_A2), "RFC5297 - A.2.  Nonce-Based Authenticated Encryption Example" }
   };
#undef PL_PAIR

   int err;
   unsigned n;
   unsigned char buf[MAX(sizeof(output_A1), sizeof(output_A2))];

   for (n = 0; n < sizeof(siv_tests)/sizeof(siv_tests[0]); ++n) {
      unsigned long buflen = sizeof(buf);
      if ((err = siv_encrypt(find_cipher("aes"),
                             siv_tests[n].Key, siv_tests[n].Keylen,
                             (const unsigned char **)siv_tests[n].ADs, siv_tests[n].ADlens,
                             siv_tests[n].Plaintext, siv_tests[n].Plaintextlen,
                             buf, &buflen)) != CRYPT_OK) {
         return err;
      }
      if (compare_testvector(buf, buflen, siv_tests[n].output, siv_tests[n].outputlen, siv_tests[n].name, n) != 0) {
         return CRYPT_FAIL_TESTVECTOR;
      }
      buflen = sizeof(buf);
      if ((err = siv_decrypt(find_cipher("aes"),
                             siv_tests[n].Key, siv_tests[n].Keylen,
                             (const unsigned char **)siv_tests[n].ADs, siv_tests[n].ADlens,
                             siv_tests[n].output, siv_tests[n].outputlen,
                             buf, &buflen)) != CRYPT_OK) {
         return err;
      }
      if (compare_testvector(buf, buflen, siv_tests[n].Plaintext, siv_tests[n].Plaintextlen, siv_tests[n].name, n + 1000) != 0) {
         return CRYPT_FAIL_TESTVECTOR;
      }
   }

   return CRYPT_OK;
}
#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
