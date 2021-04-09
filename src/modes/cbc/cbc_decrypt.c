/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file cbc_decrypt.c
   CBC implementation, encrypt block, Tom St Denis
*/


#ifdef LTC_CBC_MODE

/**
  CBC decrypt
  @param ct     Ciphertext
  @param pt     [out] Plaintext
  @param len    The number of bytes to process (must be multiple of block length)
  @param cbc    CBC state
  @return CRYPT_OK if successful
*/
int cbc_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_CBC *cbc)
{
   int x, err;
   unsigned char tmp[16];
#ifdef LTC_FAST
   LTC_FAST_TYPE tmpy;
#else
   unsigned char tmpy;
#endif

   LTC_ARGCHK(pt  != NULL);
   LTC_ARGCHK(ct  != NULL);
   LTC_ARGCHK(cbc != NULL);

   if ((err = cipher_is_valid(cbc->ecb.cipher)) != CRYPT_OK) {
       return err;
   }

   /* is blocklen valid? */
   if (cbc->ecb.blocklen < 1 || cbc->ecb.blocklen > (int)sizeof(cbc->IV) || cbc->ecb.blocklen > (int)sizeof(tmp)) {
      return CRYPT_INVALID_ARG;
   }

   if (len % cbc->ecb.blocklen) {
      return CRYPT_INVALID_ARG;
   }
#ifdef LTC_FAST
   if (cbc->ecb.blocklen % sizeof(LTC_FAST_TYPE)) {
      return CRYPT_INVALID_ARG;
   }
#endif

   if (cipher_descriptor[cbc->ecb.cipher].accel_cbc_decrypt != NULL) {
      return cipher_descriptor[cbc->ecb.cipher].accel_cbc_decrypt(ct, pt, len / cbc->ecb.blocklen, cbc->IV, &cbc->ecb.key);
   }
   while (len) {
      /* decrypt */
      if ((err = ecb_decrypt_block(ct, tmp, &cbc->ecb)) != CRYPT_OK) {
         return err;
      }

      /* xor IV against plaintext */
#if defined(LTC_FAST)
      for (x = 0; x < cbc->ecb.blocklen; x += sizeof(LTC_FAST_TYPE)) {
         tmpy = *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)cbc->IV + x)) ^ *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)tmp + x));
         *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)cbc->IV + x)) = *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)ct + x));
         *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)pt + x)) = tmpy;
      }
#else
      for (x = 0; x < cbc->ecb.blocklen; x++) {
         tmpy       = tmp[x] ^ cbc->IV[x];
         cbc->IV[x] = ct[x];
         pt[x]      = tmpy;
      }
#endif

      ct  += cbc->ecb.blocklen;
      pt  += cbc->ecb.blocklen;
      len -= cbc->ecb.blocklen;
   }
   return CRYPT_OK;
}

#endif
