/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file cbc_encrypt.c
   CBC implementation, encrypt block, Tom St Denis
*/


#ifdef LTC_CBC_MODE

/**
  CBC encrypt
  @param pt     Plaintext
  @param ct     [out] Ciphertext
  @param len    The number of bytes to process (must be multiple of block length)
  @param cbc    CBC state
  @return CRYPT_OK if successful
*/
int cbc_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CBC *cbc)
{
   int x, err;

   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(cbc != NULL);

   if ((err = cipher_is_valid(cbc->ecb.cipher)) != CRYPT_OK) {
       return err;
   }

   /* is blocklen valid? */
   if (cbc->ecb.blocklen < 1 || cbc->ecb.blocklen > (int)sizeof(cbc->IV)) {
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

   if (cipher_descriptor[cbc->ecb.cipher].accel_cbc_encrypt != NULL) {
      return cipher_descriptor[cbc->ecb.cipher].accel_cbc_encrypt(pt, ct, len / cbc->ecb.blocklen, cbc->IV, &cbc->ecb.key);
   }
   while (len) {
      /* xor IV against plaintext */
#if defined(LTC_FAST)
      for (x = 0; x < cbc->ecb.blocklen; x += sizeof(LTC_FAST_TYPE)) {
         *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)cbc->IV + x)) ^= *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)pt + x));
      }
#else
      for (x = 0; x < cbc->ecb.blocklen; x++) {
         cbc->IV[x] ^= pt[x];
      }
#endif

      /* encrypt */
      if ((err = ecb_encrypt_block(cbc->IV, ct, &cbc->ecb)) != CRYPT_OK) {
         return err;
      }

      /* store IV [ciphertext] for a future block */
#if defined(LTC_FAST)
      for (x = 0; x < cbc->ecb.blocklen; x += sizeof(LTC_FAST_TYPE)) {
         *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)cbc->IV + x)) = *(LTC_FAST_TYPE_PTR_CAST((unsigned char *)ct + x));
      }
#else
      for (x = 0; x < cbc->ecb.blocklen; x++) {
         cbc->IV[x] = ct[x];
      }
#endif

      ct  += cbc->ecb.blocklen;
      pt  += cbc->ecb.blocklen;
      len -= cbc->ecb.blocklen;
   }
   return CRYPT_OK;
}

#endif
