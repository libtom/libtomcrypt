/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file cfb_setiv.c
  CFB implementation, set IV, Tom St Denis
*/

#ifdef LTC_CFB_MODE

/**
   Set an initialization vector
   @param IV   The initialization vector
   @param len  The length of the vector (in octets)
   @param cfb  The CFB state
   @return CRYPT_OK if successful
*/
int cfb_setiv(const unsigned char *IV, unsigned long len, symmetric_CFB *cfb)
{
   int err;

   LTC_ARGCHK(IV  != NULL);
   LTC_ARGCHK(cfb != NULL);

   if ((err = cipher_is_valid(cfb->ecb.cipher)) != CRYPT_OK) {
       return err;
   }

   if (len != (unsigned long)cfb->ecb.blocklen) {
      return CRYPT_INVALID_ARG;
   }

   /* force next block */
   cfb->padlen = 0;
   return ecb_encrypt_block(IV, cfb->IV, &cfb->ecb);
}

#endif

