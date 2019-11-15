/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file ofb_start.c
   OFB implementation, start chain, Tom St Denis
*/


#ifdef LTC_OFB_MODE

/**
   Initialize a OFB context
   @param cipher      The index of the cipher desired
   @param IV          The initialization vector
   @param key         The secret key
   @param keylen      The length of the secret key (octets)
   @param num_rounds  Number of rounds in the cipher desired (0 for default)
   @param ofb         The OFB state to initialize
   @return CRYPT_OK if successful
*/
int ofb_start(int cipher, const unsigned char *IV, const unsigned char *key,
              int keylen, int num_rounds, symmetric_OFB *ofb)
{
   int x, err;

   LTC_ARGCHK(IV != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(ofb != NULL);

   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }

   /* init the cipher */
   if ((err = ecb_start(cipher, key, keylen, num_rounds, &ofb->ecb)) != CRYPT_OK) {
      return err;
   }
   ofb->padlen = cipher_descriptor[cipher].block_length;

   /* copy details */
   for (x = 0; x < ofb->ecb.blocklen; x++) {
       ofb->IV[x] = IV[x];
   }

   return CRYPT_OK;
}

#endif
