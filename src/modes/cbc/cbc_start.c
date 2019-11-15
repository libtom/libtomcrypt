/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file cbc_start.c
   CBC implementation, start chain, Tom St Denis
*/

#ifdef LTC_CBC_MODE

/**
   Initialize a CBC context
   @param cipher      The index of the cipher desired
   @param IV          The initialization vector
   @param key         The secret key
   @param keylen      The length of the secret key (octets)
   @param num_rounds  Number of rounds in the cipher desired (0 for default)
   @param cbc         The CBC state to initialize
   @return CRYPT_OK if successful
*/
int cbc_start(int cipher, const unsigned char *IV, const unsigned char *key,
              int keylen, int num_rounds, symmetric_CBC *cbc)
{
   int x, err;

   LTC_ARGCHK(IV != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(cbc != NULL);

   /* setup cipher */
   if ((err = ecb_start(cipher, key, keylen, num_rounds, &cbc->ecb)) != CRYPT_OK) {
      return err;
   }

   /* copy IV */
   for (x = 0; x < cbc->ecb.blocklen; x++) {
       cbc->IV[x] = IV[x];
   }
   return CRYPT_OK;
}

#endif
