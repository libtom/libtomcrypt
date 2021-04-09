/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  Source donated by Elliptic Semiconductor Inc (www.ellipticsemi.com) to the LibTom Projects
*/

#ifdef LTC_XTS_MODE

/** Start XTS mode
   @param cipher      The index of the cipher to use
   @param key1        The encrypt key
   @param key2        The tweak encrypt key
   @param keylen      The length of the keys (each) in octets
   @param num_rounds  The number of rounds for the cipher (0 == default)
   @param xts         [out] XTS structure
   Returns CRYPT_OK upon success.
*/
int xts_start(int cipher, const unsigned char *key1, const unsigned char *key2, unsigned long keylen, int num_rounds,
              symmetric_xts *xts)
{
   int err;

   /* check inputs */
   LTC_ARGCHK(key1 != NULL);
   LTC_ARGCHK(key2 != NULL);
   LTC_ARGCHK(xts != NULL);

   /* check if valid */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }

   if (cipher_descriptor[cipher].block_length != 16) {
      return CRYPT_INVALID_ARG;
   }

   /* schedule the two ciphers */
   if ((err = ecb_start(cipher, key1, keylen, num_rounds, &xts->key1)) != CRYPT_OK) {
      return err;
   }
   if ((err = ecb_start(cipher, key2, keylen, num_rounds, &xts->key2)) != CRYPT_OK) {
      return err;
   }
   xts->cipher = cipher;

   return err;
}

#endif
