/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x448_import_raw.c
  Set the parameters of a X448 key
*/

#ifdef LTC_CURVE448

/**
   Set the parameters of a X448 key

   @param in       The key
   @param inlen    The length of the key
   @param which    Which type of key (PK_PRIVATE or PK_PUBLIC)
   @param key      [out] Destination of the key
   @return CRYPT_OK if successful
*/
int x448_import_raw(const unsigned char *in, unsigned long inlen, int which, curve448_key *key)
{
   LTC_ARGCHK(in   != NULL);
   LTC_ARGCHK(inlen == 56uL);
   LTC_ARGCHK(key  != NULL);

   if (which == PK_PRIVATE) {
      XMEMCPY(key->priv, in, 56uL);
      ec448_scalarmult_base_internal(key->pub, key->priv);
   } else if (which == PK_PUBLIC) {
      XMEMCPY(key->pub, in, 56uL);
   } else {
      return CRYPT_INVALID_ARG;
   }
   key->pka = LTC_PKA_X448;
   key->type = which;

   return CRYPT_OK;
}

#endif
