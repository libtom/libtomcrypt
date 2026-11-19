/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ed448_import_raw.c
  Set the parameters of an Ed448 key, Steffen Jaeckel
*/

#ifdef LTC_CURVE448

/**
   Set the parameters of an Ed448 key

   @param in       The key
   @param inlen    The length of the key
   @param which    Which type of key (PK_PRIVATE or PK_PUBLIC)
   @param key      [out] Destination of the key
   @return CRYPT_OK if successful
*/
int ed448_import_raw(const unsigned char *in, unsigned long inlen, int which, curve448_key *key)
{
   LTC_ARGCHK(in   != NULL);
   LTC_ARGCHK(key  != NULL);

   if (which == PK_PRIVATE) {
      LTC_ARGCHK(inlen == 57uL);
      XMEMCPY(key->priv, in, sizeof(key->priv));
      ec448_sk_to_pk_internal(key->pub, key->priv);
   } else if (which == PK_PUBLIC) {
      LTC_ARGCHK(inlen == 57uL);
      XMEMCPY(key->pub, in, sizeof(key->pub));
   } else {
      return CRYPT_INVALID_ARG;
   }
   key->pka = LTC_PKA_ED448;
   key->type = which;

   return CRYPT_OK;
}

#endif
