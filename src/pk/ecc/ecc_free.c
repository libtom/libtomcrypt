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
  @file ecc_free.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

/**
  Free an ECC key from memory
  @param key   The key you wish to free
*/
void ecc_free(ecc_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   mp_clear_multi(key->pubkey.x, key->pubkey.y, key->pubkey.z, key->k, NULL);
   if (key->dp->name && XSTRCMP(key->dp->name, "CUSTOM") == 0) {
      /* we need to deallocate custom parameters */
      ecc_dp_clear((ltc_ecc_set_type *)(key->dp));
   }
}

#endif
/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */

