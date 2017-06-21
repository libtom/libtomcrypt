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
  @file ecc_get_size.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

/**
  Get the size of an ECC key
  @param key    The key to get the size of
  @return The size (octets) of the key or INT_MAX on error
*/
int ecc_get_size(ecc_key *key)
{
   LTC_ARGCHK(key != NULL);
   if (ltc_ecc_is_valid_idx(key->idx))
      return key->dp->size;
   else
      return INT_MAX; /* large value known to cause it to fail when passed to ecc_make_key() */
}

#endif
/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */

