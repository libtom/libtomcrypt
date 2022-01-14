/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"


#ifdef LTC_MDSA

/**
  Init DSA key
  @param key     [out] the key to init
  @return CRYPT_OK if successful.
*/
int dsa_int_init(dsa_key *key)
{
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* init key */
   return mp_init_multi(&key->p, &key->g, &key->q, &key->x, &key->y, LTC_NULL);
}

#endif
