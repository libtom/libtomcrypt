/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_MDH

/**
  Free the allocated ram for a DH key
  @param key   The key which you wish to free
*/
void dh_free(dh_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   if ( key->base ) {
      mp_clear( key->base );
      key->base = NULL;
   }
   if ( key->prime ) {
      mp_clear( key->prime );
      key->prime = NULL;
   }
   if ( key->x ) {
      mp_clear( key->x );
      key->x = NULL;
   }
   if ( key->y ) {
      mp_clear( key->y );
      key->y = NULL;
   }
}

#endif /* LTC_MDH */

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
