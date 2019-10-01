/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

/**
  @file rsa_key.c
  Free an RSA key, Tom St Denis
  Basic operations on an RSA key, Steffen Jaeckel
*/

#ifdef LTC_MRSA

/**
  Init an RSA key
  @param key   The RSA key to free
  @return CRYPT_OK if successful
*/
int rsa_init(rsa_key *key)
{
   LTC_ARGCHK(key != NULL);
   return mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, NULL);
}

/**
  Free an RSA key from memory
  @param key   The RSA key to free
*/
void rsa_free(rsa_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   mp_cleanup_multi(&key->q, &key->p, &key->qP, &key->dP, &key->dQ, &key->N, &key->d, &key->e, NULL);
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
