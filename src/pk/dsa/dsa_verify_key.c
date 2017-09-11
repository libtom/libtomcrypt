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
   @file dsa_verify_key.c
   DSA implementation, verify a key, Tom St Denis
*/

#ifdef LTC_MDSA

/**
   Validate a DSA key

     Yeah, this function should've been called dsa_validate_key()
     in the first place and for compat-reasons we keep it
     as it was (for now).

   @param key   The key to validate
   @param stat  [out]  Result of test, 1==valid, 0==invalid
   @return CRYPT_OK if successful
*/
int dsa_verify_key(dsa_key *key, int *stat)
{
   int    res, err;

   LTC_ARGCHK(key  != NULL);
   LTC_ARGCHK(stat != NULL);

   /* default to an invalid key */
   *stat = 0;

   /* first make sure key->q and key->p are prime */
   if ((err = mp_prime_is_prime(key->q, 8, &res)) != CRYPT_OK) {
      return err;
   }
   if (res == LTC_MP_NO) {
      return CRYPT_OK;
   }

   if ((err = mp_prime_is_prime(key->p, 8, &res)) != CRYPT_OK) {
      return err;
   }
   if (res == LTC_MP_NO) {
      return CRYPT_OK;
   }

   return dsa_int_validate_key(key, stat); /* 1 = full check */
}

/**
   Non-complex part of the validation of a DSA key

     This is the computation-wise 'non-complex' part of the
     DSA key validation

   @param key   The key to validate
   @param stat  [out]  Result of test, 1==valid, 0==invalid
   @return CRYPT_OK if successful
*/
int dsa_int_validate_key(dsa_key *key, int *stat)
{
   void   *tmp, *tmp2;
   int    res, err;

   LTC_ARGCHK(key  != NULL);
   LTC_ARGCHK(stat != NULL);

   /* default to an invalid key */
   *stat = 0;

   /* now make sure that g is not -1, 0 or 1 and <p */
   if (mp_cmp_d(key->g, 0) == LTC_MP_EQ || mp_cmp_d(key->g, 1) == LTC_MP_EQ) {
      return CRYPT_OK;
   }
   if ((err = mp_init_multi(&tmp, &tmp2, NULL)) != CRYPT_OK)               { return err; }
   if ((err = mp_sub_d(key->p, 1, tmp)) != CRYPT_OK)                       { goto error; }
   if (mp_cmp(tmp, key->g) == LTC_MP_EQ || mp_cmp(key->g, key->p) != LTC_MP_LT) {
      err = CRYPT_OK;
      goto error;
   }

   /* 1 < y < p-1 */
   if (!(mp_cmp_d(key->y, 1) == LTC_MP_GT && mp_cmp(key->y, tmp) == LTC_MP_LT)) {
      err = CRYPT_OK;
      goto error;
   }

   /* now we have to make sure that g^q = 1, and that p-1/q gives 0 remainder */
   if ((err = mp_div(tmp, key->q, tmp, tmp2)) != CRYPT_OK)             { goto error; }
   if (mp_iszero(tmp2) != LTC_MP_YES) {
      err = CRYPT_OK;
      goto error;
   }

   if ((err = mp_exptmod(key->g, key->q, key->p, tmp)) != CRYPT_OK)    { goto error; }
   if (mp_cmp_d(tmp, 1) != LTC_MP_EQ) {
      err = CRYPT_OK;
      goto error;
   }

   /* now we have to make sure that y^q = 1, this makes sure y \in g^x mod p */
   if ((err = mp_exptmod(key->y, key->q, key->p, tmp)) != CRYPT_OK)       { goto error; }
   if (mp_cmp_d(tmp, 1) != LTC_MP_EQ) {
      err = CRYPT_OK;
      goto error;
   }

   /* at this point we are out of tests ;-( */
   err   = CRYPT_OK;
   *stat = 1;
error:
   mp_clear_multi(tmp, tmp2, NULL);
   return err;
}
#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
