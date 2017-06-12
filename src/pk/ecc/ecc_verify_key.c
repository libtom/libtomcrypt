/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

/* origin of this code - OLPC */

#ifdef LTC_MECC

/**
  Verify a key according to ANSI spec
  @param key     The key to validate
  @return CRYPT_OK if successful
*/

int ecc_verify_key(ecc_key *key)
{
   int err;
   void *prime = NULL;
   void *order = NULL;
   void *a = NULL;
   ecc_point *point;

   if (mp_init_multi(&order, &prime, NULL) != CRYPT_OK) {
      return CRYPT_MEM;
   }

   /* Test 1: Are the x amd y points of the public key in the field? */
   if ((err = ltc_mp.read_radix(prime, key->dp->prime, 16)) != CRYPT_OK)                  { goto done2; }

   if (ltc_mp.compare_d(key->pubkey.z, 1) == LTC_MP_EQ) {
      if ((ltc_mp.compare(key->pubkey.x, prime) != LTC_MP_LT) ||
          (ltc_mp.compare(key->pubkey.y, prime) != LTC_MP_LT) ||
          (ltc_mp.compare_d(key->pubkey.x, 0)   != LTC_MP_GT) ||
          (ltc_mp.compare_d(key->pubkey.y, 0)   != LTC_MP_GT)
         )
      {
         err = CRYPT_INVALID_PACKET;
         goto done2;
      }
   }

   /* Test 2: is the public key on the curve? */
   if ((err = ltc_ecc_is_point(key->dp, key->pubkey.x, key->pubkey.y)) != CRYPT_OK)       { goto done2; }

   /* Test 3: does nG = O? (n = order, O = point at infinity, G = public key) */
   point = ltc_ecc_new_point();
   if ((err = ltc_mp.read_radix(order, key->dp->order, 16)) != CRYPT_OK)                  { goto done1; }
   if ((err = ltc_mp.read_radix(a, key->dp->A, 16)) != CRYPT_OK)                          { goto done1; }
   if ((err = ltc_ecc_mulmod(order, &(key->pubkey), point, a, prime, 1)) != CRYPT_OK)     { goto done1; }

   if (ltc_ecc_is_point_at_infinity(point, prime)) {
      err = CRYPT_ERROR;
   }
   else {
      err = CRYPT_OK;
   }

done1:
   ltc_ecc_del_point(point);
done2:
   mp_clear_multi(prime, order, NULL);
   return err;
}

#endif
