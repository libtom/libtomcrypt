/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
  Import DSA public or private key from raw numbers
  @param radix   the radix the numbers are represented in (2-64, 16 = hexadecimal)
  @param p       DSA's p  in radix representation
  @param q       DSA's q  in radix representation
  @param g       DSA's g  in radix representation
  @param x       DSA's x  in radix representation (only private key, NULL for public key)
  @param y       DSA's y  in radix representation
  @param key     [out] the destination for the imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/

#ifdef LTC_MDSA

int dsa_import_radix(int radix, char *p, char *q, char *g, char *x, char *y, dsa_key *key)
{
   int err;

   LTC_ARGCHK(p != NULL);
   LTC_ARGCHK(q != NULL);
   LTC_ARGCHK(g != NULL);
   LTC_ARGCHK(y != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* init key */
   err = mp_init_multi(&key->p, &key->g, &key->q, &key->x, &key->y, NULL);
   if (err != CRYPT_OK) return err;

   if ((err = mp_read_radix(key->p , p , radix)) != CRYPT_OK) { goto LBL_ERR; }
   if ((err = mp_read_radix(key->q , q , radix)) != CRYPT_OK) { goto LBL_ERR; }
   if ((err = mp_read_radix(key->g , g , radix)) != CRYPT_OK) { goto LBL_ERR; }
   if ((err = mp_read_radix(key->y , y , radix)) != CRYPT_OK) { goto LBL_ERR; }
   if (x && strlen(x) > 0) {
      key->type = PK_PRIVATE;
      if ((err = mp_read_radix(key->x , x , radix)) != CRYPT_OK) { goto LBL_ERR; }
   }
   else {
      key->type = PK_PUBLIC;
   }

   key->qord = mp_unsigned_bin_size(key->q);

   if (key->qord >= LTC_MDSA_MAX_GROUP || key->qord <= 15 ||
      (unsigned long)key->qord >= mp_unsigned_bin_size(key->p) || (mp_unsigned_bin_size(key->p) - key->qord) >= LTC_MDSA_DELTA) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }
   return CRYPT_OK;

LBL_ERR:
   mp_clear_multi(key->p, key->g, key->q, key->x, key->y, NULL);
   return err;
}

#endif
