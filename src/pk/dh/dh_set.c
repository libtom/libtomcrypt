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
  Import DH key parts p and g from raw numbers

  @param p       DH's p (prime)
  @param plen    DH's p's length
  @param g       DH's g (group)
  @param glen    DH's g's length
  @param key     [out] the destination for the imported key
  @return CRYPT_OK if successful
*/
int dh_set_pg(const unsigned char *p, unsigned long plen,
              const unsigned char *g, unsigned long glen,
              dh_key *key)
{
   int err;

   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(key->x      == NULL);
   LTC_ARGCHK(key->y      == NULL);
   LTC_ARGCHK(key->base   == NULL);
   LTC_ARGCHK(key->prime  == NULL);
   LTC_ARGCHK(p           != NULL);
   LTC_ARGCHK(g           != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   if ((err = mp_init_multi(&key->x, &key->y, &key->base, &key->prime, NULL)) != CRYPT_OK) {
      return err;
   }

   if ((err = mp_read_unsigned_bin(key->base, (unsigned char*)g, glen)) != CRYPT_OK)     { goto LBL_ERR; }
   if ((err = mp_read_unsigned_bin(key->prime, (unsigned char*)p, plen)) != CRYPT_OK)  { goto LBL_ERR; }

   return CRYPT_OK;

LBL_ERR:
   dh_free(key);
   return err;
}

/**
  Import DH key parts pub and priv from raw numbers

  @param pub     DH's pub (public key) (can be NULL if priv is valid)
  @param publen  DH's pub's length
  @param priv    DH's priv (private key) (can be NULL if pub is valid)
  @param privlen DH's priv's length
  @param key     [out] the destination for the imported key
  @return CRYPT_OK if successful
*/
int dh_set_key(const unsigned char *pub, unsigned long publen,
               const unsigned char *priv, unsigned long privlen,
               dh_key *key)
{
   int err;

   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(key->x      != NULL);
   LTC_ARGCHK(key->y      != NULL);
   LTC_ARGCHK(key->base   != NULL);
   LTC_ARGCHK(key->prime  != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   if(priv == NULL) {
      if ((err = mp_read_unsigned_bin(key->y, (unsigned char*)pub, publen)) != CRYPT_OK)         { goto LBL_ERR; }
      key->type = PK_PUBLIC;
      mp_clear(key->x);
      key->x = NULL;
   }
   else {
      if ((err = mp_read_unsigned_bin(key->x, (unsigned char*)priv, privlen)) != CRYPT_OK)         { goto LBL_ERR; }
      if (pub != NULL) {
         if ((err = mp_read_unsigned_bin(key->y, (unsigned char*)pub, publen)) != CRYPT_OK)         { goto LBL_ERR; }
      }
      else {
         /* compute y value */
         if ((err = mp_exptmod(key->base, key->x, key->prime, key->y)) != CRYPT_OK)  { goto LBL_ERR; }
      }
      key->type = PK_PRIVATE;
   }

   /* check public key */
   if ((err = dh_check_pubkey(key)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   return CRYPT_OK;

LBL_ERR:
   dh_free(key);
   return err;
}

#endif /* LTC_MDH */

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
