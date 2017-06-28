/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt.h"


#ifdef LTC_MDSA

/**
  Import DSA public or private key from raw numbers
  @param p       DSA's p  in binary representation
  @param q       DSA's q  in binary representation
  @param g       DSA's g  in binary representation
  @param key     [out] the destination for the imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int dsa_set_pqg(const unsigned char *p,  unsigned long plen,
                const unsigned char *q,  unsigned long qlen,
                const unsigned char *g,  unsigned long glen,
                dsa_key *key)
{
   int err;

   LTC_ARGCHK(p           != NULL);
   LTC_ARGCHK(q           != NULL);
   LTC_ARGCHK(g           != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(key->x      == NULL);
   LTC_ARGCHK(key->y      == NULL);
   LTC_ARGCHK(key->p      == NULL);
   LTC_ARGCHK(key->g      == NULL);
   LTC_ARGCHK(key->q      == NULL);
   LTC_ARGCHK(key->qord   == 0);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* init key */
   err = mp_init_multi(&key->p, &key->g, &key->q, &key->x, &key->y, NULL);
   if (err != CRYPT_OK) return err;

   if ((err = mp_read_unsigned_bin(key->p , (unsigned char *)p , plen)) != CRYPT_OK) { goto LBL_ERR; }
   if ((err = mp_read_unsigned_bin(key->g , (unsigned char *)g , glen)) != CRYPT_OK) { goto LBL_ERR; }
   if ((err = mp_read_unsigned_bin(key->q , (unsigned char *)q , qlen)) != CRYPT_OK) { goto LBL_ERR; }

   key->qord = mp_unsigned_bin_size(key->q);

   if (key->qord >= LTC_MDSA_MAX_GROUP || key->qord <= 15 ||
      (unsigned long)key->qord >= mp_unsigned_bin_size(key->p) || (mp_unsigned_bin_size(key->p) - key->qord) >= LTC_MDSA_DELTA) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }
   return CRYPT_OK;

LBL_ERR:
   dsa_free(key);
   return err;
}


/**
  Import DSA public or private key from raw numbers
  @param x       DSA's x  in binary representation (only private key, NULL for public key)
  @param y       DSA's y  in binary representation
  @param key     [out] the destination for the imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int dsa_set_key(const unsigned char *pub, unsigned long publen,
                const unsigned char *priv, unsigned long privlen,
                dsa_key *key)
{
   int err;

   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(key->x      != NULL);
   LTC_ARGCHK(key->y      != NULL);
   LTC_ARGCHK(key->p      != NULL);
   LTC_ARGCHK(key->g      != NULL);
   LTC_ARGCHK(key->q      != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   if ((err = mp_read_unsigned_bin(key->y , (unsigned char *)pub , publen)) != CRYPT_OK) { goto LBL_ERR; }
   if (priv != NULL) {
      key->type = PK_PRIVATE;
      if ((err = mp_read_unsigned_bin(key->x , (unsigned char *)priv , privlen)) != CRYPT_OK) { goto LBL_ERR; }
   }
   else {
      key->type = PK_PUBLIC;
   }

   return CRYPT_OK;

LBL_ERR:
   dsa_free(key);
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
