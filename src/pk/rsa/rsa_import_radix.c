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
  Import RSA public or private key from raw numbers
  @param radix   the radix the numbers are represented in (2-64, 16 = hexadecimal)
  @param N       RSA's N  in radix representation
  @param e       RSA's e  in radix representation
  @param d       RSA's d  in radix representation (only private key, NULL for public key)
  @param p       RSA's p  in radix representation (only private key, NULL for public key)
  @param q       RSA's q  in radix representation (only private key, NULL for public key)
  @param dP      RSA's dP in radix representation (only private key, NULL for public key)
  @param dQ      RSA's dQ in radix representation (only private key, NULL for public key)
  @param qP      RSA's qP in radix representation (only private key, NULL for public key)
  @param key     [out] the destination for the imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/

#ifdef LTC_MRSA

int rsa_import_radix(int radix, char *N, char *e, char *d, char *p, char *q, char *dP, char *dQ, char *qP, rsa_key *key)
{
   int err;

   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(N           != NULL);
   LTC_ARGCHK(e           != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, NULL);
   if (err != CRYPT_OK) return err;

   if ((err = mp_read_radix(key->N , N , radix)) != CRYPT_OK)    { goto LBL_ERR; }
   if ((err = mp_read_radix(key->e , e , radix)) != CRYPT_OK)    { goto LBL_ERR; }
   if (d && p && q && dP && dQ && qP && strlen(d)>0 && strlen(p)>0 &&
       strlen(q)>0 && strlen(dP)>0 && strlen(dQ)>0 && strlen(qP)>0) {
      if ((err = mp_read_radix(key->d , d , radix)) != CRYPT_OK) { goto LBL_ERR; }
      if ((err = mp_read_radix(key->p , p , radix)) != CRYPT_OK) { goto LBL_ERR; }
      if ((err = mp_read_radix(key->q , q , radix)) != CRYPT_OK) { goto LBL_ERR; }
      if ((err = mp_read_radix(key->dP, dP, radix)) != CRYPT_OK) { goto LBL_ERR; }
      if ((err = mp_read_radix(key->dQ, dQ, radix)) != CRYPT_OK) { goto LBL_ERR; }
      if ((err = mp_read_radix(key->qP, qP, radix)) != CRYPT_OK) { goto LBL_ERR; }
      key->type = PK_PRIVATE;
   }
   else {
      key->type = PK_PUBLIC;
   }
   return CRYPT_OK;

LBL_ERR:
   mp_clear_multi(key->d,  key->e, key->N, key->dQ, key->dP, key->qP, key->p, key->q, NULL);
   return err;
}

#endif /* LTC_MRSA */

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
