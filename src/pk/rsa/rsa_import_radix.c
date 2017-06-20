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

static int _rsa_read_pk_part(void* mpi, ltc_pk_part *p)
{
   int err;
   if(p->radix == 256) {
      if (p->len != 0) err = mp_read_unsigned_bin(mpi, p->p, p->len);
      else err = CRYPT_PK_INVALID_SIZE;
   } else {
      err = mp_read_radix(mpi, p->p , p->radix);
   }
   return err;
}

int rsa_import_radix(ltc_pk_part *N, ltc_pk_part *e, ltc_pk_part *d, ltc_pk_part *p, ltc_pk_part *q, ltc_pk_part *dP, ltc_pk_part *dQ, ltc_pk_part *qP, rsa_key *key)
{
   int err;

   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(N           != NULL);
   LTC_ARGCHK(e           != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, NULL);
   if (err != CRYPT_OK) return err;

   if ((err = _rsa_read_pk_part(key->N , N)) != CRYPT_OK)    { goto LBL_ERR; }
   if ((err = _rsa_read_pk_part(key->e , e)) != CRYPT_OK)    { goto LBL_ERR; }
   if (d && p && q && dP && dQ && qP && strlen(d->p)>0 && strlen(p->p)>0 &&
       strlen(q->p)>0 && strlen(dP->p)>0 && strlen(dQ->p)>0 && strlen(qP->p)>0) {
      if ((err = _rsa_read_pk_part(key->d , d)) != CRYPT_OK) { goto LBL_ERR; }
      if ((err = _rsa_read_pk_part(key->p , p)) != CRYPT_OK) { goto LBL_ERR; }
      if ((err = _rsa_read_pk_part(key->q , q)) != CRYPT_OK) { goto LBL_ERR; }
      if ((err = _rsa_read_pk_part(key->dP, dP)) != CRYPT_OK) { goto LBL_ERR; }
      if ((err = _rsa_read_pk_part(key->dQ, dQ)) != CRYPT_OK) { goto LBL_ERR; }
      if ((err = _rsa_read_pk_part(key->qP, qP)) != CRYPT_OK) { goto LBL_ERR; }
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
