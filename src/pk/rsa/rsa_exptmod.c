/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 *
 * Added RSA blinding --nmav
 */
#include "tomcrypt.h"

/**
  @file rsa_exptmod.c
  RSA PKCS exptmod, Tom St Denis
*/

#ifdef LTC_MRSA

/**
   Compute an RSA modular exponentiation
   @param in         The input data to send into RSA
   @param inlen      The length of the input (octets)
   @param out        [out] The destination
   @param outlen     [in/out] The max size and resulting size of the output
   @param which      Which exponent to use, e.g. PK_PRIVATE or PK_PUBLIC
   @param key        The RSA key to use
   @return CRYPT_OK if successful
*/
int rsa_exptmod(const unsigned char *in,   unsigned long inlen,
                      unsigned char *out,  unsigned long *outlen, int which,
                      rsa_key *key)
{
   void        *tmp, *tmpa, *tmpb;
   #ifdef LTC_RSA_BLINDING
   void        *rnd = NULL, *rndi = NULL /* inverse of rnd */;
   #endif
   unsigned long x;
   int           err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* is the key of the right type for the operation? */
   if (which == PK_PRIVATE && (key->type != PK_PRIVATE)) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* must be a private or public operation */
   if (which != PK_PRIVATE && which != PK_PUBLIC) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* init and copy into tmp */
   if ((err = mp_init_multi(&tmp, &tmpa, &tmpb, NULL)) != CRYPT_OK)
        { return err; }
   if ((err = mp_read_unsigned_bin(tmp, (unsigned char *)in, (int)inlen)) != CRYPT_OK)
        { goto error; }


   /* sanity check on the input */
   if (mp_cmp(key->N, tmp) == LTC_MP_LT) {
      err = CRYPT_PK_INVALID_SIZE;
      goto error;
   }

   /* are we using the private exponent and is the key optimized? */
   if (which == PK_PRIVATE) {
      #ifdef LTC_RSA_BLINDING
      if ((err = mp_init_multi(&rnd, &rndi, NULL)) != CRYPT_OK)
            { goto error; }
      /* do blinding */
      err = mp_rand(rnd, mp_count_bits(key->N));
      if (err != CRYPT_OK) {
             goto error_blind;
      }

      /* rndi = 1/rnd mod N */
      err = mp_invmod(rnd, key->N, rndi);
      if (err != CRYPT_OK) {
             goto error_blind;
      }

      /* rnd = rnd^e */
      err = mp_exptmod( rnd, key->e, key->N, rnd);
      if (err != CRYPT_OK) {
             goto error_blind;
      }

      /* tmp = tmp*rnd mod N */
      err = mp_mulmod( tmp, rnd, key->N, tmp);
      if (err != CRYPT_OK) {
             goto error_blind;
      }
      #endif /* LTC_RSA_BLINDING */

      /* tmpa = tmp^dP mod p */
      if ((err = mp_exptmod(tmp, key->dP, key->p, tmpa)) != CRYPT_OK)                               { goto error_blind; }

      /* tmpb = tmp^dQ mod q */
      if ((err = mp_exptmod(tmp, key->dQ, key->q, tmpb)) != CRYPT_OK)                               { goto error_blind; }

      /* tmp = (tmpa - tmpb) * qInv (mod p) */
      if ((err = mp_sub(tmpa, tmpb, tmp)) != CRYPT_OK)                                              { goto error_blind; }
      if ((err = mp_mulmod(tmp, key->qP, key->p, tmp)) != CRYPT_OK)                                { goto error_blind; }

      /* tmp = tmpb + q * tmp */
      if ((err = mp_mul(tmp, key->q, tmp)) != CRYPT_OK)                                             { goto error_blind; }
      if ((err = mp_add(tmp, tmpb, tmp)) != CRYPT_OK)                                               { goto error_blind; }

      #ifdef LTC_RSA_BLINDING
      /* unblind */
      err = mp_mulmod( tmp, rndi, key->N, tmp);
      if (err != CRYPT_OK) {
             goto error_blind;
      }
      #endif
   } else {
      /* exptmod it */
      if ((err = mp_exptmod(tmp, key->e, key->N, tmp)) != CRYPT_OK)                                { goto error; }
   }

   /* read it back */
   x = (unsigned long)mp_unsigned_bin_size(key->N);
   if (x > *outlen) {
      *outlen = x;
      err = CRYPT_BUFFER_OVERFLOW;
      goto error;
   }

   /* this should never happen ... */
   if (mp_unsigned_bin_size(tmp) > mp_unsigned_bin_size(key->N)) {
      err = CRYPT_ERROR;
      goto error;
   }
   *outlen = x;

   /* convert it */
   zeromem(out, x);
   if ((err = mp_to_unsigned_bin(tmp, out+(x-mp_unsigned_bin_size(tmp)))) != CRYPT_OK)               { goto error; }

   /* clean up and return */
   err = CRYPT_OK;
error_blind:
   #ifdef LTC_RSA_BLINDING
   mp_clear_multi(rnd, rndi, NULL);
   #endif
error:
   mp_clear_multi(tmp, tmpa, tmpb, NULL);
   return err;
}

#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
