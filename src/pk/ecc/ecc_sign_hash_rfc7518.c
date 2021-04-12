/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

/**
  Sign a message digest (RFC7518 format + recovery_id)
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param out       [out] The destination for the signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG you wish to use
  @param recid     [out] Recovery ID
  @param key       A private ECC key
  @return CRYPT_OK if successful
*/
int ecc_sign_hash_rfc7518_ex(const unsigned char *in,  unsigned long inlen,
                             unsigned char *out, unsigned long *outlen,
                             prng_state *prng, int wprng,
                             int *recid, const ecc_key *key)
{
   int err;
   void *r, *s;
   unsigned long pbytes, i;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* RFC7518 format - raw (r,s) */
   pbytes = mp_unsigned_bin_size(key->dp.order);
   if (*outlen < 2 * pbytes) {
      *outlen = 2 * pbytes;
      return CRYPT_BUFFER_OVERFLOW;
   }

   if ((err = mp_init_multi(&r, &s, NULL)) != CRYPT_OK) return err;
   if ((err = ecc_sign_hash_internal(in, inlen, r, s, prng, wprng, recid, key)) != CRYPT_OK) goto error;

   zeromem(out, 2 * pbytes);
   *outlen = 2 * pbytes;
   i = mp_unsigned_bin_size(r);
   if ((err = mp_to_unsigned_bin(r, out + pbytes - i)) != CRYPT_OK) goto error;
   i = mp_unsigned_bin_size(s);
   err = mp_to_unsigned_bin(s, out + 2 * pbytes - i);

error:
   mp_clear_multi(r, s, NULL);
   return err;
}

/**
  Sign a message digest (RFC7518 format)
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param out       [out] The destination for the signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG you wish to use
  @param key       A private ECC key
  @return CRYPT_OK if successful
*/
int ecc_sign_hash_rfc7518(const unsigned char *in,  unsigned long inlen,
                          unsigned char *out, unsigned long *outlen,
                          prng_state *prng, int wprng, const ecc_key *key)
{
   return ecc_sign_hash_rfc7518_ex(in, inlen, out, outlen, prng, wprng, NULL, key);
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
