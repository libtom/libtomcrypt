/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#if defined(LTC_MECC) && defined(LTC_DER)

/**
  Sign a message digest (ANSI X9.62 format)
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param out       [out] The destination for the signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG you wish to use
  @param key       A private ECC key
  @return CRYPT_OK if successful
*/
int ecc_sign_hash(const unsigned char *in,  unsigned long inlen,
                  unsigned char *out, unsigned long *outlen,
                  prng_state *prng, int wprng, const ecc_key *key)
{
   int err;
   void *r, *s;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   if ((err = mp_init_multi(&r, &s, NULL)) != CRYPT_OK) return err;
   if ((err = ecc_sign_hash_internal(in, inlen, r, s, prng, wprng, NULL, key)) != CRYPT_OK) goto error;

   /* store as ASN.1 SEQUENCE { r, s -- integer } */
   err = der_encode_sequence_multi(out, outlen,
                                   LTC_ASN1_INTEGER, 1UL, r,
                                   LTC_ASN1_INTEGER, 1UL, s,
                                   LTC_ASN1_EOL, 0UL, NULL);
error:
   mp_clear_multi(r, s, NULL);
   return err;
}

#endif
