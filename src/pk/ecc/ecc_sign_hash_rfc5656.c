/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

#if defined(LTC_MECC) && defined(LTC_SSH)

/**
  Sign a message digest (RFC5656 / SSH format)
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param out       [out] The destination for the signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG you wish to use
  @param key       A private ECC key
  @return CRYPT_OK if successful
*/
int ecc_sign_hash_rfc5656(const unsigned char *in,  unsigned long inlen,
                          unsigned char *out, unsigned long *outlen,
                          prng_state *prng, int wprng, const ecc_key *key)
{
   int err;
   void *r, *s;
   char name[64];
   unsigned long namelen = sizeof(name);

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   if ((err = mp_init_multi(&r, &s, NULL)) != CRYPT_OK) return err;
   if ((err = ecc_sign_hash_internal(in, inlen, r, s, prng, wprng, NULL, key)) != CRYPT_OK) goto error;

   /* Get identifier string */
   if ((err = ecc_ssh_ecdsa_encode_name(name, &namelen, key)) != CRYPT_OK) goto error;
   /* Store as SSH data sequence, per RFC4251 */
   err = ssh_encode_sequence_multi(out, outlen,
                                   LTC_SSHDATA_STRING, name,
                                   LTC_SSHDATA_MPINT,  r,
                                   LTC_SSHDATA_MPINT,  s,
                                   LTC_SSHDATA_EOL,    NULL);
error:
   mp_clear_multi(r, s, NULL);
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
