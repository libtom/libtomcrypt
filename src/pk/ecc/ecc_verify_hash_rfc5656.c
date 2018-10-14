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
  @file ecc_verify_hash.c
  ECC Crypto, Tom St Denis
*/

/**
   Verify an ECC signature (RFC5656 / SSH format)
   @param sig         The signature to verify
   @param siglen      The length of the signature (octets)
   @param hash        The hash (message digest) that was signed
   @param hashlen     The length of the hash (octets)
   @param stat        [out] Result of signature, 1==valid, 0==invalid
   @param key         The corresponding public ECC key
   @return CRYPT_OK if successful (even if the signature is not valid)
*/
int ecc_verify_hash_rfc5656(const unsigned char *sig,  unsigned long siglen,
                            const unsigned char *hash, unsigned long hashlen,
                            int *stat, const ecc_key *key)
{
   void *r, *s;
   int err;
   char name[64], name2[64];
   unsigned long namelen = sizeof(name2);

   LTC_ARGCHK(sig != NULL);
   LTC_ARGCHK(key != NULL);

   if ((err = mp_init_multi(&r, &s, NULL)) != CRYPT_OK) return err;

   /* Decode as SSH data sequence, per RFC4251 */
   if ((err = ssh_decode_sequence_multi(sig, siglen,
                                        LTC_SSHDATA_STRING, name, 64,
                                        LTC_SSHDATA_MPINT,  r,
                                        LTC_SSHDATA_MPINT,  s,
                                        LTC_SSHDATA_EOL,    NULL)) != CRYPT_OK) goto error;

   /* Check curve matches identifier string */
   if ((err = ecc_ssh_ecdsa_encode_name(name2, &namelen, key)) != CRYPT_OK) goto error;
   if (XSTRCMP(name,name2) != 0) {
      err = CRYPT_INVALID_ARG;
      goto error;
   }

   err = ecc_verify_hash_internal(r, s, hash, hashlen, stat, key);

error:
   mp_clear_multi(r, s, NULL);
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
