/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

/**
  @file ecc_verify_hash.c
  ECC Crypto, Tom St Denis
*/

/**
   Verify an ECC signature (ANSI X9.62 format)
   @param sig         The signature to verify
   @param siglen      The length of the signature (octets)
   @param hash        The hash (message digest) that was signed
   @param hashlen     The length of the hash (octets)
   @param stat        [out] Result of signature, 1==valid, 0==invalid
   @param key         The corresponding public ECC key
   @return CRYPT_OK if successful (even if the signature is not valid)
*/
int ecc_verify_hash(const unsigned char *sig,  unsigned long siglen,
                    const unsigned char *hash, unsigned long hashlen,
                    int *stat, const ecc_key *key)
{
   void *r, *s;
   int err;

   LTC_ARGCHK(sig != NULL);

   if ((err = mp_init_multi(&r, &s, NULL)) != CRYPT_OK) return err;

   /* ANSI X9.62 format - ASN.1 encoded SEQUENCE{ INTEGER(r), INTEGER(s) }  */
   if ((err = der_decode_sequence_multi_ex(sig, siglen, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_STRICT,
                                     LTC_ASN1_INTEGER, 1UL, r,
                                     LTC_ASN1_INTEGER, 1UL, s,
                                     LTC_ASN1_EOL, 0UL, NULL)) != CRYPT_OK) goto error;

   err = ecc_verify_hash_internal(r, s, hash, hashlen, stat, key);

error:
   mp_clear_multi(r, s, NULL);
   return err;
}

#endif
