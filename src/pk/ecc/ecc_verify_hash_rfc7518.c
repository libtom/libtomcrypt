/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

/**
  @file ecc_verify_hash.c
  ECC Crypto, Tom St Denis
*/

/**
   Verify an ECC signature (RFC7518 format)
   @param sig         The signature to verify
   @param siglen      The length of the signature (octets)
   @param hash        The hash (message digest) that was signed
   @param hashlen     The length of the hash (octets)
   @param stat        [out] Result of signature, 1==valid, 0==invalid
   @param key         The corresponding public ECC key
   @return CRYPT_OK if successful (even if the signature is not valid)
*/
int ecc_verify_hash_rfc7518(const unsigned char *sig,  unsigned long siglen,
                            const unsigned char *hash, unsigned long hashlen,
                            int *stat, const ecc_key *key)
{
   void *r, *s;
   int err;
   unsigned long i;

   LTC_ARGCHK(sig != NULL);
   LTC_ARGCHK(key != NULL);

   if ((err = mp_init_multi(&r, &s, NULL)) != CRYPT_OK) return err;

   /* RFC7518 format - raw (r,s) */
   i = mp_unsigned_bin_size(key->dp.order);
   if (siglen != (2 * i)) {
      err = CRYPT_INVALID_PACKET;
      goto error;
   }
   if ((err = mp_read_unsigned_bin(r, (unsigned char *)sig, i)) != CRYPT_OK) goto error;
   if ((err = mp_read_unsigned_bin(s, (unsigned char *)sig + i, i)) != CRYPT_OK) goto error;

   err = ecc_verify_hash_internal(r, s, hash, hashlen, stat, key);

error:
   mp_clear_multi(r, s, NULL);
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
