/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

/**
  @file ecc_verify_hash.c
  ECC Crypto, Tom St Denis
*/

/**
   Verify an ECC signature (Ethereum format with recovery_id+27)
   @param sig         The signature to verify
   @param siglen      The length of the signature (octets)
   @param hash        The hash (message digest) that was signed
   @param hashlen     The length of the hash (octets)
   @param stat        [out] Result of signature, 1==valid, 0==invalid
   @param key         The corresponding public ECC key
   @return CRYPT_OK if successful (even if the signature is not valid)
*/
int ecc_verify_hash_eth27(const unsigned char *sig,  unsigned long siglen,
                          const unsigned char *hash, unsigned long hashlen,
                          int *stat, const ecc_key *key)
{
   void *r, *s;
   int err;

   LTC_ARGCHK(sig != NULL);
   LTC_ARGCHK(key != NULL);

   /* Only valid for secp256k1 - OID 1.3.132.0.10 */
   if (pk_oid_cmp_with_ulong("1.3.132.0.10", key->dp.oid, key->dp.oidlen) != CRYPT_OK) {
      return CRYPT_ERROR;
   }
   /* Only secp256k1 curves uses this format, so must be 65 bytes long */
   if (siglen != 65) {
      return CRYPT_INVALID_PACKET;
   }

   if ((err = mp_init_multi(&r, &s, NULL)) != CRYPT_OK) return err;
   if ((err = mp_read_unsigned_bin(r, (unsigned char *)sig, 32)) != CRYPT_OK) goto error;
   if ((err = mp_read_unsigned_bin(s, (unsigned char *)sig + 32, 32)) != CRYPT_OK) goto error;

   err = ecc_verify_hash_internal(r, s, hash, hashlen, stat, key);

error:
   mp_clear_multi(r, s, NULL);
   return err;
}

#endif
