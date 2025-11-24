/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#if defined(LTC_MECC) && defined(LTC_DER)

/**
  @file ecc_verify_hash.c
  ECC Crypto, Tom St Denis
*/

typedef int (*ecc_verify_fn)(const unsigned char *sig,
                                   unsigned long  siglen,
                             const unsigned char *hash,
                                   unsigned long  hashlen,
                                             int *stat,
                             const       ecc_key *key);

static const ecc_verify_fn s_ecc_verify_hash[] = {
#ifdef LTC_DER
                                [LTC_ECCSIG_ANSIX962] = ecc_verify_hash_x962,
#endif
                                [LTC_ECCSIG_RFC7518] = ecc_verify_hash_rfc7518_internal,
                                [LTC_ECCSIG_ETH27] = ecc_verify_hash_eth27,
#ifdef LTC_SSH
                                [LTC_ECCSIG_RFC5656] = ecc_verify_hash_rfc5656,
#endif
};

/**
   Verify an ECC signature
   @param sig         The signature to verify
   @param siglen      The length of the signature (octets)
   @param hash        The hash (message digest) that was signed
   @param hashlen     The length of the hash (octets)
   @param stat        [out] Result of signature, 1==valid, 0==invalid
   @param key         The corresponding public ECC key
   @return CRYPT_OK if successful (even if the signature is not valid)
*/
int ecc_verify_hash_v2(const unsigned char *sig,
                             unsigned long  siglen,
                       const unsigned char *hash,
                             unsigned long  hashlen,
                          ltc_ecc_sig_opts *opts,
                                       int *stat,
                       const       ecc_key *key)
{
   LTC_ARGCHK(stat != NULL);
   *stat = 0;
   if (opts->type < 0 || opts->type >= LTC_ARRAY_SIZE(s_ecc_verify_hash))
      return CRYPT_PK_INVALID_TYPE;
   if (s_ecc_verify_hash[opts->type] == NULL)
      return CRYPT_PK_INVALID_TYPE;
   return s_ecc_verify_hash[opts->type](sig, siglen, hash, hashlen, stat, key);
}

#endif
