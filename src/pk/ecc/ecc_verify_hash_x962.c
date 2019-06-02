/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#if defined(LTC_MECC) && defined(LTC_DER)

/**
  @file ecc_verify_hash_x962.c
  ECC Crypto, Tom St Denis
*/

int ecc_verify_hash_x962(const unsigned char *sig,  unsigned long siglen,
                         const unsigned char *hash, unsigned long hashlen,
                         int *stat, const ecc_key *key)
{
   void *r, *s;
   int err;

   LTC_ARGCHK(sig != NULL);

   if ((err = ltc_mp_init_multi(&r, &s, NULL)) != CRYPT_OK) return err;

   /* ANSI X9.62 format - ASN.1 encoded SEQUENCE{ INTEGER(r), INTEGER(s) }  */
   if ((err = der_decode_sequence_multi_ex(sig, siglen, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_ALL_STRICT,
                                     LTC_ASN1_INTEGER, 1UL, r,
                                     LTC_ASN1_INTEGER, 1UL, s,
                                     LTC_ASN1_EOL, 0UL, LTC_NULL)) != CRYPT_OK)                         { goto error; }

   err = ecc_verify_hash_internal(r, s, hash, hashlen, stat, key);

error:
   ltc_mp_deinit_multi(r, s, LTC_NULL);
   return err;
}

#endif
