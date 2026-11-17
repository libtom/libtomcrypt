/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x448_import.c
  Import a X448 key from a SubjectPublicKeyInfo
*/

#ifdef LTC_CURVE448

/**
  Import a X448 key
  @param in     The packet to read
  @param inlen  The length of the input packet
  @param key    [out] Where to import the key to
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int x448_import(const unsigned char *in, unsigned long inlen, curve448_key *key)
{
   int err;
   unsigned long key_len;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   key_len = 56uL;
   if ((err = x509_decode_subject_public_key_info(in, inlen, LTC_OID_X448, key->pub, &key_len, LTC_ASN1_EOL, NULL, 0uL)) == CRYPT_OK && key_len != 56uL) {
      err = CRYPT_PK_INVALID_SIZE;
   }
   if (err == CRYPT_OK) {
      key->type = PK_PUBLIC;
      key->pka = LTC_PKA_X448;
   }
   return err;
}

#endif
