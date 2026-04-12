/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file slhdsa_export.c
  Export a SLH-DSA key to a binary packet
*/

#if defined(LTC_SLHDSA) && defined(LTC_DER)

static int s_slhdsa_alg_to_oid(int alg, enum ltc_oid_id *oid_id)
{
   LTC_ARGCHK(oid_id != NULL);

   switch (alg) {
      case LTC_SLHDSA_SHA2_128S:
         *oid_id = LTC_OID_SLHDSA_SHA2_128S;
         return CRYPT_OK;
      case LTC_SLHDSA_SHA2_128F:
         *oid_id = LTC_OID_SLHDSA_SHA2_128F;
         return CRYPT_OK;
      case LTC_SLHDSA_SHA2_192S:
         *oid_id = LTC_OID_SLHDSA_SHA2_192S;
         return CRYPT_OK;
      case LTC_SLHDSA_SHA2_192F:
         *oid_id = LTC_OID_SLHDSA_SHA2_192F;
         return CRYPT_OK;
      case LTC_SLHDSA_SHA2_256S:
         *oid_id = LTC_OID_SLHDSA_SHA2_256S;
         return CRYPT_OK;
      case LTC_SLHDSA_SHA2_256F:
         *oid_id = LTC_OID_SLHDSA_SHA2_256F;
         return CRYPT_OK;
      case LTC_SLHDSA_SHAKE_128S:
         *oid_id = LTC_OID_SLHDSA_SHAKE_128S;
         return CRYPT_OK;
      case LTC_SLHDSA_SHAKE_128F:
         *oid_id = LTC_OID_SLHDSA_SHAKE_128F;
         return CRYPT_OK;
      case LTC_SLHDSA_SHAKE_192S:
         *oid_id = LTC_OID_SLHDSA_SHAKE_192S;
         return CRYPT_OK;
      case LTC_SLHDSA_SHAKE_192F:
         *oid_id = LTC_OID_SLHDSA_SHAKE_192F;
         return CRYPT_OK;
      case LTC_SLHDSA_SHAKE_256S:
         *oid_id = LTC_OID_SLHDSA_SHAKE_256S;
         return CRYPT_OK;
      case LTC_SLHDSA_SHAKE_256F:
         *oid_id = LTC_OID_SLHDSA_SHAKE_256F;
         return CRYPT_OK;
      case LTC_SLHDSA_HASH_SHA2_128S_WITH_SHA256:
         *oid_id = LTC_OID_HASH_SLHDSA_SHA2_128S_WITH_SHA256;
         return CRYPT_OK;
      case LTC_SLHDSA_HASH_SHA2_128F_WITH_SHA256:
         *oid_id = LTC_OID_HASH_SLHDSA_SHA2_128F_WITH_SHA256;
         return CRYPT_OK;
      case LTC_SLHDSA_HASH_SHA2_192S_WITH_SHA512:
         *oid_id = LTC_OID_HASH_SLHDSA_SHA2_192S_WITH_SHA512;
         return CRYPT_OK;
      case LTC_SLHDSA_HASH_SHA2_192F_WITH_SHA512:
         *oid_id = LTC_OID_HASH_SLHDSA_SHA2_192F_WITH_SHA512;
         return CRYPT_OK;
      case LTC_SLHDSA_HASH_SHA2_256S_WITH_SHA512:
         *oid_id = LTC_OID_HASH_SLHDSA_SHA2_256S_WITH_SHA512;
         return CRYPT_OK;
      case LTC_SLHDSA_HASH_SHA2_256F_WITH_SHA512:
         *oid_id = LTC_OID_HASH_SLHDSA_SHA2_256F_WITH_SHA512;
         return CRYPT_OK;
      case LTC_SLHDSA_HASH_SHAKE_128S_WITH_SHAKE128:
         *oid_id = LTC_OID_HASH_SLHDSA_SHAKE_128S_WITH_SHAKE128;
         return CRYPT_OK;
      case LTC_SLHDSA_HASH_SHAKE_128F_WITH_SHAKE128:
         *oid_id = LTC_OID_HASH_SLHDSA_SHAKE_128F_WITH_SHAKE128;
         return CRYPT_OK;
      case LTC_SLHDSA_HASH_SHAKE_192S_WITH_SHAKE256:
         *oid_id = LTC_OID_HASH_SLHDSA_SHAKE_192S_WITH_SHAKE256;
         return CRYPT_OK;
      case LTC_SLHDSA_HASH_SHAKE_192F_WITH_SHAKE256:
         *oid_id = LTC_OID_HASH_SLHDSA_SHAKE_192F_WITH_SHAKE256;
         return CRYPT_OK;
      case LTC_SLHDSA_HASH_SHAKE_256S_WITH_SHAKE256:
         *oid_id = LTC_OID_HASH_SLHDSA_SHAKE_256S_WITH_SHAKE256;
         return CRYPT_OK;
      case LTC_SLHDSA_HASH_SHAKE_256F_WITH_SHAKE256:
         *oid_id = LTC_OID_HASH_SLHDSA_SHAKE_256F_WITH_SHAKE256;
         return CRYPT_OK;
      default:
         return CRYPT_PK_INVALID_TYPE;
   }
}

/**
   Export a SLH-DSA key to a binary packet
   @param out    [out] The destination for the key
   @param outlen [in/out] The max size and resulting size of the SLH-DSA key
   @param which  Which type of key (PK_PRIVATE, PK_PUBLIC|PK_STD or PK_PUBLIC)
   @param key    The key you wish to export
   @return CRYPT_OK if successful
*/
int slhdsa_export(unsigned char *out, unsigned long *outlen,
                  int which, const slhdsa_key *key)
{
   int err, std;
   enum ltc_oid_id oid_id;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   std = which & PK_STD;
   which &= ~PK_STD;

   if ((err = s_slhdsa_alg_to_oid(key->alg, &oid_id)) != CRYPT_OK) {
      return err;
   }

   if (which == PK_PRIVATE) {
      const char *OID;
      unsigned long version, oid[16], oidlen;
      ltc_asn1_list alg_id[1];

      if (key->type != PK_PRIVATE || key->sk == NULL) return CRYPT_PK_INVALID_TYPE;

      if (std != PK_STD) {
         return slhdsa_export_raw(out, outlen, which, key);
      }

      if ((err = pk_get_oid(oid_id, &OID)) != CRYPT_OK) {
         return err;
      }
      oidlen = LTC_ARRAY_SIZE(oid);
      if ((err = pk_oid_str_to_num(OID, oid, &oidlen)) != CRYPT_OK) {
         return err;
      }
      LTC_SET_ASN1(alg_id, 0, LTC_ASN1_OBJECT_IDENTIFIER, oid, oidlen);
      version = 0;
      return der_encode_sequence_multi(out, outlen,
                                       LTC_ASN1_SHORT_INTEGER, 1uL, &version,
                                       LTC_ASN1_SEQUENCE,      1uL, alg_id,
                                       LTC_ASN1_OCTET_STRING, key->sklen, key->sk,
                                       LTC_ASN1_EOL,           0uL, NULL);
   }

   if (which != PK_PUBLIC) {
      return CRYPT_INVALID_ARG;
   }
   if (key->pk == NULL) return CRYPT_PK_INVALID_TYPE;

   if (std == PK_STD) {
      return x509_encode_subject_public_key_info(out, outlen, oid_id,
                                                 key->pk, key->pklen,
                                                 LTC_ASN1_EOL, NULL, 0uL);
   }

   return slhdsa_export_raw(out, outlen, which, key);
}

#endif
