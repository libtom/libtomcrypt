/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file mldsa_export.c
  Export a ML-DSA key to a binary packet
*/

#if defined(LTC_MLDSA) && defined(LTC_DER)

static int s_mldsa_alg_to_oid(int alg, enum ltc_oid_id *oid_id)
{
   LTC_ARGCHK(oid_id != NULL);

   switch (alg) {
      case LTC_MLDSA_44:
         *oid_id = LTC_OID_MLDSA_44;
         return CRYPT_OK;
      case LTC_MLDSA_65:
         *oid_id = LTC_OID_MLDSA_65;
         return CRYPT_OK;
      case LTC_MLDSA_87:
         *oid_id = LTC_OID_MLDSA_87;
         return CRYPT_OK;
      default:
         return CRYPT_PK_INVALID_TYPE;
   }
}

static int s_mldsa_export_pkcs8(unsigned char *out, unsigned long *outlen,
                                enum ltc_pqc_privkey_format format,
                                enum ltc_oid_id oid_id, const mldsa_key *key)
{
   int err;

   switch (format) {
      case LTC_PQC_PRIVKEY_AUTO:
         if (!key->has_seed) {
            return pqc_export_privkey(out, outlen, oid_id, NULL, 0, key->sk, key->sklen);
         }
         return pqc_export_privkey(out, outlen, oid_id, key->seed, sizeof(key->seed), NULL, 0);
      case LTC_PQC_PRIVKEY_SEED:
         if (!key->has_seed) return CRYPT_PK_INVALID_TYPE;
         return pqc_export_privkey(out, outlen, oid_id, key->seed, sizeof(key->seed), NULL, 0);
      case LTC_PQC_PRIVKEY_EXPANDED:
         return pqc_export_privkey(out, outlen, oid_id, NULL, 0, key->sk, key->sklen);
      case LTC_PQC_PRIVKEY_BOTH:
         if (!key->has_seed) return CRYPT_PK_INVALID_TYPE;
         /* callers can change the key struct, so check that seed and expanded key match */
         if ((err = mldsa_check_key(key)) != CRYPT_OK) return err;
         return pqc_export_privkey(out, outlen, oid_id, key->seed, sizeof(key->seed), key->sk, key->sklen);
      default:
         return CRYPT_INVALID_ARG;
   }
}

/**
   Export a ML-DSA key to a binary packet, choosing the private-key representation
   @param out    [out] The destination for the key
   @param outlen [in/out] The max size and resulting size of the ML-DSA key
   @param which  Which type of key (PK_PRIVATE, PK_PRIVATE|PK_STD, PK_PUBLIC or PK_PUBLIC|PK_STD)
   @param format The private-key representation for PK_PRIVATE|PK_STD, has to be
                 LTC_PQC_PRIVKEY_AUTO for all other values of which
   @param key    The key you wish to export
   @return CRYPT_OK if successful, CRYPT_PK_INVALID_TYPE if the key does not have
           the requested representation
*/
int mldsa_export_ex(unsigned char *out, unsigned long *outlen,
                    int which, enum ltc_pqc_privkey_format format, const mldsa_key *key)
{
   int err, std;
   enum ltc_oid_id oid_id;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   std = which & PK_STD;
   which &= ~PK_STD;

   if ((err = s_mldsa_alg_to_oid(key->alg, &oid_id)) != CRYPT_OK) {
      return err;
   }

   if (which == PK_PRIVATE) {
      if (key->type != PK_PRIVATE || key->sk == NULL) return CRYPT_PK_INVALID_TYPE;

      if (std != PK_STD) {
         /* the raw private key is always the expanded key, use mldsa_export_seed() for the seed */
         if (format != LTC_PQC_PRIVKEY_AUTO && format != LTC_PQC_PRIVKEY_EXPANDED) return CRYPT_INVALID_ARG;
         return mldsa_export_raw(out, outlen, which, key);
      }

      return s_mldsa_export_pkcs8(out, outlen, format, oid_id, key);
   }

   if (which != PK_PUBLIC) {
      return CRYPT_INVALID_ARG;
   }
   if (format != LTC_PQC_PRIVKEY_AUTO) {
      return CRYPT_INVALID_ARG;
   }
   if (key->pk == NULL) return CRYPT_PK_INVALID_TYPE;

   if (std == PK_STD) {
      return x509_encode_subject_public_key_info(out, outlen, oid_id,
                                                 key->pk, key->pklen,
                                                 LTC_ASN1_EOL, NULL, 0uL);
   }

   return mldsa_export_raw(out, outlen, which, key);
}

/**
   Export a ML-DSA key to a binary packet
   @param out    [out] The destination for the key
   @param outlen [in/out] The max size and resulting size of the ML-DSA key
   @param which  Which type of key (PK_PRIVATE, PK_PUBLIC|PK_STD or PK_PUBLIC)
   @param key    The key you wish to export
   @return CRYPT_OK if successful

   @note PK_PRIVATE|PK_STD writes the seed if the key has one and the expanded key
         otherwise, use mldsa_export_ex() to choose the representation.
*/
int mldsa_export(unsigned char *out, unsigned long *outlen,
                 int which, const mldsa_key *key)
{
   return mldsa_export_ex(out, outlen, which, LTC_PQC_PRIVKEY_AUTO, key);
}

#endif
