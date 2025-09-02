/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file rsa_import.c
  Import an RSA key from a X.509 certificate, Steffen Jaeckel
*/

#ifdef LTC_MRSA

#ifndef S_RSA_DECODE
#define S_RSA_DECODE
static int s_rsa_decode(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   /* now it should be SEQUENCE { INTEGER, INTEGER } */
   return der_decode_sequence_multi(in, inlen,
                                        LTC_ASN1_INTEGER, 1UL, key->N,
                                        LTC_ASN1_INTEGER, 1UL, key->e,
                                        LTC_ASN1_EOL,     0UL, NULL);
}
#endif

typedef struct rsa_pss_parameters_data {
   ltc_asn1_list params[4], inner[4], hash_alg[2], mgf[2], mgf_hash_alg[2];
   unsigned long hash_alg_oid[LTC_DER_OID_DEFAULT_NODES];
   unsigned long mgf_alg_oid[LTC_DER_OID_DEFAULT_NODES];
   unsigned long mgf1_hash_alg_oid[LTC_DER_OID_DEFAULT_NODES];
   unsigned long salt_length, trailer_field;
} rsa_pss_parameters_data;

static LTC_INLINE void s_rsa_pss_parameters_data_setup(rsa_pss_parameters_data *d)
{
   unsigned long n;
   /* RSASSA-PSS
    *
    *    RSASSA-PSS-params ::= SEQUENCE {
    *        hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
    *        maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
    *        saltLength         [2] INTEGER            DEFAULT 20,
    *        trailerField       [3] TrailerField       DEFAULT trailerFieldBC
    *    }
    */

   /*        HashAlgorithm ::= AlgorithmIdentifier {
    *           {OAEP-PSSDigestAlgorithms}
    *        }
    */
   LTC_SET_ASN1(d->hash_alg, 0, LTC_ASN1_OBJECT_IDENTIFIER, d->hash_alg_oid, LTC_ARRAY_SIZE(d->hash_alg_oid));
   LTC_SET_ASN1(d->hash_alg, 1, LTC_ASN1_NULL, NULL, 0);
   d->hash_alg[1].optional = 1;

   /*        MaskGenAlgorithm ::= AlgorithmIdentifier { {PKCS1MGFAlgorithms} } */
   LTC_SET_ASN1(d->mgf_hash_alg, 0, LTC_ASN1_OBJECT_IDENTIFIER, d->mgf1_hash_alg_oid, LTC_ARRAY_SIZE(d->mgf1_hash_alg_oid));
   LTC_SET_ASN1(d->mgf_hash_alg, 1, LTC_ASN1_NULL, NULL, 0);
   d->mgf_hash_alg[1].optional = 1;

   /*        PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
    *            { OID id-mgf1 PARAMETERS HashAlgorithm },
    *            ... -- Allows for future expansion --
    *        }
    */
   LTC_SET_ASN1(d->mgf, 0, LTC_ASN1_OBJECT_IDENTIFIER, d->mgf_alg_oid, LTC_ARRAY_SIZE(d->mgf_alg_oid));
   LTC_SET_ASN1(d->mgf, 1, LTC_ASN1_SEQUENCE, d->mgf_hash_alg, LTC_ARRAY_SIZE(d->mgf_hash_alg));

   LTC_SET_ASN1(d->inner, 0, LTC_ASN1_SEQUENCE, d->hash_alg, LTC_ARRAY_SIZE(d->hash_alg));
   LTC_SET_ASN1(d->inner, 1, LTC_ASN1_SEQUENCE, d->mgf, LTC_ARRAY_SIZE(d->mgf));
   LTC_SET_ASN1(d->inner, 2, LTC_ASN1_SHORT_INTEGER, &d->salt_length, 1UL);
   LTC_SET_ASN1(d->inner, 3, LTC_ASN1_SHORT_INTEGER, &d->trailer_field, 1UL);

   LTC_SET_ASN1_CUSTOM_CONSTRUCTED(d->params, 0, LTC_ASN1_CL_CONTEXT_SPECIFIC, 0, d->inner);     /* context specific 0 */
   LTC_SET_ASN1_CUSTOM_CONSTRUCTED(d->params, 1, LTC_ASN1_CL_CONTEXT_SPECIFIC, 1, d->inner + 1); /* context specific 1 */
   LTC_SET_ASN1_CUSTOM_CONSTRUCTED(d->params, 2, LTC_ASN1_CL_CONTEXT_SPECIFIC, 2, d->inner + 2); /* context specific 2 */
   LTC_SET_ASN1_CUSTOM_CONSTRUCTED(d->params, 3, LTC_ASN1_CL_CONTEXT_SPECIFIC, 3, d->inner + 3); /* context specific 3 */
   for (n = 0; n < 4; ++n) {
      d->params[n].optional = 1;
   }
}

static int s_rsa_decode_parameters(const rsa_pss_parameters_data *d, ltc_rsa_parameters *rsa_params)
{
   unsigned long n;
   enum ltc_oid_id oid_id;
   int           err, idx;

   rsa_params->saltlen = 20;
   rsa_params->hash_alg = rsa_params->mgf1_hash_alg = "sha1";

   for (n = 0; n < 4; ++n) {
      if (d->params[n].used == 0)
         continue;
      switch (n) {
         case 0:
            idx = find_hash_oid(d->hash_alg->data, d->hash_alg->size);
            if (idx == -1) {
               return CRYPT_INVALID_HASH;
            }
            rsa_params->hash_alg = hash_descriptor[idx].name;
            break;
         case 1:
            if ((err = pk_get_oid_from_asn1(&d->mgf[0], &oid_id)) != CRYPT_OK) {
               return err;
            }
            if (oid_id != LTC_OID_RSA_MGF1) {
               return CRYPT_PK_ASN1_ERROR;
            }
            idx = find_hash_oid(d->mgf_hash_alg->data, d->mgf_hash_alg->size);
            if (idx == -1) {
               return CRYPT_INVALID_HASH;
            }
            rsa_params->mgf1_hash_alg = hash_descriptor[idx].name;
            break;
         case 2:
            rsa_params->saltlen = d->salt_length;
            break;
         case 3:
            if (d->trailer_field != 1) {
               return CRYPT_PK_ASN1_ERROR;
            }
            break;
         default:
            return CRYPT_PK_ASN1_ERROR;
      }
   }

   rsa_params->pss_oaep = 1;

   return CRYPT_OK;
}

int rsa_decode_parameters(const ltc_asn1_list *parameters, ltc_rsa_parameters *rsa_params)
{
   int           err;
   rsa_pss_parameters_data d;

   s_rsa_pss_parameters_data_setup(&d);

   if ((err = der_decode_sequence(parameters->data, parameters->size, d.params, 4)) != CRYPT_OK) {
      return err;
   }

   return s_rsa_decode_parameters(&d, rsa_params);
}

static LTC_INLINE int s_rsa_1_5_import_spki(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   return x509_process_public_key_from_spki(in, inlen,
                                            LTC_OID_RSA,
                                            LTC_ASN1_NULL, NULL, NULL,
                                            (public_key_decode_cb)s_rsa_decode, key);
}

static LTC_INLINE int s_rsa_pss_import_spki(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   int err;
   rsa_pss_parameters_data d;
   unsigned long n_params = LTC_ARRAY_SIZE(d.params);

   if (x509_process_public_key_from_spki(in, inlen,
                                         LTC_OID_RSA_PSS,
                                         LTC_ASN1_NULL, NULL, NULL,
                                         (public_key_decode_cb)s_rsa_decode, key) == CRYPT_OK) {
      return CRYPT_OK;
   }
   s_rsa_pss_parameters_data_setup(&d);
   if ((err = x509_process_public_key_from_spki(in, inlen,
                                            LTC_OID_RSA_PSS,
                                            LTC_ASN1_SEQUENCE, d.params, &n_params,
                                            (public_key_decode_cb)s_rsa_decode, key)) != CRYPT_OK) {
      return err;
   }
   return s_rsa_decode_parameters(&d, &key->params);
}

static LTC_INLINE int s_rsa_import_spki(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   int err;
   if (s_rsa_1_5_import_spki(in, inlen, key) == CRYPT_OK) {
      return CRYPT_OK;
   }

   if ((err = s_rsa_pss_import_spki(in, inlen, key)) == CRYPT_OK) {
      return CRYPT_OK;
   }
   return err;
}

/**
  Import an RSA key from SubjectPublicKeyInfo
  @param in      The packet to import from
  @param inlen   It's length (octets)
  @param key     [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int rsa_import_spki(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   int           err;

   LTC_ARGCHK(in          != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* init key */
   if ((err = rsa_init(key)) != CRYPT_OK) {
      return err;
   }

   if ((err = s_rsa_import_spki(in, inlen, key)) == CRYPT_OK) {
      key->type = PK_PUBLIC;
      return CRYPT_OK;
   }

   rsa_free(key);

   return err;
}

/**
  Import an RSA key from a X.509 certificate
  @param in      The packet to import from
  @param inlen   It's length (octets)
  @param key     [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int rsa_import_x509(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   ltc_asn1_list *decoded_list;
   const ltc_asn1_list *spki;
   int           err;

   LTC_ARGCHK(in          != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* init key */
   if ((err = rsa_init(key)) != CRYPT_OK) {
      return err;
   }

   /* First try to decode as SubjectPublicKeyInfo */
   if (s_rsa_import_spki(in, inlen, key) == CRYPT_OK) {
      key->type = PK_PUBLIC;
      return CRYPT_OK;
   }

   /* Now try to extract the SubjectPublicKeyInfo from the Certificate */
   if ((err = x509_decode_spki(in, inlen, &decoded_list, &spki)) != CRYPT_OK) {
      rsa_free(key);
      return err;
   }
   err = s_rsa_import_spki(spki->data, spki->size, key);

   der_free_sequence_flexi(decoded_list);
   if (err != CRYPT_OK) {
      rsa_free(key);
      return err;
   }
   key->type = PK_PUBLIC;
   return CRYPT_OK;
}

#endif /* LTC_MRSA */

