/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x509_utils.c
  More X.509 APIs, Steffen Jaeckel
*/

typedef struct pka_sig_args {
   int  hash_idx;
   const ltc_rsa_parameters *rsa_params;
} pka_sig_args;

static LTC_INLINE int s_pka_verify(const unsigned char *msg, unsigned long msglen,
                                   const unsigned char *sig, unsigned long siglen,
                                          pka_sig_args  *sig_args,
                                                   int *stat,
                                   const   ltc_pka_key *key)
{
   ltc_rsa_op_parameters rsa_params = { 0 };
   ltc_ecc_sig_opts ecc_opts = {
                                .type = LTC_ECCSIG_ANSIX962
   };
   switch (key->id) {
#ifdef LTC_MRSA
      case LTC_PKA_RSA:
         rsa_params.params.hash_alg = hash_descriptor[sig_args->hash_idx].name;
         rsa_params.padding = LTC_PKCS_1_V1_5;
         /* RSA Keys usually use PKCS#1 v1.5 padding */
         return rsa_verify_hash_v2(sig, siglen, msg, msglen, &rsa_params, stat, &key->u.rsa);
      case LTC_PKA_RSA_PSS:
      {
         if (sig_args->rsa_params == NULL)
            return CRYPT_PK_INVALID_TYPE;
         rsa_params.params = *sig_args->rsa_params;
         rsa_params.padding = LTC_PKCS_1_PSS;
         return rsa_verify_hash_v2(sig, siglen, msg, msglen, &rsa_params, stat, &key->u.rsa);
      }
#endif
#ifdef LTC_MDSA
      case LTC_PKA_DSA:
         return dsa_verify_hash(sig, siglen, msg, msglen, stat, &key->u.dsa);
#endif
#ifdef LTC_MECC
      case LTC_PKA_EC:
         return ecc_verify_hash_v2(sig, siglen, msg, msglen, &ecc_opts, stat, &key->u.ecc);
#endif
#ifdef LTC_CURVE25519
      case LTC_PKA_ED25519:
         return ed25519_verify(msg, msglen, sig, siglen, stat, &key->u.ed25519);
#endif
      default:
         return CRYPT_PK_INVALID_TYPE;
   }
}

/* RFC5280 Ch. 4.1.1.2.  signatureAlgorithm
 * [...]
 *    This field MUST contain the same algorithm identifier as the
 *    signature field in the sequence tbsCertificate (Section 4.1.2.3).
 */
static LTC_INLINE int s_signature_algorithms_equal(const ltc_x509_signature_algorithm *a, const ltc_x509_signature_algorithm *b)
{
   if (a->pka != b->pka)
      return 0;
   if (a->pka == LTC_PKA_RSA_PSS) {
      if (!rsa_params_equal(&a->u.rsa_params, &b->u.rsa_params))
         return 0;
   }
   return 1;
}

/**
  Check whether an X.509 certificate is signed by a specific PKA key.

  @param cert   The X.509 certificate to validate.
  @param key    The key to validate the certificate with.
  @param stat   [out] The result of the signature comparison: 1==valid, 0==invalid.
  @return CRYPT_OK if successful
*/
int x509_cert_is_signed_by(const ltc_x509_certificate *cert, const ltc_pka_key *key, int *stat)
{
   unsigned char buf[MAXBLOCKSIZE], *msg;
   unsigned long msglen = sizeof(buf);
   const char *hashalg;
   pka_sig_args sig_args = {0};
   int err;

   LTC_ARGCHK(cert != NULL);
   LTC_ARGCHK(key  != NULL);
   LTC_ARGCHK(stat != NULL);

   *stat = 0;
   /* Check that signatureAlgorithms match AND the key must be appropriate. */
   if (!s_signature_algorithms_equal(&cert->signature_algorithm, &cert->tbs_certificate.signature_algorithm)
         || (cert->signature_algorithm.pka != key->id)) {
      return CRYPT_PK_TYPE_MISMATCH;
   }
   sig_args.hash_idx = -1;
   if (key->id == LTC_PKA_ED25519) {
      msg = cert->tbs_certificate.asn1->data;
      msglen = cert->tbs_certificate.asn1->size;
   } else {
      if (key->id == LTC_PKA_RSA_PSS) {
         if (cert->signature_algorithm.u.rsa_params.pss_oaep) {
            sig_args.rsa_params = &cert->signature_algorithm.u.rsa_params;
            if (key->u.rsa.params.pss_oaep && !rsa_params_equal(&key->u.rsa.params, sig_args.rsa_params)) {
               return CRYPT_PK_TYPE_MISMATCH;
            }
         } else if (key->u.rsa.params.pss_oaep) {
            sig_args.rsa_params = &key->u.rsa.params;
         } else {
            return CRYPT_PK_TYPE_MISMATCH;
         }
         hashalg = sig_args.rsa_params->hash_alg;
      } else {
         hashalg = cert->signature_algorithm.u.hash;
      }
      if ((sig_args.hash_idx = find_hash(hashalg)) == -1) {
         return CRYPT_INVALID_HASH;
      }
      if ((err = hash_memory(sig_args.hash_idx, cert->tbs_certificate.asn1->data, cert->tbs_certificate.asn1->size, buf, &msglen)) != CRYPT_OK) {
         return err;
      }
      msg = buf;
   }
   if ((err = s_pka_verify(msg, msglen, cert->signature.signature, cert->signature.signature_len/8, &sig_args, stat, key)) != CRYPT_OK) {
      return err;
   }
   return err;
}

/**
  Compare two X.509 NAME instances.

  @param a   A X.509 NAME.
  @param b   A X.509 NAME.
  @return 1 if equal, 0 if unequal.
*/
int x509_cmp_name(const ltc_x509_name *a, const ltc_x509_name *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);

   if (a == b)
      return 1;
   if (a->asn1->size != b->asn1->size)
      return 0;
   return XMEMCMP(a->asn1->data, b->asn1->data, a->asn1->size) == 0 ? 1 : 0;
}

/**
  Retrieve a specific component from an X.509 NAME.

  @param name  A X.509 NAME.
  @param type  The type of the component to retrieve.
  @param str   The result.
  @return CRYPT_OK if successful.
*/
int x509_name_detail_get(const ltc_x509_name *name, ltc_x509_details type, const ltc_x509_string **str)
{
   unsigned long n;

   LTC_ARGCHK(name != NULL);
   LTC_ARGCHK(str != NULL);

   for (n = 0; n < name->names_num; ++n) {
      if (name->names[n].type == type) {
         *str = &name->names[n];
         return CRYPT_OK;
      }
   }
   *str = NULL;
   return CRYPT_INVALID_ARG;
}

const char *x509_name_detail_desc(ltc_x509_details type)
{
   const char *standard_attributes[] = {
                                        "Serial",
                                        "CommonName",
                                        "CountryCode",
                                        "Locality",
                                        "State or Province",
                                        "Organisation",
                                        "OrganisationalUnit",
                                        "EmailAddress",
   };
   if (type <= LTC_X509_EMAIL) {
      return standard_attributes[type];
   }
   return "Unknown";
}
