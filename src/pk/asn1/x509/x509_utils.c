/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x509_utils.c
  More X.509 APIs, Steffen Jaeckel
*/

static LTC_INLINE int s_pka_verify(const unsigned char *msg, unsigned long msglen,
               const unsigned char *sig, unsigned long siglen,
                               int  hash_idx,
                               int *stat,
               const   ltc_pka_key *key)
{
   switch (key->id) {
#ifdef LTC_MRSA
      case LTC_PKA_RSA:
         /* Hard-code Padding to PSS and SaltLen to 20, as specified in RFC 4055 */
         return rsa_verify_hash_ex(sig, siglen, msg, msglen, LTC_PKCS_1_PSS, hash_idx, 20, stat, &key->u.rsa);
#endif
#ifdef LTC_MDSA
      case LTC_PKA_DSA:
         return dsa_verify_hash(sig, siglen, msg, msglen, stat, &key->u.dsa);
#endif
#ifdef LTC_MECC
      case LTC_PKA_EC:
         return ecc_verify_hash(sig, siglen, msg, msglen, stat, &key->u.ecc);
#endif
#ifdef LTC_CURVE25519
      case LTC_PKA_ED25519:
         return ed25519_verify(msg, msglen, sig, siglen, stat, &key->u.ed25519);
#endif
      default:
         return CRYPT_PK_INVALID_TYPE;
   }
}

int x509_cert_is_signed_by(const ltc_x509_certificate *cert, const ltc_pka_key *key, int *stat)
{
   unsigned char buf[MAXBLOCKSIZE], *msg;
   unsigned long msglen = sizeof(buf);
   int err, hash = -1;
   *stat = 0;
   if (key->id == LTC_PKA_ED25519) {
      msg = cert->tbs_certificate.asn1->data;
      msglen = cert->tbs_certificate.asn1->size;
   } else {
      if ((hash = find_hash(cert->signature_algorithm.hash)) == -1) {
         return CRYPT_INVALID_HASH;
      }
      if ((err = hash_memory(hash, cert->tbs_certificate.asn1->data, cert->tbs_certificate.asn1->size, buf, &msglen)) != CRYPT_OK) {
         return err;
      }
      msg = buf;
   }
   if ((err = s_pka_verify(msg, msglen, cert->signature.signature, cert->signature.signature_len/8, hash, stat, key)) != CRYPT_OK) {
      return err;
   }
   return err;
}

int x509_cmp_name(const ltc_x509_name *a, const ltc_x509_name *b)
{
   if (a == b)
      return 1;
   if (a->asn1->size != b->asn1->size)
      return 0;
   return XMEMCMP(a->asn1->data, b->asn1->data, a->asn1->size) == 0 ? 1 : 0;
}

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
