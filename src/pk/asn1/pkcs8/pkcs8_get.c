/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pkcs8_get.c
  PKCS#8 utility functions
*/

#ifdef LTC_PKCS_8

int pkcs8_get_children(const ltc_asn1_list *decoded_list, enum ltc_oid_id *pka, ltc_asn1_list **alg_id, ltc_asn1_list **priv_key)
{
   int err;
   unsigned long n;
   der_flexi_check flexi_should[4];
   ltc_asn1_list *seq_l = NULL, *priv_l = NULL, *version = NULL;

   LTC_ARGCHK(ltc_mp.name != NULL);

   if (alg_id == NULL) alg_id = &seq_l;
   if (priv_key == NULL) priv_key = &priv_l;

   /* der_flexi_sequence_cmp() writes only matched outputs, so unmatched ones stay NULL */
   *alg_id = NULL;
   *priv_key = NULL;

   /* Setup for basic structure */
   n=0;
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_INTEGER, &version);
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_SEQUENCE, alg_id);
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_OCTET_STRING, priv_key);
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n, LTC_ASN1_EOL, NULL);

   err = der_flexi_sequence_cmp(decoded_list, flexi_should);
   switch (err) {
      case CRYPT_OK:
      case CRYPT_INPUT_TOO_LONG:
         /* If there are attributes added after the private_key it is tagged with version 1 and
          * we get an 'input too long' error but the rest is already decoded and can be
          * handled the same as for version 0
          */
         if (version == NULL) {
            return CRYPT_INVALID_PACKET;
         }
         if (ltc_mp_cmp_d(version->data, 0) != LTC_MP_EQ && ltc_mp_cmp_d(version->data, 1) != LTC_MP_EQ) {
            return CRYPT_INVALID_PACKET;
         }
         break;
      default:
         return err;
   }
   if ((*alg_id == NULL) || ((*alg_id)->child == NULL) || (*priv_key == NULL)) {
      return CRYPT_INVALID_PACKET;
   }
   return pk_get_oid_from_asn1((*alg_id)->child, pka);
}

/**
   Cross-check the optional publicKey of a OneAsymmetricKey against the imported key

   RFC 5958 4. requires publicKey, when present, to belong to the privateKey next to it.
   It is encoded as [1] IMPLICIT BIT STRING, so the content is a zero unused-bits octet
   followed by the key itself.

   @param priv_key   The privateKey element, the optional fields follow it
   @param pk         The public key derived from the privateKey
   @param pklen      The length of the derived public key
   @return CRYPT_OK if publicKey is absent or matches, CRYPT_INVALID_PACKET if it does not
*/
int pkcs8_check_public_key(const ltc_asn1_list *priv_key, const unsigned char *pk, unsigned long pklen)
{
   const ltc_asn1_list *l;
   const unsigned char *p;

   LTC_ARGCHK(priv_key != NULL);
   LTC_ARGCHK(pk       != NULL);

   for (l = priv_key->next; l != NULL; l = l->next) {
      if ((l->type != LTC_ASN1_CUSTOM_TYPE) || (l->klass != LTC_ASN1_CL_CONTEXT_SPECIFIC) || (l->tag != 1)) {
         continue;
      }
      p = l->data;
      if ((p == NULL) || (l->size != pklen + 1) || (p[0] != 0) || (XMEMCMP(p + 1, pk, pklen) != 0)) {
         return CRYPT_INVALID_PACKET;
      }
      break;
   }

   return CRYPT_OK;
}

#endif /* LTC_PKCS_8 */
