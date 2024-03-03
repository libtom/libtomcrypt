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
   ltc_asn1_list *seq_l, *version;

   LTC_ARGCHK(ltc_mp.name != NULL);

   if (alg_id == NULL) alg_id = &seq_l;

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
         if (mp_cmp_d(version->data, 0) != LTC_MP_EQ && mp_cmp_d(version->data, 1) != LTC_MP_EQ) {
            return CRYPT_INVALID_PACKET;
         }
         break;
      default:
         return err;
   }
   return pk_get_oid_from_asn1((*alg_id)->child, pka);
}

#endif /* LTC_PKCS_8 */
