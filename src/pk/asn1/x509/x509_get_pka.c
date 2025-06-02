/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x509_get_pka.c
  Extract the PKA from an X.509 cert, Steffen Jaeckel
*/

#ifdef LTC_DER

int x509_get_pka(ltc_asn1_list *pub, enum ltc_pka_id *pka)
{
   der_flexi_check flexi_should[4];
   ltc_asn1_list *seqid, *id;
   enum ltc_oid_id oid_id;
   int err;
   unsigned long n = 0;
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_SEQUENCE, &seqid);
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_BIT_STRING, NULL);
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n, LTC_ASN1_EOL, NULL);
   if ((err = der_flexi_sequence_cmp(pub, flexi_should)) != CRYPT_OK) {
      return err;
   }
   n = 0;
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_OBJECT_IDENTIFIER, &id);
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n, LTC_ASN1_EOL, NULL);
   err = der_flexi_sequence_cmp(seqid, flexi_should);
   if (err != CRYPT_OK && err != CRYPT_INPUT_TOO_LONG) {
      return err;
   }
   if ((err = pk_get_oid_from_asn1(id, &oid_id)) != CRYPT_OK) {
      return err;
   }
   return pk_get_pka_id(oid_id, pka);
}

#endif /* LTC_DER */
