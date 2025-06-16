/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x509_get_pka.c
  Extract details from an X.509 cert, Steffen Jaeckel
*/

#ifdef LTC_DER

static LTC_INLINE int s_x509_get_oid(const ltc_asn1_list *pub, enum ltc_oid_id *oid_id)
{
   der_flexi_check flexi_should[3];
   ltc_asn1_list *seqid, *id = NULL;
   int err;
   unsigned long n = 0;
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_SEQUENCE, &seqid);
   LTC_SET_DER_FLEXI_CHECK_OPT(flexi_should, n++, LTC_ASN1_BIT_STRING, NULL);
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
   return pk_get_oid_from_asn1(id, oid_id);
}

int x509_get_pka(const ltc_asn1_list *pub, enum ltc_pka_id *pka)
{
   int err;
   enum ltc_oid_id oid_id;
   if ((err = s_x509_get_oid(pub, &oid_id)) != CRYPT_OK) {
      return err;
   }
   return pk_get_pka_id(oid_id, pka);
}

int x509_get_sig_alg(const ltc_asn1_list *seq, ltc_x509_signature_algorithm *sig_alg)
{
   int err;
   enum ltc_oid_id oid_id;
   if ((err = s_x509_get_oid(seq, &oid_id)) != CRYPT_OK) {
      return err;
   }
   return pk_get_sig_alg(oid_id, sig_alg);
}

#endif /* LTC_DER */
