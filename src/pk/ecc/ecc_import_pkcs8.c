/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

int ecc_import_pkcs8_asn1(ltc_asn1_list *alg_id, ltc_asn1_list *priv_key, ecc_key *key)
{
   void          *a, *b, *gx, *gy;
   unsigned long len, cofactor, n;
   int           err;
   char          OID[256];
   const ltc_ecc_curve *curve;
   ltc_asn1_list *p = NULL;
   der_flexi_check case2_should[7];
   ltc_asn1_list *version, *field, *point, *point_g, *order, *p_cofactor;

   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* init key */
   err = mp_init_multi(&a, &b, &gx, &gy, NULL);
   if (err != CRYPT_OK) goto LBL_DER_FREE;

   /* Setup for CASE 2 */
   n=0;
   LTC_SET_DER_FLEXI_CHECK(case2_should, n++, LTC_ASN1_INTEGER, &version);
   LTC_SET_DER_FLEXI_CHECK(case2_should, n++, LTC_ASN1_SEQUENCE, &field);
   LTC_SET_DER_FLEXI_CHECK(case2_should, n++, LTC_ASN1_SEQUENCE, &point);
   LTC_SET_DER_FLEXI_CHECK(case2_should, n++, LTC_ASN1_OCTET_STRING, &point_g);
   LTC_SET_DER_FLEXI_CHECK(case2_should, n++, LTC_ASN1_INTEGER, &order);
   LTC_SET_DER_FLEXI_CHECK(case2_should, n++, LTC_ASN1_INTEGER, &p_cofactor);
   LTC_SET_DER_FLEXI_CHECK(case2_should, n, LTC_ASN1_EOL, NULL);

   if (LTC_ASN1_IS_TYPE(alg_id->child->next, LTC_ASN1_OBJECT_IDENTIFIER)) {
      /* CASE 1: curve by OID (AKA short variant):
       *   0:d=0  hl=2 l= 100 cons: SEQUENCE
       *   2:d=1  hl=2 l=   1 prim:   INTEGER        :00
       *   5:d=1  hl=2 l=  16 cons:   SEQUENCE       (== *seq)
       *   7:d=2  hl=2 l=   7 prim:     OBJECT       :id-ecPublicKey
       *  16:d=2  hl=2 l=   5 prim:     OBJECT       :(== *curve_oid (e.g. secp256k1 (== 1.3.132.0.10)))
       *  23:d=1  hl=2 l=  77 prim:   OCTET STRING   :bytes (== *priv_key)
       */
      ltc_asn1_list *curve_oid = alg_id->child->next;
      len = sizeof(OID);
      if ((err = pk_oid_num_to_str(curve_oid->data, curve_oid->size, OID, &len)) != CRYPT_OK) { goto LBL_DONE; }
      if ((err = ecc_find_curve(OID, &curve)) != CRYPT_OK)                          { goto LBL_DONE; }
      if ((err = ecc_set_curve(curve, key)) != CRYPT_OK)                            { goto LBL_DONE; }
   } else if ((err = der_flexi_sequence_cmp(alg_id->child->next, case2_should)) == CRYPT_OK) {

      /* CASE 2: explicit curve parameters (AKA long variant):
       *   0:d=0  hl=3 l= 227 cons: SEQUENCE
       *   3:d=1  hl=2 l=   1 prim:   INTEGER              :00
       *   6:d=1  hl=3 l= 142 cons:   SEQUENCE             (== *seq)
       *   9:d=2  hl=2 l=   7 prim:     OBJECT             :id-ecPublicKey
       *  18:d=2  hl=3 l= 130 cons:     SEQUENCE
       *  21:d=3  hl=2 l=   1 prim:       INTEGER          :01
       *  24:d=3  hl=2 l=  44 cons:       SEQUENCE         (== *field)
       *  26:d=4  hl=2 l=   7 prim:         OBJECT         :prime-field
       *  35:d=4  hl=2 l=  33 prim:         INTEGER        :(== *prime / curve.prime)
       *  70:d=3  hl=2 l=   6 cons:       SEQUENCE         (== *point)
       *  72:d=4  hl=2 l=   1 prim:         OCTET STRING   :bytes (== curve.A)
       *  75:d=4  hl=2 l=   1 prim:         OCTET STRING   :bytes (== curve.B)
       *  78:d=3  hl=2 l=  33 prim:       OCTET STRING     :bytes (== *g_point / curve.G-point)
       * 113:d=3  hl=2 l=  33 prim:       INTEGER          :(== *order / curve.order)
       * 148:d=3  hl=2 l=   1 prim:       INTEGER          :(== curve.cofactor)
       * 151:d=1  hl=2 l=  77 prim:   OCTET STRING         :bytes (== *priv_key)
       */

      if (mp_cmp_d(version->data, 1) != LTC_MP_EQ) {
         goto LBL_DONE;
      }
      cofactor = mp_get_int(p_cofactor->data);

      if (LTC_ASN1_IS_TYPE(field->child, LTC_ASN1_OBJECT_IDENTIFIER) &&
          LTC_ASN1_IS_TYPE(field->child->next, LTC_ASN1_INTEGER) &&
          LTC_ASN1_IS_TYPE(point->child, LTC_ASN1_OCTET_STRING) &&
          LTC_ASN1_IS_TYPE(point->child->next, LTC_ASN1_OCTET_STRING)) {

         ltc_asn1_list *prime = field->child->next;
         if ((err = mp_read_unsigned_bin(a, point->child->data, point->child->size)) != CRYPT_OK) {
            goto LBL_DONE;
         }
         if ((err = mp_read_unsigned_bin(b, point->child->next->data, point->child->next->size)) != CRYPT_OK) {
            goto LBL_DONE;
         }
         if ((err = ltc_ecc_import_point(point_g->data, point_g->size, prime->data, a, b, gx, gy)) != CRYPT_OK) {
            goto LBL_DONE;
         }
         if ((err = ecc_set_curve_from_mpis(a, b, prime->data, order->data, gx, gy, cofactor, key)) != CRYPT_OK) {
            goto LBL_DONE;
         }
      }
   } else {
      err = CRYPT_INVALID_PACKET;
      goto LBL_DONE;
   }

   /* load private key value 'k' */
   len = priv_key->size;
   if ((err = der_decode_sequence_flexi(priv_key->data, &len, &p)) == CRYPT_OK) {
      if (p->type == LTC_ASN1_SEQUENCE &&
          LTC_ASN1_IS_TYPE(p->child, LTC_ASN1_INTEGER) &&
          LTC_ASN1_IS_TYPE(p->child->next, LTC_ASN1_OCTET_STRING)) {
         ltc_asn1_list *lk = p->child->next;
         if (mp_cmp_d(p->child->data, 1) != LTC_MP_EQ) {
            err = CRYPT_INVALID_PACKET;
            goto LBL_ECCFREE;
         }
         if ((err = ecc_set_key(lk->data, lk->size, PK_PRIVATE, key)) != CRYPT_OK) {
            goto LBL_ECCFREE;
         }
         goto LBL_DONE; /* success */
      }
   }
   err = CRYPT_INVALID_PACKET;
   goto LBL_DONE;

LBL_ECCFREE:
   ecc_free(key);
LBL_DONE:
   mp_clear_multi(a, b, gx, gy, NULL);
LBL_DER_FREE:
   if (p) der_free_sequence_flexi(p);
   return err;
}

/**
  Import an ECC private from in PKCS#8 format
  @param in        The packet to import from
  @param inlen     It's length (octets)
  @param pw_ctx    The password context when decrypting the private key
  @param key       [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int ecc_import_pkcs8(const unsigned char *in, unsigned long inlen,
                     const password_ctx  *pw_ctx,
                     ecc_key *key)
{
   int           err;
   ltc_asn1_list *l = NULL;
   ltc_asn1_list *alg_id, *priv_key;
   enum ltc_oid_id pka;

   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   err = pkcs8_decode_flexi(in, inlen, pw_ctx, &l);
   if (err != CRYPT_OK) return err;

   if ((err = pkcs8_get_children(l, &pka, &alg_id, &priv_key)) != CRYPT_OK) {
      goto LBL_DER_FREE;
   }
   if (pka != LTC_OID_EC) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_DER_FREE;
   }

   err = ecc_import_pkcs8_asn1(alg_id, priv_key, key);

LBL_DER_FREE:
   der_free_sequence_flexi(l);
   return err;
}

#endif
