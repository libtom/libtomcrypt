/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_MDH

int dh_import_pkcs8_asn1(ltc_asn1_list *alg_id, ltc_asn1_list *priv_key, dh_key *key)
{
   int           err;

   LTC_ARGCHK(key != NULL);

   if (!alg_id->child ||
         !LTC_ASN1_IS_TYPE(alg_id->child->next, LTC_ASN1_SEQUENCE) ||
         !LTC_ASN1_IS_TYPE(alg_id->child->next->child, LTC_ASN1_INTEGER) ||
         !LTC_ASN1_IS_TYPE(alg_id->child->next->child->next, LTC_ASN1_INTEGER)) {
      return CRYPT_PK_INVALID_TYPE;
   }

   if ((err = dh_init(key)) != CRYPT_OK) {
      return err;
   }

   if ((err = mp_copy(alg_id->child->next->child->data, key->prime)) != CRYPT_OK) {
      goto error;
   }
   if ((err = mp_copy(alg_id->child->next->child->next->data, key->base)) != CRYPT_OK) {
      goto error;
   }

   if ((err = der_decode_integer(priv_key->data, priv_key->size, key->x)) != CRYPT_OK) {
      goto error;
   }
   /* compute public key: y = (base ^ x) mod prime */
   if ((err = mp_exptmod(key->base, key->x, key->prime, key->y)) != CRYPT_OK) {
      goto error;
   }
   /* check public key */
   if ((err = dh_check_pubkey(key)) != CRYPT_OK) {
      goto error;
   }
   key->type = PK_PRIVATE;

   return CRYPT_OK;
error:
   dh_free(key);
   return err;
}

/**
  Import a DH key in PKCS#8 format
  @param in        The packet to import from
  @param inlen     It's length (octets)
  @param pw_ctx    The password context when decrypting the private key
  @param key       [out] Destination for newly imported key
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int dh_import_pkcs8(const unsigned char *in, unsigned long inlen,
                    const password_ctx  *pw_ctx, dh_key *key)
{
   int           err;
   ltc_asn1_list *l = NULL;
   ltc_asn1_list *alg_id, *priv_key;
   enum ltc_oid_id pka;

   LTC_ARGCHK(in != NULL);

   if ((err = pkcs8_decode_flexi(in, inlen, pw_ctx, &l)) != CRYPT_OK) {
      return err;
   }
   if ((err = pkcs8_get_children(l, &pka, &alg_id, &priv_key)) != CRYPT_OK) {
      goto LBL_DER_FREE;
   }
   if (pka != LTC_OID_DH) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_DER_FREE;
   }

   err = dh_import_pkcs8_asn1(alg_id, priv_key, key);

LBL_DER_FREE:
   der_free_sequence_flexi(l);
   return err;
}

#endif /* LTC_MDH */
