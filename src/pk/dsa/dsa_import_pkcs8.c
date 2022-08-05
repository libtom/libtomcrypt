/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file dsa_import_pkcs8.c
  Import a PKCS DSA key
*/

#ifdef LTC_MDSA

int dsa_import_pkcs8_asn1(ltc_asn1_list *alg_id, ltc_asn1_list *priv_key, dsa_key *key)
{
   int err, stat;

   LTC_UNUSED_PARAM(alg_id);

   if (!alg_id->child
         || !LTC_ASN1_IS_TYPE(alg_id->child->next, LTC_ASN1_SEQUENCE)
         || !LTC_ASN1_IS_TYPE(priv_key, LTC_ASN1_OCTET_STRING)) {
      return CRYPT_INVALID_PACKET;
   }
   if ((err = dsa_set_pqg_dsaparam(alg_id->child->next->data, alg_id->child->next->size, key)) != CRYPT_OK) {
      return err;
   }
   if ((err = der_decode_integer(priv_key->data, priv_key->size, key->x)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = ltc_mp_exptmod(key->g, key->x, key->p, key->y)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* quick p, q, g validation, without primality testing
    * + x, y validation */
   if ((err = dsa_int_validate(key, &stat)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if (stat == 0) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   key->qord = ltc_mp_unsigned_bin_size(key->q);
   key->type = PK_PRIVATE;

   return err;
LBL_ERR:
   dsa_free(key);
   return err;
}
/**
  Import an RSAPrivateKey in PKCS#8 format
  @param in        The packet to import from
  @param inlen     It's length (octets)
  @param pw_ctx    The password context when decrypting the private key
  @param key       [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int dsa_import_pkcs8(const unsigned char *in, unsigned long inlen,
                     const password_ctx  *pw_ctx,
                     dsa_key *key)
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
   if (pka != LTC_OID_DSA) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_DER_FREE;
   }

   err = dsa_import_pkcs8_asn1(alg_id, priv_key, key);

LBL_DER_FREE:
   der_free_sequence_flexi(l);
   return err;
}

#endif /* LTC_MRSA */
