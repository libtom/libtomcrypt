/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ec25519_import_pkcs8.c
  Generic import of a Curve/Ed25519 private key in PKCS#8 format, Steffen Jaeckel
*/

#ifdef LTC_CURVE25519

typedef int (*sk_to_pk)(unsigned char *pk , const unsigned char *sk);

int ec25519_import_pkcs8_asn1(ltc_asn1_list *alg_id, ltc_asn1_list *priv_key,
                              enum ltc_oid_id id,
                              curve25519_key *key)
{
   int err;
   unsigned long key_len;
   sk_to_pk fp;

   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   LTC_UNUSED_PARAM(alg_id);

   switch (id) {
      case LTC_OID_ED25519:
         fp = tweetnacl_crypto_sk_to_pk;
         break;
      case LTC_OID_X25519:
         fp = tweetnacl_crypto_scalarmult_base;
         break;
      default:
         return CRYPT_PK_INVALID_TYPE;
   }

   key_len = sizeof(key->priv);
   if ((err = der_decode_octet_string(priv_key->data, priv_key->size, key->priv, &key_len)) == CRYPT_OK) {
      fp(key->pub, key->priv);
      key->type = PK_PRIVATE;
      key->algo = id;
   }
   return err;
}

/**
  Generic import of a Curve/Ed25519 private key in PKCS#8 format
  @param in        The packet to import from
  @param inlen     It's length (octets)
  @param pw_ctx    The password context when decrypting the private key
  @param id        The type of the private key
  @param key       [out] Destination for newly imported key
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int ec25519_import_pkcs8(const unsigned char *in, unsigned long inlen,
                         const password_ctx   *pw_ctx,
                         enum ltc_oid_id id,
                         curve25519_key *key)
{
   int           err;
   ltc_asn1_list *l = NULL;
   ltc_asn1_list *alg_id, *priv_key;
   enum ltc_oid_id pka;

   LTC_ARGCHK(in != NULL);

   err = pkcs8_decode_flexi(in, inlen, pw_ctx, &l);
   if (err != CRYPT_OK) return err;

   if ((err = pkcs8_get_children(l, &pka, &alg_id, &priv_key)) != CRYPT_OK) {
      goto LBL_DER_FREE;
   }
   if (pka != id) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_DER_FREE;
   }

   err = ec25519_import_pkcs8_asn1(alg_id, priv_key, id, key);

LBL_DER_FREE:
   der_free_sequence_flexi(l);
   return err;
}

#endif
