/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file rsa_import_pkcs8.c
  Import a PKCS RSA key
*/

#ifdef LTC_MRSA

int rsa_import_pkcs8_asn1(ltc_asn1_list *alg_id, ltc_asn1_list *priv_key, rsa_key *key)
{
   int           err;

   LTC_ARGCHK(key != NULL);

   LTC_UNUSED_PARAM(alg_id);

   if ((err = rsa_init(key)) != CRYPT_OK) {
      return err;
   }

   if ((err = rsa_import_pkcs1(priv_key->data, priv_key->size, key)) != CRYPT_OK) {
      rsa_free(key);
      return err;
   }
   key->type = PK_PRIVATE;

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
int rsa_import_pkcs8(const unsigned char *in, unsigned long inlen,
                     const password_ctx  *pw_ctx,
                     rsa_key *key)
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
   if (pka != LTC_OID_RSA) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_DER_FREE;
   }

   err = rsa_import_pkcs8_asn1(alg_id, priv_key, key);

LBL_DER_FREE:
   der_free_sequence_flexi(l);
   return err;
}

#endif /* LTC_MRSA */
