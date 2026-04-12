/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file slhdsa_import_pkcs8.c
  Import a SLH-DSA key in PKCS#8 format
*/

#if defined(LTC_SLHDSA) && defined(LTC_PKCS_8)

static int s_slhdsa_oid_to_alg(enum ltc_oid_id oid_id, int *alg)
{
   LTC_ARGCHK(alg != NULL);

   switch (oid_id) {
      case LTC_OID_SLHDSA_SHA2_128S:
         *alg = LTC_SLHDSA_SHA2_128S;
         return CRYPT_OK;
      case LTC_OID_SLHDSA_SHA2_128F:
         *alg = LTC_SLHDSA_SHA2_128F;
         return CRYPT_OK;
      case LTC_OID_SLHDSA_SHA2_192S:
         *alg = LTC_SLHDSA_SHA2_192S;
         return CRYPT_OK;
      case LTC_OID_SLHDSA_SHA2_192F:
         *alg = LTC_SLHDSA_SHA2_192F;
         return CRYPT_OK;
      case LTC_OID_SLHDSA_SHA2_256S:
         *alg = LTC_SLHDSA_SHA2_256S;
         return CRYPT_OK;
      case LTC_OID_SLHDSA_SHA2_256F:
         *alg = LTC_SLHDSA_SHA2_256F;
         return CRYPT_OK;
      case LTC_OID_SLHDSA_SHAKE_128S:
         *alg = LTC_SLHDSA_SHAKE_128S;
         return CRYPT_OK;
      case LTC_OID_SLHDSA_SHAKE_128F:
         *alg = LTC_SLHDSA_SHAKE_128F;
         return CRYPT_OK;
      case LTC_OID_SLHDSA_SHAKE_192S:
         *alg = LTC_SLHDSA_SHAKE_192S;
         return CRYPT_OK;
      case LTC_OID_SLHDSA_SHAKE_192F:
         *alg = LTC_SLHDSA_SHAKE_192F;
         return CRYPT_OK;
      case LTC_OID_SLHDSA_SHAKE_256S:
         *alg = LTC_SLHDSA_SHAKE_256S;
         return CRYPT_OK;
      case LTC_OID_SLHDSA_SHAKE_256F:
         *alg = LTC_SLHDSA_SHAKE_256F;
         return CRYPT_OK;
      case LTC_OID_HASH_SLHDSA_SHA2_128S_WITH_SHA256:
         *alg = LTC_SLHDSA_HASH_SHA2_128S_WITH_SHA256;
         return CRYPT_OK;
      case LTC_OID_HASH_SLHDSA_SHA2_128F_WITH_SHA256:
         *alg = LTC_SLHDSA_HASH_SHA2_128F_WITH_SHA256;
         return CRYPT_OK;
      case LTC_OID_HASH_SLHDSA_SHA2_192S_WITH_SHA512:
         *alg = LTC_SLHDSA_HASH_SHA2_192S_WITH_SHA512;
         return CRYPT_OK;
      case LTC_OID_HASH_SLHDSA_SHA2_192F_WITH_SHA512:
         *alg = LTC_SLHDSA_HASH_SHA2_192F_WITH_SHA512;
         return CRYPT_OK;
      case LTC_OID_HASH_SLHDSA_SHA2_256S_WITH_SHA512:
         *alg = LTC_SLHDSA_HASH_SHA2_256S_WITH_SHA512;
         return CRYPT_OK;
      case LTC_OID_HASH_SLHDSA_SHA2_256F_WITH_SHA512:
         *alg = LTC_SLHDSA_HASH_SHA2_256F_WITH_SHA512;
         return CRYPT_OK;
      case LTC_OID_HASH_SLHDSA_SHAKE_128S_WITH_SHAKE128:
         *alg = LTC_SLHDSA_HASH_SHAKE_128S_WITH_SHAKE128;
         return CRYPT_OK;
      case LTC_OID_HASH_SLHDSA_SHAKE_128F_WITH_SHAKE128:
         *alg = LTC_SLHDSA_HASH_SHAKE_128F_WITH_SHAKE128;
         return CRYPT_OK;
      case LTC_OID_HASH_SLHDSA_SHAKE_192S_WITH_SHAKE256:
         *alg = LTC_SLHDSA_HASH_SHAKE_192S_WITH_SHAKE256;
         return CRYPT_OK;
      case LTC_OID_HASH_SLHDSA_SHAKE_192F_WITH_SHAKE256:
         *alg = LTC_SLHDSA_HASH_SHAKE_192F_WITH_SHAKE256;
         return CRYPT_OK;
      case LTC_OID_HASH_SLHDSA_SHAKE_256S_WITH_SHAKE256:
         *alg = LTC_SLHDSA_HASH_SHAKE_256S_WITH_SHAKE256;
         return CRYPT_OK;
      case LTC_OID_HASH_SLHDSA_SHAKE_256F_WITH_SHAKE256:
         *alg = LTC_SLHDSA_HASH_SHAKE_256F_WITH_SHAKE256;
         return CRYPT_OK;
      default:
         return CRYPT_PK_INVALID_TYPE;
   }
}

static int s_slhdsa_import_pkcs8_asn1(ltc_asn1_list *alg_id, ltc_asn1_list *priv_key, slhdsa_key *key)
{
   enum ltc_oid_id oid_id;
   int alg, err;
   unsigned char *raw_buf = NULL;
   unsigned long key_len, raw_buf_len, wrapped;

   LTC_ARGCHK(alg_id   != NULL);
   LTC_ARGCHK(priv_key != NULL);
   LTC_ARGCHK(key      != NULL);

   if ((err = pk_get_oid_from_asn1(alg_id->child, &oid_id)) != CRYPT_OK) {
      return err;
   }
   if ((err = s_slhdsa_oid_to_alg(oid_id, &alg)) != CRYPT_OK) {
      return err;
   }

   if ((err = slhdsa_get_sizes(alg, NULL, &key_len, NULL, NULL, NULL)) != CRYPT_OK) {
      return err;
   }
   if (priv_key->size == key_len) {
      return slhdsa_import_raw(priv_key->data, priv_key->size, PK_PRIVATE, alg, key);
   }

   /* the expandedKey form is exactly an OCTET STRING of key_len octets */
   if ((err = der_length_octet_string(key_len, &wrapped)) != CRYPT_OK) {
      return err;
   }

   raw_buf = XMALLOC(key_len);
   if (raw_buf == NULL) {
      return CRYPT_MEM;
   }
   raw_buf_len = key_len;
   err = der_decode_octet_string(priv_key->data, priv_key->size, raw_buf, &raw_buf_len);
   if (err == CRYPT_OK) {
      /* priv_key->size pins that nothing follows the OCTET STRING */
      err = (raw_buf_len == key_len && priv_key->size == wrapped)
          ? slhdsa_import_raw(raw_buf, raw_buf_len, PK_PRIVATE, alg, key)
          : CRYPT_INVALID_PACKET;
   }
   zeromem(raw_buf, key_len);
   XFREE(raw_buf);
   if (err != CRYPT_OK) {
      return err;
   }

   return CRYPT_OK;
}

/**
  INTERNAL ONLY, declared in tomcrypt_private.h

  Import a SLH-DSA private key from its PKCS#8 elements
  @param alg_id    The algorithm identifier
  @param priv_key  The privateKey element
  @param key       [out] Destination for newly imported key
  @return CRYPT_OK if successful
*/
int slhdsa_import_pkcs8_asn1(ltc_asn1_list *alg_id, ltc_asn1_list *priv_key, slhdsa_key *key)
{
   int err;

   if ((err = s_slhdsa_import_pkcs8_asn1(alg_id, priv_key, key)) != CRYPT_OK) {
      return err;
   }
   /* RFC 5958 - reject a publicKey that does not belong to the private key */
   if ((err = pkcs8_check_public_key(priv_key, key->pk, key->pklen)) != CRYPT_OK) {
      slhdsa_free(key);
   }

   return err;
}

/**
  Import a SLH-DSA private key in PKCS#8 format
  @param in        The packet to import from
  @param inlen     It's length (octets)
  @param pw_ctx    The password context when decrypting the private key
  @param key       [out] Destination for newly imported key
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int slhdsa_import_pkcs8(const unsigned char *in, unsigned long inlen, const password_ctx  *pw_ctx, slhdsa_key *key)
{
   int alg, err;
   ltc_asn1_list *l = NULL;
   ltc_asn1_list *alg_id = NULL, *priv_key = NULL;
   enum ltc_oid_id oid_id;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   if (inlen == 0) return CRYPT_INVALID_PACKET;

   err = pkcs8_decode_flexi(in, inlen, pw_ctx, &l);
   if (err != CRYPT_OK) {
      return err;
   }

   if ((err = pkcs8_get_children(l, &oid_id, &alg_id, &priv_key)) != CRYPT_OK) {
      goto cleanup;
   }
   err = s_slhdsa_oid_to_alg(oid_id, &alg);
   if (err != CRYPT_OK) {
      err = CRYPT_INVALID_PACKET;
      goto cleanup;
   }
   LTC_UNUSED_PARAM(alg);

   err = slhdsa_import_pkcs8_asn1(alg_id, priv_key, key);

cleanup:
   der_free_sequence_flexi(l);
   return err;
}

#endif
