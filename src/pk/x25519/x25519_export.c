/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

/**
  @file x25519_export.c
  Export a X25519 key to a binary packet, Steffen Jaeckel
*/

#ifdef LTC_X25519

/**
   Export a X25519 key to a binary packet
   @param out    [out] The destination for the key
   @param outlen [in/out] The max size and resulting size of the X25519 key
   @param type   Which type of key (PK_PRIVATE, PK_PUBLIC|PK_STD or PK_PUBLIC)
   @param key    The key you wish to export
   @return CRYPT_OK if successful
*/
int x25519_export(      unsigned char *out, unsigned long *outlen,
                                  int  which,
                  const    curve25519_key *key)
{
   int err, std;
   oid_st oid;
   ltc_asn1_list alg_id[1];
   unsigned char private_key[34];
   unsigned long version, private_key_len = sizeof(private_key);

   LTC_ARGCHK(out       != NULL);
   LTC_ARGCHK(outlen    != NULL);
   LTC_ARGCHK(key       != NULL);

   if (key->algo != PKA_X25519) return CRYPT_PK_INVALID_TYPE;

   std = which & PK_STD;
   which &= ~PK_STD;

   if (which == PK_PRIVATE) {
      if(key->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;

      if ((err = pk_get_oid(PKA_X25519, &oid)) != CRYPT_OK) {
         return err;
      }

      LTC_SET_ASN1(alg_id, 0, LTC_ASN1_OBJECT_IDENTIFIER, oid.OID,   oid.OIDlen);

      /* encode private key as PKCS#8 */
      if ((err = der_encode_octet_string(key->priv, 32uL, private_key, &private_key_len)) != CRYPT_OK) {
         return err;
      }

      version = 0;
      err = der_encode_sequence_multi(out, outlen,
                                LTC_ASN1_SHORT_INTEGER,            1uL, &version,
                                LTC_ASN1_SEQUENCE,                 1uL, alg_id,
                                LTC_ASN1_OCTET_STRING, private_key_len, private_key,
                                LTC_ASN1_EOL,                      0uL, NULL);
   } else {
      if (std == PK_STD) {
         /* encode public key as SubjectPublicKeyInfo */
         err = x509_encode_subject_public_key_info(out, outlen, PKA_X25519, key->pub, 32uL, LTC_ASN1_EOL, NULL, 0uL);
      } else {
         if (*outlen < sizeof(key->pub)) {
            err = CRYPT_BUFFER_OVERFLOW;
         } else {
            XMEMCPY(out, key->pub, sizeof(key->pub));
            err = CRYPT_OK;
         }
         *outlen = sizeof(key->pub);
      }
   }

   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
