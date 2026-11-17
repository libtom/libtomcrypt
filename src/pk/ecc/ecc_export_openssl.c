/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#if defined(LTC_MECC) && defined(LTC_DER)

/* big-endian with leading zeros up to len bytes */
static int s_mp_to_fixed_bin(void *num, unsigned char *out, unsigned long len, unsigned long outsize)
{
   unsigned long n = ltc_mp_unsigned_bin_size(num);

   if (len > outsize) return CRYPT_BUFFER_OVERFLOW;
   if (n > len)       return CRYPT_PK_INVALID_SIZE;
   zeromem(out, len - n);
   return ltc_mp_to_unsigned_bin(num, out + (len - n));
}

static int s_ecc_export(unsigned char *out, unsigned long *outlen, int type, const ecc_key *key, int pkcs8)
{
   int           err;
   void *prime, *order, *a, *b, *gx, *gy;
   unsigned char bin_a[256], bin_b[256], bin_k[256], bin_g[512], bin_xy[512], bin_p8[1024];
   unsigned long len_a, len_b, len_k, len_g, len_xy, len_p8;
   unsigned long cofactor, one = 1;
   const char *OID;
   unsigned long oid[16], oidlen;
   ltc_asn1_list seq_fieldid[2], seq_curve[2], seq_ecparams[6], seq_priv[4], pub_xy, ecparams;
   int flag_oid = type & PK_CURVEOID ? 1 : 0;
   int flag_com = type & PK_COMPRESSED ? 1 : 0;
   int flag_pri = type & PK_PRIVATE ? 1 : 0;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   if (key->type != PK_PRIVATE && flag_pri) return CRYPT_PK_TYPE_MISMATCH;

   if (flag_oid) {
      /* http://tools.ietf.org/html/rfc5912
         ECParameters ::= CHOICE {
           namedCurve      CURVE.&id({NamedCurve})                # OBJECT
         }
      */
      if (key->dp.oidlen == 0)                                  { err = CRYPT_INVALID_ARG; goto error; }
      LTC_SET_ASN1(&ecparams, 0, LTC_ASN1_OBJECT_IDENTIFIER, key->dp.oid, key->dp.oidlen);
   }
   else {
      prime    = key->dp.prime;
      order    = key->dp.order;
      a        = key->dp.A;
      b        = key->dp.B;
      gx       = key->dp.base.x;
      gy       = key->dp.base.y;
      cofactor = key->dp.cofactor;

      /* curve params a and b - padded to the field size, as SEC 1 requires and OpenSSL 1.1.1 and later does */
      len_a = len_b = ltc_mp_unsigned_bin_size(prime);
      if ((err = s_mp_to_fixed_bin(a, bin_a, len_a, sizeof(bin_a))) != CRYPT_OK) { goto error; }
      if ((err = s_mp_to_fixed_bin(b, bin_b, len_b, sizeof(bin_b))) != CRYPT_OK) { goto error; }

      /* base point - (un)compressed based on flag_com */
      len_g = sizeof(bin_g);
      err = ltc_ecc_export_point(bin_g, &len_g, gx, gy, key->dp.size, flag_com);
      if (err != CRYPT_OK)                                         { goto error; }

      /* we support only prime-field EC */
      if ((err = pk_get_oid(LTC_OID_EC_PRIMEF, &OID)) != CRYPT_OK) { goto error; }

      /* http://tools.ietf.org/html/rfc3279
         ECParameters ::= SEQUENCE {                              # SEQUENCE
           version         INTEGER { ecpVer1(1) } (ecpVer1)       # INTEGER       :01
           FieldID ::= SEQUENCE {                                 # SEQUENCE
             fieldType       FIELD-ID.&id({IOSet}),               # OBJECT        :prime-field
             parameters      FIELD-ID.&Type({IOSet}{@fieldType})  # INTEGER
           }
           Curve ::= SEQUENCE {                                   # SEQUENCE
             a               FieldElement ::= OCTET STRING        # OCTET STRING
             b               FieldElement ::= OCTET STRING        # OCTET STRING
             seed            BIT STRING      OPTIONAL
           }
           base            ECPoint ::= OCTET STRING               # OCTET STRING
           order           INTEGER,                               # INTEGER
           cofactor        INTEGER OPTIONAL                       # INTEGER
         }
      */

      oidlen = LTC_ARRAY_SIZE(oid);
      if ((err = pk_oid_str_to_num(OID, oid, &oidlen)) != CRYPT_OK) {
         goto error;
      }

      /* FieldID SEQUENCE */
      LTC_SET_ASN1(seq_fieldid,  0, LTC_ASN1_OBJECT_IDENTIFIER, oid,         oidlen);
      LTC_SET_ASN1(seq_fieldid,  1, LTC_ASN1_INTEGER,           prime,       1UL);

      /* Curve SEQUENCE */
      LTC_SET_ASN1(seq_curve,    0, LTC_ASN1_OCTET_STRING,      bin_a,       len_a);
      LTC_SET_ASN1(seq_curve,    1, LTC_ASN1_OCTET_STRING,      bin_b,       len_b);

      /* ECParameters SEQUENCE */
      LTC_SET_ASN1(seq_ecparams, 0, LTC_ASN1_SHORT_INTEGER,     &one,        1UL);
      LTC_SET_ASN1(seq_ecparams, 1, LTC_ASN1_SEQUENCE,          seq_fieldid, 2UL);
      LTC_SET_ASN1(seq_ecparams, 2, LTC_ASN1_SEQUENCE,          seq_curve,   2UL);
      LTC_SET_ASN1(seq_ecparams, 3, LTC_ASN1_OCTET_STRING,      bin_g,       len_g);
      LTC_SET_ASN1(seq_ecparams, 4, LTC_ASN1_INTEGER,           order,       1UL);
      LTC_SET_ASN1(seq_ecparams, 5, LTC_ASN1_SHORT_INTEGER,     &cofactor,   1UL);

      /* ECParameters used by ECPrivateKey or SubjectPublicKeyInfo below */
      LTC_SET_ASN1(&ecparams,    0, LTC_ASN1_SEQUENCE, seq_ecparams, 6UL);
   }

   /* public key - (un)compressed based on flag_com */
   len_xy = sizeof(bin_xy);
   err = ltc_ecc_export_point(bin_xy, &len_xy, key->pubkey.x, key->pubkey.y, key->dp.size, flag_com);
   if (err != CRYPT_OK) {
      goto error;
   }

   if (flag_pri) {

      /* http://tools.ietf.org/html/rfc5915
         ECPrivateKey ::= SEQUENCE {                                    # SEQUENCE
           version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1)  # INTEGER       :01
           privateKey     OCTET STRING,                                 # OCTET STRING
           [0] ECParameters                                             # see above
           [1] publicKey                                                # BIT STRING
         }
      */

      /* private key - RFC 5915: an octet string as long as the order of the curve, so a short k gets leading zeros */
      len_k = ltc_mp_unsigned_bin_size(key->dp.order);
      if ((err = s_mp_to_fixed_bin(key->k, bin_k, len_k, sizeof(bin_k))) != CRYPT_OK) { goto error; }

      LTC_SET_ASN1(&pub_xy,  0, LTC_ASN1_RAW_BIT_STRING, bin_xy, 8*len_xy);
      LTC_SET_ASN1(seq_priv, 0, LTC_ASN1_SHORT_INTEGER,  &one,   1);
      LTC_SET_ASN1(seq_priv, 1, LTC_ASN1_OCTET_STRING,   bin_k,  len_k);
      if (pkcs8) {
         /* PrivateKeyInfo has the ECParameters in its AlgorithmIdentifier, so the ECPrivateKey inside does not repeat them */
         LTC_SET_ASN1_CUSTOM_CONSTRUCTED(seq_priv, 2, LTC_ASN1_CL_CONTEXT_SPECIFIC, 1, &pub_xy);   /* context specific 1 */
         len_p8 = sizeof(bin_p8);
         if ((err = der_encode_sequence(seq_priv, 3, bin_p8, &len_p8)) == CRYPT_OK) {
            err = pkcs8_encode(out, outlen, LTC_OID_EC, ecparams.type, ecparams.data, ecparams.size, bin_p8, len_p8);
         }
         zeromem(bin_p8, sizeof(bin_p8));
      }
      else {
         LTC_SET_ASN1_CUSTOM_CONSTRUCTED(seq_priv, 2, LTC_ASN1_CL_CONTEXT_SPECIFIC, 0, &ecparams); /* context specific 0 */
         LTC_SET_ASN1_CUSTOM_CONSTRUCTED(seq_priv, 3, LTC_ASN1_CL_CONTEXT_SPECIFIC, 1, &pub_xy);   /* context specific 1 */

         err = der_encode_sequence(seq_priv, 4, out, outlen);
      }
      zeromem(bin_k, sizeof(bin_k));
   }
   else {
      /* http://tools.ietf.org/html/rfc5480
         SubjectPublicKeyInfo ::= SEQUENCE  {                           # SEQUENCE
           AlgorithmIdentifier ::= SEQUENCE  {                          # SEQUENCE
             algorithm OBJECT IDENTIFIER                                # OBJECT        :id-ecPublicKey
             ECParameters                                               # see above
           }
           subjectPublicKey  BIT STRING                                 # BIT STRING
         }
      */
      err = x509_encode_subject_public_key_info( out, outlen, LTC_OID_EC, bin_xy, len_xy,
                                                 ecparams.type, ecparams.data, ecparams.size );
   }

error:
   return err;
}

/**
  Export an ECC key as a binary packet
  @param out     [out] Destination for the key
  @param outlen  [in/out] Max size and resulting size of the exported key
  @param type    The type of key you want to export (PK_PRIVATE or PK_PUBLIC)
  @param key     The key to export
  @return CRYPT_OK if successful
*/
int ecc_export_openssl(unsigned char *out, unsigned long *outlen, int type, const ecc_key *key)
{
   return s_ecc_export(out, outlen, type, key, 0);
}

/**
  Export a private ECC key as PKCS#8 PrivateKeyInfo
  @param out     [out] Destination for the key
  @param outlen  [in/out] Max size and resulting size of the exported key
  @param type    PK_CURVEOID and/or PK_COMPRESSED, 0 writes explicit curve parameters and an uncompressed public key
  @param key     The key to export
  @return CRYPT_OK if successful
*/
int ecc_export_pkcs8(unsigned char *out, unsigned long *outlen, int type, const ecc_key *key)
{
   return s_ecc_export(out, outlen, type | PK_PRIVATE, key, 1);
}

#endif
