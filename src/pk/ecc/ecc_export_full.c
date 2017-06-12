/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_MECC

/**
  Export an ECC key as a binary packet
  @param out     [out] Destination for the key
  @param outlen  [in/out] Max size and resulting size of the exported key
  @param type    The type of key you want to export (PK_PRIVATE or PK_PUBLIC)
  @param key     The key to export
  @return CRYPT_OK if successful
*/

int ecc_export_full(unsigned char *out, unsigned long *outlen, int type, ecc_key *key)
{
  int           err;
  void *prime, *order, *a, *b, *gx, *gy;
  unsigned char bin_a[256], bin_b[256], bin_k[256], bin_g[512], bin_xy[512];
  unsigned long len_a, len_b, len_k, len_g, len_xy;
  unsigned long cofactor, one = 1;
  oid_st oid;
  ltc_asn1_list seq_fieldid[2], seq_curve[2], seq_ecparams[6], seq_priv[4], asn_ecparams[1];

  LTC_ARGCHK(out    != NULL);
  LTC_ARGCHK(outlen != NULL);
  LTC_ARGCHK(key    != NULL);

  if (key->type != PK_PRIVATE && type == PK_PRIVATE)                                   return CRYPT_PK_TYPE_MISMATCH;
  if (ltc_ecc_is_valid_idx(key->idx) == 0)                                             return CRYPT_INVALID_ARG;
  if (key->dp == NULL)                                                                 return CRYPT_INVALID_ARG;

  if ((err = mp_init_multi(&prime, &order, &a, &b, &gx, &gy, NULL)) != CRYPT_OK)       return err;

  if ((err = mp_read_radix(prime, key->dp->prime, 16)) != CRYPT_OK)                    goto error;
  if ((err = mp_read_radix(order, key->dp->order, 16)) != CRYPT_OK)                    goto error;
  if ((err = mp_read_radix(b, key->dp->B, 16)) != CRYPT_OK)                            goto error;
  if ((err = mp_read_radix(a, key->dp->A, 16)) != CRYPT_OK)                            goto error;
  if ((err = mp_read_radix(gx, key->dp->Gx, 16)) != CRYPT_OK)                          goto error;
  if ((err = mp_read_radix(gy, key->dp->Gy, 16)) != CRYPT_OK)                          goto error;

  /* curve param a */
  len_a = mp_unsigned_bin_size(a);
  if (len_a > sizeof(bin_a))                                                           { err = CRYPT_BUFFER_OVERFLOW; goto error; }
  if ((err = mp_to_unsigned_bin(a, bin_a)) != CRYPT_OK)                                goto error;
  if (len_a == 0) { len_a = 1; bin_a[0] = 0; } /* XXX-TODO hack to handle case a == 0 */

  /* curve param b */
  len_b = mp_unsigned_bin_size(b);
  if (len_b > sizeof(bin_b))                                                           { err = CRYPT_BUFFER_OVERFLOW; goto error; }
  if ((err = mp_to_unsigned_bin(b, bin_b)) != CRYPT_OK)                                goto error;
  if (len_b == 0) { len_b = 1; bin_b[0] = 0; } /* XXX-TODO hack to handle case b == 0 */

  /* base point - we export uncompressed form */
  len_g = sizeof(bin_g);
  if ((err = ltc_ecc_export_point(bin_g, &len_g, gx, gy, key->dp->size, 0)) != CRYPT_OK) goto error;

  /* public key */
  len_xy = sizeof(bin_xy);
  if ((err = ltc_ecc_export_point(bin_xy, &len_xy, key->pubkey.x, key->pubkey.y, key->dp->size, 0)) != CRYPT_OK) goto error;

  /* co-factor */
  cofactor = key->dp->cofactor;

  /* we support only prime-field EC */
  if ((err = pk_get_oid(EC_PRIME_FIELD, &oid)) != CRYPT_OK)                            goto error;

  if (type & PK_CURVEOID) {
      /* from http://tools.ietf.org/html/rfc5912

          ECParameters ::= CHOICE {
               namedCurve      CURVE.&id({NamedCurve})                # OBJECT
          }
      */

      /* BEWARE: exporting PK_CURVEOID with custom OID means we're unable to read the curve again */
      if (key->dp->oid.OIDlen == 0) { err = CRYPT_INVALID_ARG; goto error; }

      /* ECParameters used by ECPrivateKey or SubjectPublicKeyInfo below */
      LTC_SET_ASN1(asn_ecparams, 0, LTC_ASN1_OBJECT_IDENTIFIER, key->dp->oid.OID, key->dp->oid.OIDlen);
      type &= ~PK_CURVEOID;
  }
  else {
      /* from http://tools.ietf.org/html/rfc3279

          ECParameters ::= SEQUENCE {                                   # SEQUENCE
               version         INTEGER { ecpVer1(1) } (ecpVer1),        # INTEGER       :01
               FieldID ::= SEQUENCE {                                   # SEQUENCE
                   fieldType       FIELD-ID.&id({IOSet}),               # OBJECT        :prime-field
                   parameters      FIELD-ID.&Type({IOSet}{@fieldType})  # INTEGER
               }
               Curve ::= SEQUENCE {                                     # SEQUENCE
                   a               FieldElement ::= OCTET STRING        # OCTET STRING
                   b               FieldElement ::= OCTET STRING        # OCTET STRING
                   seed            BIT STRING      OPTIONAL
               }
               base            ECPoint ::= OCTET STRING                 # OCTET STRING
               order           INTEGER,                                 # INTEGER
               cofactor        INTEGER OPTIONAL                         # INTEGER
          }
      */

      /* FieldID SEQUENCE */
      LTC_SET_ASN1(seq_fieldid,  0, LTC_ASN1_OBJECT_IDENTIFIER, oid.OID,     oid.OIDlen);
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
      LTC_SET_ASN1(asn_ecparams, 0, LTC_ASN1_SEQUENCE, seq_ecparams, 6UL);
  }

  if (type == PK_PRIVATE) {
      /* private key format: http://tools.ietf.org/html/rfc5915

          ECPrivateKey ::= SEQUENCE {                                    # SEQUENCE
           version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),  # INTEGER       :01
           privateKey     OCTET STRING,                                  # OCTET STRING
           [0] ECParameters                                              # see above
           [1] publicKey                                                 # BIT STRING
          }
      */

      /* private key */
      len_k = mp_unsigned_bin_size(key->k);
      if (len_k > sizeof(bin_k))                                                       { err = CRYPT_BUFFER_OVERFLOW; goto error; }
      if ((err = mp_to_unsigned_bin(key->k, bin_k)) != CRYPT_OK)                       goto error;

      LTC_SET_ASN1(seq_priv, 0, LTC_ASN1_SHORT_INTEGER,   &one,                 1UL);
      LTC_SET_ASN1(seq_priv, 1, LTC_ASN1_OCTET_STRING,    bin_k,                len_k);
      LTC_SET_ASN1(seq_priv, 2, asn_ecparams[0].type,     asn_ecparams[0].data, asn_ecparams[0].size);
      LTC_SET_ASN1(seq_priv, 3, LTC_ASN1_RAW_BIT_STRING,  bin_xy,               8*len_xy);
      seq_priv[2].tag = 0xA0;
      seq_priv[3].tag = 0xA1;

      err = der_encode_sequence(seq_priv, 4, out, outlen);
  }
  else {
      /* public key format: http://tools.ietf.org/html/rfc5480

          SubjectPublicKeyInfo ::= SEQUENCE  {                           # SEQUENCE
            AlgorithmIdentifier ::= SEQUENCE  {                          # SEQUENCE
              algorithm OBJECT IDENTIFIER                                # OBJECT        :id-ecPublicKey
              ECParameters                                               # see above
            }
            subjectPublicKey  BIT STRING                                 # BIT STRING
          }
      */
      err = der_encode_subject_public_key_info( out, outlen,
                                                PKA_EC, bin_xy, len_xy,
                                                asn_ecparams[0].type, asn_ecparams[0].data, asn_ecparams[0].size );
  }

error:
  mp_clear_multi(prime, order, a, b, gx, gy, NULL);
  return err;
}

#endif
