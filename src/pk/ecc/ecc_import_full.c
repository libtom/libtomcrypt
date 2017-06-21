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

int ecc_import_full(const unsigned char *in, unsigned long inlen, ecc_key *key, ltc_ecc_set_type *dp)
{
  void *prime, *order, *a, *b, *gx, *gy;
  ltc_asn1_list seq_fieldid[2], seq_curve[3], seq_ecparams[6], seq_priv[4];
  unsigned char bin_a[ECC_MAXSIZE], bin_b[ECC_MAXSIZE], bin_k[ECC_MAXSIZE], bin_g[2*ECC_MAXSIZE+1], bin_xy[2*ECC_MAXSIZE+2], bin_seed[128];
  unsigned long len_a, len_b, len_k, len_g, len_xy, len_oid;
  unsigned long cofactor = 0, ecver = 0, pkver = 0, tmpoid[16], curveoid[16];
  int err;

  if ((err = mp_init_multi(&prime, &order, &a, &b, &gx, &gy, NULL)) != CRYPT_OK)       return err;

  /* ### 1. try to load public key - no curve parameters just curve OID */

  len_xy = sizeof(bin_xy);
  err = der_decode_subject_public_key_info_ex(in, inlen, PKA_EC, bin_xy, &len_xy, LTC_ASN1_OBJECT_IDENTIFIER, curveoid, 16UL, &len_oid);
  if (err == CRYPT_OK) {
    /* load curve parameters for given curve OID */
    dp = ecc_dp_find_by_oid(curveoid, len_oid);
    if (dp == NULL)                                                  { goto error; }
    /* load public key */
    if ((err = ecc_import_raw(bin_xy, len_xy, key, dp)) != CRYPT_OK) { goto error; }
    goto success;
  }

  /* ### 2. try to load public key - curve parameters included */

  /* ECParameters SEQUENCE */
  LTC_SET_ASN1(seq_ecparams, 0, LTC_ASN1_SHORT_INTEGER,     &ecver,       1UL);
  LTC_SET_ASN1(seq_ecparams, 1, LTC_ASN1_SEQUENCE,          seq_fieldid,  2UL);
  LTC_SET_ASN1(seq_ecparams, 2, LTC_ASN1_SEQUENCE,          seq_curve,    3UL);
  LTC_SET_ASN1(seq_ecparams, 3, LTC_ASN1_OCTET_STRING,      bin_g,        (unsigned long)2*ECC_MAXSIZE+1);
  LTC_SET_ASN1(seq_ecparams, 4, LTC_ASN1_INTEGER,           order,        1UL);
  LTC_SET_ASN1(seq_ecparams, 5, LTC_ASN1_SHORT_INTEGER,     &cofactor,    1UL);
  seq_ecparams[5].optional = 1;
  /* FieldID SEQUENCE */
  LTC_SET_ASN1(seq_fieldid,  0, LTC_ASN1_OBJECT_IDENTIFIER, tmpoid,       16UL);
  LTC_SET_ASN1(seq_fieldid,  1, LTC_ASN1_INTEGER,           prime,        1UL);
  /* Curve SEQUENCE */
  LTC_SET_ASN1(seq_curve,    0, LTC_ASN1_OCTET_STRING,      bin_a,        (unsigned long)ECC_MAXSIZE);
  LTC_SET_ASN1(seq_curve,    1, LTC_ASN1_OCTET_STRING,      bin_b,        (unsigned long)ECC_MAXSIZE);
  LTC_SET_ASN1(seq_curve,    2, LTC_ASN1_RAW_BIT_STRING,    bin_seed,     (unsigned long)8*128);
  seq_curve[2].optional = 1;
  /* try to load public key */
  len_xy = sizeof(bin_xy);
  err = der_decode_subject_public_key_info(in, inlen, PKA_EC, bin_xy, &len_xy, LTC_ASN1_SEQUENCE, seq_ecparams, 6);

  if (err == CRYPT_OK) {
    len_a = seq_curve[0].size;
    len_b = seq_curve[1].size;
    len_g = seq_ecparams[3].size;
    /* create bignums */
    if ((err = mp_read_unsigned_bin(a, bin_a, len_a)) != CRYPT_OK)                   { goto error; }
    if ((err = mp_read_unsigned_bin(b, bin_b, len_b)) != CRYPT_OK)                   { goto error; }
    if ((err = ltc_ecc_import_point(bin_g, len_g, prime, a, b, gx, gy)) != CRYPT_OK) { goto error; }
    /* load curve parameters */
    if ((err = ecc_dp_alloc_bn(dp, a, b, prime, order, gx, gy, cofactor)) != CRYPT_OK) { goto error; }
    /* load public key */
    if ((err = ecc_import_raw(bin_xy, len_xy, key, dp)) != CRYPT_OK)                 { goto error; }
    goto success;
  }

  /* ### 3. try to load private key - no curve parameters just curve OID */

  /* ECPrivateKey SEQUENCE */
  LTC_SET_ASN1(seq_priv,     0, LTC_ASN1_SHORT_INTEGER,     &pkver,       1UL);
  LTC_SET_ASN1(seq_priv,     1, LTC_ASN1_OCTET_STRING,      bin_k,        (unsigned long)ECC_MAXSIZE);
  LTC_SET_ASN1(seq_priv,     2, LTC_ASN1_OBJECT_IDENTIFIER, curveoid,     16UL);
  LTC_SET_ASN1(seq_priv,     3, LTC_ASN1_RAW_BIT_STRING,    bin_xy,       (unsigned long)8*(2*ECC_MAXSIZE+2));
  seq_priv[2].tag = 0xA0; /* context specific 0 */
  seq_priv[3].tag = 0xA1; /* context specific 1 */
  /* try to load private key */
  err = der_decode_sequence(in, inlen, seq_priv, 4);

  if (err == CRYPT_OK) {
    /* load curve parameters for given curve OID */
    dp = ecc_dp_find_by_oid(curveoid, seq_priv[2].size);
    if (dp == NULL)                                                           { goto error; }
    /* load private+public key */
    if ((err = ecc_import_raw(bin_k, seq_priv[1].size, key, dp)) != CRYPT_OK) { goto error; }
    goto success;
  }

  /* ### 4. try to load private key - curve parameters included */

  /* ECPrivateKey SEQUENCE */
  LTC_SET_ASN1(seq_priv,     0, LTC_ASN1_SHORT_INTEGER,     &pkver,       1UL);
  LTC_SET_ASN1(seq_priv,     1, LTC_ASN1_OCTET_STRING,      bin_k,        (unsigned long)ECC_MAXSIZE);
  LTC_SET_ASN1(seq_priv,     2, LTC_ASN1_SEQUENCE,          seq_ecparams, 6UL);
  LTC_SET_ASN1(seq_priv,     3, LTC_ASN1_RAW_BIT_STRING,    bin_xy,       (unsigned long)8*(2*ECC_MAXSIZE+2));
  seq_priv[2].tag = 0xA0; /* context specific 0 */
  seq_priv[3].tag = 0xA1; /* context specific 1 */
  /* ECParameters SEQUENCE */
  LTC_SET_ASN1(seq_ecparams, 0, LTC_ASN1_SHORT_INTEGER,     &ecver,       1UL);
  LTC_SET_ASN1(seq_ecparams, 1, LTC_ASN1_SEQUENCE,          seq_fieldid,  2UL);
  LTC_SET_ASN1(seq_ecparams, 2, LTC_ASN1_SEQUENCE,          seq_curve,    3UL);
  LTC_SET_ASN1(seq_ecparams, 3, LTC_ASN1_OCTET_STRING,      bin_g,        (unsigned long)2*ECC_MAXSIZE+1);
  LTC_SET_ASN1(seq_ecparams, 4, LTC_ASN1_INTEGER,           order,        1UL);
  LTC_SET_ASN1(seq_ecparams, 5, LTC_ASN1_SHORT_INTEGER,     &cofactor,    1UL);
  seq_ecparams[5].optional = 1;
  /* FieldID SEQUENCE */
  LTC_SET_ASN1(seq_fieldid,  0, LTC_ASN1_OBJECT_IDENTIFIER, tmpoid,       16UL);
  LTC_SET_ASN1(seq_fieldid,  1, LTC_ASN1_INTEGER,           prime,        1UL);
  /* Curve SEQUENCE */
  LTC_SET_ASN1(seq_curve,    0, LTC_ASN1_OCTET_STRING,      bin_a,        (unsigned long)ECC_MAXSIZE);
  LTC_SET_ASN1(seq_curve,    1, LTC_ASN1_OCTET_STRING,      bin_b,        (unsigned long)ECC_MAXSIZE);
  LTC_SET_ASN1(seq_curve,    2, LTC_ASN1_RAW_BIT_STRING,    bin_seed,     (unsigned long)8*128);
  seq_curve[2].optional = 1;
  /* try to load private key */
  err = der_decode_sequence(in, inlen, seq_priv, 4);
  if (err == CRYPT_OK) {
    len_k  = seq_priv[1].size;
    len_xy = seq_priv[3].size;
    len_a  = seq_curve[0].size;
    len_b  = seq_curve[1].size;
    len_g  = seq_ecparams[3].size;
    /* create bignums */
    if ((err = mp_read_unsigned_bin(a, bin_a, len_a)) != CRYPT_OK)                   { goto error; }
    if ((err = mp_read_unsigned_bin(b, bin_b, len_b)) != CRYPT_OK)                   { goto error; }
    if ((err = ltc_ecc_import_point(bin_g, len_g, prime, a, b, gx, gy)) != CRYPT_OK) { goto error; }
    /* load curve parameters */
    if ((err = ecc_dp_alloc_bn(dp, a, b, prime, order, gx, gy, cofactor)) != CRYPT_OK) { goto error; }
    /* load private+public key */
    if ((err = ecc_import_raw(bin_k, len_k, key, dp)) != CRYPT_OK)                   { goto error; }
    goto success;
  }

  /* ### 5. backward compatibility - try to load old-DER format */
  if ((err = ecc_import(in, inlen, key)) != CRYPT_OK)                                { goto error; }

success:
  err = CRYPT_OK;
error:
  mp_clear_multi(prime, order, a, b, gx, gy, NULL);
  return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
