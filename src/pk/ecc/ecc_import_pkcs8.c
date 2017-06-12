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

int ecc_import_pkcs8(const unsigned char *in,  unsigned long inlen,
                     const void *pwd, unsigned long pwdlen,
                     ecc_key *key, ltc_ecc_set_type *dp)
{
   int err;
   void           *zero, *one, *iter;
   unsigned char  *buf1=NULL, *buf2=NULL;
   unsigned long  buf1len, buf2len;
   unsigned long  oid[16];
   oid_st         ecoid;
   ltc_asn1_list  alg_seq[2], top_seq[3];
   ltc_asn1_list  alg_seq_e[2], key_seq_e[2], top_seq_e[2];
   unsigned char  *decrypted=NULL;
   unsigned long  decryptedlen;
   void *prime, *order, *a, *b, *gx, *gy;
   ltc_asn1_list seq_fieldid[2], seq_curve[3], seq_ecparams[6], seq_priv[4];
   unsigned char bin_a[ECC_MAXSIZE], bin_b[ECC_MAXSIZE], bin_k[ECC_MAXSIZE], bin_g[2*ECC_MAXSIZE+1], bin_xy[2*ECC_MAXSIZE+2], bin_seed[128];
   unsigned long len_a, len_b, len_g;
   unsigned long cofactor = 0, ecver = 0, tmpoid[16], curveoid[16];

   LTC_ARGCHK(in          != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* get EC alg oid */
   err = pk_get_oid(PKA_EC, &ecoid);
   if (err != CRYPT_OK) { goto LBL_NOFREE; }

   /* alloc buffers */
   buf1len = inlen; /* approx. guess */
   buf1 = XMALLOC(buf1len);
   if (buf1 == NULL) { err = CRYPT_MEM; goto LBL_NOFREE; }
   buf2len = inlen; /* approx. guess */
   buf2 = XMALLOC(buf2len);
   if (buf2 == NULL) { err = CRYPT_MEM; goto LBL_FREE; }

   /* init key */
   err = mp_init_multi(&prime, &order, &a, &b, &gx, &gy, &zero, &one, &iter, NULL);
   if (err != CRYPT_OK) { goto LBL_NOCLEAR; }

   /* try to decode encrypted priv key */
   LTC_SET_ASN1(key_seq_e, 0, LTC_ASN1_OCTET_STRING, buf1, buf1len);
   LTC_SET_ASN1(key_seq_e, 1, LTC_ASN1_INTEGER, iter, 1UL);
   LTC_SET_ASN1(alg_seq_e, 0, LTC_ASN1_OBJECT_IDENTIFIER, oid, 16UL);
   LTC_SET_ASN1(alg_seq_e, 1, LTC_ASN1_SEQUENCE, key_seq_e, 2UL);
   LTC_SET_ASN1(top_seq_e, 0, LTC_ASN1_SEQUENCE, alg_seq_e, 2UL);
   LTC_SET_ASN1(top_seq_e, 1, LTC_ASN1_OCTET_STRING, buf2, buf2len);
   err=der_decode_sequence(in, inlen, top_seq_e, 2UL);
   if (err == CRYPT_OK) {
      LTC_UNUSED_PARAM(pwd);
      LTC_UNUSED_PARAM(pwdlen);
      /* unsigned long icount = mp_get_int(iter); */
      /* XXX: TODO decrypt buf1 with a key derived form password + salt + iter */
      /* fprintf(stderr, "XXX-DEBUG: gonna decrypt: iter=%ld salt.len=%ld encdata.len=%ld\n", icount, key_seq_e[0].size, top_seq_e[1].size); */
      err = CRYPT_PK_INVALID_TYPE;
      goto LBL_ERR;
   }
   else {
      decrypted = (unsigned char*)in;
      decryptedlen = inlen;
   }

   /* try to decode unencrypted priv key - curve defined by OID */
   LTC_SET_ASN1(alg_seq, 0, LTC_ASN1_OBJECT_IDENTIFIER, oid, 16UL);
   LTC_SET_ASN1(alg_seq, 1, LTC_ASN1_OBJECT_IDENTIFIER, curveoid, 16UL);
   LTC_SET_ASN1(top_seq, 0, LTC_ASN1_INTEGER, zero, 1UL);
   LTC_SET_ASN1(top_seq, 1, LTC_ASN1_SEQUENCE, alg_seq, 2UL);
   LTC_SET_ASN1(top_seq, 2, LTC_ASN1_OCTET_STRING, buf1, buf1len);
   err=der_decode_sequence(decrypted, decryptedlen, top_seq, 3UL);
   if (err == CRYPT_OK) {
      /* load curve parameters for given curve OID */
      err = ecc_dp_set_by_oid(dp, curveoid, alg_seq[1].size);
      if (err != CRYPT_OK) { goto LBL_ERR; }
   }
   else {
      /* try to decode unencrypted priv key - curve defined by params */
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
      /* */
      LTC_SET_ASN1(alg_seq,      0, LTC_ASN1_OBJECT_IDENTIFIER, oid,          16UL);
      LTC_SET_ASN1(alg_seq,      1, LTC_ASN1_SEQUENCE,          seq_ecparams, 6UL);
      LTC_SET_ASN1(top_seq,      0, LTC_ASN1_INTEGER,           zero,         1UL);
      LTC_SET_ASN1(top_seq,      1, LTC_ASN1_SEQUENCE,          alg_seq,      2UL);
      LTC_SET_ASN1(top_seq,      2, LTC_ASN1_OCTET_STRING,      buf1,         buf1len);
      seq_curve[2].optional = 1;
      err=der_decode_sequence(decrypted, decryptedlen, top_seq, 3UL);
      if (err != CRYPT_OK) { goto LBL_ERR; }
      len_a  = seq_curve[0].size;
      len_b  = seq_curve[1].size;
      len_g  = seq_ecparams[3].size;
      /* create bignums */
      if ((err = mp_read_unsigned_bin(a, bin_a, len_a)) != CRYPT_OK)                   { goto LBL_ERR; }
      if ((err = mp_read_unsigned_bin(b, bin_b, len_b)) != CRYPT_OK)                   { goto LBL_ERR; }
      if ((err = ltc_ecc_import_point(bin_g, len_g, prime, a, b, gx, gy)) != CRYPT_OK) { goto LBL_ERR; }
      /* load curve parameters */
      if ((err = ecc_dp_set_bn(dp, a, b, prime, order, gx, gy, cofactor)) != CRYPT_OK) { goto LBL_ERR; }
   }

   /* check alg oid */
   if ((alg_seq[0].size != ecoid.OIDlen) ||
      XMEMCMP(ecoid.OID, alg_seq[0].data, ecoid.OIDlen * sizeof(ecoid.OID[0]))) {
      err = CRYPT_PK_INVALID_TYPE;
      goto LBL_ERR;
   }

   /* ECPrivateKey SEQUENCE */
   LTC_SET_ASN1(seq_priv, 0, LTC_ASN1_SHORT_INTEGER,  &one,   1UL);
   LTC_SET_ASN1(seq_priv, 1, LTC_ASN1_OCTET_STRING,   bin_k,  (unsigned long)ECC_MAXSIZE);
   LTC_SET_ASN1(seq_priv, 2, LTC_ASN1_RAW_BIT_STRING, bin_xy, (unsigned long)8*(2*ECC_MAXSIZE+2));
   seq_priv[2].tag = 0xA1; /* context specific 1 */
   /* try to load private key */
   err = der_decode_sequence(buf1, top_seq[2].size, seq_priv, 3);
   if (err != CRYPT_OK) { goto LBL_ERR; }
   /* load private+public key */
   if ((err = ecc_import_raw(bin_k, seq_priv[1].size, key, dp)) != CRYPT_OK) { goto LBL_ERR; }
   /* success */
   return err;

LBL_ERR:
   mp_clear_multi(prime, order, a, b, gx, gy, NULL);
LBL_NOCLEAR:
   XFREE(buf2);
LBL_FREE:
   XFREE(buf1);
LBL_NOFREE:
   return err;
}

#endif
