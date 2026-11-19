/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

void pka_key_destroy(ltc_pka_key **key)
{
   LTC_ARGCHKVD(key != NULL);

   if (!*key)
      return;

   pka_key_free(*key);
   zeromem(*key, sizeof(**key));
   XFREE(*key);
   *key = NULL;
}

void pka_key_free(ltc_pka_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   switch (key->id) {
      case LTC_PKA_DH:
#if defined(LTC_MDH)
         dh_free(&key->u.dh);
#endif
         break;
      case LTC_PKA_DSA:
#if defined(LTC_MDSA)
         dsa_free(&key->u.dsa);
#endif
         break;
      case LTC_PKA_RSA:
      case LTC_PKA_RSA_PSS:
#if defined(LTC_MRSA)
         rsa_free(&key->u.rsa);
#endif
         break;
      case LTC_PKA_EC:
#if defined(LTC_MECC)
         ecc_free(&key->u.ecc);
#endif
         break;
      default:
         break;
   }
}

#ifdef LTC_PKCS_8

#ifdef LTC_MRSA
static int s_rsa_export_pkcs8(unsigned char *out, unsigned long *outlen, const rsa_key *key)
{
   unsigned char *p1;
   unsigned long len = 0, p1len;
   int err;

   /* a too small buffer makes rsa_export() report the size of the RSAPrivateKey */
   if ((err = rsa_export(out, &len, PK_PRIVATE, key)) != CRYPT_BUFFER_OVERFLOW) return err == CRYPT_OK ? CRYPT_ERROR : err;
   if ((p1 = XMALLOC(len)) == NULL) return CRYPT_MEM;
   p1len = len;
   if ((err = rsa_export(p1, &p1len, PK_PRIVATE, key)) == CRYPT_OK) {
      err = pkcs8_encode(out, outlen, LTC_OID_RSA, LTC_ASN1_NULL, NULL, 0, p1, p1len);
   }
   zeromem(p1, len);
   XFREE(p1);
   return err;
}
#endif

#if defined(LTC_MDSA) || defined(LTC_MDH)
/* DSA and DH have the group in the AlgorithmIdentifier and the INTEGER x as private key */
static int s_dlog_export_pkcs8(unsigned char *out, unsigned long *outlen, enum ltc_oid_id id, int type,
                               ltc_asn1_list *params, unsigned long nparams, void *x)
{
   unsigned char *tmp;
   unsigned long len;
   int err;

   if (type != PK_PRIVATE) return CRYPT_PK_TYPE_MISMATCH;
   if ((err = der_length_integer(x, &len)) != CRYPT_OK) return err;
   if ((tmp = XMALLOC(len)) == NULL) return CRYPT_MEM;
   if ((err = der_encode_integer(x, tmp, &len)) == CRYPT_OK) {
      err = pkcs8_encode(out, outlen, id, LTC_ASN1_SEQUENCE, params, nparams, tmp, len);
   }
   zeromem(tmp, len);
   XFREE(tmp);
   return err;
}
#endif

/**
   Export a key in its standard format

   @param out     [out] The destination of the DER encoded key
   @param outlen  [in/out] The max size and resulting size of the output
   @param which   PK_PRIVATE|PK_STD for a PKCS#8 PrivateKeyInfo, PK_PUBLIC|PK_STD for a SubjectPublicKeyInfo
   @param key     The key to export
   @return CRYPT_OK on success, CRYPT_BUFFER_OVERFLOW with the required size in outlen if out is too small
*/
int pka_key_export(unsigned char *out, unsigned long *outlen, int which, const ltc_pka_key *key)
{
#if defined(LTC_MDSA) || defined(LTC_MDH)
   ltc_asn1_list params[3];
#endif
#ifdef LTC_MECC
   int curve;
#endif
   int priv = which & PK_PRIVATE;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   if (which != (PK_PRIVATE | PK_STD) && which != (PK_PUBLIC | PK_STD)) return CRYPT_INVALID_ARG;

   switch (key->id) {
#ifdef LTC_MRSA
      case LTC_PKA_RSA:
         /* a key restricted to PSS or OAEP needs its parameters in the AlgorithmIdentifier, which is not implemented */
         if (key->u.rsa.pss_oaep) return CRYPT_PK_INVALID_TYPE;
         return priv ? s_rsa_export_pkcs8(out, outlen, &key->u.rsa) : rsa_export(out, outlen, which, &key->u.rsa);
#endif
#ifdef LTC_MDSA
      case LTC_PKA_DSA:
         if (!priv) return dsa_export(out, outlen, which, &key->u.dsa);
         LTC_SET_ASN1(params, 0, LTC_ASN1_INTEGER, key->u.dsa.p, 1UL);
         LTC_SET_ASN1(params, 1, LTC_ASN1_INTEGER, key->u.dsa.q, 1UL);
         LTC_SET_ASN1(params, 2, LTC_ASN1_INTEGER, key->u.dsa.g, 1UL);
         return s_dlog_export_pkcs8(out, outlen, LTC_OID_DSA, key->u.dsa.type, params, 3, key->u.dsa.x);
#endif
#ifdef LTC_MDH
      case LTC_PKA_DH:
         /* no importer reads a DH SubjectPublicKeyInfo */
         if (!priv) return CRYPT_PK_INVALID_TYPE;
         LTC_SET_ASN1(params, 0, LTC_ASN1_INTEGER, key->u.dh.prime, 1UL);
         LTC_SET_ASN1(params, 1, LTC_ASN1_INTEGER, key->u.dh.base, 1UL);
         return s_dlog_export_pkcs8(out, outlen, LTC_OID_DH, key->u.dh.type, params, 2, key->u.dh.x);
#endif
#ifdef LTC_MECC
      case LTC_PKA_EC:
         /* explicit parameters only for a curve that has no OID */
         curve = key->u.ecc.dp.oidlen > 0 ? PK_CURVEOID : 0;
         return priv ? ecc_export_pkcs8(out, outlen, curve, &key->u.ecc) : ecc_export_openssl(out, outlen, PK_PUBLIC | curve, &key->u.ecc);
#endif
#ifdef LTC_CURVE25519
      case LTC_PKA_X25519:
         return x25519_export(out, outlen, which, &key->u.x25519);
      case LTC_PKA_ED25519:
         return ed25519_export(out, outlen, which, &key->u.ed25519);
#endif
#ifdef LTC_CURVE448
      case LTC_PKA_X448:
         return x448_export(out, outlen, which, &key->u.x448);
      case LTC_PKA_ED448:
         return ed448_export(out, outlen, which, &key->u.ed448);
#endif
      default:
         return CRYPT_PK_INVALID_TYPE;
   }
}

#endif /* LTC_PKCS_8 */
