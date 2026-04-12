/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file mldsa_import_x509.c
  Import a ML-DSA key from a X.509 certificate
*/

#if defined(LTC_MLDSA) && defined(LTC_DER)

typedef struct {
   mldsa_key *key;
   int alg;
} mldsa_x509_ctx;

typedef struct {
   enum ltc_oid_id oid;
   int alg;
} mldsa_oid_map_x509;

static const mldsa_oid_map_x509 s_mldsa_oid_map_x509[] = {
   { LTC_OID_MLDSA_44, LTC_MLDSA_44 },
   { LTC_OID_MLDSA_65, LTC_MLDSA_65 },
   { LTC_OID_MLDSA_87, LTC_MLDSA_87 },
};

static int s_mldsa_decode(const unsigned char *in, unsigned long inlen, mldsa_x509_ctx *ctx)
{
   return mldsa_import_raw(in, inlen, PK_PUBLIC, ctx->alg, ctx->key);
}

/**
  Import a ML-DSA public key from a X.509 certificate
  @param in     The DER encoded X.509 certificate
  @param inlen  The length of the certificate
  @param key    [out] Where to import the key to
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int mldsa_import_x509(const unsigned char *in, unsigned long inlen, mldsa_key *key)
{
   mldsa_x509_ctx ctx;
   ltc_asn1_list *decoded_list;
   const ltc_asn1_list *spki;
   unsigned long i;
   int err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   if (inlen == 0) return CRYPT_INVALID_PACKET;

   /* decode the certificate once, the parameter set is then resolved on the SubjectPublicKeyInfo */
   if ((err = x509_decode_spki(in, inlen, &decoded_list, &spki)) != CRYPT_OK) {
      return err;
   }

   err = CRYPT_PK_INVALID_TYPE;
   for (i = 0; i < LTC_ARRAY_SIZE(s_mldsa_oid_map_x509); ++i) {
      ctx.key = key;
      ctx.alg = s_mldsa_oid_map_x509[i].alg;
      err = x509_process_public_key_from_spki(spki->data, spki->size,
                                              s_mldsa_oid_map_x509[i].oid,
                                              LTC_ASN1_EOL, NULL, NULL,
                                              (public_key_decode_cb)s_mldsa_decode, &ctx);
      if (err == CRYPT_OK) {
         break;
      }
   }

   der_free_sequence_flexi(decoded_list);

   return err;
}

#endif
