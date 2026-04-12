/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file slhdsa_import_x509.c
  Import a SLH-DSA key from a X.509 certificate
*/

#if defined(LTC_SLHDSA) && defined(LTC_DER)

typedef struct {
   slhdsa_key *key;
   int alg;
} slhdsa_x509_ctx;

typedef struct {
   enum ltc_oid_id oid;
   int alg;
} slhdsa_oid_map_x509;

static const slhdsa_oid_map_x509 s_slhdsa_oid_map_x509[] = {
   { LTC_OID_SLHDSA_SHA2_128S,  LTC_SLHDSA_SHA2_128S  },
   { LTC_OID_SLHDSA_SHA2_128F,  LTC_SLHDSA_SHA2_128F  },
   { LTC_OID_SLHDSA_SHA2_192S,  LTC_SLHDSA_SHA2_192S  },
   { LTC_OID_SLHDSA_SHA2_192F,  LTC_SLHDSA_SHA2_192F  },
   { LTC_OID_SLHDSA_SHA2_256S,  LTC_SLHDSA_SHA2_256S  },
   { LTC_OID_SLHDSA_SHA2_256F,  LTC_SLHDSA_SHA2_256F  },
   { LTC_OID_SLHDSA_SHAKE_128S, LTC_SLHDSA_SHAKE_128S },
   { LTC_OID_SLHDSA_SHAKE_128F, LTC_SLHDSA_SHAKE_128F },
   { LTC_OID_SLHDSA_SHAKE_192S, LTC_SLHDSA_SHAKE_192S },
   { LTC_OID_SLHDSA_SHAKE_192F, LTC_SLHDSA_SHAKE_192F },
   { LTC_OID_SLHDSA_SHAKE_256S, LTC_SLHDSA_SHAKE_256S },
   { LTC_OID_SLHDSA_SHAKE_256F, LTC_SLHDSA_SHAKE_256F },
   { LTC_OID_HASH_SLHDSA_SHA2_128S_WITH_SHA256,    LTC_SLHDSA_HASH_SHA2_128S_WITH_SHA256 },
   { LTC_OID_HASH_SLHDSA_SHA2_128F_WITH_SHA256,    LTC_SLHDSA_HASH_SHA2_128F_WITH_SHA256 },
   { LTC_OID_HASH_SLHDSA_SHA2_192S_WITH_SHA512,    LTC_SLHDSA_HASH_SHA2_192S_WITH_SHA512 },
   { LTC_OID_HASH_SLHDSA_SHA2_192F_WITH_SHA512,    LTC_SLHDSA_HASH_SHA2_192F_WITH_SHA512 },
   { LTC_OID_HASH_SLHDSA_SHA2_256S_WITH_SHA512,    LTC_SLHDSA_HASH_SHA2_256S_WITH_SHA512 },
   { LTC_OID_HASH_SLHDSA_SHA2_256F_WITH_SHA512,    LTC_SLHDSA_HASH_SHA2_256F_WITH_SHA512 },
   { LTC_OID_HASH_SLHDSA_SHAKE_128S_WITH_SHAKE128, LTC_SLHDSA_HASH_SHAKE_128S_WITH_SHAKE128 },
   { LTC_OID_HASH_SLHDSA_SHAKE_128F_WITH_SHAKE128, LTC_SLHDSA_HASH_SHAKE_128F_WITH_SHAKE128 },
   { LTC_OID_HASH_SLHDSA_SHAKE_192S_WITH_SHAKE256, LTC_SLHDSA_HASH_SHAKE_192S_WITH_SHAKE256 },
   { LTC_OID_HASH_SLHDSA_SHAKE_192F_WITH_SHAKE256, LTC_SLHDSA_HASH_SHAKE_192F_WITH_SHAKE256 },
   { LTC_OID_HASH_SLHDSA_SHAKE_256S_WITH_SHAKE256, LTC_SLHDSA_HASH_SHAKE_256S_WITH_SHAKE256 },
   { LTC_OID_HASH_SLHDSA_SHAKE_256F_WITH_SHAKE256, LTC_SLHDSA_HASH_SHAKE_256F_WITH_SHAKE256 },
};

static int s_slhdsa_decode(const unsigned char *in, unsigned long inlen, slhdsa_x509_ctx *ctx)
{
   return slhdsa_import_raw(in, inlen, PK_PUBLIC, ctx->alg, ctx->key);
}

/**
  Import a SLH-DSA public key from a X.509 certificate
  @param in     The DER encoded X.509 certificate
  @param inlen  The length of the certificate
  @param key    [out] Where to import the key to
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int slhdsa_import_x509(const unsigned char *in, unsigned long inlen, slhdsa_key *key)
{
   slhdsa_x509_ctx ctx;
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
   for (i = 0; i < LTC_ARRAY_SIZE(s_slhdsa_oid_map_x509); ++i) {
      ctx.key = key;
      ctx.alg = s_slhdsa_oid_map_x509[i].alg;
      err = x509_process_public_key_from_spki(spki->data, spki->size,
                                              s_slhdsa_oid_map_x509[i].oid,
                                              LTC_ASN1_EOL, NULL, NULL,
                                              (public_key_decode_cb)s_slhdsa_decode, &ctx);
      if (err == CRYPT_OK) {
         break;
      }
   }

   der_free_sequence_flexi(decoded_list);

   return err;
}

#endif
