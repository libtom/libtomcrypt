/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file slhdsa_import.c
  Import a SLH-DSA key from a SubjectPublicKeyInfo
*/

#if defined(LTC_SLHDSA) && defined(LTC_DER)

typedef struct {
   enum ltc_oid_id oid;
   int alg;
} slhdsa_oid_map;

static const slhdsa_oid_map s_slhdsa_oid_map[] = {
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

/**
  Import a SLH-DSA public key
  @param in     The packet to read
  @param inlen  The length of the input packet
  @param key    [out] Where to import the key to
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int slhdsa_import(const unsigned char *in, unsigned long inlen, slhdsa_key *key)
{
   unsigned char *pub;
   unsigned long max_pub_len, pub_len;
   unsigned long i;
   int err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   if (inlen == 0) return CRYPT_INVALID_PACKET;

   max_pub_len = 0;
   for (i = 0; i < LTC_ARRAY_SIZE(s_slhdsa_oid_map); ++i) {
      if ((err = slhdsa_get_sizes(s_slhdsa_oid_map[i].alg, &pub_len, NULL, NULL, NULL, NULL)) != CRYPT_OK) {
         return err;
      }
      if (pub_len > max_pub_len) {
         max_pub_len = pub_len;
      }
   }

   pub = XMALLOC(max_pub_len);
   if (pub == NULL) {
      return CRYPT_MEM;
   }

   err = CRYPT_PK_INVALID_TYPE;
   for (i = 0; i < LTC_ARRAY_SIZE(s_slhdsa_oid_map); ++i) {
      pub_len = max_pub_len;
      err = x509_decode_subject_public_key_info(in, inlen, s_slhdsa_oid_map[i].oid,
                                                pub, &pub_len,
                                                LTC_ASN1_EOL, NULL, 0uL);
      if (err == CRYPT_OK) {
         err = slhdsa_import_raw(pub, pub_len, PK_PUBLIC, s_slhdsa_oid_map[i].alg, key);
         break;
      }
   }

   XFREE(pub);
   return err;
}

#endif
