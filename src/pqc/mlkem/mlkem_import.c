/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file mlkem_import.c
  Import a ML-KEM key from a SubjectPublicKeyInfo
*/

#if defined(LTC_MLKEM) && defined(LTC_DER)

typedef struct {
   enum ltc_oid_id oid;
   int alg;
} mlkem_oid_map;

static const mlkem_oid_map s_mlkem_oid_map[] = {
   { LTC_OID_MLKEM_512,  LTC_MLKEM_512  },
   { LTC_OID_MLKEM_768,  LTC_MLKEM_768  },
   { LTC_OID_MLKEM_1024, LTC_MLKEM_1024 },
};

/**
  Import a ML-KEM public key
  @param in     The packet to read
  @param inlen  The length of the input packet
  @param key    [out] Where to import the key to
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int mlkem_import(const unsigned char *in, unsigned long inlen, mlkem_key *key)
{
   unsigned char *pub;
   unsigned long pub_len, max_pub_len;
   unsigned long i;
   int err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   if (inlen == 0) return CRYPT_INVALID_PACKET;

   if ((err = mlkem_get_sizes(LTC_MLKEM_1024, &max_pub_len, NULL, NULL, NULL, NULL, NULL)) != CRYPT_OK) {
      return err;
   }

   pub = XMALLOC(max_pub_len);
   if (pub == NULL) {
      return CRYPT_MEM;
   }

   err = CRYPT_PK_INVALID_TYPE;
   for (i = 0; i < LTC_ARRAY_SIZE(s_mlkem_oid_map); ++i) {
      pub_len = max_pub_len;
      err = x509_decode_subject_public_key_info(in, inlen, s_mlkem_oid_map[i].oid,
                                                pub, &pub_len,
                                                LTC_ASN1_EOL, NULL, 0uL);
      if (err == CRYPT_OK) {
         err = mlkem_import_raw(pub, pub_len, PK_PUBLIC, s_mlkem_oid_map[i].alg, key);
         break;
      }
   }

   XFREE(pub);
   return err;
}

#endif
