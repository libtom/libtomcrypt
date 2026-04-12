/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pqc_prehash.c
  Pre-hash functions shared by HashSLH-DSA (FIPS 205 10.3) and HashML-DSA (FIPS 204 5.4)
*/

#if defined(LTC_SLHDSA) || defined(LTC_MLDSA)

/* the SHA-2 pre-hashes are only there if they were compiled in, the SHAKE ones come with LTC_SHA3
   which both algorithms require anyway */
static const struct ltc_hash_descriptor* s_pqc_prehash_desc(int ph)
{
#ifdef LTC_SHA256
   if (ph == LTC_PQC_PH_SHA256) return &sha256_desc;
#endif
#ifdef LTC_SHA512
   if (ph == LTC_PQC_PH_SHA512) return &sha512_desc;
#endif
   LTC_UNUSED_PARAM(ph);
   return NULL;
}

/**
   INTERNAL ONLY, declared in tomcrypt_private.h

   Return the DER encoding of a pre-hash function's OID, tag and length included.
   @param ph       The pre-hash function (one of ltc_pqc_prehash)
   @param oid      [out] Pointer to a static DER blob, must not be freed by the caller
   @param oidlen   [out] Length of the DER blob
   @return CRYPT_OK if successful
*/
int pqc_prehash_oid_der(int ph, const unsigned char **oid, unsigned long *oidlen)
{
   static const unsigned char sha256_oid[]   = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
   static const unsigned char sha512_oid[]   = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
   static const unsigned char shake128_oid[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B };
   static const unsigned char shake256_oid[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C };

   LTC_ARGCHK(oid    != NULL);
   LTC_ARGCHK(oidlen != NULL);

   switch (ph) {
      case LTC_PQC_PH_SHA256:
         *oid = sha256_oid;
         *oidlen = sizeof(sha256_oid);
         return CRYPT_OK;
      case LTC_PQC_PH_SHA512:
         *oid = sha512_oid;
         *oidlen = sizeof(sha512_oid);
         return CRYPT_OK;
      case LTC_PQC_PH_SHAKE128:
         *oid = shake128_oid;
         *oidlen = sizeof(shake128_oid);
         return CRYPT_OK;
      case LTC_PQC_PH_SHAKE256:
         *oid = shake256_oid;
         *oidlen = sizeof(shake256_oid);
         return CRYPT_OK;
      default:
         return CRYPT_INVALID_ARG;
   }
}

/**
   INTERNAL ONLY, declared in tomcrypt_private.h

   Compute PH(M), the pre-hash of the message that goes into M'.
   The XOF output lengths are fixed by the standards, SHAKE128 gives 32 octets and SHAKE256 64.
   @param ph       The pre-hash function (one of ltc_pqc_prehash)
   @param msg      The message, may be NULL when msglen is 0
   @param msglen   Length of the message
   @param out      [out] Destination for PH(M)
   @param outlen   [in/out] Max size and resulting size of PH(M)
   @return CRYPT_OK if successful, CRYPT_INVALID_HASH if the pre-hash was not compiled in
*/
int pqc_prehash(int ph, const unsigned char *msg, unsigned long msglen,
                unsigned char *out, unsigned long *outlen)
{
   static const unsigned char empty_msg = 0;
   const struct ltc_hash_descriptor *desc;
   hash_state md;
   int err;

   LTC_ARGCHK(msg    != NULL || msglen == 0);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* the hashes reject a NULL pointer even for an empty input */
   if (msg == NULL) msg = &empty_msg;

   switch (ph) {
      case LTC_PQC_PH_SHA256:
      case LTC_PQC_PH_SHA512:
         desc = s_pqc_prehash_desc(ph);
         if (desc == NULL) return CRYPT_INVALID_HASH;
         if (*outlen < desc->hashsize) { *outlen = desc->hashsize; return CRYPT_BUFFER_OVERFLOW; }
         if ((err = desc->init(&md)) != CRYPT_OK) return err;
         if ((err = desc->process(&md, msg, msglen)) != CRYPT_OK) return err;
         if ((err = desc->done(&md, out)) != CRYPT_OK) return err;
         *outlen = desc->hashsize;
         return CRYPT_OK;
      case LTC_PQC_PH_SHAKE128:
         /* sha3_shake_memory() takes outlen as input only */
         if (*outlen < 32) return CRYPT_BUFFER_OVERFLOW;
         *outlen = 32;
         return sha3_shake_memory(128, msg, msglen, out, outlen);
      case LTC_PQC_PH_SHAKE256:
         if (*outlen < 64) return CRYPT_BUFFER_OVERFLOW;
         *outlen = 64;
         return sha3_shake_memory(256, msg, msglen, out, outlen);
      default:
         return CRYPT_INVALID_ARG;
   }
}

#endif
