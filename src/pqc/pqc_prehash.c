/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pqc_prehash.c
  Pre-hash functions shared by HashSLH-DSA (FIPS 205 10.2.2 and 10.3) and HashML-DSA (FIPS 204 5.4)
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

   Return the length of PH(M), the same value pqc_prehash() writes.
   @param ph       The pre-hash function (one of ltc_pqc_prehash)
   @param outlen   [out] Length of PH(M) in octets
   @return CRYPT_OK if successful
*/
int pqc_prehash_size(int ph, unsigned long *outlen)
{
   LTC_ARGCHK(outlen != NULL);

   switch (ph) {
      case LTC_PQC_PH_SHA256:
      case LTC_PQC_PH_SHAKE128:
         *outlen = 32;
         return CRYPT_OK;
      case LTC_PQC_PH_SHA512:
      case LTC_PQC_PH_SHAKE256:
         *outlen = 64;
         return CRYPT_OK;
      default:
         return CRYPT_INVALID_ARG;
   }
}

/**
   INTERNAL ONLY, declared in tomcrypt_private.h

   Compute PH(M), the pre-hash of the message that goes into M', in one call.
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
   hash_state md;
   unsigned long len;
   int err;

   LTC_ARGCHK(msg    != NULL || msglen == 0);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* check the room before the message is hashed */
   if ((err = pqc_prehash_size(ph, &len)) != CRYPT_OK) return err;
   if (*outlen < len) { *outlen = len; return CRYPT_BUFFER_OVERFLOW; }

   if ((err = pqc_prehash_init(ph, &md)) != CRYPT_OK) return err;
   if ((err = pqc_prehash_process(ph, &md, msg, msglen)) != CRYPT_OK) return err;
   return pqc_prehash_done(ph, &md, out, outlen);
}

/**
   INTERNAL ONLY, declared in tomcrypt_private.h

   Start the incremental computation of PH(M).
   @param ph       The pre-hash function (one of ltc_pqc_prehash)
   @param md       [out] The hash state to set up
   @return CRYPT_OK if successful, CRYPT_INVALID_HASH if the pre-hash was not compiled in
*/
int pqc_prehash_init(int ph, hash_state *md)
{
   const struct ltc_hash_descriptor *desc;

   LTC_ARGCHK(md != NULL);

   switch (ph) {
      case LTC_PQC_PH_SHA256:
      case LTC_PQC_PH_SHA512:
         if ((desc = s_pqc_prehash_desc(ph)) == NULL) return CRYPT_INVALID_HASH;
         return desc->init(md);
      case LTC_PQC_PH_SHAKE128:
         return sha3_shake_init(md, 128);
      case LTC_PQC_PH_SHAKE256:
         return sha3_shake_init(md, 256);
      default:
         return CRYPT_INVALID_ARG;
   }
}

/**
   INTERNAL ONLY, declared in tomcrypt_private.h

   Add a piece of the message to PH(M).
   @param ph       The pre-hash function pqc_prehash_init() was called with
   @param md       The hash state
   @param in       The piece of the message, may be NULL when inlen is 0
   @param inlen    Length of the piece
   @return CRYPT_OK if successful
*/
int pqc_prehash_process(int ph, hash_state *md, const unsigned char *in, unsigned long inlen)
{
   const struct ltc_hash_descriptor *desc;

   LTC_ARGCHK(md != NULL);
   LTC_ARGCHK(in != NULL || inlen == 0);

   switch (ph) {
      case LTC_PQC_PH_SHA256:
      case LTC_PQC_PH_SHA512:
         if ((desc = s_pqc_prehash_desc(ph)) == NULL) return CRYPT_INVALID_HASH;
         /* the hashes reject a NULL pointer even for an empty input */
         return inlen == 0 ? CRYPT_OK : desc->process(md, in, inlen);
      case LTC_PQC_PH_SHAKE128:
      case LTC_PQC_PH_SHAKE256:
         return inlen == 0 ? CRYPT_OK : sha3_shake_process(md, in, inlen);
      default:
         return CRYPT_INVALID_ARG;
   }
}

/**
   INTERNAL ONLY, declared in tomcrypt_private.h

   Finish PH(M).
   The XOF output lengths are fixed by the standards, SHAKE128 gives 32 octets and SHAKE256 64.
   @param ph       The pre-hash function pqc_prehash_init() was called with
   @param md       The hash state
   @param out      [out] Destination for PH(M)
   @param outlen   [in/out] Max size and resulting size of PH(M)
   @return CRYPT_OK if successful
*/
int pqc_prehash_done(int ph, hash_state *md, unsigned char *out, unsigned long *outlen)
{
   const struct ltc_hash_descriptor *desc;
   unsigned long len;
   int err;

   LTC_ARGCHK(md     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   if ((err = pqc_prehash_size(ph, &len)) != CRYPT_OK) return err;
   if (*outlen < len) { *outlen = len; return CRYPT_BUFFER_OVERFLOW; }

   if (ph == LTC_PQC_PH_SHAKE128 || ph == LTC_PQC_PH_SHAKE256) {
      err = sha3_shake_done(md, out, len);
   }
   else {
      if ((desc = s_pqc_prehash_desc(ph)) == NULL) return CRYPT_INVALID_HASH;
      err = desc->done(md, out);
   }
   if (err == CRYPT_OK) *outlen = len;

   return err;
}

#endif
