/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ed25519_verify.c
  Verify an Ed25519 signature, Steffen Jaeckel
*/

#ifdef LTC_CURVE25519

static int ed25519_verify_private(
                   const unsigned char *msg, unsigned long msglen,
                   const unsigned char *sig, unsigned long siglen,
                   int *stat,
                   const char *ctx, unsigned long ctxlen,
                   const curve25519_key *public_key)
{
   unsigned char* m;
   unsigned long long mlen;
   int err;

   LTC_ARGCHK(msg        != NULL);
   LTC_ARGCHK(sig        != NULL);
   LTC_ARGCHK(stat       != NULL);
   LTC_ARGCHK(public_key != NULL);

   *stat = 0;

   if (siglen != 64uL) return CRYPT_INVALID_ARG;
   if (public_key->algo != LTC_OID_ED25519) return CRYPT_PK_INVALID_TYPE;

   mlen = msglen + siglen;
   if ((mlen < msglen) || (mlen < siglen)) return CRYPT_OVERFLOW;

   m = XMALLOC(mlen);
   if (m == NULL) return CRYPT_MEM;

   XMEMCPY(m, sig, siglen);
   XMEMCPY(m + siglen, msg, msglen);

   err = tweetnacl_crypto_sign_open(stat,
                                    m, &mlen,
                                    m, mlen,
                                    ctx, ctxlen,
                                    public_key->pub);

#ifdef LTC_CLEAN_STACK
   zeromem(m, mlen);
#endif
   XFREE(m);

   return err;
}

/**
   Verify an Ed25519 signature.
   @param sig             [in] The signature to be verified
   @param siglen          [in] The size of the signature to be verified
   @param stat            [out] The result of the signature verification, 1==valid, 0==invalid
   @param ctx             [in] The context is a constant null terminated string
   @param public_key      [in] The public Ed25519 key in the pair
   @return CRYPT_OK if successful
*/
int ed25519ctx_verify(const unsigned char *msg, unsigned long msglen,
                      const unsigned char *sig, unsigned long siglen,
                      int *stat, const char *ctx,
                      const curve25519_key *public_key)
{
   unsigned char ctx_prefix[512] = {0};
   unsigned long ctx_prefix_size = 0;

   LTC_ARGCHK(ctx != NULL);

   if(tweetnacl_crypto_ctx(ctx_prefix, &ctx_prefix_size, 0,
                           ED25519_CONTEXT_PREFIX, ctx) != CRYPT_OK)
      return CRYPT_INVALID_ARG;

   return ed25519_verify_private(msg, msglen, sig, siglen, stat,
                                 ctx_prefix, ctx_prefix_size, public_key);
}

/**
   Verify an Ed25519 signature.
   @param msg             [in] The data to be signed
   @param msglen          [in] The size of the data to be signed
   @param sig             [in] The signature to be verified
   @param siglen          [in] The size of the signature to be verified
   @param stat            [out] The result of the signature verification, 1==valid, 0==invalid
   @param ctx             [in] The context is a constant null terminated string
   @param public_key      [in] The public Ed25519 key in the pair
   @return CRYPT_OK if successful
*/
int ed25519ph_verify(const unsigned char *msg, unsigned long msglen,
                     const unsigned char *sig, unsigned long siglen,
                     int *stat, const char *ctx,
                     const curve25519_key *public_key)
{
   unsigned char ctx_prefix[512] = {0};
   unsigned char msg_hash[64] = {0};
   unsigned long ctx_prefix_size = 0;

   if(tweetnacl_crypto_ctx(ctx_prefix, &ctx_prefix_size, 1,
                           ED25519_CONTEXT_PREFIX, ctx) != CRYPT_OK)
      return CRYPT_INVALID_ARG;

   if (tweetnacl_crypto_ph(msg_hash, msg, msglen) != CRYPT_OK)
      return CRYPT_INVALID_ARG;

   msg = msg_hash;
   msglen = 64;

   return ed25519_verify_private(msg, msglen, sig, siglen, stat,
                                 ctx_prefix, ctx_prefix_size, public_key);
}

/**
   Verify an Ed25519 signature.
   @param msg             [in] The data to be signed
   @param msglen          [in] The size of the data to be signed
   @param sig             [in] The signature to be verified
   @param siglen          [in] The size of the signature to be verified
   @param stat            [out] The result of the signature verification, 1==valid, 0==invalid
   @param public_key      [in] The public Ed25519 key in the pair
   @return CRYPT_OK if successful
*/
int ed25519_verify(const unsigned char *msg, unsigned long msglen,
                   const unsigned char *sig, unsigned long siglen,
                   int *stat, const curve25519_key *public_key)
{
   return ed25519_verify_private(msg, msglen, sig, siglen,
                                 stat, 0, 0, public_key);
}

#endif
