/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file ed25519_shared_secret.c
  Create an Ed25519 signature, Steffen Jaeckel
*/

#ifdef LTC_CURVE25519

static int ed25519_sign_private(const unsigned char *msg, unsigned long msglen,
                       unsigned char *sig, unsigned long *siglen,
                          const char* ctx, unsigned long ctxlen,
                          const curve25519_key *private_key)
{
   unsigned char *s;
   unsigned long long smlen;
   int err;

   LTC_ARGCHK(msg         != NULL);
   LTC_ARGCHK(sig         != NULL);
   LTC_ARGCHK(siglen      != NULL);
   LTC_ARGCHK(private_key != NULL);

   if (private_key->algo != LTC_OID_ED25519) return CRYPT_PK_INVALID_TYPE;
   if (private_key->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;

   if (*siglen < 64uL) {
      *siglen = 64uL;
      return CRYPT_BUFFER_OVERFLOW;
   }

   smlen = msglen + 64;
   s = XMALLOC(smlen);
   if (s == NULL) return CRYPT_MEM;

   err = tweetnacl_crypto_sign(s, &smlen,
                               msg, msglen,
                               private_key->priv, private_key->pub,
                               ctx, ctxlen);

   XMEMCPY(sig, s, 64uL);
   *siglen = 64uL;

#ifdef LTC_CLEAN_STACK
   zeromem(s, smlen);
#endif
   XFREE(s);

   return err;
}

/**
   Create an Ed25519ctx signature.
   @param msg             The data to be signed
   @param msglen          [in] The size of the date to be signed
   @param sig             [out] The destination of the shared data
   @param siglen          [in/out] The max size and resulting size of the shared data.
   @param ctx             [in] The context is a constant null terminated string
   @param private_key     The private Ed25519 key in the pair
   @return CRYPT_OK if successful
*/
int ed25519ctx_sign(const unsigned char *msg, unsigned long msglen,
                          unsigned char *sig, unsigned long *siglen,
                    const char* ctx, const curve25519_key *private_key)
{
   unsigned char ctx_prefix[512] = {0};
   unsigned long ctx_prefix_size = 0;

   LTC_ARGCHK(ctx != NULL);

   if(tweetnacl_crypto_ctx(ctx_prefix, &ctx_prefix_size, 0,
                           ED25519_CONTEXT_PREFIX, ctx) != CRYPT_OK)
      return CRYPT_INVALID_ARG;

   return ed25519_sign_private(msg, msglen, sig, siglen, ctx_prefix,
                               ctx_prefix_size, private_key);
}

/**
   Create an Ed25519ph signature.
   @param msg             The data to be signed
   @param msglen          [in] The size of the date to be signed
   @param sig             [out] The destination of the shared data
   @param siglen          [in/out] The max size and resulting size of the shared data.
   @param ctx             [in] The context is a constant null terminated string
   @param private_key     The private Ed25519 key in the pair
   @return CRYPT_OK if successful
*/
int ed25519ph_sign(const unsigned char *msg, unsigned long msglen,
                         unsigned char *sig, unsigned long *siglen,
                   const char *ctx, const curve25519_key *private_key)
{
   unsigned char ctx_prefix[512] = {0};
   unsigned char msg_hash[64] = {0};
   unsigned long ctx_prefix_size = 0;

   if (tweetnacl_crypto_ctx(ctx_prefix, &ctx_prefix_size, 1,
                            ED25519_CONTEXT_PREFIX, ctx) != CRYPT_OK)
      return CRYPT_INVALID_ARG;

   if (tweetnacl_crypto_ph(msg_hash, msg, msglen) != CRYPT_OK)
      return CRYPT_INVALID_ARG;

   msg = msg_hash;
   msglen = 64;

   return ed25519_sign_private(msg, msglen, sig, siglen, ctx_prefix,
                               ctx_prefix_size, private_key);
}

/**
   Create an Ed25519 signature.
   @param msg             The data to be signed
   @param msglen          [in] The size of the date to be signed
   @param sig             [out] The destination of the shared data
   @param siglen          [in/out] The max size and resulting size of the shared data.
   @param private_key     The private Ed25519 key in the pair
   @return CRYPT_OK if successful
*/
int ed25519_sign(const unsigned char *msg, unsigned long msglen,
                       unsigned char *sig, unsigned long *siglen,
                 const curve25519_key *private_key)
{
   return ed25519_sign_private(msg, msglen, sig, siglen, 0, 0, private_key);
}

#endif
