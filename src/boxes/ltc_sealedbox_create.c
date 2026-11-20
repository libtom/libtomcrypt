/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

/**
  @file ltc_sealedbox_create.c
  libsodium-compatible sealed box encryption helper
*/

#if defined(LTC_XSALSA20) && defined(LTC_POLY1305) && defined(LTC_CURVE25519) && defined(LTC_BLAKE2B)

/**
  Encrypt a message with a crypto_box sealed box using an imported recipient key
  @param msg       The plaintext message to encrypt for the recipient public key
  @param msglen    The length of the plaintext message in octets
  @param pk        The recipient public X25519 key as an initialized key object
  @param prng      An active PRNG state used to generate the ephemeral X25519 key
  @param wprng     The registered PRNG descriptor index matching prng
  @param out       [out] The destination for ephemeral public key || tag || ciphertext
  @param outlen    [in/out] Available out size on entry, bytes written or required on return
  @return CRYPT_OK if successful
*/
int ltc_sealedbox_create_ck(const unsigned char *msg, unsigned long msglen,
                            const curve25519_key *pk,
                            prng_state *prng, int wprng,
                            unsigned char *out, unsigned long *outlen)
{
   curve25519_key eph;
   hash_state md;
   unsigned char nonce[LTC_SECRETBOX_NONCELEN];
   unsigned long need;
   unsigned long inner_outlen;
   int err;

   LTC_ARGCHK(msg != NULL);
   LTC_ARGCHK(pk != NULL);
   LTC_ARGCHK(prng != NULL);
   LTC_ARGCHK(outlen != NULL);
   if (pk->pka != LTC_PKA_X25519) return CRYPT_PK_INVALID_TYPE;
   if (msglen > ULONG_MAX - LTC_SEALBOX_OVERHEAD) return CRYPT_OVERFLOW;
   need = msglen + LTC_SEALBOX_OVERHEAD;
   if (*outlen < need) {
      *outlen = need;
      return CRYPT_BUFFER_OVERFLOW;
   }
   LTC_ARGCHK(out != NULL);
   *outlen = need;

   if ((err = x25519_make_key(prng, wprng, &eph)) != CRYPT_OK) return err;

   XMEMCPY(out, eph.pub, LTC_SEALBOX_PREAMBLE);
   if ((err = blake2b_init(&md, sizeof(nonce), NULL, 0)) != CRYPT_OK) goto cleanup;
   if ((err = blake2b_process(&md, eph.pub, LTC_SEALBOX_PREAMBLE)) != CRYPT_OK) goto cleanup;
   if ((err = blake2b_process(&md, pk->pub, LTC_SEALBOX_PREAMBLE)) != CRYPT_OK) goto cleanup;
   if ((err = blake2b_done(&md, nonce)) != CRYPT_OK) goto cleanup;
   inner_outlen = *outlen - LTC_SEALBOX_PREAMBLE;
   err = ltc_cryptobox_create_ck(msg, msglen, nonce, sizeof(nonce), pk, &eph, out + LTC_SEALBOX_PREAMBLE, &inner_outlen);
   if (err == CRYPT_OK) *outlen = LTC_SEALBOX_PREAMBLE + inner_outlen;

cleanup:
   zeromem(&md, sizeof(md));
   zeromem(nonce, sizeof(nonce));
   zeromem(&eph, sizeof(eph));
   return err;
}

/**
  Encrypt a message with a crypto_box sealed box using a raw recipient key
  @param msg       The plaintext message to encrypt for the recipient public key
  @param msglen    The length of the plaintext message in octets
  @param pk        The recipient raw public X25519 key, must be 32 octets
  @param pklen     The length of the recipient public key, must be LTC_BOX_KEYLEN
  @param prng      An active PRNG state used to generate the ephemeral X25519 key
  @param wprng     The registered PRNG descriptor index matching prng
  @param out       [out] The destination for ephemeral public key || tag || ciphertext
  @param outlen    [in/out] Available out size on entry, bytes written or required on return
  @return CRYPT_OK if successful
*/
int ltc_sealedbox_create(const unsigned char *msg, unsigned long msglen,
                         const unsigned char *pk, unsigned long pklen,
                         prng_state *prng, int wprng,
                         unsigned char *out, unsigned long *outlen)
{
   curve25519_key recipient_pk;
   int err;

   LTC_ARGCHK(pk != NULL);
   LTC_ARGCHK(pklen == LTC_BOX_KEYLEN);

   if ((err = x25519_import_raw(pk, pklen, PK_PUBLIC, &recipient_pk)) != CRYPT_OK) return err;
   err = ltc_sealedbox_create_ck(msg, msglen, &recipient_pk, prng, wprng, out, outlen);
   zeromem(&recipient_pk, sizeof(recipient_pk));
   return err;
}

#endif
