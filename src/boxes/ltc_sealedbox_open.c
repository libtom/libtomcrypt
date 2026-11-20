/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

/**
  @file ltc_sealedbox_open.c
  libsodium-compatible sealed box decryption helper
*/

#if defined(LTC_XSALSA20) && defined(LTC_POLY1305) && defined(LTC_CURVE25519) && defined(LTC_BLAKE2B)

/**
  Decrypt a crypto_box sealed box message using an imported recipient key
  @param enc       The encrypted sealed box: ephemeral public key || tag || ciphertext
  @param enclen    The length of the encrypted sealed box in octets
  @param sk        The recipient private X25519 key as an initialized key object
  @param out       [out] The destination for the decrypted plaintext
  @param outlen    [in/out] Available out size on entry, bytes written or required on return
  @return CRYPT_OK if successful
*/
int ltc_sealedbox_open_ck(const unsigned char *enc, unsigned long enclen,
                          const curve25519_key *sk,
                          unsigned char *out, unsigned long *outlen)
{
   curve25519_key eph_pk;
   hash_state md;
   unsigned char nonce[LTC_SECRETBOX_NONCELEN];
   int err;

   LTC_ARGCHK(enc != NULL);
   LTC_ARGCHK(sk != NULL);
   LTC_ARGCHK(enclen >= LTC_SEALBOX_OVERHEAD);
   if (sk->pka != LTC_PKA_X25519) return CRYPT_PK_INVALID_TYPE;
   if (sk->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;

   if ((err = x25519_import_raw(enc, LTC_SEALBOX_PREAMBLE, PK_PUBLIC, &eph_pk)) != CRYPT_OK) return err;
   if ((err = blake2b_init(&md, sizeof(nonce), NULL, 0)) != CRYPT_OK) goto cleanup;
   if ((err = blake2b_process(&md, enc, LTC_SEALBOX_PREAMBLE)) != CRYPT_OK) goto cleanup;
   if ((err = blake2b_process(&md, sk->pub, LTC_SEALBOX_PREAMBLE)) != CRYPT_OK) goto cleanup;
   if ((err = blake2b_done(&md, nonce)) != CRYPT_OK) goto cleanup;
   err = ltc_cryptobox_open_ck(enc + LTC_SEALBOX_PREAMBLE, enclen - LTC_SEALBOX_PREAMBLE, nonce, sizeof(nonce), &eph_pk, sk, out, outlen);

cleanup:
   zeromem(&md, sizeof(md));
   zeromem(&eph_pk, sizeof(eph_pk));
   zeromem(nonce, sizeof(nonce));
   return err;
}

/**
  Decrypt a crypto_box sealed box message using a raw recipient private key
  @param enc       The encrypted sealed box: ephemeral public key || tag || ciphertext
  @param enclen    The length of the encrypted sealed box in octets
  @param sk        The recipient raw private X25519 key, must be 32 octets
  @param sklen     The length of the recipient private key, must be LTC_BOX_KEYLEN
  @param out       [out] The destination for the decrypted plaintext
  @param outlen    [in/out] Available out size on entry, bytes written or required on return
  @return CRYPT_OK if successful
*/
int ltc_sealedbox_open(const unsigned char *enc, unsigned long enclen,
                       const unsigned char *sk, unsigned long sklen,
                       unsigned char *out, unsigned long *outlen)
{
   curve25519_key recipient_sk;
   int err;

   LTC_ARGCHK(enc != NULL);
   LTC_ARGCHK(sk != NULL);
   LTC_ARGCHK(sklen == LTC_BOX_KEYLEN);
   LTC_ARGCHK(enclen >= LTC_SEALBOX_OVERHEAD);

   if ((err = x25519_import_raw(sk, sklen, PK_PRIVATE, &recipient_sk)) != CRYPT_OK) return err;
   err = ltc_sealedbox_open_ck(enc, enclen, &recipient_sk, out, outlen);
   zeromem(&recipient_sk, sizeof(recipient_sk));
   return err;
}

#endif
