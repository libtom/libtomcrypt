/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

/**
  @file ltc_cryptobox_open.c
  libsodium-compatible crypto_box decryption helpers
*/

#if defined(LTC_XSALSA20) && defined(LTC_POLY1305) && defined(LTC_CURVE25519) && defined(LTC_BLAKE2B)

/**
  Decrypt a crypto_box message using imported X25519 keys
  @param enc       The encrypted input, a 16-octet tag followed by ciphertext
  @param enclen    The length of the encrypted input in octets
  @param nonce     The nonce used for encryption, must be 24 octets
  @param noncelen  The length of the nonce, must be LTC_SECRETBOX_NONCELEN
  @param pk        The sender public X25519 key as an initialized key object
  @param sk        The recipient private X25519 key as an initialized key object
  @param out       [out] The destination for the decrypted plaintext
  @param outlen    [in/out] Available out size on entry, bytes written or required on return
  @return CRYPT_OK if successful
*/
int ltc_cryptobox_open_ck(const unsigned char *enc, unsigned long enclen,
                          const unsigned char *nonce, unsigned long noncelen,
                          const curve25519_key *pk,
                          const curve25519_key *sk,
                          unsigned char *out, unsigned long *outlen)
{
   unsigned char shared[LTC_BOX_KEYLEN], symkey[LTC_BOX_KEYLEN];
   const unsigned char zero16[16] = {0};
   unsigned long shared_len = sizeof(shared);
   int err;

   LTC_ARGCHK(enc != NULL);
   LTC_ARGCHK(nonce != NULL);
   LTC_ARGCHK(pk != NULL);
   LTC_ARGCHK(sk != NULL);
   LTC_ARGCHK(noncelen == LTC_SECRETBOX_NONCELEN);
   if (pk->pka != LTC_PKA_X25519) return CRYPT_PK_INVALID_TYPE;
   if (sk->pka != LTC_PKA_X25519) return CRYPT_PK_INVALID_TYPE;
   if (sk->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;

   if ((err = x25519_shared_secret(sk, pk, shared, &shared_len)) != CRYPT_OK) goto cleanup;
   if ((err = xsalsa20_hsalsa20(symkey, sizeof(symkey), shared, shared_len, zero16, sizeof(zero16), 20)) != CRYPT_OK) goto cleanup;
   err = ltc_secretbox_open(enc, enclen, nonce, noncelen, symkey, sizeof(symkey), out, outlen);

cleanup:
   zeromem(shared, sizeof(shared));
   zeromem(symkey, sizeof(symkey));
   return err;
}

/**
  Decrypt a crypto_box message using raw 32-byte X25519 keys
  @param enc       The encrypted input, a 16-octet tag followed by ciphertext
  @param enclen    The length of the encrypted input in octets
  @param nonce     The nonce used for encryption, must be 24 octets
  @param noncelen  The length of the nonce, must be LTC_SECRETBOX_NONCELEN
  @param pk        The sender raw public X25519 key, must be 32 octets
  @param pklen     The length of the sender public key, must be LTC_BOX_KEYLEN
  @param sk        The recipient raw private X25519 key, must be 32 octets
  @param sklen     The length of the recipient private key, must be LTC_BOX_KEYLEN
  @param out       [out] The destination for the decrypted plaintext
  @param outlen    [in/out] Available out size on entry, bytes written or required on return
  @return CRYPT_OK if successful
*/
int ltc_cryptobox_open(const unsigned char *enc, unsigned long enclen,
                       const unsigned char *nonce, unsigned long noncelen,
                       const unsigned char *pk, unsigned long pklen,
                       const unsigned char *sk, unsigned long sklen,
                       unsigned char *out, unsigned long *outlen)
{
   curve25519_key recipient_sk, sender_pk;
   int err;

   LTC_ARGCHK(enc != NULL);
   LTC_ARGCHK(nonce != NULL);
   LTC_ARGCHK(pk != NULL);
   LTC_ARGCHK(sk != NULL);
   LTC_ARGCHK(noncelen == LTC_SECRETBOX_NONCELEN);
   LTC_ARGCHK(pklen == LTC_BOX_KEYLEN);
   LTC_ARGCHK(sklen == LTC_BOX_KEYLEN);

   if ((err = x25519_import_raw(sk, sklen, PK_PRIVATE, &recipient_sk)) != CRYPT_OK) return err;
   if ((err = x25519_import_raw(pk, pklen, PK_PUBLIC, &sender_pk)) != CRYPT_OK) goto cleanup;
   err = ltc_cryptobox_open_ck(enc, enclen, nonce, noncelen, &sender_pk, &recipient_sk, out, outlen);

cleanup:
   zeromem(&recipient_sk, sizeof(recipient_sk));
   zeromem(&sender_pk, sizeof(sender_pk));
   return err;
}

#endif
