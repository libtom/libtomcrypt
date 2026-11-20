/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

/**
  @file ltc_secretbox_create.c
  libsodium-compatible secretbox encryption helper
*/

#if defined(LTC_XSALSA20) && defined(LTC_POLY1305)

/**
  Encrypt a message with XSalsa20-Poly1305 secretbox
  @param msg       The plaintext message to authenticate and encrypt
  @param msglen    The length of the plaintext message in octets
  @param nonce     The nonce to use for XSalsa20-Poly1305, must be 24 octets
  @param noncelen  The length of the nonce, must be LTC_SECRETBOX_NONCELEN
  @param key       The symmetric secretbox key, must be 32 octets
  @param keylen    The length of the symmetric key, must be LTC_SECRETBOX_KEYLEN
  @param out       [out] The destination for the 16-octet tag followed by ciphertext
  @param outlen    [in/out] Available out size on entry, bytes written or required on return
  @return CRYPT_OK if successful
*/
int ltc_secretbox_create(const unsigned char *msg, unsigned long msglen,
                         const unsigned char *nonce, unsigned long noncelen,
                         const unsigned char *key, unsigned long keylen,
                         unsigned char *out, unsigned long *outlen)
{
   salsa20_state st;
   poly1305_state poly;
   unsigned char polykey[LTC_SECRETBOX_KEYLEN];
   unsigned long need;
   unsigned long taglen = LTC_SECRETBOX_TAGLEN;
   int err;

   LTC_ARGCHK(msg != NULL);
   LTC_ARGCHK(nonce != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(noncelen == LTC_SECRETBOX_NONCELEN);
   LTC_ARGCHK(keylen == LTC_SECRETBOX_KEYLEN);
   LTC_ARGCHK(outlen != NULL);
   if (msglen > ULONG_MAX - LTC_SECRETBOX_TAGLEN) return CRYPT_OVERFLOW;
   need = msglen + LTC_SECRETBOX_TAGLEN;
   if (*outlen < need) {
      *outlen = need;
      return CRYPT_BUFFER_OVERFLOW;
   }
   LTC_ARGCHK(out != NULL);
   *outlen = need;

   if ((err = xsalsa20_setup(&st, key, keylen, nonce, noncelen, 20)) != CRYPT_OK) goto cleanup;
   if ((err = salsa20_keystream(&st, polykey, sizeof(polykey))) != CRYPT_OK) goto cleanup;
   if ((err = salsa20_crypt(&st, msg, msglen, out + LTC_SECRETBOX_TAGLEN)) != CRYPT_OK) goto cleanup;

   if ((err = poly1305_init(&poly, polykey, sizeof(polykey))) != CRYPT_OK) goto cleanup;
   if ((err = poly1305_process(&poly, out + LTC_SECRETBOX_TAGLEN, msglen)) != CRYPT_OK) goto cleanup;
   err = poly1305_done(&poly, out, &taglen);

cleanup:
   salsa20_done(&st);
   zeromem(&poly, sizeof(poly));
   zeromem(polykey, sizeof(polykey));
   return err;
}

#endif
