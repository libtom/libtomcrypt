/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

/**
  @file ltc_secretbox_open.c
  libsodium-compatible secretbox decryption helper
*/

#if defined(LTC_XSALSA20) && defined(LTC_POLY1305)

/**
  Decrypt a XSalsa20-Poly1305 secretbox message
  @param enc       The encrypted input, a 16-octet tag followed by ciphertext
  @param enclen    The length of the encrypted input in octets
  @param nonce     The nonce used for encryption, must be 24 octets
  @param noncelen  The length of the nonce, must be LTC_SECRETBOX_NONCELEN
  @param key       The symmetric secretbox key, must be 32 octets
  @param keylen    The length of the symmetric key, must be LTC_SECRETBOX_KEYLEN
  @param out       [out] The destination for the decrypted plaintext
  @param outlen    [in/out] Available out size on entry, bytes written or required on return
  @return CRYPT_OK if successful
*/
int ltc_secretbox_open(const unsigned char *enc, unsigned long enclen,
                       const unsigned char *nonce, unsigned long noncelen,
                       const unsigned char *key, unsigned long keylen,
                       unsigned char *out, unsigned long *outlen)
{
   salsa20_state st;
   poly1305_state poly;
   unsigned char polykey[LTC_SECRETBOX_KEYLEN], tag[LTC_SECRETBOX_TAGLEN];
   unsigned long taglen = LTC_SECRETBOX_TAGLEN;
   unsigned long msglen;
   int err;

   LTC_ARGCHK(enc != NULL);
   LTC_ARGCHK(nonce != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(noncelen == LTC_SECRETBOX_NONCELEN);
   LTC_ARGCHK(keylen == LTC_SECRETBOX_KEYLEN);
   LTC_ARGCHK(enclen >= LTC_SECRETBOX_TAGLEN);

   msglen = enclen - LTC_SECRETBOX_TAGLEN;
   LTC_ARGCHK(outlen != NULL);
   if (*outlen < msglen) {
      *outlen = msglen;
      return CRYPT_BUFFER_OVERFLOW;
   }
   LTC_ARGCHK(out != NULL);
   *outlen = msglen;

   if ((err = xsalsa20_setup(&st, key, keylen, nonce, noncelen, 20)) != CRYPT_OK) return err;
   if ((err = salsa20_keystream(&st, polykey, sizeof(polykey))) != CRYPT_OK) goto done;
   if ((err = poly1305_init(&poly, polykey, sizeof(polykey))) != CRYPT_OK) goto done;
   if ((err = poly1305_process(&poly, enc + LTC_SECRETBOX_TAGLEN, msglen)) != CRYPT_OK) goto done;
   if ((err = poly1305_done(&poly, tag, &taglen)) != CRYPT_OK) goto done;
   if (mem_neq(tag, enc, LTC_SECRETBOX_TAGLEN) != 0) {
      err = CRYPT_ERROR;
      goto done;
   }
   err = salsa20_crypt(&st, enc + LTC_SECRETBOX_TAGLEN, msglen, out);

done:
   salsa20_done(&st);
   zeromem(&poly, sizeof(poly));
   zeromem(tag, sizeof(tag));
   zeromem(polykey, sizeof(polykey));
   return err;
}

#endif
