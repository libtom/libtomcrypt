/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

#ifdef LTC_RC4_STREAM

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with RC4
   @param st      The RC4 state
   @param in      The plaintext (or ciphertext)
   @param inlen   The length of the input (octets)
   @param out     [out] The ciphertext (or plaintext), length inlen
   @return CRYPT_OK if successful
*/
int rc4_stream_crypt(rc4_state *st, const unsigned char *in, unsigned long inlen, unsigned char *out)
{
   unsigned char x, y, *s, tmp;

   LTC_ARGCHK(st  != NULL);
   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(out != NULL);

   x = st->x;
   y = st->y;
   s = st->buf;
   while (inlen--) {
      x = (x + 1) & 255;
      y = (y + s[x]) & 255;
      tmp = s[x]; s[x] = s[y]; s[y] = tmp;
      tmp = (s[x] + s[y]) & 255;
      *out++ = *in++ ^ s[tmp];
   }
   st->x = x;
   st->y = y;
   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
