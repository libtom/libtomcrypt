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
   Initialize an RC4 context (only the key)
   @param st        [out] The destination of the RC4 state
   @param key       The secret key
   @param keylen    The length of the secret key (8 - 256 bytes)
   @return CRYPT_OK if successful
*/
int rc4_stream_setup(rc4_state *st, const unsigned char *key, unsigned long keylen)
{
   unsigned char tmp, *s;
   int x, y;
   unsigned long j;

   LTC_ARGCHK(st  != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(keylen >= 5); /* 40-2048 bits */

   s = st->buf;
   for (x = 0; x < 256; x++) {
      s[x] = x;
   }

   for (j = x = y = 0; x < 256; x++) {
      y = (y + s[x] + key[j++]) & 255;
      if (j == keylen) {
         j = 0;
      }
      tmp = s[x]; s[x] = s[y]; s[y] = tmp;
   }
   st->x = 0;
   st->y = 0;

   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
