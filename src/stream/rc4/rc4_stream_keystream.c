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
  Generate a stream of random bytes via RC4
  @param st      The RC420 state
  @param out     [out] The output buffer
  @param outlen  The output length
  @return CRYPT_OK on success
 */
int rc4_stream_keystream(rc4_state *st, unsigned char *out, unsigned long outlen)
{
   if (outlen == 0) return CRYPT_OK; /* nothing to do */
   LTC_ARGCHK(out != NULL);
   XMEMSET(out, 0, outlen);
   return rc4_stream_crypt(st, out, outlen, out);
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
