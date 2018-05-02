/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/* The implementation is based on:
 * "Salsa20 specification", http://cr.yp.to/snuffle/spec.pdf
 * and salsa20-ref.c version 20051118
 * Public domain from D. J. Bernstein
 */

#include "tomcrypt.h"

#if defined(LTC_SALSA20) || defined(LTC_XSALSA20)

/**
  Generate a stream of random bytes via Salsa20
  @param st      The Salsa20 state
  @param out     [out] The output buffer
  @param outlen  The output length
  @return CRYPT_OK on success
 */
int salsa20_keystream(salsa20_state *st, unsigned char *out, unsigned long outlen)
{
   if (outlen == 0) return CRYPT_OK; /* nothing to do */
   LTC_ARGCHK(out != NULL);
   XMEMSET(out, 0, outlen);
   return salsa20_crypt(st, out, outlen, out);
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  af67321bf3cde1a470c679e459ebb8189e38c9bd */
/* commit time: 2018-04-13 09:42:47 +0200 */
