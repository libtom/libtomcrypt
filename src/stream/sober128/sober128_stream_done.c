/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

/**
 @file sober128_stream.c
 Implementation of SOBER-128 by Tom St Denis.
 Based on s128fast.c reference code supplied by Greg Rose of QUALCOMM.
*/

#ifdef LTC_SOBER128

/**
  Terminate and clear Sober128 state
  @param st      The Sober128 state
  @return CRYPT_OK on success
*/
int sober128_stream_done(sober128_state *st)
{
   LTC_ARGCHK(st != NULL);
   XMEMSET(st, 0, sizeof(sober128_state));
   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
