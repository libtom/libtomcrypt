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

#define __LTC_SOBER128TAB_C__
#include "sober128tab.c"

#define LTC_SOBER128_STREAM_SETIV
#include "sober128_stream_common.h"
#undef  LTC_SOBER128_STREAM_SETIV


/* initialise to previously saved register state
 */
static void _s128_reloadstate(sober128_state *st)
{
    int i;

    for (i = 0; i < N; ++i) {
        st->R[i] = st->initR[i];
    }
}


/**
  Set IV to the Sober128 state
  @param st      The Sober12820 state
  @param iv      The IV data to add
  @param ivlen   The length of the IV (must be 12)
  @return CRYPT_OK on success
 */
int sober128_stream_setiv(sober128_state *st, const unsigned char *iv, unsigned long ivlen)
{
   ulong32 i, k;

   LTC_ARGCHK(st != NULL);
   LTC_ARGCHK(iv != NULL);
   LTC_ARGCHK(ivlen > 0);

   /* ok we are adding an IV then... */
   _s128_reloadstate(st);

   /* ivlen must be multiple of 4 bytes */
   if ((ivlen & 3) != 0) {
      return CRYPT_INVALID_KEYSIZE;
   }

   for (i = 0; i < ivlen; i += 4) {
      LOAD32L(k, (unsigned char *)&iv[i]);
      ADDKEY(k);
      _cycle(st->R);
      XORNL(_nltap(st));
   }

   /* also fold in the length of the key */
   ADDKEY(ivlen);

   /* now diffuse */
   _s128_diffuse(st);
   st->nbuf = 0;

   return CRYPT_OK;
}


#endif


/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
