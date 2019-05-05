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

#define LTC_SOBER128_STREAM_SETUP
#include "sober128_stream_common.h"
#undef  LTC_SOBER128_STREAM_SETUP


/*
 * Save the current register state
 */
static void _s128_savestate(sober128_state *st)
{
    int i;
    for (i = 0; i < N; ++i) {
        st->initR[i] = st->R[i];
    }
}

/*
 * Initialise "konst"
 */
static void _s128_genkonst(sober128_state *st)
{
    ulong32 newkonst;

    do {
       _cycle(st->R);
       newkonst = _nltap(st);
    } while ((newkonst & 0xFF000000) == 0);
    st->konst = newkonst;
}


/**
   Initialize an Sober128 context (only the key)
   @param st        [out] The destination of the Sober128 state
   @param key       The secret key
   @param keylen    The length of the secret key (octets)
   @return CRYPT_OK if successful
*/
int sober128_stream_setup(sober128_state *st, const unsigned char *key, unsigned long keylen)
{
   ulong32 i, k;

   LTC_ARGCHK(st  != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(keylen > 0);

   /* keylen must be multiple of 4 bytes */
   if ((keylen & 3) != 0) {
      return CRYPT_INVALID_KEYSIZE;
   }

   /* Register initialised to Fibonacci numbers */
   st->R[0] = 1;
   st->R[1] = 1;
   for (i = 2; i < N; ++i) {
      st->R[i] = st->R[i-1] + st->R[i-2];
   }
   st->konst = INITKONST;

   for (i = 0; i < keylen; i += 4) {
      LOAD32L(k, (unsigned char *)&key[i]);
      ADDKEY(k);
      _cycle(st->R);
      XORNL(_nltap(st));
   }

   /* also fold in the length of the key */
   ADDKEY(keylen);

   /* now diffuse */
   _s128_diffuse(st);
   _s128_genkonst(st);
   _s128_savestate(st);
   st->nbuf = 0;

   return CRYPT_OK;
}


#endif


/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
