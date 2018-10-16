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

#include "sober128_stream_common.h"


static void _xorword(ulong32 w, const unsigned char *in, unsigned char *out)
{
   ulong32 t;
   LOAD32L(t, in);
   t ^= w;
   STORE32L(t, out);
}


/* XOR pseudo-random bytes into buffer
 */
#define SROUND(z) STEP(st->R,z); NLFUNC(st,(z+1)); _xorword(t, in+(z*4), out+(z*4));

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with Sober128
   @param st      The Sober128 state
   @param in      The plaintext (or ciphertext)
   @param inlen   The length of the input (octets)
   @param out     [out] The ciphertext (or plaintext), length inlen
   @return CRYPT_OK if successful
*/
int sober128_stream_crypt(sober128_state *st, const unsigned char *in, unsigned long inlen, unsigned char *out)
{
   ulong32 t;

   if (inlen == 0) return CRYPT_OK; /* nothing to do */
   LTC_ARGCHK(out != NULL);
   LTC_ARGCHK(st  != NULL);

   /* handle any previously buffered bytes */
   while (st->nbuf != 0 && inlen != 0) {
      *out++ = *in++ ^ (unsigned char)(st->sbuf & 0xFF);
      st->sbuf >>= 8;
      st->nbuf -= 8;
      --inlen;
   }

#ifndef LTC_SMALL_CODE
   /* do lots at a time, if there's enough to do */
   while (inlen >= N*4) {
      SROUND(0);
      SROUND(1);
      SROUND(2);
      SROUND(3);
      SROUND(4);
      SROUND(5);
      SROUND(6);
      SROUND(7);
      SROUND(8);
      SROUND(9);
      SROUND(10);
      SROUND(11);
      SROUND(12);
      SROUND(13);
      SROUND(14);
      SROUND(15);
      SROUND(16);
      out    += 4*N;
      in     += 4*N;
      inlen  -= 4*N;
   }
#endif

   /* do small or odd size buffers the slow way */
   while (4 <= inlen) {
      _cycle(st->R);
      t = _nltap(st);
      _xorword(t, in, out);
      out    += 4;
      in     += 4;
      inlen  -= 4;
   }

   /* handle any trailing bytes */
   if (inlen != 0) {
      _cycle(st->R);
      st->sbuf = _nltap(st);
      st->nbuf = 32;
      while (st->nbuf != 0 && inlen != 0) {
          *out++ = *in++ ^ (unsigned char)(st->sbuf & 0xFF);
          st->sbuf >>= 8;
          st->nbuf -= 8;
          --inlen;
      }
   }

   return CRYPT_OK;
}


#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
