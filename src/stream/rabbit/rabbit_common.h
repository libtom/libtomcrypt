/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/******************************************************************************
 * This Rabbit C source code was morphed fm the EU eSTREAM ECRYPT submission
 * and should run on any conforming C implementation (C90 or later).
 *
 * This implementation supports any key length up to 128 bits (16 bytes) and
 * works in increments of 8-bit bytes.  Keys must be submitted as whole bytes
 * and shorter keys will be right-null-padded to 16 bytes.  Likewise, an iv
 * may be any length up to 8 bytes and will be padded out to 8 bytes.
 *
 * The eSTREAM submission was rather picky about the calling sequence of
 * ECRYPT_process_blocks() and ECRYPT_process_bytes().  That version allowed
 * calling ECRYPT_process_blocks() multiple times for a multiple of whole
 * 16-byte blocks, but once ECRYPT_process_bytes() was called. no more calls
 * were supported correctly.  This implementation handles the keystream
 * differently and rabbit_crypt() may be called as many times as desired,
 * crypting any number of bytes each time.
 *
 *   http://www.ecrypt.eu.org/stream/e2-rabbit.html
 *
 * NB: One of the test vectors distributed by the eSTREAM site in the file
 *     "rabbit_p3source.zip" is in error.  Referring to "test-vectors.txt"
 *     in that ZIP file, the 3rd line in "out1" should be
 *     "96 D6 73 16 88 D1 68 DA 51 D4 0C 70 C3 A1 16 F4".
 *
 * Here is the original legal notice accompanying the Rabbit submission
 * to the EU eSTREAM competition.
 *---------------------------------------------------------------------------
 * Copyright (C) Cryptico A/S. All rights reserved.
 *
 * YOU SHOULD CAREFULLY READ THIS LEGAL NOTICE BEFORE USING THIS SOFTWARE.
 *
 * This software is developed by Cryptico A/S and/or its suppliers.
 * All title and intellectual property rights in and to the software,
 * including but not limited to patent rights and copyrights, are owned
 * by Cryptico A/S and/or its suppliers.
 *
 * The software may be used solely for non-commercial purposes
 * without the prior written consent of Cryptico A/S. For further
 * information on licensing terms and conditions please contact
 * Cryptico A/S at info@cryptico.com
 *
 * Cryptico, CryptiCore, the Cryptico logo and "Re-thinking encryption"
 * are either trademarks or registered trademarks of Cryptico A/S.
 *
 * Cryptico A/S shall not in any way be liable for any use of this
 * software. The software is provided "as is" without any express or
 * implied warranty.
 *---------------------------------------------------------------------------
 * On October 6, 2008, Rabbit was "released into the public domain and
 * may be used freely for any purpose."
 *   http://www.ecrypt.eu.org/stream/rabbitpf.html
 *   https://web.archive.org/web/20090630021733/http://www.ecrypt.eu.org/stream/phorum/read.php?1,1244
 ******************************************************************************/


#ifdef LTC_RABBIT

/* local/private prototypes  (NB: rabbit_ctx and rabbit_state are different)  */
static LTC_INLINE ulong32 _rabbit_g_func(ulong32 x);
static LTC_INLINE void _rabbit_next_state(rabbit_ctx *p_instance);
static LTC_INLINE void _rabbit_gen_1_block(rabbit_state* st, unsigned char *out);

/* -------------------------------------------------------------------------- */

/* Square a 32-bit unsigned integer to obtain the 64-bit result and return */
/* the upper 32 bits XOR the lower 32 bits */
static LTC_INLINE ulong32 _rabbit_g_func(ulong32 x)
{
   ulong32 a, b, h, l;

   /* Construct high and low argument for squaring */
   a = x &  0xFFFF;
   b = x >> 16;

   /* Calculate high and low result of squaring */
   h = ((((ulong32)(a*a)>>17) + (ulong32)(a*b))>>15) + b*b;
   l = x * x;

   /* Return high XOR low */
   return (ulong32)(h^l);
}

/* -------------------------------------------------------------------------- */

/* Calculate the next internal state */
static LTC_INLINE void _rabbit_next_state(rabbit_ctx *p_instance)
{
   ulong32 g[8], c_old[8], i;

   /* Save old counter values */
   for (i=0; i<8; i++) {
      c_old[i] = p_instance->c[i];
   }

   /* Calculate new counter values */
   p_instance->c[0] = (ulong32)(p_instance->c[0] + 0x4D34D34D + p_instance->carry);
   p_instance->c[1] = (ulong32)(p_instance->c[1] + 0xD34D34D3 + (p_instance->c[0] < c_old[0]));
   p_instance->c[2] = (ulong32)(p_instance->c[2] + 0x34D34D34 + (p_instance->c[1] < c_old[1]));
   p_instance->c[3] = (ulong32)(p_instance->c[3] + 0x4D34D34D + (p_instance->c[2] < c_old[2]));
   p_instance->c[4] = (ulong32)(p_instance->c[4] + 0xD34D34D3 + (p_instance->c[3] < c_old[3]));
   p_instance->c[5] = (ulong32)(p_instance->c[5] + 0x34D34D34 + (p_instance->c[4] < c_old[4]));
   p_instance->c[6] = (ulong32)(p_instance->c[6] + 0x4D34D34D + (p_instance->c[5] < c_old[5]));
   p_instance->c[7] = (ulong32)(p_instance->c[7] + 0xD34D34D3 + (p_instance->c[6] < c_old[6]));
   p_instance->carry = (p_instance->c[7] < c_old[7]);

   /* Calculate the g-values */
   for (i=0;i<8;i++) {
      g[i] = _rabbit_g_func((ulong32)(p_instance->x[i] + p_instance->c[i]));
   }

   /* Calculate new state values */
   p_instance->x[0] = (ulong32)(g[0] + ROLc(g[7],16) + ROLc(g[6], 16));
   p_instance->x[1] = (ulong32)(g[1] + ROLc(g[0], 8) + g[7]);
   p_instance->x[2] = (ulong32)(g[2] + ROLc(g[1],16) + ROLc(g[0], 16));
   p_instance->x[3] = (ulong32)(g[3] + ROLc(g[2], 8) + g[1]);
   p_instance->x[4] = (ulong32)(g[4] + ROLc(g[3],16) + ROLc(g[2], 16));
   p_instance->x[5] = (ulong32)(g[5] + ROLc(g[4], 8) + g[3]);
   p_instance->x[6] = (ulong32)(g[6] + ROLc(g[5],16) + ROLc(g[4], 16));
   p_instance->x[7] = (ulong32)(g[7] + ROLc(g[6], 8) + g[5]);
}

/* ------------------------------------------------------------------------- */

static LTC_INLINE void _rabbit_gen_1_block(rabbit_state* st, unsigned char *out)
{
    ulong32 *ptr;

    /* Iterate the work context once */
    _rabbit_next_state(&(st->work_ctx));

    /* Generate 16 bytes of pseudo-random data */
    ptr = (ulong32*)&(st->work_ctx.x);
    STORE32L((ptr[0] ^ (ptr[5]>>16) ^ (ulong32)(ptr[3]<<16)), out+ 0);
    STORE32L((ptr[2] ^ (ptr[7]>>16) ^ (ulong32)(ptr[5]<<16)), out+ 4);
    STORE32L((ptr[4] ^ (ptr[1]>>16) ^ (ulong32)(ptr[7]<<16)), out+ 8);
    STORE32L((ptr[6] ^ (ptr[3]>>16) ^ (ulong32)(ptr[1]<<16)), out+12);
}

/* -------------------------------------------------------------------------- */

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
