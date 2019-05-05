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


#include "tomcrypt_private.h"

#ifdef LTC_RABBIT

#include "rabbit_common.h"

/* -------------------------------------------------------------------------- */

/* IV setup */
int rabbit_setiv(rabbit_state* st, const unsigned char *iv, unsigned long ivlen)
{
   ulong32 i0, i1, i2, i3, i;
   unsigned char  tmpiv[8] = {0};

   LTC_ARGCHK(st != NULL);
   LTC_ARGCHK(iv != NULL || ivlen == 0);
   LTC_ARGCHK(ivlen <= 8);

   /* pad iv in tmpiv */
   if (iv && ivlen > 0) XMEMCPY(tmpiv, iv, ivlen);

   /* Generate four subvectors */
   LOAD32L(i0, tmpiv+0);
   LOAD32L(i2, tmpiv+4);
   i1 = (i0>>16) | (i2&0xFFFF0000);
   i3 = (i2<<16) | (i0&0x0000FFFF);

   /* Modify counter values */
   st->work_ctx.c[0] = st->master_ctx.c[0] ^ i0;
   st->work_ctx.c[1] = st->master_ctx.c[1] ^ i1;
   st->work_ctx.c[2] = st->master_ctx.c[2] ^ i2;
   st->work_ctx.c[3] = st->master_ctx.c[3] ^ i3;
   st->work_ctx.c[4] = st->master_ctx.c[4] ^ i0;
   st->work_ctx.c[5] = st->master_ctx.c[5] ^ i1;
   st->work_ctx.c[6] = st->master_ctx.c[6] ^ i2;
   st->work_ctx.c[7] = st->master_ctx.c[7] ^ i3;

   /* Copy state variables */
   for (i=0; i<8; i++) {
      st->work_ctx.x[i] = st->master_ctx.x[i];
   }
   st->work_ctx.carry = st->master_ctx.carry;

   /* Iterate the work context four times */
   for (i=0; i<4; i++) {
      _rabbit_next_state(&(st->work_ctx));
   }

   /* reset keystream buffer and unused count */
   XMEMSET(&(st->block), 0, sizeof(st->block));
   st->unused = 0;

   return CRYPT_OK;
}

/* ------------------------------------------------------------------------- */

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
