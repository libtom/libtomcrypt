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
 * 16-byte blocks, but once ECRYPT_process_bytes() was called, no more calls
 * were supported correctly.  This implementation handles the keystream
 * differently and rabbit_crypt() may be called as many times as desired,
 * crypting any number of bytes each time.
 *
 *   http://www.ecrypt.eu.org/stream/e2-rabbit.html
 *   https://www.ietf.org/rfc/rfc4503.txt
 *
 * NB: One of the test vectors distributed by the eSTREAM site in the file
 *     "rabbit_p3source.zip" is in error.  Referring to "test-vectors.txt"
 *     in that ZIP file, the 3rd line in "out1" should be
 *     "96 D6 73 16 88 D1 68 DA 51 D4 0C 70 C3 A1 16 F4".
 *
 *---------------------------------------------------------------------------
 * Here is the original legal notice accompanying the Rabbit submission
 * to the EU eSTREAM competition.
 *
 *   Copyright (C) Cryptico A/S. All rights reserved.
 *
 *   YOU SHOULD CAREFULLY READ THIS LEGAL NOTICE BEFORE USING THIS SOFTWARE.
 *
 *   This software is developed by Cryptico A/S and/or its suppliers.
 *   All title and intellectual property rights in and to the software,
 *   including but not limited to patent rights and copyrights, are owned
 *   by Cryptico A/S and/or its suppliers.
 *
 *   The software may be used solely for non-commercial purposes
 *   without the prior written consent of Cryptico A/S. For further
 *   information on licensing terms and conditions please contact
 *   Cryptico A/S at info@cryptico.com
 *
 *   Cryptico, CryptiCore, the Cryptico logo and "Re-thinking encryption"
 *   are either trademarks or registered trademarks of Cryptico A/S.
 *
 *   Cryptico A/S shall not in any way be liable for any use of this
 *   software. The software is provided "as is" without any express or
 *   implied warranty.
 *
 *---------------------------------------------------------------------------
 * On October 6, 2008, Rabbit was "released into the public domain and
 * may be used freely for any purpose."
 *
 *   http://www.ecrypt.eu.org/stream/rabbitpf.html
 *
 ******************************************************************************/


#include "tomcrypt_private.h"

#ifdef LTC_RABBIT

int rabbit_keystream(rabbit_state *st, unsigned char *out, unsigned long outlen)
{
   if (outlen == 0) return CRYPT_OK; /* nothing to do */

   LTC_ARGCHK(out != NULL);

   XMEMSET(out, 0, outlen);
   return rabbit_crypt(st, out, outlen, out);
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
