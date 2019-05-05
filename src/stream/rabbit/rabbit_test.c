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

int rabbit_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   rabbit_state st;
   int err;
   unsigned char out[1000] = { 0 };
   {
      /* all 3 tests use key and iv fm set 6, vector 3, the last vector in:
         http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/rabbit/verified.test-vectors?rev=210&view=log
      */

      /* --- Test 1 (generate whole blocks) --------------------------------- */

      {
         unsigned char k[]  = { 0x0F, 0x62, 0xB5, 0x08, 0x5B, 0xAE, 0x01, 0x54,
                                0xA7, 0xFA, 0x4D, 0xA0, 0xF3, 0x46, 0x99, 0xEC };
         unsigned char iv[] = { 0x28, 0x8F, 0xF6, 0x5D, 0xC4, 0x2B, 0x92, 0xF9 };
         char pt[64]        = { 0 };
         unsigned char ct[] = { 0x61, 0x3C, 0xB0, 0xBA, 0x96, 0xAF, 0xF6, 0xCA,
                                0xCF, 0x2A, 0x45, 0x9A, 0x10, 0x2A, 0x7F, 0x78,
                                0xCA, 0x98, 0x5C, 0xF8, 0xFD, 0xD1, 0x47, 0x40,
                                0x18, 0x75, 0x8E, 0x36, 0xAE, 0x99, 0x23, 0xF5,
                                0x19, 0xD1, 0x3D, 0x71, 0x8D, 0xAF, 0x8D, 0x7C,
                                0x0C, 0x10, 0x9B, 0x79, 0xD5, 0x74, 0x94, 0x39,
                                0xB7, 0xEF, 0xA4, 0xC4, 0xC9, 0xC8, 0xD2, 0x9D,
                                0xC5, 0xB3, 0x88, 0x83, 0x14, 0xA6, 0x81, 0x6F };
         unsigned long ptlen = sizeof(pt);

         /* crypt 64 nulls */
         if ((err = rabbit_setup(&st, k, sizeof(k)))                   != CRYPT_OK) return err;
         if ((err = rabbit_setiv(&st, iv, sizeof(iv)))                 != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt, ptlen, out)) != CRYPT_OK) return err;
         if (compare_testvector(out, ptlen, ct, ptlen, "RABBIT-TV1", 1))   return CRYPT_FAIL_TESTVECTOR;
      }

      /* --- Test 2 (generate unusual number of bytes each time) ------------ */

      {
         unsigned char k[]  = { 0x0F, 0x62, 0xB5, 0x08, 0x5B, 0xAE, 0x01, 0x54,
                                0xA7, 0xFA, 0x4D, 0xA0, 0xF3, 0x46, 0x99, 0xEC };
         unsigned char iv[] = { 0x28, 0x8F, 0xF6, 0x5D, 0xC4, 0x2B, 0x92, 0xF9 };
         char          pt[39] = { 0 };
         unsigned char ct[] = { 0x61, 0x3C, 0xB0, 0xBA,   0x96, 0xAF, 0xF6, 0xCA,
                                0xCF, 0x2A, 0x45, 0x9A,   0x10, 0x2A, 0x7F, 0x78,
                                0xCA, 0x98, 0x5C, 0xF8,   0xFD, 0xD1, 0x47, 0x40,
                                0x18, 0x75, 0x8E, 0x36,   0xAE, 0x99, 0x23, 0xF5,
                                0x19, 0xD1, 0x3D, 0x71,   0x8D, 0xAF, 0x8D };
         unsigned long ptlen = sizeof(pt);

         /* crypt piece by piece (hit at least one 16-byte boundary) */
         if ((err = rabbit_setup(&st, k, sizeof(k)))                          != CRYPT_OK) return err;
         if ((err = rabbit_setiv(&st, iv, sizeof(iv)))                        != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt,       5, out))      != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt +  5, 11, out +  5)) != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt + 16, 14, out + 16)) != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt + 30,  2, out + 30)) != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt + 32,  7, out + 32)) != CRYPT_OK) return err;
         if (compare_testvector(out, ptlen, ct, ptlen, "RABBIT-TV2", 1))   return CRYPT_FAIL_TESTVECTOR;
      }

      /* --- Test 3 (use non-null data) ------------------------------------- */

      {
         unsigned char k[]  = { 0x0F, 0x62, 0xB5, 0x08, 0x5B, 0xAE, 0x01, 0x54,
                                0xA7, 0xFA, 0x4D, 0xA0, 0xF3, 0x46, 0x99, 0xEC };
         unsigned char iv[] = { 0x28, 0x8F, 0xF6, 0x5D, 0xC4, 0x2B, 0x92, 0xF9 };
         char          pt[] = "Kilroy was here, there, and everywhere!";
         unsigned char ct[] = { 0x2a, 0x55, 0xdc, 0xc8,   0xf9, 0xd6, 0xd6, 0xbd,
                                0xae, 0x59, 0x65, 0xf2,   0x75, 0x58, 0x1a, 0x54,
                                0xea, 0xec, 0x34, 0x9d,   0x8f, 0xb4, 0x6b, 0x60,
                                0x79, 0x1b, 0xea, 0x16,   0xcb, 0xef, 0x46, 0x87,
                                0x60, 0xa6, 0x55, 0x14,   0xff, 0xca, 0xac };
         unsigned long ptlen = strlen(pt);
         unsigned char out2[1000] = { 0 };
         unsigned char nulls[1000] = { 0 };

         /* crypt piece by piece */
         if ((err = rabbit_setup(&st, k, sizeof(k)))                          != CRYPT_OK) return err;
         if ((err = rabbit_setiv(&st, iv, sizeof(iv)))                        != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt,       5, out))      != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt +  5, 29, out +  5)) != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt + 34,  5, out + 34)) != CRYPT_OK) return err;
         if (compare_testvector(out, ptlen, ct, ptlen, "RABBIT-TV3", 1))   return CRYPT_FAIL_TESTVECTOR;

      /* --- Test 4 (crypt in a single call) ------------------------------------ */

         if ((err = rabbit_memory(k, sizeof(k), iv, sizeof(iv),
                                   (unsigned char*)pt, sizeof(pt), out))      != CRYPT_OK) return err;
         if (compare_testvector(out, ptlen, ct, ptlen, "RABBIT-TV4", 1))   return CRYPT_FAIL_TESTVECTOR;
         /* use 'out' (ciphertext) in the next decryption test */

      /* --- Test 5 (decrypt ciphertext) ------------------------------------ */

         /* decrypt ct (out) and compare with pt (start with only setiv() to reset) */
         if ((err = rabbit_setiv(&st, iv, sizeof(iv)))                        != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, out, ptlen, out2))                      != CRYPT_OK) return err;
         if (compare_testvector(out2, ptlen, pt, ptlen, "RABBIT-TV5", 1))  return CRYPT_FAIL_TESTVECTOR;

      /* --- Test 6 (wipe state, incl key) ---------------------------------- */

         if ((err = rabbit_done(&st))                      != CRYPT_OK) return err;
         if (compare_testvector(&st, sizeof(st), nulls, sizeof(st), "RABBIT-TV6", 1))  return CRYPT_FAIL_TESTVECTOR;

      }

      return CRYPT_OK;
   }
#endif
}

/* -------------------------------------------------------------------------- */

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
