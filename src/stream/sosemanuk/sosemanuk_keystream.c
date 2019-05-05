/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/*
 * This LTC implementation was adapted from:
 *    http://www.ecrypt.eu.org/stream/e2-sosemanuk.html
 *
 * Sosemanuk specifications require:
 *    1- a key of at least 128 bits (16 bytes), not exceeding 256 bits (32 bytes).
 *    2- keys < 32 bytes are terminated with 0x01 followed by NULLs as needed.
 *    3- an iv of 128 bits (16 bytes).
 * See http://www.ecrypt.eu.org/stream/p3ciphers/sosemanuk/sosemanuk_p3.pdf
 */

/*
 * SOSEMANUK reference implementation.
 *
 * This code is supposed to run on any conforming C implementation (C90
 * or later).
 *
 * (c) 2005 X-CRYPT project. This software is provided 'as-is', without
 * any express or implied warranty. In no event will the authors be held
 * liable for any damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to no restriction.
 *
 * Technical remarks and questions can be addressed to
 * <thomas.pornin@cryptolog.com>
 */

#include "tomcrypt_private.h"

#ifdef LTC_SOSEMANUK

/*
 * Cipher operation, as a PRNG: the provided output buffer is filled with
 * pseudo-random bytes as output from the stream cipher.
 * @param st       The Sosemanuk state
 * @param out      Data out
 * @param outlen   Length of output in bytes
 * @return CRYPT_OK on success
 */
int sosemanuk_keystream(sosemanuk_state *st, unsigned char *out, unsigned long outlen)
{
   if (outlen == 0) return CRYPT_OK; /* nothing to do */
   LTC_ARGCHK(out != NULL);
   XMEMSET(out, 0, outlen);
   return sosemanuk_crypt(st, out, outlen, out);
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
