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

#include "sosemanuk_common.h"

/* ======================================================================== */

/*
 * The Serpent linear transform.
 */
#define SERPENT_LT(x0, x1, x2, x3)  do { \
        x0 = ROLc(x0, 13); \
        x2 = ROLc(x2, 3); \
        x1 = x1 ^ x0 ^ x2; \
        x3 = x3 ^ x2 ^ T32(x0 << 3); \
        x1 = ROLc(x1, 1); \
        x3 = ROLc(x3, 7); \
        x0 = x0 ^ x1 ^ x3; \
        x2 = x2 ^ x3 ^ T32(x1 << 7); \
        x0 = ROLc(x0, 5); \
        x2 = ROLc(x2, 22); \
    } while (0)

/* ======================================================================== */

/*
 * Initialization continues by setting the IV. The IV length is up to 16 bytes.
 * If "ivlen" is 0 (no IV), then the "iv" parameter can be NULL.  If multiple
 * encryptions/decryptions are to be performed with the same key and
 * sosemanuk_done() has not been called, only sosemanuk_setiv() need be called
 * to set the state.
 * @param st       The Sosemanuk state
 * @param iv       Initialization vector
 * @param ivlen    Length of iv in bytes
 * @return CRYPT_OK on success
 */
int sosemanuk_setiv(sosemanuk_state *st, const unsigned char *iv, unsigned long ivlen)
{

    /*
     * The Serpent key addition step.
     */
#define KA(zc, x0, x1, x2, x3)  do { \
        x0 ^= st->kc[(zc)]; \
        x1 ^= st->kc[(zc) + 1]; \
        x2 ^= st->kc[(zc) + 2]; \
        x3 ^= st->kc[(zc) + 3]; \
    } while (0)

    /*
     * One Serpent round.
     *   zc = current subkey counter
     *   S = S-box macro for this round
     *   i0 to i4 = input register numbers (the fifth is a scratch register)
     *   o0 to o3 = output register numbers
     */
#define FSS(zc, S, i0, i1, i2, i3, i4, o0, o1, o2, o3)  do { \
        KA(zc, r ## i0, r ## i1, r ## i2, r ## i3); \
        S(r ## i0, r ## i1, r ## i2, r ## i3, r ## i4); \
        SERPENT_LT(r ## o0, r ## o1, r ## o2, r ## o3); \
    } while (0)

    /*
     * Last Serpent round. Contrary to the "true" Serpent, we keep
     * the linear transformation for that last round.
     */
#define FSF(zc, S, i0, i1, i2, i3, i4, o0, o1, o2, o3)  do { \
        KA(zc, r ## i0, r ## i1, r ## i2, r ## i3); \
        S(r ## i0, r ## i1, r ## i2, r ## i3, r ## i4); \
        SERPENT_LT(r ## o0, r ## o1, r ## o2, r ## o3); \
        KA(zc + 4, r ## o0, r ## o1, r ## o2, r ## o3); \
    } while (0)

    ulong32 r0, r1, r2, r3, r4;
    unsigned char ivtmp[16] = {0};

    LTC_ARGCHK(st != NULL);
    LTC_ARGCHK(ivlen <= 16);
    LTC_ARGCHK(iv != NULL || ivlen == 0);

    if (ivlen > 0) XMEMCPY(ivtmp, iv, ivlen);

    /*
     * Decode IV into four 32-bit words (little-endian).
     */
    LOAD32L(r0, ivtmp);
    LOAD32L(r1, ivtmp + 4);
    LOAD32L(r2, ivtmp + 8);
    LOAD32L(r3, ivtmp + 12);

    /*
     * Encrypt IV with Serpent24. Some values are extracted from the
     * output of the twelfth, eighteenth and twenty-fourth rounds.
     */
    FSS(0, S0, 0, 1, 2, 3, 4, 1, 4, 2, 0);
    FSS(4, S1, 1, 4, 2, 0, 3, 2, 1, 0, 4);
    FSS(8, S2, 2, 1, 0, 4, 3, 0, 4, 1, 3);
    FSS(12, S3, 0, 4, 1, 3, 2, 4, 1, 3, 2);
    FSS(16, S4, 4, 1, 3, 2, 0, 1, 0, 4, 2);
    FSS(20, S5, 1, 0, 4, 2, 3, 0, 2, 1, 4);
    FSS(24, S6, 0, 2, 1, 4, 3, 0, 2, 3, 1);
    FSS(28, S7, 0, 2, 3, 1, 4, 4, 1, 2, 0);
    FSS(32, S0, 4, 1, 2, 0, 3, 1, 3, 2, 4);
    FSS(36, S1, 1, 3, 2, 4, 0, 2, 1, 4, 3);
    FSS(40, S2, 2, 1, 4, 3, 0, 4, 3, 1, 0);
    FSS(44, S3, 4, 3, 1, 0, 2, 3, 1, 0, 2);
    st->s09 = r3;
    st->s08 = r1;
    st->s07 = r0;
    st->s06 = r2;

    FSS(48, S4, 3, 1, 0, 2, 4, 1, 4, 3, 2);
    FSS(52, S5, 1, 4, 3, 2, 0, 4, 2, 1, 3);
    FSS(56, S6, 4, 2, 1, 3, 0, 4, 2, 0, 1);
    FSS(60, S7, 4, 2, 0, 1, 3, 3, 1, 2, 4);
    FSS(64, S0, 3, 1, 2, 4, 0, 1, 0, 2, 3);
    FSS(68, S1, 1, 0, 2, 3, 4, 2, 1, 3, 0);
    st->r1  = r2;
    st->s04 = r1;
    st->r2  = r3;
    st->s05 = r0;

    FSS(72, S2, 2, 1, 3, 0, 4, 3, 0, 1, 4);
    FSS(76, S3, 3, 0, 1, 4, 2, 0, 1, 4, 2);
    FSS(80, S4, 0, 1, 4, 2, 3, 1, 3, 0, 2);
    FSS(84, S5, 1, 3, 0, 2, 4, 3, 2, 1, 0);
    FSS(88, S6, 3, 2, 1, 0, 4, 3, 2, 4, 1);
    FSF(92, S7, 3, 2, 4, 1, 0, 0, 1, 2, 3);
    st->s03 = r0;
    st->s02 = r1;
    st->s01 = r2;
    st->s00 = r3;

    st->ptr = sizeof(st->buf);

#undef KA
#undef FSS
#undef FSF

    return CRYPT_OK;
}


#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
