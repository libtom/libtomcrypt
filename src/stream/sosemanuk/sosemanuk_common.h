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

#ifdef LTC_SOSEMANUK

/*
 * this code is common to sosemanuk_setup(), sosemanuk_setiv(), sosemanuk_crypt()
 */

/* ======================================================================== */

/*
 * We want (and sometimes need) to perform explicit truncations to 32 bits.
 */
#define T32(x)   ((x) & (ulong32)0xFFFFFFFF)

/*
 * Some of our functions will be tagged as "inline" to help the compiler
 * optimize things. We use "inline" only if the compiler is advanced
 * enough to understand it; C99 compilers, and pre-C99 versions of gcc,
 * understand enough "inline" for our purposes.
 */

/* ======================================================================== */

/*
 * Serpent S-boxes, implemented in bitslice mode. These circuits have
 * been published by Dag Arne Osvik ("Speeding up Serpent", published in
 * the 3rd AES Candidate Conference) and work on five 32-bit registers:
 * the four inputs, and a fifth scratch register. There are meant to be
 * quite fast on Pentium-class processors. These are not the fastest
 * published, but they are "fast enough" and they are unencumbered as
 * far as intellectual property is concerned (note: these are rewritten
 * from the article itself, and hence are not covered by the GPL on
 * Dag's code, which was not used here).
 *
 * The output bits are permuted. Here is the correspondance:
 *   S0:  1420
 *   S1:  2031
 *   S2:  2314
 *   S3:  1234
 *   S4:  1403
 *   S5:  1302
 *   S6:  0142
 *   S7:  4310
 * (for instance, the output of S0 is in "r1, r4, r2, r0").
 */

#define S0(r0, r1, r2, r3, r4)   do { \
        r3 ^= r0;  r4  = r1; \
        r1 &= r3;  r4 ^= r2; \
        r1 ^= r0;  r0 |= r3; \
        r0 ^= r4;  r4 ^= r3; \
        r3 ^= r2;  r2 |= r1; \
        r2 ^= r4;  r4 = ~r4; \
        r4 |= r1;  r1 ^= r3; \
        r1 ^= r4;  r3 |= r0; \
        r1 ^= r3;  r4 ^= r3; \
    } while (0)

#define S1(r0, r1, r2, r3, r4)   do { \
        r0 = ~r0;  r2 = ~r2; \
        r4  = r0;  r0 &= r1; \
        r2 ^= r0;  r0 |= r3; \
        r3 ^= r2;  r1 ^= r0; \
        r0 ^= r4;  r4 |= r1; \
        r1 ^= r3;  r2 |= r0; \
        r2 &= r4;  r0 ^= r1; \
        r1 &= r2; \
        r1 ^= r0;  r0 &= r2; \
        r0 ^= r4; \
    } while (0)

#define S2(r0, r1, r2, r3, r4)   do { \
        r4  = r0;  r0 &= r2; \
        r0 ^= r3;  r2 ^= r1; \
        r2 ^= r0;  r3 |= r4; \
        r3 ^= r1;  r4 ^= r2; \
        r1  = r3;  r3 |= r4; \
        r3 ^= r0;  r0 &= r1; \
        r4 ^= r0;  r1 ^= r3; \
        r1 ^= r4;  r4 = ~r4; \
    } while (0)

#define S3(r0, r1, r2, r3, r4)   do { \
        r4  = r0;  r0 |= r3; \
        r3 ^= r1;  r1 &= r4; \
        r4 ^= r2;  r2 ^= r3; \
        r3 &= r0;  r4 |= r1; \
        r3 ^= r4;  r0 ^= r1; \
        r4 &= r0;  r1 ^= r3; \
        r4 ^= r2;  r1 |= r0; \
        r1 ^= r2;  r0 ^= r3; \
        r2  = r1;  r1 |= r3; \
        r1 ^= r0; \
    } while (0)

#define S4(r0, r1, r2, r3, r4)   do { \
        r1 ^= r3;  r3 = ~r3; \
        r2 ^= r3;  r3 ^= r0; \
        r4  = r1;  r1 &= r3; \
        r1 ^= r2;  r4 ^= r3; \
        r0 ^= r4;  r2 &= r4; \
        r2 ^= r0;  r0 &= r1; \
        r3 ^= r0;  r4 |= r1; \
        r4 ^= r0;  r0 |= r3; \
        r0 ^= r2;  r2 &= r3; \
        r0 = ~r0;  r4 ^= r2; \
    } while (0)

#define S5(r0, r1, r2, r3, r4)   do { \
        r0 ^= r1;  r1 ^= r3; \
        r3 = ~r3;  r4  = r1; \
        r1 &= r0;  r2 ^= r3; \
        r1 ^= r2;  r2 |= r4; \
        r4 ^= r3;  r3 &= r1; \
        r3 ^= r0;  r4 ^= r1; \
        r4 ^= r2;  r2 ^= r0; \
        r0 &= r3;  r2 = ~r2; \
        r0 ^= r4;  r4 |= r3; \
        r2 ^= r4; \
    } while (0)

#define S6(r0, r1, r2, r3, r4)   do { \
        r2 = ~r2;  r4  = r3; \
        r3 &= r0;  r0 ^= r4; \
        r3 ^= r2;  r2 |= r4; \
        r1 ^= r3;  r2 ^= r0; \
        r0 |= r1;  r2 ^= r1; \
        r4 ^= r0;  r0 |= r3; \
        r0 ^= r2;  r4 ^= r3; \
        r4 ^= r0;  r3 = ~r3; \
        r2 &= r4; \
        r2 ^= r3; \
    } while (0)

#define S7(r0, r1, r2, r3, r4)   do { \
        r4  = r1;  r1 |= r2; \
        r1 ^= r3;  r4 ^= r2; \
        r2 ^= r1;  r3 |= r4; \
        r3 &= r0;  r4 ^= r2; \
        r3 ^= r1;  r1 |= r4; \
        r1 ^= r0;  r0 |= r4; \
        r0 ^= r2;  r1 ^= r4; \
        r2 ^= r1;  r1 &= r0; \
        r1 ^= r4;  r2 = ~r2; \
        r2 |= r0; \
        r4 ^= r2; \
    } while (0)

/* ======================================================================== */


#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
