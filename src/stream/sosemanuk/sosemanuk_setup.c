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
 * Initialize Sosemanuk's state by providing a key. The key is an array of
 * 1 to 32 bytes.
 * @param st       The Sosemanuk state
 * @param key      Key
 * @param keylen   Length of key in bytes
 * @return CRYPT_OK on success
 */
int sosemanuk_setup(sosemanuk_state *st, const unsigned char *key, unsigned long keylen)
{
    /*
     * This key schedule is actually a truncated Serpent key schedule.
     * The key-derived words (w_i) are computed within the eight
     * local variables w0 to w7, which are reused again and again.
     */

#define SKS(S, o0, o1, o2, o3, d0, d1, d2, d3)   do { \
        ulong32 r0, r1, r2, r3, r4; \
        r0 = w ## o0; \
        r1 = w ## o1; \
        r2 = w ## o2; \
        r3 = w ## o3; \
        S(r0, r1, r2, r3, r4); \
        st->kc[i ++] = r ## d0; \
        st->kc[i ++] = r ## d1; \
        st->kc[i ++] = r ## d2; \
        st->kc[i ++] = r ## d3; \
    } while (0)

#define SKS0    SKS(S0, 4, 5, 6, 7, 1, 4, 2, 0)
#define SKS1    SKS(S1, 0, 1, 2, 3, 2, 0, 3, 1)
#define SKS2    SKS(S2, 4, 5, 6, 7, 2, 3, 1, 4)
#define SKS3    SKS(S3, 0, 1, 2, 3, 1, 2, 3, 4)
#define SKS4    SKS(S4, 4, 5, 6, 7, 1, 4, 0, 3)
#define SKS5    SKS(S5, 0, 1, 2, 3, 1, 3, 0, 2)
#define SKS6    SKS(S6, 4, 5, 6, 7, 0, 1, 4, 2)
#define SKS7    SKS(S7, 0, 1, 2, 3, 4, 3, 1, 0)

#define WUP(wi, wi5, wi3, wi1, cc)   do { \
        ulong32 tt = (wi) ^ (wi5) ^ (wi3) \
            ^ (wi1) ^ (0x9E3779B9 ^ (ulong32)(cc)); \
        (wi) = ROLc(tt, 11); \
    } while (0)

#define WUP0(cc)   do { \
        WUP(w0, w3, w5, w7, cc); \
        WUP(w1, w4, w6, w0, cc + 1); \
        WUP(w2, w5, w7, w1, cc + 2); \
        WUP(w3, w6, w0, w2, cc + 3); \
    } while (0)

#define WUP1(cc)   do { \
        WUP(w4, w7, w1, w3, cc); \
        WUP(w5, w0, w2, w4, cc + 1); \
        WUP(w6, w1, w3, w5, cc + 2); \
        WUP(w7, w2, w4, w6, cc + 3); \
    } while (0)

    unsigned char wbuf[32];
    ulong32 w0, w1, w2, w3, w4, w5, w6, w7;
    int i = 0;

   LTC_ARGCHK(st  != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(keylen > 0 && keylen <= 32);

    /*
     * The key is copied into the wbuf[] buffer and padded to 256 bits
     * as described in the Serpent specification.
     */
    XMEMCPY(wbuf, key, keylen);
    if (keylen < 32) {
        wbuf[keylen] = 0x01;
        if (keylen < 31) {
            XMEMSET(wbuf + keylen + 1, 0, 31 - keylen);
        }
    }

    LOAD32L(w0, wbuf);
    LOAD32L(w1, wbuf + 4);
    LOAD32L(w2, wbuf + 8);
    LOAD32L(w3, wbuf + 12);
    LOAD32L(w4, wbuf + 16);
    LOAD32L(w5, wbuf + 20);
    LOAD32L(w6, wbuf + 24);
    LOAD32L(w7, wbuf + 28);

    WUP0(0);   SKS3;
    WUP1(4);   SKS2;
    WUP0(8);   SKS1;
    WUP1(12);  SKS0;
    WUP0(16);  SKS7;
    WUP1(20);  SKS6;
    WUP0(24);  SKS5;
    WUP1(28);  SKS4;
    WUP0(32);  SKS3;
    WUP1(36);  SKS2;
    WUP0(40);  SKS1;
    WUP1(44);  SKS0;
    WUP0(48);  SKS7;
    WUP1(52);  SKS6;
    WUP0(56);  SKS5;
    WUP1(60);  SKS4;
    WUP0(64);  SKS3;
    WUP1(68);  SKS2;
    WUP0(72);  SKS1;
    WUP1(76);  SKS0;
    WUP0(80);  SKS7;
    WUP1(84);  SKS6;
    WUP0(88);  SKS5;
    WUP1(92);  SKS4;
    WUP0(96);  SKS3;

#undef SKS
#undef SKS0
#undef SKS1
#undef SKS2
#undef SKS3
#undef SKS4
#undef SKS5
#undef SKS6
#undef SKS7
#undef WUP
#undef WUP0
#undef WUP1

    return CRYPT_OK;
}



#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
