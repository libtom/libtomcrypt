/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include "tomcrypt.h"
#include "sms4_lcl.h"

#ifdef LTC_SM4


#define L32(x)							\
    ((x) ^							    \
    ROL32((x),  2) ^					\
    ROL32((x), 10) ^					\
    ROL32((x), 18) ^					\
    ROL32((x), 24))

#define ROUND_SBOX(x0, x1, x2, x3, x4, i)		\
    x4 = x1 ^ x2 ^ x3 ^ *(rk + i);				\
    x4 = S32(x4);						        \
    x4 = x0 ^ L32(x4)

#define ROUND_TBOX(x0, x1, x2, x3, x4, i)		\
    x4 = x1 ^ x2 ^ x3 ^ *(rk + i);				\
    t0 = ROL32(SMS4_T[(unsigned char)x4], 8);			\
    x4 >>= 8;						            \
    x0 ^= t0;						            \
    t0 = ROL32(SMS4_T[(unsigned char)x4], 16);		\
    x4 >>= 8;						            \
    x0 ^= t0;						            \
    t0 = ROL32(SMS4_T[(unsigned char)x4], 24);		\
    x4 >>= 8;						            \
    x0 ^= t0;						            \
    t1 = SMS4_T[x4];					        \
    x4 = x0 ^ t1

#define ROUND_DBOX(x0, x1, x2, x3, x4, i)		\
    x4 = x1 ^ x2 ^ x3 ^ *(rk + i);				\
    x4 = x0 ^ SMS4_D[(uint16_t)(x4 >> 16)] ^	\
        ROL32(SMS4_D[(uint16_t)x4], 16)

#define ROUND ROUND_TBOX


static void docrypt(const unsigned char in[16], unsigned char out[16], const sms4_key_t *key, int encrypt)
{
    const ulong32 *rk;
    ulong32 x0, x1, x2, x3, x4;
    ulong32 t0, t1;

    if (encrypt)
        rk = key->rk;
    else
        rk = key->rk_d;
    
    x0 = GETU32(in     );
    x1 = GETU32(in +  4);
    x2 = GETU32(in +  8);
    x3 = GETU32(in + 12);
    ROUNDS(x0, x1, x2, x3, x4);
    PUTU32(out     , x0);
    PUTU32(out +  4, x4);
    PUTU32(out +  8, x3);
    PUTU32(out + 12, x2);
}

void sms4_encrypt(const unsigned char in[16], unsigned char out[16], const sms4_key_t *key)
{
    docrypt(in, out, key, 1);
}

void sms4_decrypt(const unsigned char in[16], unsigned char out[16], const sms4_key_t *key)
{
    docrypt(in, out, key, 0);
}

#endif
