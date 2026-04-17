/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file sha512_x86.c
  SHA512 by Marek Knapek
*/

#if defined(LTC_SHA512) && defined(LTC_SHA512_X86)

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wunused-function"
#elif defined(_MSC_VER)
#include <intrin.h>
#endif
#include <emmintrin.h> /* SSE2 _mm_set_epi64x */
#include <immintrin.h> /* AVX _mm256_castsi128_si256 _mm256_castsi256_si128 _mm256_load_si256 _mm256_loadu_si256 _mm256_store_si256 */
#include <immintrin.h> /* AVX2 _mm256_add_epi64 _mm256_blend_epi32 _mm256_permute4x64_epi64 _mm256_shuffle_epi8 */
#include <immintrin.h> /* SHA512 _mm256_sha512msg1_epi64 _mm256_sha512msg2_epi64 _mm256_sha512rnds2_epi64 */
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

const struct ltc_hash_descriptor sha512_x86_desc =
{
    "sha512",
    5,
    64,
    128,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 3,  },
   9,

    &sha512_x86_init,
    &sha512_x86_process,
    &sha512_x86_done,
    &sha512_x86_test,
    NULL
};

/* the K array */
#define K sha512_x86_k
LTC_ALIGN_MSVC(32)
static const ulong64 K[80] LTC_ALIGN(32) = {
CONST64(0x428a2f98d728ae22), CONST64(0x7137449123ef65cd),
CONST64(0xb5c0fbcfec4d3b2f), CONST64(0xe9b5dba58189dbbc),
CONST64(0x3956c25bf348b538), CONST64(0x59f111f1b605d019),
CONST64(0x923f82a4af194f9b), CONST64(0xab1c5ed5da6d8118),
CONST64(0xd807aa98a3030242), CONST64(0x12835b0145706fbe),
CONST64(0x243185be4ee4b28c), CONST64(0x550c7dc3d5ffb4e2),
CONST64(0x72be5d74f27b896f), CONST64(0x80deb1fe3b1696b1),
CONST64(0x9bdc06a725c71235), CONST64(0xc19bf174cf692694),
CONST64(0xe49b69c19ef14ad2), CONST64(0xefbe4786384f25e3),
CONST64(0x0fc19dc68b8cd5b5), CONST64(0x240ca1cc77ac9c65),
CONST64(0x2de92c6f592b0275), CONST64(0x4a7484aa6ea6e483),
CONST64(0x5cb0a9dcbd41fbd4), CONST64(0x76f988da831153b5),
CONST64(0x983e5152ee66dfab), CONST64(0xa831c66d2db43210),
CONST64(0xb00327c898fb213f), CONST64(0xbf597fc7beef0ee4),
CONST64(0xc6e00bf33da88fc2), CONST64(0xd5a79147930aa725),
CONST64(0x06ca6351e003826f), CONST64(0x142929670a0e6e70),
CONST64(0x27b70a8546d22ffc), CONST64(0x2e1b21385c26c926),
CONST64(0x4d2c6dfc5ac42aed), CONST64(0x53380d139d95b3df),
CONST64(0x650a73548baf63de), CONST64(0x766a0abb3c77b2a8),
CONST64(0x81c2c92e47edaee6), CONST64(0x92722c851482353b),
CONST64(0xa2bfe8a14cf10364), CONST64(0xa81a664bbc423001),
CONST64(0xc24b8b70d0f89791), CONST64(0xc76c51a30654be30),
CONST64(0xd192e819d6ef5218), CONST64(0xd69906245565a910),
CONST64(0xf40e35855771202a), CONST64(0x106aa07032bbd1b8),
CONST64(0x19a4c116b8d2d0c8), CONST64(0x1e376c085141ab53),
CONST64(0x2748774cdf8eeb99), CONST64(0x34b0bcb5e19b48a8),
CONST64(0x391c0cb3c5c95a63), CONST64(0x4ed8aa4ae3418acb),
CONST64(0x5b9cca4f7763e373), CONST64(0x682e6ff3d6b2b8a3),
CONST64(0x748f82ee5defb2fc), CONST64(0x78a5636f43172f60),
CONST64(0x84c87814a1f0ab72), CONST64(0x8cc702081a6439ec),
CONST64(0x90befffa23631e28), CONST64(0xa4506cebde82bde9),
CONST64(0xbef9a3f7b2c67915), CONST64(0xc67178f2e372532b),
CONST64(0xca273eceea26619c), CONST64(0xd186b8c721c0c207),
CONST64(0xeada7dd6cde0eb1e), CONST64(0xf57d4f7fee6ed178),
CONST64(0x06f067aa72176fba), CONST64(0x0a637dc5a2c898a6),
CONST64(0x113f9804bef90dae), CONST64(0x1b710b35131c471b),
CONST64(0x28db77f523047d84), CONST64(0x32caab7b40c72493),
CONST64(0x3c9ebe0a15c9bebc), CONST64(0x431d67c49c100d4c),
CONST64(0x4cc5d4becb3e42b6), CONST64(0x597f299cfc657e2a),
CONST64(0x5fcb6fab3ad6faec), CONST64(0x6c44198c4a475817)
};

/* compress 1024-bits */
#ifdef LTC_CLEAN_STACK
static int LTC_SHA512_TARGET ss_sha512_x86_compress(hash_state * md, const unsigned char *buf)
#else
static int LTC_SHA512_TARGET s_sha512_x86_compress(hash_state * md, const unsigned char *buf)
#endif
{
#define ltc_permute_epi64_k(a, b, c, d) ((((a) & 0x3) << (3 * 2)) | (((b) & 0x3) << (2 * 2)) | (((c) & 0x3) << (1 * 2)) | (((d) & 0x3) << (0 * 2)))
#define ltc_blend_epi32_k(a, b, c, d, e, f, g, h) ((((a) & 0x1) << 7) | (((b) & 0x1) << 6) | (((c) & 0x1) << 5) | (((d) & 0x1) << 4) | (((e) & 0x1) << 3) | (((f) & 0x1) << 2) | (((g) & 0x1) << 1) | (((h) & 0x1) << 0))
#define ltc_blend_epi64_k(a, b, c, d) ((((a) & 0x1) << 3) | (((b) & 0x1) << 2) | (((c) & 0x1) << 1) | (((d) & 0x1) << 0))
#define ltc_mm256_blend_epi64(a, b, c) _mm256_blend_epi32((a), (b), ltc_blend_epi32_k((((c) >> 3) & 0x1), (((c) >> 3) & 0x1), (((c) >> 2) & 0x1), (((c) >> 2) & 0x1), (((c) >> 1) & 0x1), (((c) >> 1) & 0x1), (((c) >> 0) & 0x1), (((c) >> 0) & 0x1)))
#define any 0

    __m256i reverse;
    __m256i state_a;
    __m256i state_b;
    __m256i tmp_a;
    __m256i tmp_b;
    __m256i tmp_c;
    __m256i tmp_d;
    __m256i old_a;
    __m256i old_b;
    __m256i msg_a;
    __m256i msg_b;
    __m256i msg_c;
    __m256i msg_d;

    reverse = _mm256_permute4x64_epi64(_mm256_castsi128_si256(_mm_set_epi64x(0x08090a0b0c0d0e0full, 0x0001020304050607ull)), ltc_permute_epi64_k(0x1, 0x0, 0x1, 0x0));
    state_a = _mm256_load_si256(((__m256i const*)(&md->sha512.state[0])));
    state_b = _mm256_load_si256(((__m256i const*)(&md->sha512.state[4])));
    tmp_a = _mm256_permute4x64_epi64(state_b, ltc_permute_epi64_k(any, any, 0x2, 0x3));
    tmp_b = _mm256_permute4x64_epi64(state_a, ltc_permute_epi64_k(0x2, 0x3, any, any));
    tmp_c = _mm256_permute4x64_epi64(state_b, ltc_permute_epi64_k(any, any, 0x0, 0x1));
    tmp_d = _mm256_permute4x64_epi64(state_a, ltc_permute_epi64_k(0x0, 0x1, any, any));
    state_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x1, 0x0, 0x0));
    state_b = ltc_mm256_blend_epi64(tmp_c, tmp_d, ltc_blend_epi64_k(0x1, 0x1, 0x0, 0x0));

    old_a = state_a;
    old_b = state_b;
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[0 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    msg_a = _mm256_loadu_si256(((__m256i const*)(&buf[0 * (256 / CHAR_BIT)])));
    msg_a = _mm256_shuffle_epi8(msg_a, reverse);
    tmp_a = _mm256_add_epi64(tmp_a, msg_a);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[1 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    msg_b = _mm256_loadu_si256(((__m256i const*)(&buf[1 * (256 / CHAR_BIT)])));
    msg_b = _mm256_shuffle_epi8(msg_b, reverse);
    tmp_a = _mm256_add_epi64(tmp_a, msg_b);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[2 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    msg_c = _mm256_loadu_si256(((__m256i const*)(&buf[2 * (256 / CHAR_BIT)])));
    msg_c = _mm256_shuffle_epi8(msg_c, reverse);
    tmp_a = _mm256_add_epi64(tmp_a, msg_c);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[3 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    msg_d = _mm256_loadu_si256(((__m256i const*)(&buf[3 * (256 / CHAR_BIT)])));
    msg_d = _mm256_shuffle_epi8(msg_d, reverse);
    tmp_a = _mm256_add_epi64(tmp_a, msg_d);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_a = _mm256_sha512msg1_epi64(msg_a, _mm256_castsi256_si128(msg_b));
    tmp_a = _mm256_permute4x64_epi64(msg_c, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_d, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_a);
    msg_a = _mm256_sha512msg2_epi64(tmp_a, msg_d);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[4 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_a);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_b = _mm256_sha512msg1_epi64(msg_b, _mm256_castsi256_si128(msg_c));
    tmp_a = _mm256_permute4x64_epi64(msg_d, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_a, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_b);
    msg_b = _mm256_sha512msg2_epi64(tmp_a, msg_a);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[5 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_b);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_c = _mm256_sha512msg1_epi64(msg_c, _mm256_castsi256_si128(msg_d));
    tmp_a = _mm256_permute4x64_epi64(msg_a, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_b, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_c);
    msg_c = _mm256_sha512msg2_epi64(tmp_a, msg_b);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[6 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_c);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_d = _mm256_sha512msg1_epi64(msg_d, _mm256_castsi256_si128(msg_a));
    tmp_a = _mm256_permute4x64_epi64(msg_b, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_c, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_d);
    msg_d = _mm256_sha512msg2_epi64(tmp_a, msg_c);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[7 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_d);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_a = _mm256_sha512msg1_epi64(msg_a, _mm256_castsi256_si128(msg_b));
    tmp_a = _mm256_permute4x64_epi64(msg_c, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_d, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_a);
    msg_a = _mm256_sha512msg2_epi64(tmp_a, msg_d);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[8 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_a);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_b = _mm256_sha512msg1_epi64(msg_b, _mm256_castsi256_si128(msg_c));
    tmp_a = _mm256_permute4x64_epi64(msg_d, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_a, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_b);
    msg_b = _mm256_sha512msg2_epi64(tmp_a, msg_a);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[9 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_b);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_c = _mm256_sha512msg1_epi64(msg_c, _mm256_castsi256_si128(msg_d));
    tmp_a = _mm256_permute4x64_epi64(msg_a, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_b, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_c);
    msg_c = _mm256_sha512msg2_epi64(tmp_a, msg_b);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[10 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_c);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_d = _mm256_sha512msg1_epi64(msg_d, _mm256_castsi256_si128(msg_a));
    tmp_a = _mm256_permute4x64_epi64(msg_b, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_c, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_d);
    msg_d = _mm256_sha512msg2_epi64(tmp_a, msg_c);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[11 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_d);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_a = _mm256_sha512msg1_epi64(msg_a, _mm256_castsi256_si128(msg_b));
    tmp_a = _mm256_permute4x64_epi64(msg_c, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_d, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_a);
    msg_a = _mm256_sha512msg2_epi64(tmp_a, msg_d);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[12 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_a);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_b = _mm256_sha512msg1_epi64(msg_b, _mm256_castsi256_si128(msg_c));
    tmp_a = _mm256_permute4x64_epi64(msg_d, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_a, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_b);
    msg_b = _mm256_sha512msg2_epi64(tmp_a, msg_a);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[13 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_b);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_c = _mm256_sha512msg1_epi64(msg_c, _mm256_castsi256_si128(msg_d));
    tmp_a = _mm256_permute4x64_epi64(msg_a, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_b, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_c);
    msg_c = _mm256_sha512msg2_epi64(tmp_a, msg_b);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[14 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_c);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_d = _mm256_sha512msg1_epi64(msg_d, _mm256_castsi256_si128(msg_a));
    tmp_a = _mm256_permute4x64_epi64(msg_b, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_c, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_d);
    msg_d = _mm256_sha512msg2_epi64(tmp_a, msg_c);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[15 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_d);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_a = _mm256_sha512msg1_epi64(msg_a, _mm256_castsi256_si128(msg_b));
    tmp_a = _mm256_permute4x64_epi64(msg_c, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_d, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_a);
    msg_a = _mm256_sha512msg2_epi64(tmp_a, msg_d);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[16 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_a);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_b = _mm256_sha512msg1_epi64(msg_b, _mm256_castsi256_si128(msg_c));
    tmp_a = _mm256_permute4x64_epi64(msg_d, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_a, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_b);
    msg_b = _mm256_sha512msg2_epi64(tmp_a, msg_a);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[17 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_b);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_c = _mm256_sha512msg1_epi64(msg_c, _mm256_castsi256_si128(msg_d));
    tmp_a = _mm256_permute4x64_epi64(msg_a, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_b, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_c);
    msg_c = _mm256_sha512msg2_epi64(tmp_a, msg_b);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[18 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_c);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    msg_d = _mm256_sha512msg1_epi64(msg_d, _mm256_castsi256_si128(msg_a));
    tmp_a = _mm256_permute4x64_epi64(msg_b, ltc_permute_epi64_k(any, 0x3, 0x2, 0x1));
    tmp_b = _mm256_permute4x64_epi64(msg_c, ltc_permute_epi64_k(0x0, any, any, any));
    tmp_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x0, 0x0, 0x0));
    tmp_a = _mm256_add_epi64(tmp_a, msg_d);
    msg_d = _mm256_sha512msg2_epi64(tmp_a, msg_c);
    tmp_a = _mm256_load_si256(((__m256i const*)(&K[19 * (256 / (sizeof(ulong64) * CHAR_BIT))])));
    tmp_a = _mm256_add_epi64(tmp_a, msg_d);
    state_a = _mm256_sha512rnds2_epi64(state_a, state_b, _mm256_castsi256_si128(tmp_a));
    tmp_a = _mm256_permute4x64_epi64(tmp_a, ltc_permute_epi64_k(any, any, 0x3, 0x2));
    state_b = _mm256_sha512rnds2_epi64(state_b, state_a, _mm256_castsi256_si128(tmp_a));
    state_a = _mm256_add_epi64(state_a, old_a);
    state_b = _mm256_add_epi64(state_b, old_b);

    tmp_a = _mm256_permute4x64_epi64(state_b, ltc_permute_epi64_k(any, any, 0x2, 0x3));
    tmp_b = _mm256_permute4x64_epi64(state_a, ltc_permute_epi64_k(0x2, 0x3, any, any));
    tmp_c = _mm256_permute4x64_epi64(state_b, ltc_permute_epi64_k(any, any, 0x0, 0x1));
    tmp_d = _mm256_permute4x64_epi64(state_a, ltc_permute_epi64_k(0x0, 0x1, any, any));
    state_a = ltc_mm256_blend_epi64(tmp_a, tmp_b, ltc_blend_epi64_k(0x1, 0x1, 0x0, 0x0));
    state_b = ltc_mm256_blend_epi64(tmp_c, tmp_d, ltc_blend_epi64_k(0x1, 0x1, 0x0, 0x0));
    _mm256_store_si256(((__m256i*)(&md->sha512.state[0])), state_a);
    _mm256_store_si256(((__m256i*)(&md->sha512.state[4])), state_b);
  return CRYPT_OK;

#undef ltc_permute_epi64_k
#undef ltc_blend_epi32_k
#undef ltc_blend_epi64_k
#undef ltc_mm256_blend_epi64
#undef any
}
#undef K

/* compress 1024-bits */
#ifdef LTC_CLEAN_STACK
static int s_sha512_compress(hash_state * md, const unsigned char *buf)
{
    int err;
    err = ss_sha512_compress(md, buf);
    burn_stack(sizeof(ulong64) * 90 + sizeof(int));
    return err;
}
#endif

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha512_x86_init(hash_state * md)
{
    LTC_ARGCHK(md != NULL);

    md->sha512.state = LTC_ALIGN_BUF(md->sha512.state_buf, 32);
    md->sha512.curlen = 0;
    md->sha512.length = 0;
    md->sha512.state[0] = CONST64(0x6a09e667f3bcc908);
    md->sha512.state[1] = CONST64(0xbb67ae8584caa73b);
    md->sha512.state[2] = CONST64(0x3c6ef372fe94f82b);
    md->sha512.state[3] = CONST64(0xa54ff53a5f1d36f1);
    md->sha512.state[4] = CONST64(0x510e527fade682d1);
    md->sha512.state[5] = CONST64(0x9b05688c2b3e6c1f);
    md->sha512.state[6] = CONST64(0x1f83d9abfb41bd6b);
    md->sha512.state[7] = CONST64(0x5be0cd19137e2179);
    return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
HASH_PROCESS(sha512_x86_process,s_sha512_x86_compress, sha512, 128)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (64 bytes)
   @return CRYPT_OK if successful
*/
int sha512_x86_done(hash_state * md, unsigned char *out)
{
    int i;

    LTC_ARGCHK(md  != NULL);
    LTC_ARGCHK(out != NULL);

    if (md->sha512.curlen >= sizeof(md->sha512.buf)) {
       return CRYPT_INVALID_ARG;
    }


    /* increase the length of the message */
    md->sha512.length += md->sha512.curlen * CONST64(8);

    /* append the '1' bit */
    md->sha512.buf[md->sha512.curlen++] = (unsigned char)0x80;

    /* if the length is currently above 112 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->sha512.curlen > 112) {
        while (md->sha512.curlen < 128) {
            md->sha512.buf[md->sha512.curlen++] = (unsigned char)0;
        }
        s_sha512_x86_compress(md, md->sha512.buf);
        md->sha512.curlen = 0;
    }

    /* pad upto 120 bytes of zeroes
     * note: that from 112 to 120 is the 64 MSB of the length.  We assume that you won't hash
     * > 2^64 bits of data... :-)
     */
    while (md->sha512.curlen < 120) {
        md->sha512.buf[md->sha512.curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64H(md->sha512.length, md->sha512.buf+120);
    s_sha512_x86_compress(md, md->sha512.buf);

    /* copy output */
    for (i = 0; i < 8; i++) {
        STORE64H(md->sha512.state[i], out+(8*i));
    }
#ifdef LTC_CLEAN_STACK
    zeromem(md, sizeof(hash_state));
#endif
    return CRYPT_OK;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha512_x86_test(void)
{
   return sha512_test_desc(&sha512_x86_desc, "SHA512 x86");
}

#endif /* defined(LTC_SHA512) && defined(LTC_SHA512_X86) */
