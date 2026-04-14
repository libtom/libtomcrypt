/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file sha256_x86.c
  SHA256 by Marek Knapek
*/

#if defined(LTC_SHA256) && defined(LTC_SHA256_X86)

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wunused-function"
#elif defined(_MSC_VER)
#include <intrin.h>
#endif
#include <emmintrin.h> /* SSE2 _mm_load_si128 _mm_loadu_si128 _mm_store_si128 _mm_set_epi64x _mm_add_epi32 _mm_shuffle_epi32 */
#include <tmmintrin.h> /* SSSE3 _mm_alignr_epi8 _mm_shuffle_epi8 */
#include <smmintrin.h> /* SSE4.1 _mm_blend_epi16 */
#include <immintrin.h> /* SHA _mm_sha256msg1_epu32 _mm_sha256msg2_epu32 _mm_sha256rnds2_epu32 */
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

const struct ltc_hash_descriptor sha256_x86_desc =
{
    "sha256",
    0,
    32,
    64,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 1,  },
   9,

    &sha256_x86_init,
    &sha256_x86_process,
    &sha256_x86_done,
    &sha256_x86_test,
    NULL
};

/* the K array */
#define K sha256_x86_K
LTC_ALIGN_MSVC(16)
static const ulong32 K[64] LTC_ALIGN(16) = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
    0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
    0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
    0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
    0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
    0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
    0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
    0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

/* compress 512-bits */
#ifdef LTC_CLEAN_STACK
static int LTC_SHA_TARGET ss_sha256_x86_compress(hash_state * md, const unsigned char *buf)
#else
static int LTC_SHA_TARGET s_sha256_x86_compress(hash_state * md, const unsigned char *buf)
#endif
{
#define k_blend_epi16(a, b, c, d, e, f, g, h) ((((a) & 0x1) << 7) | (((b) & 0x1) << 6) | (((c) & 0x1) << 5) | (((d) & 0x1) << 4) | (((e) & 0x1) << 3) | (((f) & 0x1) << 2) | (((g) & 0x1) << 1) | (((h) & 0x1) << 0))
#define ltc_mm_blend_epi32(a, b, c) _mm_blend_epi16((a), (b), k_blend_epi16((((c) >> 3) & 0x1), (((c) >> 3) & 0x1), (((c) >> 2) & 0x1), (((c) >> 2) & 0x1), (((c) >> 1) & 0x1), (((c) >> 1) & 0x1), (((c) >> 0) & 0x1), (((c) >> 0) & 0x1)))
#define k_shuffle_epi32(a, b, c, d) ((((a) & 0x3) << (3 * 2)) | (((b) & 0x3) << (2 * 2)) | (((c) & 0x3) << (1 * 2)) | (((d) & 0x3) << (0 * 2)))
#define k_blend_epi32(a, b, c, d) ((((a) & 0x1) << (3 * 1)) | (((b) & 0x1) << (2 * 1)) | (((c) & 0x1) << (1 * 1)) | (((d) & 0x1) << (0 * 1)))
#define k_alignr_epi8(a) (((a) & 0x3) * 4)
#define k_any 0x0

    __m128i reverse;
    __m128i state_0;
    __m128i state_1;
    __m128i tmp;
    __m128i old_0;
    __m128i old_1;
    __m128i msg_0;
    __m128i msg;
    __m128i msg_1;
    __m128i msg_2;
    __m128i msg_3;

    reverse = _mm_set_epi64x(0x0c0d0e0f08090a0bull, 0x0405060700010203ull);
    state_0 = _mm_load_si128(((__m128i const*)(&md->sha256.state[0])));
    state_1 = _mm_load_si128(((__m128i const*)(&md->sha256.state[4])));
    tmp = _mm_shuffle_epi32(state_0, k_shuffle_epi32(0x2, 0x3, 0x0, 0x1));
    state_1 = _mm_shuffle_epi32(state_1, k_shuffle_epi32(0x0, 0x1, 0x2, 0x3));
    state_0 = _mm_alignr_epi8(tmp, state_1, k_alignr_epi8(2));
    state_1 = ltc_mm_blend_epi32(state_1, tmp, k_blend_epi32(0x1, 0x1, 0x0, 0x0));

    old_0 = state_0;
    old_1 = state_1;
    msg_0 = _mm_loadu_si128(((__m128i const*)(&buf[0 * 16])));
    msg_0 = _mm_shuffle_epi8(msg_0, reverse);
    tmp = _mm_load_si128(((__m128i const*)(&K[0 * 4])));
    msg = _mm_add_epi32(msg_0, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_1 = _mm_loadu_si128(((__m128i const*)(&buf[1 * 16])));
    msg_1 = _mm_shuffle_epi8(msg_1, reverse);
    tmp = _mm_load_si128(((__m128i const*)(&K[1 * 4])));
    msg = _mm_add_epi32(msg_1, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_2 = _mm_loadu_si128(((__m128i const*)(&buf[2 * 16])));
    msg_2 = _mm_shuffle_epi8(msg_2, reverse);
    tmp = _mm_load_si128(((__m128i const*)(&K[2 * 4])));
    msg = _mm_add_epi32(msg_2, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_3 = _mm_loadu_si128(((__m128i const*)(&buf[3 * 16])));
    msg_3 = _mm_shuffle_epi8(msg_3, reverse);
    tmp = _mm_load_si128(((__m128i const*)(&K[3 * 4])));
    msg = _mm_add_epi32(msg_3, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_0 = _mm_sha256msg1_epu32(msg_0, msg_1);
    tmp = _mm_alignr_epi8(msg_3, msg_2, k_alignr_epi8(1));
    msg_0 = _mm_add_epi32(msg_0, tmp);
    msg_0 = _mm_sha256msg2_epu32(msg_0, msg_3);
    tmp = _mm_load_si128(((__m128i const*)(&K[4 * 4])));
    msg = _mm_add_epi32(msg_0, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_1 = _mm_sha256msg1_epu32(msg_1, msg_2);
    tmp = _mm_alignr_epi8(msg_0, msg_3, k_alignr_epi8(1));
    msg_1 = _mm_add_epi32(msg_1, tmp);
    msg_1 = _mm_sha256msg2_epu32(msg_1, msg_0);
    tmp = _mm_load_si128(((__m128i const*)(&K[5 * 4])));
    msg = _mm_add_epi32(msg_1, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_2 = _mm_sha256msg1_epu32(msg_2, msg_3);
    tmp = _mm_alignr_epi8(msg_1, msg_0, k_alignr_epi8(1));
    msg_2 = _mm_add_epi32(msg_2, tmp);
    msg_2 = _mm_sha256msg2_epu32(msg_2, msg_1);
    tmp = _mm_load_si128(((__m128i const*)(&K[6 * 4])));
    msg = _mm_add_epi32(msg_2, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_3 = _mm_sha256msg1_epu32(msg_3, msg_0);
    tmp = _mm_alignr_epi8(msg_2, msg_1, k_alignr_epi8(1));
    msg_3 = _mm_add_epi32(msg_3, tmp);
    msg_3 = _mm_sha256msg2_epu32(msg_3, msg_2);
    tmp = _mm_load_si128(((__m128i const*)(&K[7 * 4])));
    msg = _mm_add_epi32(msg_3, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_0 = _mm_sha256msg1_epu32(msg_0, msg_1);
    tmp = _mm_alignr_epi8(msg_3, msg_2, k_alignr_epi8(1));
    msg_0 = _mm_add_epi32(msg_0, tmp);
    msg_0 = _mm_sha256msg2_epu32(msg_0, msg_3);
    tmp = _mm_load_si128(((__m128i const*)(&K[8 * 4])));
    msg = _mm_add_epi32(msg_0, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_1 = _mm_sha256msg1_epu32(msg_1, msg_2);
    tmp = _mm_alignr_epi8(msg_0, msg_3, k_alignr_epi8(1));
    msg_1 = _mm_add_epi32(msg_1, tmp);
    msg_1 = _mm_sha256msg2_epu32(msg_1, msg_0);
    tmp = _mm_load_si128(((__m128i const*)(&K[9 * 4])));
    msg = _mm_add_epi32(msg_1, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_2 = _mm_sha256msg1_epu32(msg_2, msg_3);
    tmp = _mm_alignr_epi8(msg_1, msg_0, k_alignr_epi8(1));
    msg_2 = _mm_add_epi32(msg_2, tmp);
    msg_2 = _mm_sha256msg2_epu32(msg_2, msg_1);
    tmp = _mm_load_si128(((__m128i const*)(&K[10 * 4])));
    msg = _mm_add_epi32(msg_2, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_3 = _mm_sha256msg1_epu32(msg_3, msg_0);
    tmp = _mm_alignr_epi8(msg_2, msg_1, k_alignr_epi8(1));
    msg_3 = _mm_add_epi32(msg_3, tmp);
    msg_3 = _mm_sha256msg2_epu32(msg_3, msg_2);
    tmp = _mm_load_si128(((__m128i const*)(&K[11 * 4])));
    msg = _mm_add_epi32(msg_3, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_0 = _mm_sha256msg1_epu32(msg_0, msg_1);
    tmp = _mm_alignr_epi8(msg_3, msg_2, k_alignr_epi8(1));
    msg_0 = _mm_add_epi32(msg_0, tmp);
    msg_0 = _mm_sha256msg2_epu32(msg_0, msg_3);
    tmp = _mm_load_si128(((__m128i const*)(&K[12 * 4])));
    msg = _mm_add_epi32(msg_0, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_1 = _mm_sha256msg1_epu32(msg_1, msg_2);
    tmp = _mm_alignr_epi8(msg_0, msg_3, k_alignr_epi8(1));
    msg_1 = _mm_add_epi32(msg_1, tmp);
    msg_1 = _mm_sha256msg2_epu32(msg_1, msg_0);
    tmp = _mm_load_si128(((__m128i const*)(&K[13 * 4])));
    msg = _mm_add_epi32(msg_1, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_2 = _mm_sha256msg1_epu32(msg_2, msg_3);
    tmp = _mm_alignr_epi8(msg_1, msg_0, k_alignr_epi8(1));
    msg_2 = _mm_add_epi32(msg_2, tmp);
    msg_2 = _mm_sha256msg2_epu32(msg_2, msg_1);
    tmp = _mm_load_si128(((__m128i const*)(&K[14 * 4])));
    msg = _mm_add_epi32(msg_2, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    msg_3 = _mm_sha256msg1_epu32(msg_3, msg_0);
    tmp = _mm_alignr_epi8(msg_2, msg_1, k_alignr_epi8(1));
    msg_3 = _mm_add_epi32(msg_3, tmp);
    msg_3 = _mm_sha256msg2_epu32(msg_3, msg_2);
    tmp = _mm_load_si128(((__m128i const*)(&K[15 * 4])));
    msg = _mm_add_epi32(msg_3, tmp);
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, k_shuffle_epi32(k_any, k_any, 0x3, 0x2));
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);
    state_0 = _mm_add_epi32(state_0, old_0);
    state_1 = _mm_add_epi32(state_1, old_1);

    tmp = _mm_shuffle_epi32(state_0, k_shuffle_epi32(0x0, 0x1, 0x2, 0x3));
    state_1 = _mm_shuffle_epi32(state_1, k_shuffle_epi32(0x2, 0x3, 0x0, 0x1));
    state_0 = ltc_mm_blend_epi32(tmp, state_1, k_blend_epi32(0x1, 0x1, 0x0, 0x0));
    state_1 = _mm_alignr_epi8(state_1, tmp, k_alignr_epi8(2));
    _mm_store_si128(((__m128i*)(&md->sha256.state[0])), state_0);
    _mm_store_si128(((__m128i*)(&md->sha256.state[4])), state_1);
    return CRYPT_OK;
}
#undef K

#ifdef LTC_CLEAN_STACK
static int s_sha256_compress(hash_state * md, const unsigned char *buf)
{
    int err;
    err = ss_sha256_compress(md, buf);
    burn_stack(sizeof(ulong32) * 74);
    return err;
}
#endif

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha256_x86_init(hash_state * md)
{
    LTC_ARGCHK(md != NULL);

    md->sha256.state = LTC_ALIGN_BUF(md->sha256.state_buf, 16);

    md->sha256.curlen = 0;
    md->sha256.length = 0;
    md->sha256.state[0] = 0x6A09E667UL;
    md->sha256.state[1] = 0xBB67AE85UL;
    md->sha256.state[2] = 0x3C6EF372UL;
    md->sha256.state[3] = 0xA54FF53AUL;
    md->sha256.state[4] = 0x510E527FUL;
    md->sha256.state[5] = 0x9B05688CUL;
    md->sha256.state[6] = 0x1F83D9ABUL;
    md->sha256.state[7] = 0x5BE0CD19UL;
    return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
HASH_PROCESS(sha256_x86_process,s_sha256_x86_compress, sha256, 64)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (32 bytes)
   @return CRYPT_OK if successful
*/
int sha256_x86_done(hash_state * md, unsigned char *out)
{
    int i;

    LTC_ARGCHK(md  != NULL);
    LTC_ARGCHK(out != NULL);

    if (md->sha256.curlen >= sizeof(md->sha256.buf)) {
       return CRYPT_INVALID_ARG;
    }


    /* increase the length of the message */
    md->sha256.length += md->sha256.curlen * 8;

    /* append the '1' bit */
    md->sha256.buf[md->sha256.curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->sha256.curlen > 56) {
        while (md->sha256.curlen < 64) {
            md->sha256.buf[md->sha256.curlen++] = (unsigned char)0;
        }
        s_sha256_x86_compress(md, md->sha256.buf);
        md->sha256.curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->sha256.curlen < 56) {
        md->sha256.buf[md->sha256.curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64H(md->sha256.length, md->sha256.buf+56);
    s_sha256_x86_compress(md, md->sha256.buf);

    /* copy output */
    for (i = 0; i < 8; i++) {
        STORE32H(md->sha256.state[i], out+(4*i));
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
int sha256_x86_test(void)
{
   return sha256_test_desc(&sha256_x86_desc, "SHA256 x86");
}

#endif
