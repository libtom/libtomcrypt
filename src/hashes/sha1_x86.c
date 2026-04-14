/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file sha1_x86.c
  SHA1 code by Marek Knapek
*/


#ifdef LTC_SHA1_X86

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wunused-function"
#elif defined(_MSC_VER)
#include <intrin.h>
#endif
#include <emmintrin.h> /* SSE2 _mm_load_si128 _mm_loadu_si128 _mm_store_si128 _mm_set_epi32 _mm_set_epi64x _mm_setzero_si128 _mm_xor_si128 _mm_add_epi32 _mm_shuffle_epi32 */
#include <tmmintrin.h> /* SSSE3 _mm_shuffle_epi8 */
#include <smmintrin.h> /* SSE4.1 _mm_extract_epi32 */
#include <immintrin.h> /* SHA _mm_sha1msg1_epu32 _mm_sha1msg2_epu32 _mm_sha1rnds4_epu32 _mm_sha1nexte_epu32 */

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

const struct ltc_hash_descriptor sha1_x86_desc =
{
    "sha1",
    2,
    20,
    64,

    /* OID */
    { 1, 3, 14, 3, 2, 26,  },
    6,

    &sha1_x86_init,
    &sha1_x86_process,
    &sha1_x86_done,
    &sha1_x86_test,
    NULL
};

#ifdef LTC_CLEAN_STACK
static int LTC_SHA_TARGET ss_sha1_x86_compress(hash_state *md, const unsigned char *buf)
#else
static int LTC_SHA_TARGET s_sha1_x86_compress(hash_state *md, const unsigned char *buf)
#endif
{
#define k_reverse_32 ((0x0 << (3 * 2)) | (0x1 << (2 * 2)) | (0x2 << (1 * 2)) | (0x3 << (0 * 2)))

    __m128i reverse_8;
    __m128i abcdx;
    __m128i e;
    __m128i old_abcd;
    __m128i old_e;
    __m128i msg_0;
    __m128i abcdy;
    __m128i msg_1;
    __m128i msg_2;
    __m128i msg_3;

    reverse_8 = _mm_set_epi64x(0x0001020304050607ull, 0x08090a0b0c0d0e0full);
    abcdx = _mm_load_si128(((__m128i const*)(&md->sha1.state[0])));
    abcdx = _mm_shuffle_epi32(abcdx, k_reverse_32);
    e = _mm_set_epi32(*((int const*)(&md->sha1.state[4])), 0, 0, 0);

    old_abcd = abcdx;
    old_e = e;
    msg_0 = _mm_loadu_si128(((__m128i const*)(&buf[0 * 16])));
    msg_0 = _mm_shuffle_epi8(msg_0, reverse_8);
    e = _mm_add_epi32(e, msg_0);
    abcdy = _mm_sha1rnds4_epu32(abcdx, e, 0);
    msg_1 = _mm_loadu_si128(((__m128i const*)(&buf[1 * 16])));
    msg_1 = _mm_shuffle_epi8(msg_1, reverse_8);
    e = _mm_sha1nexte_epu32(abcdx, msg_1);
    abcdx = _mm_sha1rnds4_epu32(abcdy, e, 0);
    msg_2 = _mm_loadu_si128(((__m128i const*)(&buf[2 * 16])));
    msg_2 = _mm_shuffle_epi8(msg_2, reverse_8);
    e = _mm_sha1nexte_epu32(abcdy, msg_2);
    abcdy = _mm_sha1rnds4_epu32(abcdx, e, 0);
    msg_3 = _mm_loadu_si128(((__m128i const*)(&buf[3 * 16])));
    msg_3 = _mm_shuffle_epi8(msg_3, reverse_8);
    e = _mm_sha1nexte_epu32(abcdx, msg_3);
    abcdx = _mm_sha1rnds4_epu32(abcdy, e, 0);
    msg_0 = _mm_sha1msg1_epu32(msg_0, msg_1);
    msg_0 = _mm_xor_si128(msg_0, msg_2);
    msg_0 = _mm_sha1msg2_epu32(msg_0, msg_3);
    e = _mm_sha1nexte_epu32(abcdy, msg_0);
    abcdy = _mm_sha1rnds4_epu32(abcdx, e, 0);
    msg_1 = _mm_sha1msg1_epu32(msg_1, msg_2);
    msg_1 = _mm_xor_si128(msg_1, msg_3);
    msg_1 = _mm_sha1msg2_epu32(msg_1, msg_0);
    e = _mm_sha1nexte_epu32(abcdx, msg_1);
    abcdx = _mm_sha1rnds4_epu32(abcdy, e, 1);
    msg_2 = _mm_sha1msg1_epu32(msg_2, msg_3);
    msg_2 = _mm_xor_si128(msg_2, msg_0);
    msg_2 = _mm_sha1msg2_epu32(msg_2, msg_1);
    e = _mm_sha1nexte_epu32(abcdy, msg_2);
    abcdy = _mm_sha1rnds4_epu32(abcdx, e, 1);
    msg_3 = _mm_sha1msg1_epu32(msg_3, msg_0);
    msg_3 = _mm_xor_si128(msg_3, msg_1);
    msg_3 = _mm_sha1msg2_epu32(msg_3, msg_2);
    e = _mm_sha1nexte_epu32(abcdx, msg_3);
    abcdx = _mm_sha1rnds4_epu32(abcdy, e, 1);
    msg_0 = _mm_sha1msg1_epu32(msg_0, msg_1);
    msg_0 = _mm_xor_si128(msg_0, msg_2);
    msg_0 = _mm_sha1msg2_epu32(msg_0, msg_3);
    e = _mm_sha1nexte_epu32(abcdy, msg_0);
    abcdy = _mm_sha1rnds4_epu32(abcdx, e, 1);
    msg_1 = _mm_sha1msg1_epu32(msg_1, msg_2);
    msg_1 = _mm_xor_si128(msg_1, msg_3);
    msg_1 = _mm_sha1msg2_epu32(msg_1, msg_0);
    e = _mm_sha1nexte_epu32(abcdx, msg_1);
    abcdx = _mm_sha1rnds4_epu32(abcdy, e, 1);
    msg_2 = _mm_sha1msg1_epu32(msg_2, msg_3);
    msg_2 = _mm_xor_si128(msg_2, msg_0);
    msg_2 = _mm_sha1msg2_epu32(msg_2, msg_1);
    e = _mm_sha1nexte_epu32(abcdy, msg_2);
    abcdy = _mm_sha1rnds4_epu32(abcdx, e, 2);
    msg_3 = _mm_sha1msg1_epu32(msg_3, msg_0);
    msg_3 = _mm_xor_si128(msg_3, msg_1);
    msg_3 = _mm_sha1msg2_epu32(msg_3, msg_2);
    e = _mm_sha1nexte_epu32(abcdx, msg_3);
    abcdx = _mm_sha1rnds4_epu32(abcdy, e, 2);
    msg_0 = _mm_sha1msg1_epu32(msg_0, msg_1);
    msg_0 = _mm_xor_si128(msg_0, msg_2);
    msg_0 = _mm_sha1msg2_epu32(msg_0, msg_3);
    e = _mm_sha1nexte_epu32(abcdy, msg_0);
    abcdy = _mm_sha1rnds4_epu32(abcdx, e, 2);
    msg_1 = _mm_sha1msg1_epu32(msg_1, msg_2);
    msg_1 = _mm_xor_si128(msg_1, msg_3);
    msg_1 = _mm_sha1msg2_epu32(msg_1, msg_0);
    e = _mm_sha1nexte_epu32(abcdx, msg_1);
    abcdx = _mm_sha1rnds4_epu32(abcdy, e, 2);
    msg_2 = _mm_sha1msg1_epu32(msg_2, msg_3);
    msg_2 = _mm_xor_si128(msg_2, msg_0);
    msg_2 = _mm_sha1msg2_epu32(msg_2, msg_1);
    e = _mm_sha1nexte_epu32(abcdy, msg_2);
    abcdy = _mm_sha1rnds4_epu32(abcdx, e, 2);
    msg_3 = _mm_sha1msg1_epu32(msg_3, msg_0);
    msg_3 = _mm_xor_si128(msg_3, msg_1);
    msg_3 = _mm_sha1msg2_epu32(msg_3, msg_2);
    e = _mm_sha1nexte_epu32(abcdx, msg_3);
    abcdx = _mm_sha1rnds4_epu32(abcdy, e, 3);
    msg_0 = _mm_sha1msg1_epu32(msg_0, msg_1);
    msg_0 = _mm_xor_si128(msg_0, msg_2);
    msg_0 = _mm_sha1msg2_epu32(msg_0, msg_3);
    e = _mm_sha1nexte_epu32(abcdy, msg_0);
    abcdy = _mm_sha1rnds4_epu32(abcdx, e, 3);
    msg_1 = _mm_sha1msg1_epu32(msg_1, msg_2);
    msg_1 = _mm_xor_si128(msg_1, msg_3);
    msg_1 = _mm_sha1msg2_epu32(msg_1, msg_0);
    e = _mm_sha1nexte_epu32(abcdx, msg_1);
    abcdx = _mm_sha1rnds4_epu32(abcdy, e, 3);
    msg_2 = _mm_sha1msg1_epu32(msg_2, msg_3);
    msg_2 = _mm_xor_si128(msg_2, msg_0);
    msg_2 = _mm_sha1msg2_epu32(msg_2, msg_1);
    e = _mm_sha1nexte_epu32(abcdy, msg_2);
    abcdy = _mm_sha1rnds4_epu32(abcdx, e, 3);
    msg_3 = _mm_sha1msg1_epu32(msg_3, msg_0);
    msg_3 = _mm_xor_si128(msg_3, msg_1);
    msg_3 = _mm_sha1msg2_epu32(msg_3, msg_2);
    e = _mm_sha1nexte_epu32(abcdx, msg_3);
    abcdx = _mm_sha1rnds4_epu32(abcdy, e, 3);
    msg_0 = _mm_setzero_si128();
    e = _mm_sha1nexte_epu32(abcdy, msg_0);
    abcdx = _mm_add_epi32(abcdx, old_abcd);
    e = _mm_add_epi32(e, old_e);

    abcdx = _mm_shuffle_epi32(abcdx, k_reverse_32);
    _mm_store_si128(((__m128i*)(&md->sha1.state[0])), abcdx);
    *((int*)(&md->sha1.state[4])) = _mm_extract_epi32(e, 3);

    return CRYPT_OK;

#undef k_reverse_32
}

#ifdef LTC_CLEAN_STACK
static int s_sha1_x86_compress(hash_state *md, const unsigned char *buf)
{
   int err;
   err = ss_sha1_x86_compress(md, buf);
   burn_stack(sizeof(ulong32) * 87);
   return err;
}
#endif

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha1_x86_init(hash_state * md)
{
   LTC_ARGCHK(md != NULL);

   md->sha1.state = LTC_ALIGN_BUF(md->sha1.state_buf, 16);

   md->sha1.state[0] = 0x67452301UL;
   md->sha1.state[1] = 0xefcdab89UL;
   md->sha1.state[2] = 0x98badcfeUL;
   md->sha1.state[3] = 0x10325476UL;
   md->sha1.state[4] = 0xc3d2e1f0UL;
   md->sha1.curlen = 0;
   md->sha1.length = 0;
   return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
HASH_PROCESS(sha1_x86_process, s_sha1_x86_compress, sha1, 64)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (20 bytes)
   @return CRYPT_OK if successful
*/
int sha1_x86_done(hash_state * md, unsigned char *out)
{
    int i;

    LTC_ARGCHK(md  != NULL);
    LTC_ARGCHK(out != NULL);

    if (md->sha1.curlen >= ((int)(sizeof(md->sha1.buf)))) {
       return CRYPT_INVALID_ARG;
    }

    /* increase the length of the message */
    md->sha1.length += md->sha1.curlen * 8;

    /* append the '1' bit */
    md->sha1.buf[md->sha1.curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->sha1.curlen > 56) {
        while (md->sha1.curlen < 64) {
            md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
        }
        s_sha1_x86_compress(md, md->sha1.buf);
        md->sha1.curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->sha1.curlen < 56) {
        md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64H(md->sha1.length, md->sha1.buf+56);
    s_sha1_x86_compress(md, md->sha1.buf);

    /* copy output */
    for (i = 0; i < 5; i++) {
        STORE32H(md->sha1.state[i], out+(4*i));
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
int sha1_x86_test(void)
{
   return sha1_test_desc(&sha1_x86_desc, "SHA1 x86");
}

#endif
