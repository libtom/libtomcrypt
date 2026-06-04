/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/**
   @file gcm_gf_mult.c
   GCM implementation, do the GF mult, by Tom St Denis
*/
#include "tomcrypt_private.h"

#if defined(LTC_GCM_MODE) || defined(LTC_LRW_MODE) || defined(LTC_GCM_SIV_MODE)
#if defined(LTC_GCM_PCLMUL)

#define LTC_GCM_PCLMUL_TARGET LTC_TARGET("pclmul,ssse3")

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#endif
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#include <wmmintrin.h>
#include <smmintrin.h>
#include <emmintrin.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#if !defined (LTC_S_X86_CPUID)
#define LTC_S_X86_CPUID
static LTC_INLINE void s_x86_cpuid(int* regs, int leaf)
{
#if defined(_MSC_VER) && !defined(__clang__) // MSVC but not ClangCL
   __cpuid(regs, leaf);
#else
   int a, b, c, d;

   a = leaf;
   b = c = d = 0;
   __asm__ volatile ("cpuid"
       :"=a"(a), "=b"(b), "=c"(c), "=d"(d)
       :"a"(a), "c"(c)
   );
   regs[0] = a;
   regs[1] = b;
   regs[2] = c;
   regs[3] = d;
#endif
}
#endif /* LTC_S_X86_CPUID */

static LTC_INLINE int s_pclmul_is_supported(void)
{
   static int initialized = 0, is_supported = 0;

   if (initialized == 0) {
      int regs[4];
      s_x86_cpuid(regs, 1);
      /* Test CPUID.1.0.ECX[1] (PCLMUL) and CPUID.1.0.ECX[9] (SSSE3) */
      is_supported = ((regs[2] >> 1) & 1) && ((regs[2] >> 9) & 1);
      initialized = 1;
   }

   return is_supported;
}

/*
 * 128x128-bit binary polynomial multiplication for Intel x86 and x86_64
 * Based on "Intel Carry-Less Multiplication Instruction and its Usage for
 * Computing the GCM Mode", Shay Gueron, Michael E. Kounavis
 * https://cdrdv2-public.intel.com/836172/clmul-wp-rev-2-02-2014-04-20.pdf
 */
LTC_GCM_PCLMUL_TARGET
static void s_gfmul_pclmul(__m128i a, __m128i b, __m128i *res){
   /* Page 25. Figure 5. Code Sample - Performing Ghash Using Algorithms 1 and 5 (C) */
   __m128i /*tmp0, tmp1,*/ tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;
   tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
   tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
   tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
   tmp6 = _mm_clmulepi64_si128(a, b, 0x11);
   tmp4 = _mm_xor_si128(tmp4, tmp5);
   tmp5 = _mm_slli_si128(tmp4, 8);
   tmp4 = _mm_srli_si128(tmp4, 8);
   tmp3 = _mm_xor_si128(tmp3, tmp5);
   tmp6 = _mm_xor_si128(tmp6, tmp4);
   tmp7 = _mm_srli_epi32(tmp3, 31);
   tmp8 = _mm_srli_epi32(tmp6, 31);
   tmp3 = _mm_slli_epi32(tmp3, 1);
   tmp6 = _mm_slli_epi32(tmp6, 1);
   tmp9 = _mm_srli_si128(tmp7, 12);
   tmp8 = _mm_slli_si128(tmp8, 4);
   tmp7 = _mm_slli_si128(tmp7, 4);
   tmp3 = _mm_or_si128(tmp3, tmp7);
   tmp6 = _mm_or_si128(tmp6, tmp8);
   tmp6 = _mm_or_si128(tmp6, tmp9);
   tmp7 = _mm_slli_epi32(tmp3, 31);
   tmp8 = _mm_slli_epi32(tmp3, 30);
   tmp9 = _mm_slli_epi32(tmp3, 25);
   tmp7 = _mm_xor_si128(tmp7, tmp8);
   tmp7 = _mm_xor_si128(tmp7, tmp9);
   tmp8 = _mm_srli_si128(tmp7, 4);
   tmp7 = _mm_slli_si128(tmp7, 12);
   tmp3 = _mm_xor_si128(tmp3, tmp7);
   tmp2 = _mm_srli_epi32(tmp3, 1);
   tmp4 = _mm_srli_epi32(tmp3, 2);
   tmp5 = _mm_srli_epi32(tmp3, 7);
   tmp2 = _mm_xor_si128(tmp2, tmp4);
   tmp2 = _mm_xor_si128(tmp2, tmp5);
   tmp2 = _mm_xor_si128(tmp2, tmp8);
   tmp3 = _mm_xor_si128(tmp3, tmp2);
   tmp6 = _mm_xor_si128(tmp6, tmp3);
   *res = tmp6;
}

LTC_GCM_PCLMUL_TARGET
static void s_gcm_gf_mult_pclmul(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
   __m128i ci;
   __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
   __m128i ai = _mm_loadu_si128((const __m128i *) a);
   __m128i bi = _mm_loadu_si128((const __m128i *) b);

   ai = _mm_shuffle_epi8(ai, BSWAP_MASK);
   bi = _mm_shuffle_epi8(bi, BSWAP_MASK);

   s_gfmul_pclmul(ai, bi, &ci);

   ci = _mm_shuffle_epi8(ci, BSWAP_MASK);

   XMEMCPY(c, &ci, sizeof(ci));
}
#endif /* defined(LTC_GCM_PCLMUL) */

#if defined(LTC_GCM_PMULL)

#define LTC_GCM_PMULL_TARGET LTC_TARGET("+crypto")

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wbad-function-cast"
#pragma GCC diagnostic ignored "-Wcast-align"
#pragma GCC diagnostic ignored "-Wmissing-braces"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <arm_neon.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#elif defined(__FreeBSD__)
#include <sys/auxv.h>
#endif

static LTC_INLINE int s_pmull_is_supported(void)
{
   static int initialized = 0, is_supported = 0;

   if (initialized == 0) {
#if defined(__APPLE__)
      int val = 0;
      size_t len = sizeof(val);
      if (sysctlbyname("hw.optional.arm.FEAT_PMULL", &val, &len, NULL, 0) == 0) {
        is_supported = (val != 0);
      }
#elif defined (_WIN32)
      is_supported = IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE);
#elif defined(__linux__)
      unsigned long hwcaps = getauxval(AT_HWCAP);
      is_supported = (hwcaps & HWCAP_PMULL);
#elif defined(__FreeBSD__)
      unsigned long hwcaps = 0;
      if (elf_aux_info(AT_HWCAP, &hwcaps, sizeof(hwcaps)) == 0) {
         is_supported = (hwcaps & HWCAP_PMULL) != 0;
      }
#endif
      initialized = 1;
   }

   return is_supported;
}

/*
 * 128x128-bit binary polynomial multiplication for AArch64 using PMULL/PMULL2
 * Based on "Implementing GCM on ARMv8", Conrado P. L. Gouvea and Julio Lopez
 * https://conradoplg.modp.net/files/2010/12/gcm14.pdf
 */
#if defined(_MSC_VER)
#define GET_LOW_P64(x) vreinterpret_p64_u64(vcreate_u64((uint64_t)vgetq_lane_p64((x), 0)))
#else
#define GET_LOW_P64(x) vgetq_lane_p64((x), 0)
#endif

LTC_GCM_PMULL_TARGET
static void s_gfmul_pmull(uint8x16_t a, uint8x16_t b, uint8x16_t *res) {
   uint8x16_t r0, r1, t0, t1, z, p;
   poly64x2_t pa, pb, pt0, pr1, pp;

   z = vdupq_n_u8(0);

   pa = vreinterpretq_p64_u8(a);
   pb = vreinterpretq_p64_u8(b);

   /* Page 7. Algorithm 3 128 x 128-bit binary polynomial multiplier for ARMv8 AArch64 (PMULL) */
   r0 = vreinterpretq_u8_p128(vmull_p64(GET_LOW_P64(pa), GET_LOW_P64(pb)));
   r1 = vreinterpretq_u8_p128(vmull_high_p64(pa, pb));
   t0 = vextq_u8(b, b, 8);
   pt0 = vreinterpretq_p64_u8(t0);

   t1 = vreinterpretq_u8_p128(vmull_p64(GET_LOW_P64(pa), GET_LOW_P64(pt0)));
   t0 = vreinterpretq_u8_p128(vmull_high_p64(pa, pt0));
   t0 = veorq_u8(t0, t1);
   t1 = vextq_u8(z, t0, 8);
   r0 = veorq_u8(r0, t1);
   t1 = vextq_u8(t0, z, 8);
   r1 = veorq_u8(r1, t1);

   /* Page 8. Algorithm 5 256-bit to 128-bit GCM polynomial reduction for ARMv8 AAarch64 using PMULL */
   p = vreinterpretq_u8_u64(vdupq_n_u64(0x0000000000000087ULL));
   pp = vreinterpretq_p64_u8(p);
   pr1 = vreinterpretq_p64_u8(r1);
   t0 = vreinterpretq_u8_p128(vmull_high_p64(pr1, pp));
   t1 = vextq_u8(t0, z, 8);
   r1 = veorq_u8(r1, t1);
   t1 = vextq_u8(z, t0, 8);
   r0 = veorq_u8(r0, t1);
   pr1 = vreinterpretq_p64_u8(r1);

   t0 = vreinterpretq_u8_p128(vmull_p64(GET_LOW_P64(pr1), GET_LOW_P64(pp)));
   a  = veorq_u8(r0, t0);

   *res = a;
}

LTC_GCM_PMULL_TARGET
static void s_gcm_gf_mult_pmull(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
   uint8x16_t va, vb, vc;

   va = vld1q_u8(a);
   vb = vld1q_u8(b);
   va = vrbitq_u8(va);
   vb = vrbitq_u8(vb);

   s_gfmul_pmull(va, vb, &vc);

   vc = vrbitq_u8(vc);

   XMEMCPY(c, &vc, sizeof(vc));
}

#endif /* defined(LTC_GCM_PMULL) */
#endif /* defined(LTC_GCM_MODE) || defined(LTC_LRW_MODE) */

#if defined(LTC_GCM_TABLES) || defined(LTC_LRW_TABLES) || ((defined(LTC_GCM_MODE) || defined(LTC_GCM_SIV_MODE)) && defined(LTC_FAST))

/* this is x*2^128 mod p(x) ... the results are 16 bytes each stored in a packed format.  Since only the
 * lower 16 bits are not zero'ed I removed the upper 14 bytes */
const unsigned char gcm_shift_table[256*2] = {
0x00, 0x00, 0x01, 0xc2, 0x03, 0x84, 0x02, 0x46, 0x07, 0x08, 0x06, 0xca, 0x04, 0x8c, 0x05, 0x4e,
0x0e, 0x10, 0x0f, 0xd2, 0x0d, 0x94, 0x0c, 0x56, 0x09, 0x18, 0x08, 0xda, 0x0a, 0x9c, 0x0b, 0x5e,
0x1c, 0x20, 0x1d, 0xe2, 0x1f, 0xa4, 0x1e, 0x66, 0x1b, 0x28, 0x1a, 0xea, 0x18, 0xac, 0x19, 0x6e,
0x12, 0x30, 0x13, 0xf2, 0x11, 0xb4, 0x10, 0x76, 0x15, 0x38, 0x14, 0xfa, 0x16, 0xbc, 0x17, 0x7e,
0x38, 0x40, 0x39, 0x82, 0x3b, 0xc4, 0x3a, 0x06, 0x3f, 0x48, 0x3e, 0x8a, 0x3c, 0xcc, 0x3d, 0x0e,
0x36, 0x50, 0x37, 0x92, 0x35, 0xd4, 0x34, 0x16, 0x31, 0x58, 0x30, 0x9a, 0x32, 0xdc, 0x33, 0x1e,
0x24, 0x60, 0x25, 0xa2, 0x27, 0xe4, 0x26, 0x26, 0x23, 0x68, 0x22, 0xaa, 0x20, 0xec, 0x21, 0x2e,
0x2a, 0x70, 0x2b, 0xb2, 0x29, 0xf4, 0x28, 0x36, 0x2d, 0x78, 0x2c, 0xba, 0x2e, 0xfc, 0x2f, 0x3e,
0x70, 0x80, 0x71, 0x42, 0x73, 0x04, 0x72, 0xc6, 0x77, 0x88, 0x76, 0x4a, 0x74, 0x0c, 0x75, 0xce,
0x7e, 0x90, 0x7f, 0x52, 0x7d, 0x14, 0x7c, 0xd6, 0x79, 0x98, 0x78, 0x5a, 0x7a, 0x1c, 0x7b, 0xde,
0x6c, 0xa0, 0x6d, 0x62, 0x6f, 0x24, 0x6e, 0xe6, 0x6b, 0xa8, 0x6a, 0x6a, 0x68, 0x2c, 0x69, 0xee,
0x62, 0xb0, 0x63, 0x72, 0x61, 0x34, 0x60, 0xf6, 0x65, 0xb8, 0x64, 0x7a, 0x66, 0x3c, 0x67, 0xfe,
0x48, 0xc0, 0x49, 0x02, 0x4b, 0x44, 0x4a, 0x86, 0x4f, 0xc8, 0x4e, 0x0a, 0x4c, 0x4c, 0x4d, 0x8e,
0x46, 0xd0, 0x47, 0x12, 0x45, 0x54, 0x44, 0x96, 0x41, 0xd8, 0x40, 0x1a, 0x42, 0x5c, 0x43, 0x9e,
0x54, 0xe0, 0x55, 0x22, 0x57, 0x64, 0x56, 0xa6, 0x53, 0xe8, 0x52, 0x2a, 0x50, 0x6c, 0x51, 0xae,
0x5a, 0xf0, 0x5b, 0x32, 0x59, 0x74, 0x58, 0xb6, 0x5d, 0xf8, 0x5c, 0x3a, 0x5e, 0x7c, 0x5f, 0xbe,
0xe1, 0x00, 0xe0, 0xc2, 0xe2, 0x84, 0xe3, 0x46, 0xe6, 0x08, 0xe7, 0xca, 0xe5, 0x8c, 0xe4, 0x4e,
0xef, 0x10, 0xee, 0xd2, 0xec, 0x94, 0xed, 0x56, 0xe8, 0x18, 0xe9, 0xda, 0xeb, 0x9c, 0xea, 0x5e,
0xfd, 0x20, 0xfc, 0xe2, 0xfe, 0xa4, 0xff, 0x66, 0xfa, 0x28, 0xfb, 0xea, 0xf9, 0xac, 0xf8, 0x6e,
0xf3, 0x30, 0xf2, 0xf2, 0xf0, 0xb4, 0xf1, 0x76, 0xf4, 0x38, 0xf5, 0xfa, 0xf7, 0xbc, 0xf6, 0x7e,
0xd9, 0x40, 0xd8, 0x82, 0xda, 0xc4, 0xdb, 0x06, 0xde, 0x48, 0xdf, 0x8a, 0xdd, 0xcc, 0xdc, 0x0e,
0xd7, 0x50, 0xd6, 0x92, 0xd4, 0xd4, 0xd5, 0x16, 0xd0, 0x58, 0xd1, 0x9a, 0xd3, 0xdc, 0xd2, 0x1e,
0xc5, 0x60, 0xc4, 0xa2, 0xc6, 0xe4, 0xc7, 0x26, 0xc2, 0x68, 0xc3, 0xaa, 0xc1, 0xec, 0xc0, 0x2e,
0xcb, 0x70, 0xca, 0xb2, 0xc8, 0xf4, 0xc9, 0x36, 0xcc, 0x78, 0xcd, 0xba, 0xcf, 0xfc, 0xce, 0x3e,
0x91, 0x80, 0x90, 0x42, 0x92, 0x04, 0x93, 0xc6, 0x96, 0x88, 0x97, 0x4a, 0x95, 0x0c, 0x94, 0xce,
0x9f, 0x90, 0x9e, 0x52, 0x9c, 0x14, 0x9d, 0xd6, 0x98, 0x98, 0x99, 0x5a, 0x9b, 0x1c, 0x9a, 0xde,
0x8d, 0xa0, 0x8c, 0x62, 0x8e, 0x24, 0x8f, 0xe6, 0x8a, 0xa8, 0x8b, 0x6a, 0x89, 0x2c, 0x88, 0xee,
0x83, 0xb0, 0x82, 0x72, 0x80, 0x34, 0x81, 0xf6, 0x84, 0xb8, 0x85, 0x7a, 0x87, 0x3c, 0x86, 0xfe,
0xa9, 0xc0, 0xa8, 0x02, 0xaa, 0x44, 0xab, 0x86, 0xae, 0xc8, 0xaf, 0x0a, 0xad, 0x4c, 0xac, 0x8e,
0xa7, 0xd0, 0xa6, 0x12, 0xa4, 0x54, 0xa5, 0x96, 0xa0, 0xd8, 0xa1, 0x1a, 0xa3, 0x5c, 0xa2, 0x9e,
0xb5, 0xe0, 0xb4, 0x22, 0xb6, 0x64, 0xb7, 0xa6, 0xb2, 0xe8, 0xb3, 0x2a, 0xb1, 0x6c, 0xb0, 0xae,
0xbb, 0xf0, 0xba, 0x32, 0xb8, 0x74, 0xb9, 0xb6, 0xbc, 0xf8, 0xbd, 0x3a, 0xbf, 0x7c, 0xbe, 0xbe };

#endif


#if defined(LTC_GCM_MODE) || defined(LTC_LRW_MODE) || defined(LTC_GCM_SIV_MODE)


#ifndef LTC_FAST
/* right shift */
static void s_gcm_rightshift(unsigned char *a)
{
   int x;
   for (x = 15; x > 0; x--) {
       a[x] = (a[x]>>1) | ((a[x-1]<<7)&0x80);
   }
   a[0] >>= 1;
}

/* c = b*a */
static const unsigned char mask[] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
static const unsigned char poly[] = { 0x00, 0xE1 };


/**
  GCM GF multiplier (internal use only)  bitserial
  @param a   First value
  @param b   Second value
  @param c   Destination for a * b
 */
static void s_gcm_gf_mult_sw(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
   unsigned char Z[16], V[16];
   unsigned char x, y, z;

   zeromem(Z, 16);
   XMEMCPY(V, a, 16);
   for (x = 0; x < 128; x++) {
       if (b[x>>3] & mask[x&7]) {
          for (y = 0; y < 16; y++) {
              Z[y] ^= V[y];
          }
       }
       z     = V[15] & 0x01;
       s_gcm_rightshift(V);
       V[0] ^= poly[z];
   }
   XMEMCPY(c, Z, 16);
}

#else

/* map normal numbers to "ieee" way ... e.g. bit reversed */
#define M(x) ( ((x&8)>>3) | ((x&4)>>1) | ((x&2)<<1) | ((x&1)<<3) )

#define BPD (sizeof(LTC_FAST_TYPE) * 8)
#define WPV (1 + (16 / sizeof(LTC_FAST_TYPE)))

/**
  GCM GF multiplier (internal use only)  word oriented
  @param a   First value
  @param b   Second value
  @param c   Destination for a * b
 */
static void s_gcm_gf_mult_sw(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
   int i, j, k, u;
   LTC_FAST_TYPE B[16][WPV], tmp[32 / sizeof(LTC_FAST_TYPE)], pB[16 / sizeof(LTC_FAST_TYPE)], zz, z;
   unsigned char pTmp[32];

   /* create simple tables */
   zeromem(B[0],       sizeof(B[0]));
   zeromem(B[M(1)],    sizeof(B[M(1)]));

#ifdef ENDIAN_32BITWORD
   for (i = 0; i < 4; i++) {
       LOAD32H(B[M(1)][i], a + (i<<2));
       LOAD32L(pB[i],      b + (i<<2));
   }
#else
   for (i = 0; i < 2; i++) {
       LOAD64H(B[M(1)][i], a + (i<<3));
       LOAD64L(pB[i],      b + (i<<3));
   }
#endif

   /* now create 2, 4 and 8 */
   B[M(2)][0] = B[M(1)][0] >> 1;
   B[M(4)][0] = B[M(1)][0] >> 2;
   B[M(8)][0] = B[M(1)][0] >> 3;
   for (i = 1; i < (int)WPV; i++) {
      B[M(2)][i] = (B[M(1)][i-1] << (BPD-1)) | (B[M(1)][i] >> 1);
      B[M(4)][i] = (B[M(1)][i-1] << (BPD-2)) | (B[M(1)][i] >> 2);
      B[M(8)][i] = (B[M(1)][i-1] << (BPD-3)) | (B[M(1)][i] >> 3);
   }

   /*  now all values with two bits which are 3, 5, 6, 9, 10, 12 */
   for (i = 0; i < (int)WPV; i++) {
      B[M(3)][i]  = B[M(1)][i] ^ B[M(2)][i];
      B[M(5)][i]  = B[M(1)][i] ^ B[M(4)][i];
      B[M(6)][i]  = B[M(2)][i] ^ B[M(4)][i];
      B[M(9)][i]  = B[M(1)][i] ^ B[M(8)][i];
      B[M(10)][i] = B[M(2)][i] ^ B[M(8)][i];
      B[M(12)][i] = B[M(8)][i] ^ B[M(4)][i];

   /*  now all 3 bit values and the only 4 bit value: 7, 11, 13, 14, 15 */
      B[M(7)][i]  = B[M(3)][i] ^ B[M(4)][i];
      B[M(11)][i] = B[M(3)][i] ^ B[M(8)][i];
      B[M(13)][i] = B[M(1)][i] ^ B[M(12)][i];
      B[M(14)][i] = B[M(6)][i] ^ B[M(8)][i];
      B[M(15)][i] = B[M(7)][i] ^ B[M(8)][i];
   }

   zeromem(tmp, sizeof(tmp));

   /* compute product four bits of each word at a time */
   /* for each nibble */
   for (i = (BPD/4)-1; i >= 0; i--) {
       /* for each word */
       for (j = 0; j < (int)(WPV-1); j++) {
        /* grab the 4 bits recall the nibbles are backwards so it's a shift by (i^1)*4 */
           u = (pB[j] >> ((i^1)<<2)) & 15;

        /* add offset by the word count the table looked up value to the result */
           for (k = 0; k < (int)WPV; k++) {
               tmp[k+j] ^= B[u][k];
           }
       }
     /* shift result up by 4 bits */
       if (i != 0) {
          for (z = j = 0; j < (int)(32 / sizeof(LTC_FAST_TYPE)); j++) {
              zz = tmp[j] << (BPD-4);
              tmp[j] = (tmp[j] >> 4) | z;
              z = zz;
          }
       }
   }

   /* store product */
#ifdef ENDIAN_32BITWORD
   for (i = 0; i < 8; i++) {
       STORE32H(tmp[i], pTmp + (i<<2));
   }
#else
   for (i = 0; i < 4; i++) {
       STORE64H(tmp[i], pTmp + (i<<3));
   }
#endif

   /* reduce by taking most significant byte and adding the appropriate two byte sequence 16 bytes down */
   for (i = 31; i >= 16; i--) {
       pTmp[i-16] ^= gcm_shift_table[((unsigned)pTmp[i]<<1)];
       pTmp[i-15] ^= gcm_shift_table[((unsigned)pTmp[i]<<1)+1];
   }

   for (i = 0; i < 16; i++) {
       c[i] = pTmp[i];
   }

}

#undef M
#undef BPD
#undef WPV

#endif

/**
  GCM GF multiplier (internal use only)
  @param a   First value
  @param b   Second value
  @param c   Destination for a * b
 */
void gcm_gf_mult(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
#if defined(LTC_GCM_PCLMUL)
   if(s_pclmul_is_supported()) {
      s_gcm_gf_mult_pclmul(a, b, c);
      return;
   }
#endif
#if defined(LTC_GCM_PMULL)
   if(s_pmull_is_supported()) {
      s_gcm_gf_mult_pmull(a, b, c);
      return;
   }
#endif
   s_gcm_gf_mult_sw(a, b, c);
}


#endif

int gcm_hw_pmul_is_supported(void)
{
#if defined(LTC_GCM_PCLMUL_TARGET)
   return s_pclmul_is_supported();
#elif defined(LTC_GCM_PMULL_TARGET)
   return s_pmull_is_supported();
#else
   return 0;
#endif
}

