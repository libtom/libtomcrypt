/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @param sha512.c
   SHA512 by Tom St Denis
*/

#if defined LTC_ARCH_X86

#if !defined (LTC_S_X86_CPUID)
#define LTC_S_X86_CPUID
#if defined _MSC_VER
#include <intrin.h>
#endif
static LTC_INLINE void s_x86_cpuid(int* regs, int leaf)
{
#if defined _MSC_VER
   __cpuid(regs, leaf);
#else
    int a, b, c, d;

    a = leaf;
    b = c = d = 0;
    asm volatile ("cpuid"
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

#if !defined (LTC_S_X86_CPUIDEX)
#define LTC_S_X86_CPUIDEX
#if defined _MSC_VER
#include <intrin.h>
#endif
static LTC_INLINE void s_x86_cpuidex(int* regs, int eax, int ecx)
{
#if defined _MSC_VER
   __cpuidex(regs, eax, ecx);
#else
    int a, b, c, d;

    a = eax;
    c = ecx;
    b = d = 0;
    asm volatile ("cpuid"
        :"=a"(a), "=b"(b), "=c"(c), "=d"(d)
        :"0"(a), "2"(c)
    );
    regs[0] = a;
    regs[1] = b;
    regs[2] = c;
    regs[3] = d;
#endif
}
#endif /* LTC_S_X86_CPUIDEX */

static LTC_INLINE int s_sha512_x86_is_supported(void)
{
    static int initialized = 0;
    static int is_supported = 0;

    if (initialized == 0) {
        int regs[4];
        int sse2, avx, avx2, sha512;
        /* Leaf 0, Reg 0 contains the number of leafs available */
        s_x86_cpuid(regs, 0);
        if(regs[0] >= 7) {
           s_x86_cpuid(regs, 1);
           sse2 = ((((unsigned int)(regs[3])) >> 26) & 1u) != 0; /* SSE2, leaf 1, edx, bit 26 */
           avx  = ((((unsigned int)(regs[2])) >> 28) & 1u) != 0; /* AVX,  leaf 1, ecx, bit 28 */
           s_x86_cpuid(regs, 7);
           avx2 = ((((unsigned int)(regs[1])) >> 5) & 1u) != 0; /* AVX2, leaf 7, ebx, bit 5 */
           /* Leaf 7, Reg 0 contains the number of sub leafs available */
           if(regs[0] >= 1)
           {
             s_x86_cpuidex(regs, 7, 1);
             sha512 = ((((unsigned int)(regs[0])) >> 0) & 1u) != 0; /* SHA-512, leaf 7, sub leaf 1, eax, bit 0 */
             is_supported = sse2 && avx && avx2 && sha512;
           }
        }
        initialized = 1;
    }
    return is_supported;
}

#endif /* LTC_ARCH_X86 */

int sha512ni_is_supported(void)
{
#ifdef LTC_ARCH_X86
   return s_sha512_x86_is_supported();
#else
   return 0;
#endif
}

#ifdef LTC_SHA512

const struct ltc_hash_descriptor sha512_desc =
{
    "sha512",
    5,
    64,
    128,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 3,  },
   9,

    &sha512_init,
    &sha512_process,
    &sha512_done,
    &sha512_test,
    NULL
};

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha512_init(hash_state * md)
{
#if defined LTC_SHA512_X86
    if(s_sha512_x86_is_supported()) {
        return sha512_x86_init(md);
    }
#endif
    return sha512_c_init(md);
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
int sha512_process(hash_state * md, const unsigned char *in, unsigned long inlen)
{
#if defined LTC_SHA512_X86
    if(s_sha512_x86_is_supported()) {
        return sha512_x86_process(md, in, inlen);
    }
#endif
    return sha512_c_process(md, in, inlen);
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (64 bytes)
   @return CRYPT_OK if successful
*/
int sha512_done(hash_state * md, unsigned char *out)
{
#if defined LTC_SHA512_X86
    if(s_sha512_x86_is_supported()) {
        return sha512_x86_done(md, out);
    }
#endif
    return sha512_c_done(md, out);
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha512_test(void)
{
   return sha512_test_desc(&sha512_desc, "SHA512");
}

int sha512_test_desc(const struct ltc_hash_descriptor *desc, const char *name)
{
 #ifndef LTC_TEST
    LTC_UNUSED_PARAM(desc);
    LTC_UNUSED_PARAM(name);
    return CRYPT_NOP;
 #else
  static const struct {
      const char *msg;
      unsigned char hash[64];
  } tests[] = {
    { "abc",
     { 0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
       0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
       0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
       0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
       0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
       0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
       0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
       0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f }
    },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     { 0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda,
       0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
       0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1,
       0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
       0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4,
       0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
       0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
       0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09 }
    },
  };

  int i;
  unsigned char tmp[64];
  hash_state md;

  for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
       desc->init(&md);
       desc->process(&md, (unsigned char*)tests[i].msg, (unsigned long)XSTRLEN(tests[i].msg));
       desc->done(&md, tmp);
       if (ltc_compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), name, i)) {
         return CRYPT_FAIL_TESTVECTOR;
      }
  }
  return CRYPT_OK;
  #endif
}

#endif
