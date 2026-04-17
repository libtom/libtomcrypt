/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/**
   @param sha512_224.c
   SHA512/224 hash included in sha512.c
*/

#include "tomcrypt_private.h"

#if defined(LTC_SHA512_224) && defined(LTC_SHA512)

const struct ltc_hash_descriptor sha512_224_desc =
{
    "sha512-224",
    15,
    28,
    128,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 5,  },
   9,

    &sha512_224_init,
    &sha512_process,
    &sha512_224_done,
    &sha512_224_test,
    NULL
};

#if defined LTC_SHA512_224_X86

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

static LTC_INLINE int s_sha512_224_x86_is_supported(void)
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
#endif /* LTC_SHA512_224_X86 */

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha512_224_init(hash_state * md)
{
#if defined LTC_SHA512_224_X86
    if(s_sha512_224_x86_is_supported()) {
        return sha512_224_x86_init(md);
    }
#endif
    return sha512_224_c_init(md);
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (48 bytes)
   @return CRYPT_OK if successful
*/
int sha512_224_done(hash_state * md, unsigned char *out)
{
#if defined LTC_SHA512_224_X86
    if(s_sha512_224_x86_is_supported()) {
        return sha512_224_x86_done(md, out);
    }
#endif
    return sha512_224_c_done(md, out);
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int  sha512_224_test(void)
{
   return sha512_224_test_desc(&sha512_224_desc, "SHA512-224");
}

int sha512_224_test_desc(const struct ltc_hash_descriptor *desc, const char *name)
{
 #ifndef LTC_TEST
    LTC_UNUSED_PARAM(desc);
    LTC_UNUSED_PARAM(name);
    return CRYPT_NOP;
 #else
  static const struct {
      const char *msg;
      unsigned char hash[28];
  } tests[] = {
    { "abc",
      { 0x46, 0x34, 0x27, 0x0F, 0x70, 0x7B, 0x6A, 0x54,
        0xDA, 0xAE, 0x75, 0x30, 0x46, 0x08, 0x42, 0xE2,
        0x0E, 0x37, 0xED, 0x26, 0x5C, 0xEE, 0xE9, 0xA4,
        0x3E, 0x89, 0x24, 0xAA }
    },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      { 0x23, 0xFE, 0xC5, 0xBB, 0x94, 0xD6, 0x0B, 0x23,
        0x30, 0x81, 0x92, 0x64, 0x0B, 0x0C, 0x45, 0x33,
        0x35, 0xD6, 0x64, 0x73, 0x4F, 0xE4, 0x0E, 0x72,
        0x68, 0x67, 0x4A, 0xF9 }
    },
  };

  int i;
  unsigned char tmp[28];
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

#endif /* defined(LTC_SHA512_224) && defined(LTC_SHA512) */
