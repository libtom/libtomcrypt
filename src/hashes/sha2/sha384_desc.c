/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/**
   @param sha384.c
   LTC_SHA384 hash included in sha512.c, Tom St Denis
*/

#include "tomcrypt_private.h"

#if defined(LTC_SHA384) && defined(LTC_SHA512)

const struct ltc_hash_descriptor sha384_desc =
{
    "sha384",
    4,
    48,
    128,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 2,  },
   9,

    &sha384_init,
    &sha512_process,
    &sha384_done,
    &sha384_test,
    NULL
};

#if defined LTC_SHA384_X86

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

static LTC_INLINE int s_sha384_x86_is_supported(void)
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
#endif /* LTC_SHA384_X86 */

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha384_init(hash_state * md)
{
#if defined LTC_SHA384_X86
    if(s_sha384_x86_is_supported()) {
        return sha384_x86_init(md);
    }
#endif
    return sha384_c_init(md);
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (48 bytes)
   @return CRYPT_OK if successful
*/
int sha384_done(hash_state * md, unsigned char *out)
{
#if defined LTC_SHA384_X86
    if(s_sha384_x86_is_supported()) {
        return sha384_x86_done(md, out);
    }
#endif
    return sha384_c_done(md, out);
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha384_test(void)
{
   return sha384_test_desc(&sha384_desc, "SHA384");
}

int sha384_test_desc(const struct ltc_hash_descriptor *desc, const char *name)
{
 #ifndef LTC_TEST
    LTC_UNUSED_PARAM(desc);
    LTC_UNUSED_PARAM(name);
    return CRYPT_NOP;
 #else
  static const struct {
      const char *msg;
      unsigned char hash[48];
  } tests[] = {
    { "abc",
      { 0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
        0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
        0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7 }
    },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      { 0x09, 0x33, 0x0c, 0x33, 0xf7, 0x11, 0x47, 0xe8,
        0x3d, 0x19, 0x2f, 0xc7, 0x82, 0xcd, 0x1b, 0x47,
        0x53, 0x11, 0x1b, 0x17, 0x3b, 0x3b, 0x05, 0xd2,
        0x2f, 0xa0, 0x80, 0x86, 0xe3, 0xb0, 0xf7, 0x12,
        0xfc, 0xc7, 0xc7, 0x1a, 0x55, 0x7e, 0x2d, 0xb9,
        0x66, 0xc3, 0xe9, 0xfa, 0x91, 0x74, 0x60, 0x39 }
    },
  };

  int i;
  unsigned char tmp[48];
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

#endif /* defined(LTC_SHA384) && defined(LTC_SHA512) */
