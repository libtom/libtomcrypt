/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_SHA256

const struct ltc_hash_descriptor sha256_desc =
{
    "sha256",
    0,
    32,
    64,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 1,  },
   9,

    &sha256_init,
    &sha256_process,
    &sha256_done,
    &sha256_test,
    NULL
};

#if defined LTC_SHA256_X86

#if !defined (LTC_S_X86_CPUID)
#define LTC_S_X86_CPUID
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

static LTC_INLINE int s_sha256_x86_is_supported(void)
{
    static int initialized = 0;
    static int is_supported = 0;

    if (initialized == 0) {
        int regs[4];
        int sse2, ssse3, sse41, sha;
        /* Leaf 0, Reg 0 contains the number of leafs available */
        s_x86_cpuid(regs, 0);
        if(regs[0] >= 7) {
           s_x86_cpuid(regs, 1);
           sse2  = ((((unsigned int)(regs[3])) >> 26) & 1u) != 0; /* SSE2,   leaf 1, edx, bit 26 */
           ssse3 = ((((unsigned int)(regs[2])) >>  9) & 1u) != 0; /* SSSE3,  leaf 1, ecx, bit  9 */
           sse41 = ((((unsigned int)(regs[2])) >> 19) & 1u) != 0; /* SSE4.1, leaf 1, ecx, bit 19 */
           s_x86_cpuid(regs, 7);
           sha = ((((unsigned int)(regs[1])) >> 29) & 1u) != 0; /* SHA, leaf 7, ebx, bit 29 */
           is_supported = sse2 && ssse3 && sse41 && sha;
        }
        initialized = 1;
    }
    return is_supported;
}
#endif /* LTC_SHA256_X86 */

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha256_init(hash_state * md)
{
#if defined LTC_SHA256_X86
    if(s_sha256_x86_is_supported()) {
        return sha256_x86_init(md);
    }
#endif
    return sha256_c_init(md);
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
int sha256_process(hash_state * md, const unsigned char *in, unsigned long inlen)
{
#if defined LTC_SHA256_X86
    if(s_sha256_x86_is_supported()) {
        return sha256_x86_process(md, in, inlen);
    }
#endif
    return sha256_c_process(md, in, inlen);
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (32 bytes)
   @return CRYPT_OK if successful
*/
int sha256_done(hash_state * md, unsigned char *out)
{
#if defined LTC_SHA256_X86
    if(s_sha256_x86_is_supported()) {
        return sha256_x86_done(md, out);
    }
#endif
    return sha256_c_done(md, out);
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha256_test(void)
{
   return sha256_test_desc(&sha256_desc, "SHA256");
}

int sha256_test_desc(const struct ltc_hash_descriptor *desc, const char *name)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   static const struct {
       const char *msg;
       unsigned char hash[32];
   } tests[] = {
     { "abc",
      { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad }
    },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 }
    },
   };

   int i;
   unsigned char tmp[32];
   hash_state md;

   LTC_ARGCHK(desc != NULL);
   LTC_ARGCHK(desc->init != NULL);
   LTC_ARGCHK(desc->process != NULL);
   LTC_ARGCHK(desc->done != NULL);
   LTC_ARGCHK(name != NULL);

   for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0]));  i++) {
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
