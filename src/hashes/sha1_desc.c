/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_SHA1

const struct ltc_hash_descriptor sha1_desc =
{
    "sha1",
    2,
    20,
    64,

    /* OID */
   { 1, 3, 14, 3, 2, 26,  },
   6,

    &sha1_init,
    &sha1_process,
    &sha1_done,
    &sha1_test,
    NULL
};

#if defined LTC_SHA1_X86

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

static LTC_INLINE int s_sha1_x86_is_supported(void)
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
#endif /* LTC_SHA1_X86 */

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha1_init(hash_state * md)
{
#if defined LTC_SHA1_X86
    if(s_sha1_x86_is_supported()) {
        return sha1_x86_init(md);
    }
#endif
    return sha1_c_init(md);
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
int sha1_process(hash_state * md, const unsigned char *in, unsigned long inlen)
{
#if defined LTC_SHA1_X86
    if(s_sha1_x86_is_supported()) {
        return sha1_x86_process(md, in, inlen);
    }
#endif
    return sha1_c_process(md, in, inlen);
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (20 bytes)
   @return CRYPT_OK if successful
*/
int sha1_done(hash_state * md, unsigned char *out)
{
#if defined LTC_SHA1_X86
    if(s_sha1_x86_is_supported()) {
        return sha1_x86_done(md, out);
    }
#endif
    return sha1_c_done(md, out);
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha1_test(void)
{
   return sha1_test_desc(&sha1_desc, "SHA1");
}

int sha1_test_desc(const struct ltc_hash_descriptor *desc, const char *name)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   static const struct {
       const char *msg;
       unsigned char hash[20];
   } tests[] = {
     { "abc",
       { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
         0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
         0x9c, 0xd0, 0xd8, 0x9d }
     },
     { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E,
         0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5,
         0xE5, 0x46, 0x70, 0xF1 }
     }
   };

   int i;
   unsigned char tmp[20];
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
