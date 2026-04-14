/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/**
   @param sha224.c
   LTC_SHA-224 new NIST standard based off of LTC_SHA-256 truncated to 224 bits (Tom St Denis)
*/

#include "tomcrypt_private.h"

#if defined(LTC_SHA224) && defined(LTC_SHA256)

const struct ltc_hash_descriptor sha224_desc =
{
    "sha224",
    10,
    28,
    64,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 4,  },
   9,

    &sha224_init,
    &sha256_process,
    &sha224_done,
    &sha224_test,
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

static LTC_INLINE int s_sha224_x86_is_supported(void)
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
#endif /* LTC_SHA224_X86 */

/* init the sha256 er... sha224 state ;-) */
/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha224_init(hash_state * md)
{
#if defined LTC_SHA224_X86
    if(s_sha224_x86_is_supported()) {
        return sha224_x86_init(md);
    }
#endif
    return sha224_c_init(md);
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (28 bytes)
   @return CRYPT_OK if successful
*/
int sha224_done(hash_state * md, unsigned char *out)
{
#if defined LTC_SHA224_X86
    if(s_sha224_x86_is_supported()) {
        return sha224_x86_done(md, out);
    }
#endif
    return sha224_c_done(md, out);
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha224_test(void)
{
   return sha224_test_desc(&sha224_desc, "SHA224");
}

int sha224_test_desc(const struct ltc_hash_descriptor *desc, const char *name)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else
  static const struct {
      const char *msg;
      unsigned char hash[28];
  } tests[] = {
    { "abc",
      { 0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8,
        0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
        0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd,
        0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7 }
    },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      { 0x75, 0x38, 0x8b, 0x16, 0x51, 0x27, 0x76,
        0xcc, 0x5d, 0xba, 0x5d, 0xa1, 0xfd, 0x89,
        0x01, 0x50, 0xb0, 0xc6, 0x45, 0x5c, 0xb4,
        0xf5, 0x8b, 0x19, 0x52, 0x52, 0x25, 0x25 }
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
       if (ltc_compare_testvector(tmp, 28, tests[i].hash, sizeof(tests[i].hash), name, i)) {
          return CRYPT_FAIL_TESTVECTOR;
       }
   }
   return CRYPT_OK;
#endif
}

#endif /* defined(LTC_SHA224) && defined(LTC_SHA256) */

