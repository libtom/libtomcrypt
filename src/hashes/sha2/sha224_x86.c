/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/**
   @param sha224.c
   LTC_SHA-224 new NIST standard based off of LTC_SHA-256 truncated to 224 bits (Tom St Denis)
*/

#include "tomcrypt_private.h"

#if defined(LTC_SHA224) && defined(LTC_SHA256) && defined(LTC_SHA224_X86)

const struct ltc_hash_descriptor sha224_x86_desc =
{
    "sha224",
    10,
    28,
    64,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 4,  },
   9,

    &sha224_x86_init,
    &sha256_x86_process,
    &sha224_x86_done,
    &sha224_x86_test,
    NULL
};

/* init the sha256 er... sha224 state ;-) */
/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha224_x86_init(hash_state * md)
{
    LTC_ARGCHK(md != NULL);

    md->sha256.state = LTC_ALIGN_BUF(md->sha256.state_buf, 16);

    md->sha256.curlen = 0;
    md->sha256.length = 0;
    md->sha256.state[0] = 0xc1059ed8UL;
    md->sha256.state[1] = 0x367cd507UL;
    md->sha256.state[2] = 0x3070dd17UL;
    md->sha256.state[3] = 0xf70e5939UL;
    md->sha256.state[4] = 0xffc00b31UL;
    md->sha256.state[5] = 0x68581511UL;
    md->sha256.state[6] = 0x64f98fa7UL;
    md->sha256.state[7] = 0xbefa4fa4UL;
    return CRYPT_OK;
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (28 bytes)
   @return CRYPT_OK if successful
*/
int sha224_x86_done(hash_state * md, unsigned char *out)
{
    unsigned char buf[32];
    int err;

    LTC_ARGCHK(md  != NULL);
    LTC_ARGCHK(out != NULL);

    err = sha256_done(md, buf);
    XMEMCPY(out, buf, 28);
#ifdef LTC_CLEAN_STACK
    zeromem(buf, sizeof(buf));
#endif
    return err;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha224_x86_test(void)
{
   return sha224_test_desc(&sha224_x86_desc, "SHA224 x86");
}

#endif /* defined(LTC_SHA224) && defined(LTC_SHA256) */

