/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/**
   @param sha512_256_x86.c
   SHA512/256 hash included in sha512_x86.c
*/

#include "tomcrypt_private.h"

#if defined(LTC_SHA512_256) && defined(LTC_SHA512) && defined(LTC_SHA512_256_X86)

const struct ltc_hash_descriptor sha512_256_x86_desc =
{
    "sha512-256",
    16,
    32,
    128,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 6,  },
   9,

    &sha512_256_x86_init,
    &sha512_x86_process,
    &sha512_256_x86_done,
    &sha512_256_x86_test,
    NULL
};

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha512_256_x86_init(hash_state * md)
{
    LTC_ARGCHK(md != NULL);

    md->sha512.state = LTC_ALIGN_BUF(md->sha512.state_buf, 32);
    md->sha512.curlen = 0;
    md->sha512.length = 0;
    md->sha512.state[0] = CONST64(0x22312194FC2BF72C);
    md->sha512.state[1] = CONST64(0x9F555FA3C84C64C2);
    md->sha512.state[2] = CONST64(0x2393B86B6F53B151);
    md->sha512.state[3] = CONST64(0x963877195940EABD);
    md->sha512.state[4] = CONST64(0x96283EE2A88EFFE3);
    md->sha512.state[5] = CONST64(0xBE5E1E2553863992);
    md->sha512.state[6] = CONST64(0x2B0199FC2C85B8AA);
    md->sha512.state[7] = CONST64(0x0EB72DDC81C52CA2);
    return CRYPT_OK;
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (48 bytes)
   @return CRYPT_OK if successful
*/
int sha512_256_x86_done(hash_state * md, unsigned char *out)
{
   unsigned char buf[64];

   LTC_ARGCHK(md  != NULL);
   LTC_ARGCHK(out != NULL);

    if (md->sha512.curlen >= sizeof(md->sha512.buf)) {
       return CRYPT_INVALID_ARG;
    }

   sha512_x86_done(md, buf);
   XMEMCPY(out, buf, 32);
#ifdef LTC_CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return CRYPT_OK;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha512_256_x86_test(void)
{
   return sha512_256_test_desc(&sha512_256_x86_desc, "SHA512-256 x86");
}

#endif /* defined(LTC_SHA512_256) && defined(LTC_SHA512) && defined(LTC_SHA512_256_X86) */

