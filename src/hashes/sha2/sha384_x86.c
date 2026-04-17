/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/**
   @param sha384_x86.c
   LTC_SHA384 hash included in sha512_x86.c, Marek Knapek
*/

#include "tomcrypt_private.h"

#if defined(LTC_SHA384) && defined(LTC_SHA512) && defined(LTC_SHA384_X86)

const struct ltc_hash_descriptor sha384_x86_desc =
{
    "sha384",
    4,
    48,
    128,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 2,  },
   9,

    &sha384_x86_init,
    &sha512_x86_process,
    &sha384_x86_done,
    &sha384_x86_test,
    NULL
};

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha384_x86_init(hash_state * md)
{
    LTC_ARGCHK(md != NULL);

    md->sha512.state = LTC_ALIGN_BUF(md->sha512.state_buf, 32);
    md->sha512.curlen = 0;
    md->sha512.length = 0;
    md->sha512.state[0] = CONST64(0xcbbb9d5dc1059ed8);
    md->sha512.state[1] = CONST64(0x629a292a367cd507);
    md->sha512.state[2] = CONST64(0x9159015a3070dd17);
    md->sha512.state[3] = CONST64(0x152fecd8f70e5939);
    md->sha512.state[4] = CONST64(0x67332667ffc00b31);
    md->sha512.state[5] = CONST64(0x8eb44a8768581511);
    md->sha512.state[6] = CONST64(0xdb0c2e0d64f98fa7);
    md->sha512.state[7] = CONST64(0x47b5481dbefa4fa4);
    return CRYPT_OK;
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (48 bytes)
   @return CRYPT_OK if successful
*/
int sha384_x86_done(hash_state * md, unsigned char *out)
{
   unsigned char buf[64];

   LTC_ARGCHK(md  != NULL);
   LTC_ARGCHK(out != NULL);

    if (md->sha512.curlen >= sizeof(md->sha512.buf)) {
       return CRYPT_INVALID_ARG;
    }

   sha512_x86_done(md, buf);
   XMEMCPY(out, buf, 48);
#ifdef LTC_CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return CRYPT_OK;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int sha384_x86_test(void)
{
   return sha384_test_desc(&sha384_x86_desc, "SHA384 x86");
}

#endif /* defined(LTC_SHA384) && defined(LTC_SHA512) && defined(LTC_SHA384_X86) */
