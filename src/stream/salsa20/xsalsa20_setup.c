/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* The implementation is based on:
 * "Extending the Salsa20 nonce", https://cr.yp.to/snuffle/xsalsa-20081128.pdf
 * "Salsa20 specification", http://cr.yp.to/snuffle/spec.pdf
 * and salsa20-ref.c version 20051118
 * Public domain from D. J. Bernstein
 */

#include "tomcrypt.h"

#ifdef LTC_XSALSA20

#define QUARTERROUND(a,b,c,d) \
    x[b] ^= (ROL((x[a] + x[d]),  7)); \
    x[c] ^= (ROL((x[b] + x[a]),  9)); \
    x[d] ^= (ROL((x[c] + x[b]), 13)); \
    x[a] ^= (ROL((x[d] + x[c]), 18));

/* use modified salsa20 doubleround (no final addition as in salsa20) */
static void s_xsalsa20_doubleround(ulong32 *x, int rounds)
{
   int i;

   for (i = rounds; i > 0; i -= 2) {
      /* columnround */
      QUARTERROUND( 0, 4, 8,12)
      QUARTERROUND( 5, 9,13, 1)
      QUARTERROUND(10,14, 2, 6)
      QUARTERROUND(15, 3, 7,11)
      /* rowround */
      QUARTERROUND( 0, 1, 2, 3)
      QUARTERROUND( 5, 6, 7, 4)
      QUARTERROUND(10,11, 8, 9)
      QUARTERROUND(15,12,13,14)
   }
}

#undef QUARTERROUND

/**
   HSalsa20: derive a 256-bit subkey from a 256-bit key and 128-bit input.
   This is the Salsa20 core (double-rounds) without the final addition step,
   extracting output from state positions {0,5,10,15,6,7,8,9}.
   @param out       [out] The derived 32-byte subkey
   @param outlen    The length of the output buffer, must be 32 (octets)
   @param key       The secret key
   @param keylen    The length of the secret key, must be 32 (octets)
   @param in        The 16-byte input (nonce or constant)
   @param inlen     The length of the input, must be 16 (octets)
   @param rounds    Number of rounds (must be evenly divisible by 2, default is 20)
   @return CRYPT_OK if successful
*/
int xsalsa20_hsalsa20(unsigned char *out,  unsigned long outlen,
                       const unsigned char *key, unsigned long keylen,
                       const unsigned char *in,  unsigned long inlen,
                       int rounds)
{
   const char * const constants = "expand 32-byte k";
   const int sti[] = {0, 5, 10, 15, 6, 7, 8, 9};
   ulong32 x[16];
   int i;

   LTC_ARGCHK(out != NULL);
   LTC_ARGCHK(outlen == 32);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(keylen == 32);
   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(inlen == 16);
   if (rounds == 0) rounds = 20;
   LTC_ARGCHK(rounds % 2 == 0);

   LOAD32L(x[ 0], constants +  0);
   LOAD32L(x[ 5], constants +  4);
   LOAD32L(x[10], constants +  8);
   LOAD32L(x[15], constants + 12);
   LOAD32L(x[ 1], key +  0);
   LOAD32L(x[ 2], key +  4);
   LOAD32L(x[ 3], key +  8);
   LOAD32L(x[ 4], key + 12);
   LOAD32L(x[11], key + 16);
   LOAD32L(x[12], key + 20);
   LOAD32L(x[13], key + 24);
   LOAD32L(x[14], key + 28);
   LOAD32L(x[ 6], in +  0);
   LOAD32L(x[ 7], in +  4);
   LOAD32L(x[ 8], in +  8);
   LOAD32L(x[ 9], in + 12);

   s_xsalsa20_doubleround(x, rounds);

   for (i = 0; i < 8; ++i) {
      STORE32L(x[sti[i]], out + 4 * i);
   }

   zeromem(x, sizeof(x));
   return CRYPT_OK;
}

/**
   Initialize an XSalsa20 context
   @param st        [out] The destination of the XSalsa20 state
   @param key       The secret key
   @param keylen    The length of the secret key, must be 32 (octets)
   @param nonce     The nonce
   @param noncelen  The length of the nonce, must be 24 (octets)
   @param rounds    Number of rounds (must be evenly divisible by 2, default is 20)
   @return CRYPT_OK if successful
*/
int xsalsa20_setup(salsa20_state *st, const unsigned char *key, unsigned long keylen,
                                      const unsigned char *nonce, unsigned long noncelen,
                                      int rounds)
{
   const char * const constants = "expand 32-byte k";
   unsigned char subkey[32];
   int err;

   LTC_ARGCHK(st != NULL);
   LTC_ARGCHK(nonce != NULL);
   LTC_ARGCHK(noncelen == 24);
   if (rounds == 0) rounds = 20;

   /* HSalsa20: derive subkey from key and first 16 bytes of nonce */
   if ((err = xsalsa20_hsalsa20(subkey, 32, key, keylen, nonce, 16, rounds)) != CRYPT_OK) goto cleanup;

   /* load the final initial state with the derived subkey */
   LOAD32L(st->input[ 0], constants +  0);
   LOAD32L(st->input[ 5], constants +  4);
   LOAD32L(st->input[10], constants +  8);
   LOAD32L(st->input[15], constants + 12);
   LOAD32L(st->input[ 1], subkey +  0);
   LOAD32L(st->input[ 2], subkey +  4);
   LOAD32L(st->input[ 3], subkey +  8);
   LOAD32L(st->input[ 4], subkey + 12);
   LOAD32L(st->input[11], subkey + 16);
   LOAD32L(st->input[12], subkey + 20);
   LOAD32L(st->input[13], subkey + 24);
   LOAD32L(st->input[14], subkey + 28);
   LOAD32L(st->input[ 6], &(nonce[16]) + 0);
   LOAD32L(st->input[ 7], &(nonce[16]) + 4);
   st->input[ 8] = 0;
   st->input[ 9] = 0;
   st->rounds = rounds;
   st->ksleft = 0;
   st->ivlen  = 24;           /* set switch to say nonce/IV has been loaded */

cleanup:
#ifdef LTC_CLEAN_STACK
   zeromem(subkey, sizeof(subkey));
#endif

   return err;
}


#endif
