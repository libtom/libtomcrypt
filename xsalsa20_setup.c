/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/* The implementation is based on:
 * "Extending the Salsa20 nonce", https://cr.yp.to/snuffle/xsalsa-20081128.pdf
 * "Salsa20 specification", http://cr.yp.to/snuffle/spec.pdf
 * and salsa20-ref.c version 20051118
 * Public domain from D. J. Bernstein
 */

#include "tomcrypt.h"

#ifdef LTC_XSALSA20

static const char * const constants = "expand 32-byte k";

#define QUARTERROUND(a,b,c,d) \
    x[b] ^= (ROL((x[a] + x[d]),  7)); \
    x[c] ^= (ROL((x[b] + x[a]),  9)); \
    x[d] ^= (ROL((x[c] + x[b]), 13)); \
    x[a] ^= (ROL((x[d] + x[c]), 18));

/* use modified salsa20 doubleround (no final addition as in salsa20) */
static void _xsalsa20_doubleround(ulong32 *x, int rounds) {
   for (int i = rounds; i > 0; i -= 2) {
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
   Initialize an XSalsa20 context
   @param st        [out] The destination of the XSalsa20 state
   @param key       The secret key
   @param keylen    The length of the secret key, must be 32 (octets)
   @param nonce     The nonce
   @param noncelen  The length of the nonce, must be 24 (octets)
   @param rounds    Number of rounds (e.g. 20 for Salsa20)
   @param subkey    [out] The subkey, NULL if not want a copy 
   @return CRYPT_OK if successful
*/
int xsalsa20_setup(salsa20_state *st, 
                   const unsigned char *key, unsigned long keylen, 
                   const unsigned char *nonce,    unsigned long noncelen, 
                   int rounds, unsigned char *subkey) {
   unsigned char secondkey[32];
   ulong32       x[64];                     /* input to & output fm doubleround */
   int sti[] = {0, 5, 10, 15, 6, 7, 8, 9};  /* indices used to build subkey fm x */

   LTC_ARGCHK(st        != NULL);
   LTC_ARGCHK(secondkey != NULL);
   LTC_ARGCHK(key  != NULL);
   LTC_ARGCHK(keylen    == 32);
   LTC_ARGCHK(nonce     != NULL);
   LTC_ARGCHK(noncelen  == 24);

   if (rounds == 0) rounds = 20;
   LTC_ARGCHK(rounds % 2 == 0); /* number of rounds must be evenly divisible by 2 */

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
   LOAD32L(x[ 6], nonce +  0);
   LOAD32L(x[ 7], nonce +  4);
   LOAD32L(x[ 8], nonce +  8);
   LOAD32L(x[ 9], nonce + 12);

   /* use modified salsa20 doubleround (no final addition) */
   _xsalsa20_doubleround(x, rounds);

   for (int i = 0; i < 8; ++i) {
     STORE32L(x[sti[i]], secondkey + 4 * i);
   }

   /* this is equivalent to... */
   LOAD32L(st->input[ 0], constants +  0);
   LOAD32L(st->input[ 5], constants +  4);
   LOAD32L(st->input[10], constants +  8);
   LOAD32L(st->input[15], constants + 12);
   LOAD32L(st->input[ 1], secondkey +  0);
   LOAD32L(st->input[ 2], secondkey +  4);
   LOAD32L(st->input[ 3], secondkey +  8);
   LOAD32L(st->input[ 4], secondkey + 12);
   LOAD32L(st->input[11], secondkey + 16);
   LOAD32L(st->input[12], secondkey + 20);
   LOAD32L(st->input[13], secondkey + 24);
   LOAD32L(st->input[14], secondkey + 28);
   LOAD32L(st->input[ 6], &(nonce[16]) + 0);
   LOAD32L(st->input[ 7], &(nonce[16]) + 4);
   st->input[ 8] = 0;
   st->input[ 9] = 0;
   /* ...this... 
       salsa20_setup(st, secondkey, 32, rounds);
       salsa20_ivctr64(st, &nonce[16], 8, 0);
   */
   st->rounds = rounds;
   st->ksleft = 0;
   st->ivlen = 8;           /* set switch to say nonce/IV has been loaded */

   /* copy out subkey if not NULL */
   if (subkey != NULL) XMEMCPY(subkey, secondkey, sizeof(secondkey));
   return CRYPT_OK;
}


#endif

/* ref:         HEAD -> develop */
/* git commit:  af67321bf3cde1a470c679e459ebb8189e38c9bd */
/* commit time: 2018-04-13 09:42:47 +0200 */
