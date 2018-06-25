/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

/**
  @file crypt_helper_functions.c

  A home for the "one call" and other helper functions.
  Larry Bugbee - June 2018
*/

/* ======================================================================== */

#ifdef LTC_SALSA20

int salsa20_onecall(const unsigned char *key,    unsigned long keylen,
                    const unsigned char *iv,     unsigned long ivlen,
                    const unsigned char *datain, unsigned long datalen,
                    unsigned long rounds,
                    unsigned char *dataout)
{
   salsa20_state state;
   int err;

   if ((err = salsa20_setup(&state, key, keylen, rounds))      != CRYPT_OK) return err;
   if ((err = salsa20_ivctr64(&state, iv, ivlen, 0))           != CRYPT_OK) return err;
   if ((err = salsa20_crypt(&state, datain, datalen, dataout)) != CRYPT_OK) return err;
   if ((err = salsa20_done(&state))                            != CRYPT_OK) return err;

   return CRYPT_OK;
}

#endif

#ifdef LTC_XSALSA20

int xsalsa20_onecall(const unsigned char *key,    unsigned long keylen,
                     const unsigned char *nonce,  unsigned long noncelen,
                     const unsigned char *datain, unsigned long datalen,
                     unsigned long rounds,
                     unsigned char *dataout)
{
   salsa20_state state;
   int err;

   if ((err = xsalsa20_setup(&state, key, keylen, nonce, noncelen, rounds)) != CRYPT_OK) return err;
   if ((err = salsa20_crypt(&state, datain, datalen, dataout))              != CRYPT_OK) return err;
   if ((err = salsa20_done(&state))                                         != CRYPT_OK) return err;

   return CRYPT_OK;
}

#endif

#ifdef LTC_SOSEMANUK

int sosemanuk_onecall(const unsigned char *key,    unsigned long keylen,
                      const unsigned char *iv,     unsigned long ivlen,
                      const unsigned char *datain, unsigned long datalen,
                      unsigned char *dataout)
{
   sosemanuk_state state;
   int err;

   if ((err = sosemanuk_setup(&state, key, keylen))              != CRYPT_OK) return err;
   if ((err = sosemanuk_setiv(&state, iv, ivlen))                != CRYPT_OK) return err;
   if ((err = sosemanuk_crypt(&state, datain, datalen, dataout)) != CRYPT_OK) return err;
   if ((err = sosemanuk_done(&state))                            != CRYPT_OK) return err;

   return CRYPT_OK;
}

#endif

/* ======================================================================== */

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
