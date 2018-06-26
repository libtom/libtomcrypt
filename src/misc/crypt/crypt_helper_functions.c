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

#ifdef LTC_CHACHA

int chacha_memory(const unsigned char *key,    unsigned long keylen,
                  const unsigned char *iv,     unsigned long ivlen,
                  const unsigned char *datain, unsigned long datalen,
                  unsigned long rounds,
                  unsigned char *dataout)
{
   chacha_state state;
   int err;

   if ((err = chacha_setup(&state, key, keylen, rounds)) != CRYPT_OK) goto WIPE_KEY;
   if (ivlen == 12) {
        if ((err = chacha_ivctr32(&state, iv, ivlen, 0)) != CRYPT_OK) goto WIPE_KEY;
   } else {
        if ((err = chacha_ivctr64(&state, iv, ivlen, 0)) != CRYPT_OK) goto WIPE_KEY;
   )
   err = chacha_crypt(&state, datain, datalen, dataout);
WIPE_KEY:
   err = chacha_done(&state);
   return err;
}

#endif /* LTC_CHACHA */

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#ifdef LTC_SALSA20

int salsa20_onecall(const unsigned char *key,    unsigned long keylen,
                    const unsigned char *iv,     unsigned long ivlen,
                    const unsigned char *datain, unsigned long datalen,
                    unsigned long rounds,
                    unsigned char *dataout)
{
   salsa20_state state;
   int err;

   if ((err = salsa20_setup(&state, key, keylen, rounds)) != CRYPT_OK) goto WIPE_KEY;
   if ((err = salsa20_ivctr64(&state, iv, ivlen, 0))      != CRYPT_OK) goto WIPE_KEY;
   err = salsa20_crypt(&state, datain, datalen, dataout);
WIPE_KEY:
   err = salsa20_done(&state);
   return err;
}

#endif /* LTC_SALSA20 */

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#ifdef LTC_XSALSA20

int xsalsa20_onecall(const unsigned char *key,    unsigned long keylen,
                     const unsigned char *nonce,  unsigned long noncelen,
                     const unsigned char *datain, unsigned long datalen,
                     unsigned long rounds,
                     unsigned char *dataout)
{
   salsa20_state state;
   int err;

   if ((err = xsalsa20_setup(&state, key, keylen, nonce, noncelen, rounds)) != CRYPT_OK) goto WIPE_KEY;
   err = salsa20_crypt(&state, datain, datalen, dataout);
WIPE_KEY:
   err = salsa20_done(&state);
   return err;
}

#endif /* LTC_XSALSA20 */

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */


#ifdef LTC_SOSEMANUK

int sosemanuk_onecall(const unsigned char *key,    unsigned long keylen,
                      const unsigned char *iv,     unsigned long ivlen,
                      const unsigned char *datain, unsigned long datalen,
                      unsigned char *dataout)
{
   sosemanuk_state state;
   int err;

   if ((err = sosemanuk_setup(&state, key, keylen)) != CRYPT_OK) goto WIPE_KEY;
   if ((err = sosemanuk_setiv(&state, iv, ivlen))   != CRYPT_OK) goto WIPE_KEY;
   err = sosemanuk_crypt(&state, datain, datalen, dataout);
WIPE_KEY:
   err = sosemanuk_done(&state);
   return err;
}

#endif /* LTC_SOSEMANUK */

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#ifdef LTC_RABBIT

int rabbit_onecall(const unsigned char *key,    unsigned long keylen,
                   const unsigned char *iv,     unsigned long ivlen,
                   const unsigned char *datain, unsigned long datalen,
                   unsigned char *dataout)
{
   rabbit_state state;
   int err;

   if ((err = rabbit_setup(&state, key, keylen)) != CRYPT_OK) goto WIPE_KEY;
   if ((err = rabbit_setiv(&state, iv, ivlen))   != CRYPT_OK) goto WIPE_KEY;
   err = rabbit_crypt(&state, datain, datalen, dataout);
WIPE_KEY:
   err = rabbit_done(&state);
   return err;
}

#endif /* LTC_RABBIT */

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#ifdef LTC_RC4_STREAM

int rc4_stream_onecall(const unsigned char *key,    unsigned long keylen,
                       const unsigned char *datain, unsigned long datalen,
                       unsigned char *dataout)
{
   rc4_state state;
   int err;

   if ((err = rc4_stream_setup(&state, key, keylen)) != CRYPT_OK) goto WIPE_KEY;
   err = rc4_stream_crypt(&state, datain, datalen, dataout);
WIPE_KEY:
   err = rc4_stream_done(&state);
   return err;
}

#endif /* LTC_RC4_STREAM */

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#ifdef LTC_SOBER128_STREAM

int sober128_stream_onecall(const unsigned char *key,    unsigned long keylen,
                   const unsigned char *iv,     unsigned long ivlen,
                   const unsigned char *datain, unsigned long datalen,
                   unsigned char *dataout)
{
   sober128_state state;
   int err;

   if ((err = sober128_stream_setup(&state, key, keylen)) != CRYPT_OK) goto WIPE_KEY;
   if ((err = sober128_stream_setiv(&state, iv, ivlen))   != CRYPT_OK) goto WIPE_KEY;
   err = sober128_stream_crypt(&state, datain, datalen, dataout);
WIPE_KEY:
   err = sober128_stream_done(&state);
   return err;
}

#endif /* LTC_SOBER128_STREAM */

/* ======================================================================== */

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
