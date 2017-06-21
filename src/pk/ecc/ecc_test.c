/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

/**
  @file ecc_test.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

int ecc_test(void)
{
   /* the main ECC tests are in tests/ecc_test.c
    * this function is kept just for API compatibility
    */
   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */

