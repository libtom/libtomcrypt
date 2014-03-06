/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
  @file crypt_inits.c
  
  Provide math library functions for dynamic languages 
  like Python - Larry Bugbee, February 2013
*/


#ifdef USE_LTM
void init_LTM(void) {
    ltc_mp = ltm_desc;
}
#endif

#ifdef USE_TFM
void init_TFM(void) {
    ltc_mp = tfm_desc;
}
#endif

/*                          *** use of GMP is untested ***
    #ifdef USE_GMP
    void init_GMP(void) {
        ltc_mp = gmp_desc;
    }
    #endif
*/


/* $Source: /cvs/libtom/libtomcrypt/src/misc/crypt/crypt_inits.c,v $ */
/* $Revision:  $ */
/* $Date:  $ */
