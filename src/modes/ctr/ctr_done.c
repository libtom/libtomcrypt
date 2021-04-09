/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file ctr_done.c
   CTR implementation, finish chain, Tom St Denis
*/

#ifdef LTC_CTR_MODE

/** Terminate the chain
  @param ctr    The CTR chain to terminate
  @return CRYPT_OK on success
*/
int ctr_done(symmetric_CTR *ctr)
{
   LTC_ARGCHK(ctr != NULL);

   return ecb_done(&ctr->ecb);
}



#endif
