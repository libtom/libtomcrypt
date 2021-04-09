/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file cfb_done.c
   CFB implementation, finish chain, Tom St Denis
*/

#ifdef LTC_CFB_MODE

/** Terminate the chain
  @param cfb    The CFB chain to terminate
  @return CRYPT_OK on success
*/
int cfb_done(symmetric_CFB *cfb)
{
   LTC_ARGCHK(cfb != NULL);

   return ecb_done(&cfb->ecb);
}



#endif
