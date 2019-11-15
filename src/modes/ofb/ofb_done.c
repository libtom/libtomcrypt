/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file ofb_done.c
   OFB implementation, finish chain, Tom St Denis
*/

#ifdef LTC_OFB_MODE

/** Terminate the chain
  @param ofb    The OFB chain to terminate
  @return CRYPT_OK on success
*/
int ofb_done(symmetric_OFB *ofb)
{
   LTC_ARGCHK(ofb != NULL);

   return ecb_done(&ofb->ecb);
}



#endif
