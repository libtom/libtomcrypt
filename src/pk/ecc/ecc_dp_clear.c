/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_MECC

int ecc_dp_clear(ltc_ecc_set_type *dp)
{
  if (dp == NULL) return CRYPT_INVALID_ARG;

  if (dp->name  != NULL) { XFREE(dp->name ); dp->name  = NULL; }
  if (dp->prime != NULL) { XFREE(dp->prime); dp->prime = NULL; }
  if (dp->A     != NULL) { XFREE(dp->A    ); dp->A     = NULL; }
  if (dp->B     != NULL) { XFREE(dp->B    ); dp->B     = NULL; }
  if (dp->order != NULL) { XFREE(dp->order); dp->order = NULL; }
  if (dp->Gx    != NULL) { XFREE(dp->Gx   ); dp->Gx    = NULL; }
  if (dp->Gy    != NULL) { XFREE(dp->Gy   ); dp->Gy    = NULL; }
  dp->cofactor   = 0;
  dp->oid.OIDlen = 0;

  return CRYPT_OK;
}

#endif
