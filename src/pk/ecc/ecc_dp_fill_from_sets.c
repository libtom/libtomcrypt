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

/* search known curve by curve parameters and fill in missing parameters into dp
 * we assume every parameter has the same case (usually uppercase) and no leading zeros
 */
int ecc_dp_fill_from_sets(ltc_ecc_set_type *dp)
{
  ltc_ecc_set_type params;
  int x;

  if (!dp)                return CRYPT_INVALID_ARG;
  if (dp->oid.OIDlen > 0) return CRYPT_OK;
  if (!dp->prime || !dp->A || !dp->B || !dp->order || !dp->Gx || !dp->Gy || dp->cofactor == 0) return CRYPT_INVALID_ARG;

  for (x = 0; ltc_ecc_sets[x].size != 0; x++) {
    if (XSTRCMP(ltc_ecc_sets[x].prime, dp->prime) == 0 &&
        XSTRCMP(ltc_ecc_sets[x].A,     dp->A)     == 0 &&
        XSTRCMP(ltc_ecc_sets[x].B,     dp->B)     == 0 &&
        XSTRCMP(ltc_ecc_sets[x].order, dp->order) == 0 &&
        XSTRCMP(ltc_ecc_sets[x].Gx,    dp->Gx)    == 0 &&
        XSTRCMP(ltc_ecc_sets[x].Gy,    dp->Gy)    == 0 &&
        ltc_ecc_sets[x].cofactor == dp->cofactor) {

      params = ltc_ecc_sets[x];

      /* copy oid */
      dp->oid.OIDlen = params.oid.OIDlen;
      XMEMCPY(dp->oid.OID, params.oid.OID, dp->oid.OIDlen * sizeof(dp->oid.OID[0]));

      /* copy name */
      if (dp->name != NULL) XFREE(dp->name);
      if ((dp->name = XMALLOC(1+strlen(params.name))) == NULL) return CRYPT_MEM;
      strcpy(dp->name, params.name);

      return CRYPT_OK;
    }
  }

  return CRYPT_INVALID_ARG;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
