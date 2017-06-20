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

int ecc_dp_set_by_oid(ltc_ecc_set_type *dp, unsigned long *oid, unsigned long oidsize)
{
  int i;
  unsigned long len;

  for(i=0; ltc_ecc_sets[i].size != 0; i++) {
    if ((oidsize == ltc_ecc_sets[i].oid.OIDlen) &&
        (XMEM_NEQ(oid, ltc_ecc_sets[i].oid.OID, sizeof(unsigned long) * ltc_ecc_sets[i].oid.OIDlen) == 0)) {
      break;
    }
  }
  if (ltc_ecc_sets[i].size == 0) return CRYPT_INVALID_ARG; /* not found */

  /* a */
  len = (unsigned long)strlen(ltc_ecc_sets[i].A);
  if ((dp->A = XMALLOC(1+len)) == NULL)         goto cleanup1;
  strncpy(dp->A, ltc_ecc_sets[i].A, 1+len);
  /* b */
  len = (unsigned long)strlen(ltc_ecc_sets[i].B);
  if ((dp->B = XMALLOC(1+len)) == NULL)         goto cleanup2;
  strncpy(dp->B, ltc_ecc_sets[i].B, 1+len);
  /* order */
  len = (unsigned long)strlen(ltc_ecc_sets[i].order);
  if ((dp->order = XMALLOC(1+len)) == NULL)     goto cleanup3;
  strncpy(dp->order, ltc_ecc_sets[i].order, 1+len);
  /* prime */
  len = (unsigned long)strlen(ltc_ecc_sets[i].prime);
  if ((dp->prime = XMALLOC(1+len)) == NULL)     goto cleanup4;
  strncpy(dp->prime, ltc_ecc_sets[i].prime, 1+len);
  /* gx */
  len = (unsigned long)strlen(ltc_ecc_sets[i].Gx);
  if ((dp->Gx = XMALLOC(1+len)) == NULL)        goto cleanup5;
  strncpy(dp->Gx, ltc_ecc_sets[i].Gx, 1+len);
  /* gy */
  len = (unsigned long)strlen(ltc_ecc_sets[i].Gy);
  if ((dp->Gy = XMALLOC(1+len)) == NULL)        goto cleanup6;
  strncpy(dp->Gy, ltc_ecc_sets[i].Gy, 1+len);
  /* cofactor & size */
  dp->cofactor = ltc_ecc_sets[i].cofactor;
  dp->size = ltc_ecc_sets[i].size;
  /* name */
  len = (unsigned long)strlen(ltc_ecc_sets[i].name);
  if ((dp->name = XMALLOC(1+len)) == NULL)      goto cleanup7;
  strncpy(dp->name, ltc_ecc_sets[i].name, 1+len);
  /* oid */
  dp->oid.OIDlen = ltc_ecc_sets[i].oid.OIDlen;
  XMEMCPY(dp->oid.OID, ltc_ecc_sets[i].oid.OID, dp->oid.OIDlen * sizeof(dp->oid.OID[0]));
  /* done - success */
  return CRYPT_OK;

cleanup7:
  XFREE(dp->Gy);
cleanup6:
  XFREE(dp->Gx);
cleanup5:
  XFREE(dp->prime);
cleanup4:
  XFREE(dp->order);
cleanup3:
  XFREE(dp->B);
cleanup2:
  XFREE(dp->A);
cleanup1:
  return CRYPT_MEM;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
