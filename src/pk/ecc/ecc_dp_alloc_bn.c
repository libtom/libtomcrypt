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

int ecc_dp_alloc_bn(ltc_ecc_set_type *dp, void *a, void *b, void *prime, void *order, void *gx, void *gy, unsigned long cofactor)
{
  unsigned char buf[ECC_BUF_SIZE];
  unsigned long len;

  /* a */
  mp_tohex(a, (char *)buf);
  len = (unsigned long)strlen((char *)buf);
  if ((dp->A = XMALLOC(1+len)) == NULL)         goto cleanup1;
  strncpy(dp->A, (char*)buf, 1+len);
  /* b */
  mp_tohex(b, (char *)buf);
  len = (unsigned long)strlen((char *)buf);
  if ((dp->B = XMALLOC(1+len)) == NULL)         goto cleanup2;
  strncpy(dp->B, (char*)buf, 1+len);
  /* order */
  mp_tohex(order, (char *)buf);
  len = (unsigned long)strlen((char *)buf);
  if ((dp->order = XMALLOC(1+len)) == NULL)     goto cleanup3;
  strncpy(dp->order, (char*)buf, 1+len);
  /* prime */
  mp_tohex(prime, (char *)buf);
  len = (unsigned long)strlen((char *)buf);
  if ((dp->prime = XMALLOC(1+len)) == NULL)     goto cleanup4;
  strncpy(dp->prime, (char*)buf, 1+len);
  /* gx */
  mp_tohex(gx, (char *)buf);
  len = (unsigned long)strlen((char *)buf);
  if ((dp->Gx = XMALLOC(1+len)) == NULL)        goto cleanup5;
  strncpy(dp->Gx, (char*)buf, 1+len);
  /* gy */
  mp_tohex(gy, (char *)buf);
  len = (unsigned long)strlen((char *)buf);
  if ((dp->Gy = XMALLOC(1+len)) == NULL)        goto cleanup6;
  strncpy(dp->Gy, (char*)buf, 1+len);
  /* cofactor & size */
  dp->cofactor = cofactor;
  dp->size = mp_unsigned_bin_size(prime);
  /* custom name */
  if ((dp->name = XMALLOC(7)) == NULL)          goto cleanup7;
  strcpy(dp->name, "CUSTOM");
  /* no oid */
  dp->oid.OIDlen = 0;
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
