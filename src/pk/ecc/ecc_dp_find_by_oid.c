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

ltc_ecc_set_type* ecc_dp_find_by_oid(unsigned long *oid, unsigned long oidsize)
{
   int i;

   for (i = 0; ltc_ecc_sets[i].size != 0; i++) {
      if ((oidsize == ltc_ecc_sets[i].oid.OIDlen) &&
          (XMEM_NEQ(oid, ltc_ecc_sets[i].oid.OID, sizeof(unsigned long) * ltc_ecc_sets[i].oid.OIDlen) == 0)) {
         return (ltc_ecc_set_type*)&ltc_ecc_sets[i];
      }
   }
   return NULL;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
