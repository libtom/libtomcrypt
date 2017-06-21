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

ltc_ecc_set_type* ecc_dp_find_by_name(char *curve_name)
{
   int i;

   for (i = 0; ltc_ecc_sets[i].size != 0; i++) {
      if (ltc_ecc_sets[i].name != NULL && XSTRCMP(ltc_ecc_sets[i].name, curve_name) == 0) {
         return (ltc_ecc_set_type*)&ltc_ecc_sets[i];
      }
   }
   return NULL;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
