/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

void pka_key_free(ltc_pka_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   switch (key->id) {
      case LTC_PKA_DH:
#if defined(LTC_MDH)
         dh_free(&key->u.dh);
#endif
         break;
      case LTC_PKA_DSA:
#if defined(LTC_MDSA)
         dsa_free(&key->u.dsa);
#endif
         break;
      case LTC_PKA_RSA:
#if defined(LTC_MRSA)
         rsa_free(&key->u.rsa);
#endif
         break;
      case LTC_PKA_EC:
#if defined(LTC_MECC)
         ecc_free(&key->u.ecc);
#endif
         break;
      default:
         break;
   }
}
