/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/* test pmac/omac/hmac */
#include <tomcrypt_test.h>

int mac_test(void)
{
#ifdef LTC_HMAC
   DO(hmac_test());
#endif
#ifdef LTC_PMAC
   DO(pmac_test());
#endif
#ifdef LTC_OMAC
   DO(omac_test());
#endif
#ifdef LTC_XCBC
   DO(xcbc_test());
#endif
#ifdef LTC_F9_MODE
   DO(f9_test());
#endif
#ifdef LTC_EAX_MODE
   DO(eax_test());
#endif
#ifdef LTC_OCB_MODE
   DO(ocb_test());
#endif
#ifdef LTC_OCB3_MODE
   DO(ocb3_test());
#endif
#ifdef LTC_CCM_MODE
   DO(ccm_test());
#endif
#ifdef LTC_GCM_MODE
   DO(gcm_test());
#endif
#ifdef LTC_PELICAN
   DO(pelican_test());
#endif
#ifdef LTC_POLY1305
   DO(poly1305_test());
#endif
#ifdef LTC_CHACHA20POLY1305_MODE
   DO(chacha20poly1305_test());
#endif
#ifdef LTC_BLAKE2SMAC
   DO(blake2smac_test());
#endif
#ifdef LTC_BLAKE2BMAC
   DO(blake2bmac_test());
#endif
   return 0;
}
