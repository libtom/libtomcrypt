#include  <tomcrypt_test.h>

int misc_test(void)
{
#ifdef LTC_HKDF
   DO(hkdf_test());
#endif
   return 0;
}

/* $Source$ */
/* $Revision$ */
/* $Date$ */
