/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#define LTC_NO_NULL_TERMINATION_CHECK
#include "tomcrypt.h"

#define NNTCT_NULL ((void *)0)

int no_null_termination_check_test(void)
{
   return crypt_fsa(NNTCT_NULL, NNTCT_NULL, NNTCT_NULL, NNTCT_NULL, NNTCT_NULL, NNTCT_NULL, 0);
}
