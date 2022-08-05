/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_MPI
#include <stdarg.h>

int ltc_mp_init_multi(void **a, ...)
{
   void    **cur = a;
   int       np  = 0;
   va_list   args;

   va_start(args, a);
   while (cur != NULL) {
       if (ltc_mp_init(cur) != CRYPT_OK) {
          /* failed */
          va_list clean_list;

          va_start(clean_list, a);
          cur = a;
          while (np--) {
              ltc_mp_clear(*cur);
              cur = va_arg(clean_list, void**);
          }
          va_end(clean_list);
          va_end(args);
          return CRYPT_MEM;
       }
       ++np;
       cur = va_arg(args, void**);
   }
   va_end(args);
   return CRYPT_OK;
}

void ltc_mp_deinit_multi(void *a, ...)
{
   void     *cur = a;
   va_list   args;

   va_start(args, a);
   while (cur != NULL) {
       ltc_mp_clear(cur);
       cur = va_arg(args, void *);
   }
   va_end(args);
}

void ltc_mp_cleanup_multi(void **a, ...)
{
   void **cur = a;
   va_list args;

   va_start(args, a);
   while (cur != NULL) {
      if (*cur != NULL) {
         ltc_mp_clear(*cur);
         *cur = NULL;
      }
      cur = va_arg(args, void**);
   }
   va_end(args);
}

#endif
