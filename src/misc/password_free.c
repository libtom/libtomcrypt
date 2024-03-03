/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file password_free.c
   Free the password inside a `struct password`, Steffen Jaeckel
*/

/**
   Free a password
   @param pw   The password to be free'd
   @param ctx  The password context
*/
void password_free(struct password *pw, const struct password_ctx *ctx)
{
   if (!ctx || !pw || !pw->pw)
      return;

   zeromem(pw->pw, pw->l);
   if (ctx->free) {
      ctx->free(pw->pw);
   } else {
      XFREE(pw->pw);
   }
   pw->pw = NULL;
   pw->l = 0;
}
