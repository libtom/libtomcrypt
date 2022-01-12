/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include <tomcrypt_test.h>

#if defined(LTC_PEM) && defined(LTC_TEST_READDIR) && !defined(LTC_EASY)

static int password_get(void **p, unsigned long *l, void *u)
{
   LTC_UNUSED_PARAM(u);
   *p = strdup("secret");
   *l = 6;
   return 0;
}

static int s_pem_decode_filehandle(const void *in, unsigned long inlen, void *key)
{
   password_ctx pw_ctx;
   pw_ctx.callback = password_get;
   return pem_decode(in, inlen, key, &pw_ctx);
}

static void s_pem_free_key(ltc_pka_key *key)
{
   switch (key->id) {
      case LTC_PKA_RSA:
         rsa_free(&key->u.rsa);
         break;
      case LTC_PKA_EC:
         ecc_free(&key->u.ecc);
         break;
      default:
         break;
   }
}

int pem_test(void)
{
   ltc_pka_key key;

   if (ltc_mp.name == NULL) return CRYPT_NOP;

   DO(test_process_dir("tests/pem", &key, s_pem_decode_filehandle, (dir_cleanup_cb)s_pem_free_key, "pem_test"));
   DO(test_process_dir("tests/pem-ecc-pkcs8", &key, s_pem_decode_filehandle, (dir_cleanup_cb)s_pem_free_key, "pem_test+ecc"));

   return 0;
}

#else

int pem_test(void)
{
   return CRYPT_NOP;
}

#endif
