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

#if defined(LTC_MDSA)
static dsa_key s_dsa_key_should;
#endif
#if defined(LTC_MRSA)
static rsa_key s_rsa_key_should;
#endif
#if defined(LTC_MECC)
static ecc_key s_ecc_key_should;
#endif

static int s_key_cmp(ltc_pka_key *key)
{
   switch (key->id) {
      case LTC_PKA_DSA:
#if defined(LTC_MDSA)
         return dsa_key_cmp(PK_PRIVATE, &s_dsa_key_should, &key->u.dsa);
#endif
         break;
      case LTC_PKA_RSA:
#if defined(LTC_MRSA)
         return rsa_key_cmp(PK_PRIVATE, &s_rsa_key_should, &key->u.rsa);
#endif
         break;
      case LTC_PKA_EC:
#if defined(LTC_MECC)
         return ecc_key_cmp(PK_PRIVATE, &s_ecc_key_should, &key->u.ecc);
#endif
         break;
      case LTC_PKA_CURVE25519:
         return CRYPT_OK;
      default:
         return CRYPT_INVALID_ARG;
   }
   return CRYPT_INVALID_ARG;
}

static int s_pem_decode(const void *in, unsigned long inlen, void *key)
{
   password_ctx pw_ctx;
   int err;
   pw_ctx.callback = password_get;
   if ((err = pem_decode(in, inlen, key, &pw_ctx)) != CRYPT_OK) {
      return err;
   }
   return s_key_cmp(key);
}

static void s_pem_free_key(ltc_pka_key *key)
{
   switch (key->id) {
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

int pem_test(void)
{
   ltc_pka_key key;

   if (ltc_mp.name == NULL) return CRYPT_NOP;

#if defined(LTC_MDSA)
   DO(dsa_import(ltc_dsa_private_test_key, ltc_dsa_private_test_key_sz, &s_dsa_key_should));
#endif
#if defined(LTC_MRSA)
   DO(rsa_import(ltc_rsa_private_test_key, ltc_rsa_private_test_key_sz, &s_rsa_key_should));
#endif
#if defined(LTC_MECC)
   DO(ecc_import_openssl(ltc_ecc_long_pri_test_key, ltc_ecc_long_pri_test_key_sz, &s_ecc_key_should));
#endif


   DO(test_process_dir("tests/pem", &key, s_pem_decode, NULL, (dir_cleanup_cb)s_pem_free_key, "pem_test"));
   DO(test_process_dir("tests/pem-ecc-pkcs8", &key, s_pem_decode, NULL, (dir_cleanup_cb)s_pem_free_key, "pem_test+ecc"));
   DO(test_process_dir("tests/ssh", &key, s_pem_decode_ssh, NULL, (dir_cleanup_cb)s_pem_free_key, "pem_test+ssh"));

#if defined(LTC_MDSA)
   dsa_free(&s_dsa_key_should);
#endif
#if defined(LTC_MRSA)
   rsa_free(&s_rsa_key_should);
#endif
#if defined(LTC_MECC)
   ecc_free(&s_ecc_key_should);
#endif

   return 0;
}

#else

int pem_test(void)
{
   return CRYPT_NOP;
}

#endif
