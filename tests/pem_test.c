/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include <tomcrypt_test.h>

#if defined(LTC_PEM) && defined(LTC_TEST_READDIR) && !defined(LTC_EASY)

#ifdef LTC_SSH

static int password_get_ssh(void **p, unsigned long *l, void *u)
{
   LTC_UNUSED_PARAM(u);
   *p = strdup("abc123");
   *l = 6;
   return 0;
}
static int s_pem_decode_ssh(const void *in, unsigned long inlen, void *key)
{
   password_ctx pw_ctx;
   pw_ctx.callback = password_get_ssh;
   return pem_decode_openssh(in, inlen, key, &pw_ctx);
}
static int s_pem_decode_ssh_f(FILE *f, void *key)
{
   password_ctx pw_ctx;
   pw_ctx.callback = password_get_ssh;
   return pem_decode_openssh_filehandle(f, key, &pw_ctx);
}

#endif

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
         return dsa_key_cmp(key->u.dsa.type, &s_dsa_key_should, &key->u.dsa);
#endif
         break;
      case LTC_PKA_RSA:
#if defined(LTC_MRSA)
         return rsa_key_cmp(key->u.rsa.type, &s_rsa_key_should, &key->u.rsa);
#endif
         break;
      case LTC_PKA_EC:
#if defined(LTC_MECC)
         return ecc_key_cmp(key->u.ecc.type, &s_ecc_key_should, &key->u.ecc);
#endif
         break;
      case LTC_PKA_ED25519:
      case LTC_PKA_X25519:
      case LTC_PKA_DH:
         return CRYPT_OK;
      default:
         return CRYPT_INVALID_ARG;
   }
   return CRYPT_INVALID_ARG;
}

static int s_pem_only_decode(const void *in, unsigned long inlen, void *key)
{
   password_ctx pw_ctx;
   pw_ctx.callback = password_get;
   return pem_decode_pkcs(in, inlen, key, &pw_ctx);
}

static int s_pem_decode(const void *in, unsigned long inlen, void *key)
{
   int err;
   if ((err = s_pem_only_decode(in, inlen, key)) != CRYPT_OK) {
      return err;
   }
   return s_key_cmp(key);
}

static int s_pem_decode_f(FILE *f, void *key)
{
   password_ctx pw_ctx;
   int err;
   pw_ctx.callback = password_get;
   if ((err = pem_decode_pkcs_filehandle(f, key, &pw_ctx)) != CRYPT_OK) {
      return err;
   }
   return s_key_cmp(key);
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


   DO(test_process_dir("tests/pem", &key, s_pem_decode, NULL, (dir_cleanup_cb)pka_key_free, "pem_test"));
   DO(test_process_dir("tests/pem", &key, NULL, s_pem_decode_f, (dir_cleanup_cb)pka_key_free, "pem_test_filehandle"));
   DO(test_process_dir("tests/pem/ecc-pkcs8", &key, s_pem_decode, NULL, (dir_cleanup_cb)pka_key_free, "pem_test+ecc"));
   DO(test_process_dir("tests/pem/ecc-pkcs8", &key, NULL, s_pem_decode_f, (dir_cleanup_cb)pka_key_free, "pem_test_filehandle+ecc"));
   DO(test_process_dir("tests/pem/extra", &key, s_pem_only_decode, NULL, (dir_cleanup_cb)pka_key_free, "pem_test+extra"));
#ifdef LTC_SSH
   DO(test_process_dir("tests/ssh", &key, s_pem_decode_ssh, NULL, (dir_cleanup_cb)pka_key_free, "pem_test+ssh"));
   DO(test_process_dir("tests/ssh", &key, NULL, s_pem_decode_ssh_f, (dir_cleanup_cb)pka_key_free, "pem_test_filehandle+ssh"));
   DO(test_process_dir("tests/ssh/extra", &key, s_pem_decode_ssh, NULL, (dir_cleanup_cb)pka_key_free, "pem_test+ssh+extra"));
#endif

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
