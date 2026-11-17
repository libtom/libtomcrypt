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
   password_ctx pw_ctx = { .callback = password_get_ssh };
   return pem_decode_openssh(in, inlen, key, &pw_ctx);
}
static int s_pem_decode_ssh_f(FILE *f, void *key)
{
   password_ctx pw_ctx = { .callback = password_get_ssh };
   return pem_decode_openssh_filehandle(f, key, &pw_ctx);
}

static int s_authorized_key_cb(ltc_pka_key *k, const char *comment, void *ctx)
{
   LTC_UNUSED_PARAM(comment);
   LTC_UNUSED_PARAM(ctx);
   pka_key_destroy(&k);
   return 0;
}
static int s_read_authorized_keys(const void *in, unsigned long inlen, void *ctx)
{
   return ssh_read_authorized_keys(in, inlen, s_authorized_key_cb, ctx);
}
static int s_read_authorized_keys_f(FILE *f, void *ctx)
{
   return ssh_read_authorized_keys_filehandle(f, s_authorized_key_cb, ctx);
}
static int s_read_invalid_authorized_keys(const void *in, unsigned long inlen, void *ctx)
{
   SHOULD_FAIL(ssh_read_authorized_keys(in, inlen, s_authorized_key_cb, ctx));
   return CRYPT_OK;
}

/* An entry whose last element isn't followed by a space, tab, CR or LF used to run the parser past the end of its input copy.
 * All fixtures under tests/pem/ end with a newline, so these inputs are built in-code with explicit lengths and no trailing newline. */
struct authorized_key_expect {
   const char *comment;    /* comment the callback should get */
   int         stop;       /* what the callback returns */
   unsigned    seen;       /* keys passed to the callback */
   unsigned    bad;        /* keys with an unexpected comment */
};

static int s_authorized_key_expect_cb(ltc_pka_key *k, const char *comment, void *ctx)
{
   struct authorized_key_expect *e = ctx;
   e->seen++;
   if (e->comment == NULL ? comment != NULL : (comment == NULL || XSTRCMP(comment, e->comment) != 0)) {
      e->bad++;
   }
   pka_key_destroy(&k);
   return e->stop;
}

#define AK_STR(s) s, (sizeof(s) - 1)

static int s_test_authorized_keys_no_eol(void)
{
   /* chopping runs before the algorithm is matched, so these fail regardless of the PKAs compiled in */
   static const struct {
      const char   *in;
      unsigned long inlen;
   } malformed[] = {
      { AK_STR("ssh-ed25519") },           /* algorithm name only, no delimiter */
      { AK_STR("ecdsa-sha2-nistp256") },   /* ditto, and reaches strstr()       */
      { AK_STR("x") },                     /* single byte, no delimiter         */
      { AK_STR(" ") },                     /* nothing but a space               */
      { AK_STR("\n") },                    /* nothing but a newline             */
      { AK_STR("ssh-ed25519 ") },          /* empty key blob                    */
      { AK_STR("ssh-ed25519 AAAA") },      /* key blob runs to the end          */
   };
   unsigned long n;
   struct authorized_key_expect e;

   for (n = 0; n < sizeof(malformed)/sizeof(malformed[0]); ++n) {
      XMEMSET(&e, 0, sizeof(e));
      SHOULD_FAIL(ssh_read_authorized_keys(malformed[n].in, malformed[n].inlen, s_authorized_key_expect_cb, &e));
      ENSUREX(e.seen == 0, malformed[n].in);
   }

#ifdef LTC_CURVE25519
   {
      /* a valid entry must parse identically with and without the trailing newline, comment included */
      static const char ed25519[] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0XsiFcRDp6Hpsoak8OdiiBMJhM2UKszNTxoGS7dJ++ This is a test key!";
      static const char ed25519_eol[] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0XsiFcRDp6Hpsoak8OdiiBMJhM2UKszNTxoGS7dJ++ This is a test key!\n";
      static const char ed25519_no_comment[] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0XsiFcRDp6Hpsoak8OdiiBMJhM2UKszNTxoGS7dJ++";
      static const char ed25519_twice[] =
         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0XsiFcRDp6Hpsoak8OdiiBMJhM2UKszNTxoGS7dJ++ This is a test key!\n"
         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0XsiFcRDp6Hpsoak8OdiiBMJhM2UKszNTxoGS7dJ++ This is a test key!";

      XMEMSET(&e, 0, sizeof(e));
      e.comment = "This is a test key!";
      DO(ssh_read_authorized_keys(AK_STR(ed25519), s_authorized_key_expect_cb, &e));
      ENSURE(e.seen == 1 && e.bad == 0);

      XMEMSET(&e, 0, sizeof(e));
      e.comment = "This is a test key!";
      DO(ssh_read_authorized_keys(AK_STR(ed25519_eol), s_authorized_key_expect_cb, &e));
      ENSURE(e.seen == 1 && e.bad == 0);

      /* the unterminated entry must not swallow the one before it */
      XMEMSET(&e, 0, sizeof(e));
      e.comment = "This is a test key!";
      DO(ssh_read_authorized_keys(AK_STR(ed25519_twice), s_authorized_key_expect_cb, &e));
      ENSURE(e.seen == 2 && e.bad == 0);

      /* key blob runs to the end of the buffer, no comment to pick up */
      XMEMSET(&e, 0, sizeof(e));
      e.comment = NULL;
      DO(ssh_read_authorized_keys(AK_STR(ed25519_no_comment), s_authorized_key_expect_cb, &e));
      ENSURE(e.seen == 1 && e.bad == 0);

      /* cb() owns the key after asking to stop, it must not be freed twice */
      XMEMSET(&e, 0, sizeof(e));
      e.comment = "This is a test key!";
      e.stop = 1;
      DO(ssh_read_authorized_keys(AK_STR(ed25519_twice), s_authorized_key_expect_cb, &e));
      ENSURE(e.seen == 1 && e.bad == 0);
   }
#endif

   return CRYPT_OK;
}

#undef AK_STR

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
      case LTC_PKA_X448:
      case LTC_PKA_ED448:
         return CRYPT_OK;
      default:
         return CRYPT_INVALID_ARG;
   }
   return CRYPT_INVALID_ARG;
}

static int s_pem_decode_invalid_pkcs(const void *in, unsigned long inlen, void *key)
{
   password_ctx pw_ctx = { .callback = password_get };
   SHOULD_FAIL(pem_decode_pkcs(in, inlen, key, &pw_ctx));
   return CRYPT_OK;
}

static int s_pem_only_decode_pkcs(const void *in, unsigned long inlen, void *key)
{
   password_ctx pw_ctx = { .callback = password_get };
   return pem_decode_pkcs(in, inlen, key, &pw_ctx);
}

static int s_pem_decode_pkcs(const void *in, unsigned long inlen, void *key)
{
   int err;
   if ((err = s_pem_only_decode_pkcs(in, inlen, key)) != CRYPT_OK) {
      return err;
   }
   return s_key_cmp(key);
}

static int s_pem_decode_pkcs_f(FILE *f, void *key)
{
   int err;
   password_ctx pw_ctx = { .callback = password_get };
   if ((err = pem_decode_pkcs_filehandle(f, key, &pw_ctx)) != CRYPT_OK) {
      return err;
   }
   return s_key_cmp(key);
}

static int s_pem_only_decode(const void *in, unsigned long inlen, void *key)
{
   password_ctx pw_ctx = { .callback = password_get };
   if ((strcmp(ltc_mp.name, "TomsFastMath") == 0) && (inlen > 2048)) {
#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
      fprintf(stderr, "Skipping testcase because of TomsFastMath\n");
#endif
      return CRYPT_NOP;
   }
   return pem_decode(in, inlen, key, &pw_ctx);
}

static int s_pem_only_decode_f(FILE *f, void *key)
{
   password_ctx pw_ctx = { .callback = password_get };
   return pem_decode_filehandle(f, key, &pw_ctx);
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


   DO(test_process_dir("tests/pem/pkcs", &key, s_pem_decode_pkcs, NULL, (dir_cleanup_cb)pka_key_free, "pem_pkcs_test"));
   DO(test_process_dir("tests/pem/pkcs", &key, NULL, s_pem_decode_pkcs_f, (dir_cleanup_cb)pka_key_free, "pem_pkcs_test_filehandle"));
   DO(test_process_dir("tests/pem/pkcs/ecc-pkcs8", &key, s_pem_decode_pkcs, NULL, (dir_cleanup_cb)pka_key_free, "pem_pkcs_test+ecc"));
   DO(test_process_dir("tests/pem/pkcs/ecc-pkcs8", &key, NULL, s_pem_decode_pkcs_f, (dir_cleanup_cb)pka_key_free, "pem_pkcs_test_filehandle+ecc"));
   DO(test_process_dir("tests/pem/pkcs/extra", &key, s_pem_only_decode_pkcs, NULL, (dir_cleanup_cb)pka_key_free, "pem_pkcs_test+extra"));
   DO(test_process_dir("tests/pem/pkcs/invalid", &key, s_pem_decode_invalid_pkcs, NULL, NULL, "pem_test_invalid"));
   DO(test_process_dir("tests/pem/pkcs/invalid_but_supported", &key, s_pem_only_decode_pkcs, NULL, (dir_cleanup_cb)pka_key_free, "pem_pkcs_invalid_but_supported"));
#ifdef LTC_SSH
   DO(test_process_dir("tests/pem/ssh", &key, s_pem_decode_ssh, NULL, (dir_cleanup_cb)pka_key_free, "pem_ssh_test"));
   DO(test_process_dir("tests/pem/ssh", &key, NULL, s_pem_decode_ssh_f, (dir_cleanup_cb)pka_key_free, "pem_ssh_test_filehandle"));
   DO(test_process_dir("tests/pem/ssh/authorized_keys", &key, s_read_authorized_keys, NULL, (dir_cleanup_cb)pka_key_free, "pem_ssh_authorized_keys_test"));
   DO(test_process_dir("tests/pem/ssh/authorized_keys", &key, NULL, s_read_authorized_keys_f, (dir_cleanup_cb)pka_key_free, "pem_ssh_authorized_keys_test"));
   DO(test_process_dir("tests/pem/ssh/authorized_keys-invalid", &key, s_read_invalid_authorized_keys, NULL, NULL, "pem_ssh_authorized_keys_invalid_test"));
   DO(s_test_authorized_keys_no_eol());
   DO(test_process_dir("tests/pem/ssh/extra", &key, s_pem_decode_ssh, NULL, (dir_cleanup_cb)pka_key_free, "pem_ssh_test+extra"));
   DO(test_process_dir("tests/pem/pubkeys", &key, s_pem_only_decode, NULL, (dir_cleanup_cb)pka_key_free, "pem_pubkeys_test"));
   DO(test_process_dir("tests/pem/pubkeys", &key, NULL, s_pem_only_decode_f, (dir_cleanup_cb)pka_key_free, "pem_pubkeys_test_filehandle"));
   DO(test_process_dir("tests/pem/pubkeys/authorized_keys", &key, s_read_authorized_keys, NULL, (dir_cleanup_cb)pka_key_free, "pem_pubkeys_authorized_keys_test"));
   DO(test_process_dir("tests/pem/pubkeys/authorized_keys", &key, NULL, s_read_authorized_keys_f, (dir_cleanup_cb)pka_key_free, "pem_pubkeys_authorized_keys_test"));
#endif
   DO(test_process_dir("tests/pem", &key, s_pem_only_decode, NULL, (dir_cleanup_cb)pka_key_free, "pem_test"));
   DO(test_process_dir("tests/pem", &key, NULL, s_pem_only_decode_f, (dir_cleanup_cb)pka_key_free, "pem_test_filehandle"));
   if (strcmp(ltc_mp.name, "TomsFastMath") != 0) {
      DO(test_process_dir("tests/pem/non-tfm", &key, s_pem_only_decode, NULL, (dir_cleanup_cb)pka_key_free, "pem_test"));
      DO(test_process_dir("tests/pem/non-tfm", &key, NULL, s_pem_only_decode_f, (dir_cleanup_cb)pka_key_free, "pem_test_filehandle"));
   }

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
LTC_NOP_TEST(pem_test)
#endif
