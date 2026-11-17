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

/* guarantee: what pbes2_encrypt() writes, pbes2_extract() and pbes_decrypt() accept */
static int s_pbes2_roundtrip(const pbes2_enc_params *params, const unsigned char *in, unsigned long inlen)
{
   unsigned char enc[256], dec[256];
   unsigned long enclen = 0, need, len, declen;
   ltc_asn1_list *l = NULL;
   pbes_arg pbes;
   int prng_idx = find_prng("yarrow");

   SHOULD_FAIL_WITH(pbes2_encrypt(enc, &enclen, in, inlen, (const unsigned char*)"secret", 6, params, &yarrow_prng, prng_idx), CRYPT_BUFFER_OVERFLOW);
   need = enclen;
   ENSURE(need > 0 && need <= sizeof(enc));
   enclen = need - 1;
   SHOULD_FAIL_WITH(pbes2_encrypt(enc, &enclen, in, inlen, (const unsigned char*)"secret", 6, params, &yarrow_prng, prng_idx), CRYPT_BUFFER_OVERFLOW);
   ENSURE(enclen == need);
   DO(pbes2_encrypt(enc, &enclen, in, inlen, (const unsigned char*)"secret", 6, params, &yarrow_prng, prng_idx));
   ENSURE(enclen == need);

   len = enclen;
   DO(der_decode_sequence_flexi(enc, &len, &l));
   ENSURE(len == enclen);
   XMEMSET(&pbes, 0, sizeof(pbes));
   DO(pbes2_extract(l->child->child, &pbes));
   pbes.pw.pw = (void*)"secret";
   pbes.pw.l = 6;
   pbes.enc_data = l->child->next;
   declen = sizeof(dec);
   DO(pbes_decrypt(&pbes, dec, &declen));
   COMPARE_TESTVECTOR(dec, declen, in, inlen, "pbes2_encrypt", (int)inlen);
   der_free_sequence_flexi(l);
   return CRYPT_OK;
}

static int s_pbes2_encrypt_test(void)
{
   static const struct {
      const char *cipher;
      unsigned long keylen;
   } ciphers[] = {
      { NULL, 0 }, { "aes", 0 }, { "aes", 16 }, { "aes", 24 }, { "aes", 32 }, { "3des", 0 }, { "3des", 24 },
   };
   static const char * const prfs[] = {
      NULL, "sha1", "sha224", "sha256", "sha384", "sha512", "sha512-224", "sha512-256", "sha3-224", "sha3-256", "sha3-384", "sha3-512",
   };
   /* the INTEGER encoding of the count changes its length at these values */
   static const unsigned long iterations[] = { 1, 127, 128, 255, 256, 32767, 32768, 65536 };
   static const unsigned long inlens[] = { 1, 7, 8, 9, 15, 16, 17, 48, 100 };
   unsigned char in[100], enc1[256], enc2[256], seed[32];
   unsigned long c, h, n, l1, l2;
   pbes2_enc_params params;
   struct ltc_prng_descriptor *no_prng_desc = no_prng_desc_get();
   int prng_idx = find_prng("yarrow"), no_prng_idx = register_prng(no_prng_desc);

   ENSURE(yarrow_read(in, sizeof(in), &yarrow_prng) == sizeof(in));

   for (c = 0; c < LTC_ARRAY_SIZE(ciphers); c++) {
      for (h = 0; h < LTC_ARRAY_SIZE(prfs); h++) {
         if (ciphers[c].cipher != NULL && find_cipher(ciphers[c].cipher) == -1) continue;
         if (prfs[h] != NULL && find_hash(prfs[h]) == -1) continue;
         for (n = 0; n < LTC_ARRAY_SIZE(inlens); n++) {
            XMEMSET(&params, 0, sizeof(params));
            params.cipher = ciphers[c].cipher;
            params.keylen = ciphers[c].keylen;
            params.prf = prfs[h];
            params.iterations = 1;
            DO(s_pbes2_roundtrip(&params, in, inlens[n]));
         }
      }
   }
   XMEMSET(&params, 0, sizeof(params));
   for (n = 0; n < LTC_ARRAY_SIZE(iterations); n++) {
      params.iterations = iterations[n];
      DO(s_pbes2_roundtrip(&params, in, 48));
   }
   params.iterations = 1;
   params.saltlen = 8;
   DO(s_pbes2_roundtrip(&params, in, 48));
   params.saltlen = 64;
   DO(s_pbes2_roundtrip(&params, in, 48));
   /* all defaults, this is the one run that pays for LTC_PBES2_DEFAULT_ITERATIONS */
   DO(s_pbes2_roundtrip(NULL, in, 48));

   /* salt and IV are fresh for every call */
   params.saltlen = 0;
   l1 = sizeof(enc1);
   DO(pbes2_encrypt(enc1, &l1, in, 48, (const unsigned char*)"secret", 6, &params, &yarrow_prng, prng_idx));
   l2 = sizeof(enc2);
   DO(pbes2_encrypt(enc2, &l2, in, 48, (const unsigned char*)"secret", 6, &params, &yarrow_prng, prng_idx));
   ENSURE(l1 == l2 && memcmp(enc1, enc2, l1) != 0);

   /* a size query takes nothing from the PRNG, a PRNG that runs dry is an error */
   XMEMSET(seed, 0x55, sizeof(seed));
   DO(no_prng_desc->add_entropy(seed, 32, (prng_state*)no_prng_desc));
   l1 = 0;
   SHOULD_FAIL_WITH(pbes2_encrypt(enc1, &l1, in, 48, (const unsigned char*)"secret", 6, &params, (prng_state*)no_prng_desc, no_prng_idx), CRYPT_BUFFER_OVERFLOW);
   DO(pbes2_encrypt(enc1, &l1, in, 48, (const unsigned char*)"secret", 6, &params, (prng_state*)no_prng_desc, no_prng_idx));
   DO(no_prng_desc->add_entropy(seed, 31, (prng_state*)no_prng_desc));
   l1 = sizeof(enc1);
   SHOULD_FAIL_WITH(pbes2_encrypt(enc1, &l1, in, 48, (const unsigned char*)"secret", 6, &params, (prng_state*)no_prng_desc, no_prng_idx), CRYPT_ERROR_READPRNG);
   unregister_prng(no_prng_desc);
   no_prng_desc_free(no_prng_desc);

#define PBES2_SHOULD_FAIL(pwlen, e) do { \
      l1 = sizeof(enc1); \
      SHOULD_FAIL_WITH(pbes2_encrypt(enc1, &l1, in, 48, (const unsigned char*)"secret", pwlen, &params, &yarrow_prng, prng_idx), e); \
   } while (0)

   PBES2_SHOULD_FAIL(0, CRYPT_INVALID_ARG);
   params.iterations = LTC_PBES_MAX_ITERATIONS + 1;
   PBES2_SHOULD_FAIL(6, CRYPT_INVALID_ARG);
   params.iterations = 1;
   params.saltlen = 7;
   PBES2_SHOULD_FAIL(6, CRYPT_INVALID_ARG);
   params.saltlen = 65;
   PBES2_SHOULD_FAIL(6, CRYPT_INVALID_ARG);
   params.saltlen = 0;
   params.keylen = 20;
   PBES2_SHOULD_FAIL(6, CRYPT_INVALID_KEYSIZE);
   params.keylen = 0;
   params.prf = "no-such-hash";
   PBES2_SHOULD_FAIL(6, CRYPT_INVALID_HASH);
   params.prf = NULL;
   /* des and rc2 are read but never written, anything else has no PBES2 OID here */
   params.cipher = "des";
   PBES2_SHOULD_FAIL(6, CRYPT_INVALID_CIPHER);
   params.cipher = "rc2";
   PBES2_SHOULD_FAIL(6, CRYPT_INVALID_CIPHER);
   params.cipher = "blowfish";
   PBES2_SHOULD_FAIL(6, CRYPT_INVALID_CIPHER);
   params.cipher = NULL;
   l1 = sizeof(enc1);
   SHOULD_FAIL(pbes2_encrypt(enc1, &l1, in, 48, (const unsigned char*)"secret", 6, &params, &yarrow_prng, -1));

#undef PBES2_SHOULD_FAIL

   return CRYPT_OK;
}

/* PEM encoding */

static int s_password_get_str(void **p, unsigned long *l, void *u)
{
   *p = strdup(u);
   *l = strlen(u);
   return 0;
}

/* RFC 7468: one label line at each end, base64 lines of at most 64 chars, no RFC 1421 headers */
static int s_pem_encode_check_text(const unsigned char *pem, unsigned long len, const char *label, int crlf)
{
   char first[64], last[64];
   const char *eol = crlf ? "\r\n" : "\n";
   unsigned long n, col = 0;

   sprintf(first, "-----BEGIN %s-----%s", label, eol);
   sprintf(last, "-----END %s-----%s", label, eol);
   ENSURE(len > strlen(first) + strlen(last));
   ENSURE(memcmp(pem, first, strlen(first)) == 0);
   ENSURE(memcmp(pem + len - strlen(last), last, strlen(last)) == 0);
   ENSURE(strstr((const char*)pem, "Proc-Type") == NULL && strstr((const char*)pem, "DEK-Info") == NULL);
   for (n = 0; n < len; n++) {
      if (pem[n] == '\n') {
         ENSURE(col > 0 && col <= 64);
         ENSURE(crlf ? (pem[n - 1] == '\r') : (pem[n - 1] != '\r'));
         col = 0;
      } else if (pem[n] != '\r') {
         col++;
      }
   }
   ENSURE(col == 0);
   return CRYPT_OK;
}

/* guarantee: what pem_encode_pkcs() writes, pem_decode_pkcs() reads back to an equal key */
static int s_pem_encode_roundtrip(const ltc_pka_key *k, int which, const pem_encode_opts *opts, const char *label)
{
   unsigned char pem[8192], der1[4096], der2[4096];
   unsigned long len = 0, need, l1 = sizeof(der1), l2 = sizeof(der2);
   password_ctx pw_ctx = { .callback = s_password_get_str, .userdata = (void*)"secret" };
   ltc_pka_key k2;
   int prng_idx = find_prng("yarrow");

   /* a too small buffer reports the size that is enough, one byte less is still too small */
   SHOULD_FAIL_WITH(pem_encode_pkcs(pem, &len, which, k, opts, &yarrow_prng, prng_idx), CRYPT_BUFFER_OVERFLOW);
   need = len;
   ENSURE(need > 1 && need <= sizeof(pem));
   len = need - 1;
   SHOULD_FAIL_WITH(pem_encode_pkcs(pem, &len, which, k, opts, &yarrow_prng, prng_idx), CRYPT_BUFFER_OVERFLOW);
   ENSURE(len == need);
   DO(pem_encode_pkcs(pem, &len, which, k, opts, &yarrow_prng, prng_idx));
   ENSURE(len == need - 1 && pem[len] == '\0');
   DO(s_pem_encode_check_text(pem, len, label, opts != NULL && (opts->flags & LTC_PEM_CRLF)));

   DO(pem_decode_pkcs(pem, len, &k2, &pw_ctx));
   ENSURE(k2.id == k->id);
#ifdef LTC_MECC
   /* the import recognises a known curve from its explicit parameters, the export of the copy must not switch to the OID */
   if (k->id == LTC_PKA_EC && k->u.ecc.dp.oidlen == 0) k2.u.ecc.dp.oidlen = 0;
#endif
   DO(pka_key_export(der1, &l1, which, k));
   DO(pka_key_export(der2, &l2, which, &k2));
   COMPARE_TESTVECTOR(der2, l2, der1, l1, label, which);
   pka_key_free(&k2);

   if (opts != NULL && opts->pw != NULL) {
      pw_ctx.userdata = (void*)"wrong";
      SHOULD_FAIL(pem_decode_pkcs(pem, len, &k2, &pw_ctx));
   }
   return CRYPT_OK;
}

static int s_pem_encode_key(const ltc_pka_key *k, int has_public)
{
   pbes2_enc_params cheap = { NULL, 0, NULL, 2, 0 }; /* the KDF cost is not what gets tested here */
   pem_encode_opts crlf = { NULL, 0, NULL, LTC_PEM_CRLF };
   pem_encode_opts enc = { (const unsigned char*)"secret", 6, &cheap, 0 };
   pem_encode_opts enc_crlf = { (const unsigned char*)"secret", 6, &cheap, LTC_PEM_CRLF };
   unsigned char buf[8192];
   unsigned long len = sizeof(buf);

   DO(s_pem_encode_roundtrip(k, PK_PRIVATE | PK_STD, NULL, "PRIVATE KEY"));
   DO(s_pem_encode_roundtrip(k, PK_PRIVATE | PK_STD, &crlf, "PRIVATE KEY"));
   DO(s_pem_encode_roundtrip(k, PK_PRIVATE | PK_STD, &enc, "ENCRYPTED PRIVATE KEY"));
   DO(s_pem_encode_roundtrip(k, PK_PRIVATE | PK_STD, &enc_crlf, "ENCRYPTED PRIVATE KEY"));
   if (has_public) {
      DO(s_pem_encode_roundtrip(k, PK_PUBLIC | PK_STD, NULL, "PUBLIC KEY"));
      DO(s_pem_encode_roundtrip(k, PK_PUBLIC | PK_STD, &crlf, "PUBLIC KEY"));
   } else {
      SHOULD_FAIL_WITH(pem_encode_pkcs(buf, &len, PK_PUBLIC | PK_STD, k, NULL, NULL, -1), CRYPT_PK_INVALID_TYPE);
   }
   return CRYPT_OK;
}

#ifdef LTC_CURVE25519
/* Ed25519 secret key of RFC 8032 test 1, password "secret", salt 00..0f, IV 10..1f, 2048 iterations, AES-256-CBC, HMAC-SHA256.
   The expected text was not made by this library: PBKDF2 by Python hashlib, AES-CBC by "openssl enc", DER put together by hand. */
static int s_pem_encode_kat(void)
{
   static const unsigned char sk[32] = {
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
      0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
   };
   static const char kat[] =
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
      "MIGjMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBAAAQIDBAUGBwgJCgsM\n"
      "DQ4PAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQEBESExQVFhcYGRob\n"
      "HB0eHwRASo70MuD4ER7He18h2Mcl4z0dzy3FcVI/uVyPR/mzrJ3INxHLGQ3R18eo\n"
      "68A4AJhdk+AaYRnJqDN5IGZLdg6YgQ==\n"
      "-----END ENCRYPTED PRIVATE KEY-----\n";
   pbes2_enc_params params = { "aes", 32, "sha256", 2048, 16 };
   pem_encode_opts opts = { (const unsigned char*)"secret", 6, &params, 0 };
   password_ctx pw_ctx = { .callback = s_password_get_str, .userdata = (void*)"secret" };
   struct ltc_prng_descriptor *no_prng_desc = no_prng_desc_get();
   int no_prng_idx = register_prng(no_prng_desc);
   unsigned char pem[512], seed[32];
   unsigned long len = sizeof(pem), n;
   ltc_pka_key k, k2;

   for (n = 0; n < sizeof(seed); n++) seed[n] = (unsigned char)n;
   DO(no_prng_desc->add_entropy(seed, sizeof(seed), (prng_state*)no_prng_desc));
   k.id = LTC_PKA_ED25519;
   DO(ed25519_import_raw(sk, sizeof(sk), PK_PRIVATE, &k.u.ed25519));
   DO(pem_encode_pkcs(pem, &len, PK_PRIVATE | PK_STD, &k, &opts, (prng_state*)no_prng_desc, no_prng_idx));
   COMPARE_TESTVECTOR(pem, len, kat, strlen(kat), "pem_encode_pkcs KAT", 0);
   unregister_prng(no_prng_desc);
   no_prng_desc_free(no_prng_desc);

   DO(pem_decode_pkcs(kat, strlen(kat), &k2, &pw_ctx));
   ENSURE(k2.id == LTC_PKA_ED25519 && k2.u.ed25519.type == PK_PRIVATE);
   COMPARE_TESTVECTOR(k2.u.ed25519.priv, sizeof(k2.u.ed25519.priv), sk, sizeof(sk), "pem_decode_pkcs KAT", 0);
   COMPARE_TESTVECTOR(k2.u.ed25519.pub, sizeof(k2.u.ed25519.pub), k.u.ed25519.pub, sizeof(k.u.ed25519.pub), "pem_decode_pkcs KAT", 1);
   return CRYPT_OK;
}
#endif

static int s_pem_encode_test(void)
{
   ltc_pka_key k;
   int prng_idx = find_prng("yarrow");

   LTC_UNUSED_PARAM(prng_idx);

   /* every key type that has an importer, plain and encrypted, private and public */
#if defined(LTC_MRSA)
   {
      unsigned char buf[16];
      unsigned long len = sizeof(buf);
      k.id = LTC_PKA_RSA;
      k.u.rsa = s_rsa_key_should;
      DO(s_pem_encode_key(&k, 1));
      /* there is no encoder for the parameters of a restricted key */
      k.id = LTC_PKA_RSA_PSS;
      SHOULD_FAIL_WITH(pem_encode_pkcs(buf, &len, PK_PRIVATE | PK_STD, &k, NULL, NULL, -1), CRYPT_PK_INVALID_TYPE);
      SHOULD_FAIL_WITH(pem_encode_pkcs(buf, &len, PK_PUBLIC | PK_STD, &k, NULL, NULL, -1), CRYPT_PK_INVALID_TYPE);
      k.id = LTC_PKA_RSA;
      k.u.rsa.pss_oaep = 1;
      SHOULD_FAIL_WITH(pem_encode_pkcs(buf, &len, PK_PRIVATE | PK_STD, &k, NULL, NULL, -1), CRYPT_PK_INVALID_TYPE);
   }
#endif
#if defined(LTC_MDSA)
   k.id = LTC_PKA_DSA;
   k.u.dsa = s_dsa_key_should;
   DO(s_pem_encode_key(&k, 1));
#endif
#if defined(LTC_MECC)
   k.id = LTC_PKA_EC;
   k.u.ecc = s_ecc_key_should;
   ENSURE(k.u.ecc.dp.oidlen > 0);
   DO(s_pem_encode_key(&k, 1));
   k.u.ecc.dp.oidlen = 0; /* a curve without OID is written with explicit parameters */
   DO(s_pem_encode_key(&k, 1));
#endif
#if defined(LTC_MDH)
   k.id = LTC_PKA_DH;
   DO(dh_set_pg_groupsize(96, &k.u.dh));
   DO(dh_generate_key(&yarrow_prng, prng_idx, &k.u.dh));
   DO(s_pem_encode_key(&k, 0));
   dh_free(&k.u.dh);
#endif
#if defined(LTC_CURVE25519)
   k.id = LTC_PKA_X25519;
   DO(x25519_make_key(&yarrow_prng, prng_idx, &k.u.x25519));
   DO(s_pem_encode_key(&k, 1));
   k.id = LTC_PKA_ED25519;
   DO(ed25519_make_key(&yarrow_prng, prng_idx, &k.u.ed25519));
   DO(s_pem_encode_key(&k, 1));
   DO(s_pem_encode_kat());
   {
      pem_encode_opts opts = { (const unsigned char*)"secret", 6, NULL, 0 };
      password_ctx pw_ctx = { .callback = s_password_get_str, .userdata = (void*)"secret" };
      unsigned char buf[512];
      unsigned long len;
      ltc_pka_key k2;

      /* a password is not ignored where it cannot be used */
      len = sizeof(buf);
      SHOULD_FAIL_WITH(pem_encode_pkcs(buf, &len, PK_PUBLIC | PK_STD, &k, &opts, &yarrow_prng, prng_idx), CRYPT_INVALID_ARG);
      /* an empty password must not end up as an unencrypted key */
      opts.pwlen = 0;
      len = sizeof(buf);
      SHOULD_FAIL_WITH(pem_encode_pkcs(buf, &len, PK_PRIVATE | PK_STD, &k, &opts, &yarrow_prng, prng_idx), CRYPT_INVALID_ARG);
      /* the raw formats have no PEM label */
      len = sizeof(buf);
      SHOULD_FAIL_WITH(pem_encode_pkcs(buf, &len, PK_PUBLIC, &k, NULL, NULL, -1), CRYPT_INVALID_ARG);
      len = sizeof(buf);
      SHOULD_FAIL_WITH(pem_encode_pkcs(buf, &len, PK_PRIVATE, &k, NULL, NULL, -1), CRYPT_INVALID_ARG);
      SHOULD_FAIL_WITH(pka_key_export(buf, &len, PK_PUBLIC, &k), CRYPT_INVALID_ARG);
      SHOULD_FAIL_WITH(pka_key_export(buf, &len, PK_PRIVATE, &k), CRYPT_INVALID_ARG);
      SHOULD_FAIL_WITH(pka_key_export(buf, &len, PK_PRIVATE | PK_STD | PK_COMPRESSED, &k), CRYPT_INVALID_ARG);
      /* a public key has no private part to write */
      k.u.ed25519.type = PK_PUBLIC;
      len = sizeof(buf);
      SHOULD_FAIL(pem_encode_pkcs(buf, &len, PK_PRIVATE | PK_STD, &k, NULL, NULL, -1));
      k.u.ed25519.type = PK_PRIVATE;

#ifndef LTC_NO_FILE
      {
         FILE *f = tmpfile();
         if (f != NULL) {
            opts.pwlen = 6;
            DO(pem_encode_pkcs_filehandle(f, PK_PRIVATE | PK_STD, &k, &opts, &yarrow_prng, prng_idx));
            rewind(f);
            DO(pem_decode_pkcs_filehandle(f, &k2, &pw_ctx));
            ENSURE(k2.id == LTC_PKA_ED25519);
            COMPARE_TESTVECTOR(k2.u.ed25519.priv, sizeof(k2.u.ed25519.priv), k.u.ed25519.priv, sizeof(k.u.ed25519.priv), "pem_encode_pkcs_filehandle", 0);
            fclose(f);
         }
      }
#else
      LTC_UNUSED_PARAM(pw_ctx);
      LTC_UNUSED_PARAM(k2);
#endif
   }
#endif
#if defined(LTC_CURVE448)
   k.id = LTC_PKA_X448;
   DO(x448_make_key(&yarrow_prng, prng_idx, &k.u.x448));
   DO(s_pem_encode_key(&k, 1));
   k.id = LTC_PKA_ED448;
   DO(ed448_make_key(&yarrow_prng, prng_idx, &k.u.ed448));
   DO(s_pem_encode_key(&k, 1));
#endif

   return CRYPT_OK;
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

   DO(s_pbes2_encrypt_test());
   DO(s_pem_encode_test());

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
