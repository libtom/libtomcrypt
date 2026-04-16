/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include <tomcrypt_test.h>

#if defined(LTC_PEM) && defined(LTC_TEST_READDIR) && !defined(LTC_EASY)

static int s_x509_decode(const void *in, unsigned long inlen, void *cert)
{
   return x509_import_pem(in, &inlen, cert);
}

static int s_x509_decode_f(FILE *f, void *cert)
{
   int err = x509_import_pem_filehandle(f, cert);
   if (err == CRYPT_UNKNOWN_PEM)
      err = CRYPT_NOP;
   return err;
}

static int s_x509_decode_bad(const void *in, unsigned long inlen, void *cert)
{
   SHOULD_FAIL(x509_import_pem(in, &inlen, cert));
   return CRYPT_OK;
}

static int s_x509_decode_bad_f(FILE *f, void *cert)
{
   SHOULD_FAIL(x509_import_pem_filehandle(f, cert));
   return CRYPT_OK;
}

static int s_x509_test_sig_algo_mismatch(void)
{
   const ltc_x509_certificate *cert;
   int err, stat;
   FILE *f;

   f = fopen("tests/x509/invalid/sig_algo_mismatch.pem", "r");
   if (f == NULL) return CRYPT_FILE_NOTFOUND;
   err = x509_import_pem_filehandle(f, &cert);
   fclose(f);
   if (err != CRYPT_OK) return err;
   /* The cert has sha384 in TBS but sha256 in outer signatureAlgorithm, x509_cert_is_signed_by must reject the algorithm mismatch. */
   SHOULD_FAIL_WITH(x509_cert_is_signed_by(cert, &cert->tbs_certificate.subject_public_key_info, &stat), CRYPT_PK_TYPE_MISMATCH);
   x509_free(&cert);
   return CRYPT_OK;
}

int x509_test(void)
{
   const ltc_x509_certificate *cert;

   if (ltc_mp.name == NULL) return CRYPT_NOP;

   DO(s_x509_test_sig_algo_mismatch());
   DO(test_process_dir("tests/x509", &cert, (dir_iter_cb)s_x509_decode, NULL, (dir_cleanup_cb)x509_free, "x509_test"));
   DO(test_process_dir("tests/x509", &cert, NULL, (dir_fiter_cb)s_x509_decode_f, (dir_cleanup_cb)x509_free, "x509_test_filehandle"));
   DO(test_process_dir("tests/x509/openssl", &cert, (dir_iter_cb)s_x509_decode, NULL, (dir_cleanup_cb)x509_free, "x509_test_openssl"));
   DO(test_process_dir("tests/x509/openssl", &cert, NULL, (dir_fiter_cb)s_x509_decode_f, (dir_cleanup_cb)x509_free, "x509_test_openssl_filehandle"));
   DO(test_process_dir("tests/x509/openssl/bad", &cert, (dir_iter_cb)s_x509_decode_bad, NULL, NULL, "x509_test_openssl_bad"));
   DO(test_process_dir("tests/x509/openssl/bad", &cert, NULL, (dir_fiter_cb)s_x509_decode_bad_f, NULL, "x509_test_openssl_bad_filehandle"));
   DO(test_process_dir("tests/x509/gnutls", &cert, (dir_iter_cb)s_x509_decode, NULL, (dir_cleanup_cb)x509_free, "x509_test_gnutls"));
   DO(test_process_dir("tests/x509/gnutls", &cert, NULL, (dir_fiter_cb)s_x509_decode_f, (dir_cleanup_cb)x509_free, "x509_test_gnutls_filehandle"));
   DO(test_process_dir("tests/x509/gnutls/bad", &cert, (dir_iter_cb)s_x509_decode_bad, NULL, NULL, "x509_test_gnutls_bad"));
   DO(test_process_dir("tests/x509/gnutls/bad", &cert, NULL, (dir_fiter_cb)s_x509_decode_bad_f, NULL, "x509_test_gnutls_bad_filehandle"));
   if (strcmp(ltc_mp.name, "TomsFastMath") == 0)
      return 0;
   DO(test_process_dir("tests/x509/openssl/non-tfm", &cert, (dir_iter_cb)s_x509_decode, NULL, (dir_cleanup_cb)x509_free, "x509_test_openssl_non_tfm"));
   DO(test_process_dir("tests/x509/openssl/non-tfm", &cert, NULL, (dir_fiter_cb)s_x509_decode_f, (dir_cleanup_cb)x509_free, "x509_test_openssl_filehandle_non_tfm"));
   DO(test_process_dir("tests/x509/gnutls/non-tfm", &cert, (dir_iter_cb)s_x509_decode, NULL, (dir_cleanup_cb)x509_free, "x509_test_gnutls_non_tfm"));
   DO(test_process_dir("tests/x509/gnutls/non-tfm", &cert, NULL, (dir_fiter_cb)s_x509_decode_f, (dir_cleanup_cb)x509_free, "x509_test_gnutls_filehandle_non_tfm"));

   return 0;
}

#else

int x509_test(void)
{
   return CRYPT_NOP;
}

#endif
