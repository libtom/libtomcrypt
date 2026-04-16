/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/* load a X.509 certificate chain and verify its validity */
#include <tomcrypt.h>
#include <stdarg.h>

#ifdef LTC_QUIET
static void print_err(const char *fmt, ...)
{
   LTC_UNUSED_PARAM(fmt);
}

#define print_stderr(...)
#else
static void print_err(const char *fmt, ...)
{
   va_list args;

   va_start(args, fmt);
   vfprintf(stderr, fmt, args);
   va_end(args);
}

#define print_stderr(...) fprintf(stderr, ##__VA_ARGS__)
#endif

#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
#define LTC_DER_PRINT_FLEXI_NO_MAIN
#include "der_print_flexi.c"

static void s_der_print_flexi(const ltc_asn1_list* l)
{
   print_stderr("\n\n");
   s_der_print_flexi_i(l, 0);
   print_stderr("\n\n");
}
#else
static void s_der_print_flexi(const ltc_asn1_list* l)
{
   LTC_UNUSED_PARAM(l);
}
#endif

static unsigned long num_certs;
static const ltc_x509_certificate *cert[256] = {0};
static FILE *f;

static void die_(int err, int line)
{
   unsigned long n;
   print_err("%3d: LTC sez %s\n", line, error_to_string(err));
   for (n = num_certs; n --> 0;) {
      x509_free(&cert[n]);
   }
   if (f) fclose(f);
   exit(EXIT_FAILURE);
}

#define die(i) do { die_(i, __LINE__); } while(0)
#define DIE(s, ...) do { print_err("%3d: " s "\n", __LINE__, ##__VA_ARGS__); exit(EXIT_FAILURE); } while(0)
#ifndef LTC_ARRAY_SIZE
#define LTC_ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))
#endif

int main(int argc, char **argv)
{
   const unsigned char zero_cert_buf[sizeof(cert)] = {0};
   int err, argn = 1;
   unsigned long len, processed, n;
   long tell, tot_data = 0;

   if ((err = register_all_hashes()) != CRYPT_OK) {
      die(err);
   }
   if ((err = crypt_mp_init("ltm")) != CRYPT_OK) {
      die(err);
   }

next:
   tot_data = processed = num_certs = n = 0;
   if (argc > argn) f = fopen(argv[argn], "r");
   else f = stdin;
   if (f == NULL) DIE("fopen sez no");
   if (f != stdin) {
      fseek(f, 0, SEEK_END);
      tot_data = ftell(f);
      fseek(f, 0, SEEK_SET);
      tell = 0;
   } else {
      tell = -1;
   }

   print_stderr("-=-=-=-=-=-=-\nDecode %s\n=-=-=-=-=-=-=\n", argv[argn]);

   while (tell != tot_data) {
      err = x509_import_pem_filehandle(f, &cert[n]);
      if (err == CRYPT_PK_ASN1_ERROR || err == CRYPT_UNKNOWN_PEM)
         continue;
      else if (err != CRYPT_OK)
         break;
      if (cert[n] && cert[n]->asn1)
         s_der_print_flexi(cert[n]->asn1);
      if (f != stdin) {
         tell = ftell(f);
         print_stderr("%2lu len: %ld - tot: %ld - processed: %lu (%s)\n", n, tell, tot_data, processed, error_to_string(err));
         len = tell - processed;
         processed += len;
      }
      n++;
      if (n == LTC_ARRAY_SIZE(cert))
         break;
   }
   num_certs = n;
   print_stderr("len: %ld - tot: %ld - processed: %lu (%s)\n", tell, tot_data, processed, error_to_string(err));
   if (err && argc > argn) goto check_next;
   if (err && err != CRYPT_NOP) die(err);
   for (n = 0; n < num_certs; ++n) {
      unsigned long m = n + 1 == num_certs ? n : n + 1;
      int stat;
      if ((err = x509_cert_is_signed_by(cert[n], &cert[m]->tbs_certificate.subject_public_key_info, &stat)) != CRYPT_OK) {
         print_err("%3d: LTC sez %s\n", __LINE__, error_to_string(err));
         if (m == n) {
            print_stderr("Cert is last in chain, but not self-signed.\n");
         } else {
            break;
         }
      }
      {
         const ltc_x509_string *subjects[4];
         const ltc_x509_name *subject, *issuer;
         int issuer_matches_next_subject = x509_name_eq(&cert[n]->tbs_certificate.issuer, &cert[m]->tbs_certificate.subject);
         subject = &cert[n]->tbs_certificate.subject;
         if (n != m) {
            issuer = &cert[m]->tbs_certificate.subject;
         } else {
            issuer = &cert[m]->tbs_certificate.issuer;
         }
         x509_name_detail_get(subject, LTC_X509_CN, &subjects[0]);
         x509_name_detail_get(subject, LTC_X509_O, &subjects[2]);
         x509_name_detail_get(issuer, LTC_X509_CN, &subjects[1]);
         x509_name_detail_get(issuer, LTC_X509_O, &subjects[3]);
#define X509_STRING_STR(s) (s) ? (s)->str : "NULL"
         print_stderr("Cert: %s - %s\nCA: %s - %s\nIssuer matches next subject: %s\nVerify: %s\n",
                         X509_STRING_STR(subjects[0]), X509_STRING_STR(subjects[2]),
                         X509_STRING_STR(subjects[1]), X509_STRING_STR(subjects[3]),
                         issuer_matches_next_subject ? "True" : "False", stat ? "Success" : "Failed");
         /* In case of LTC_QUIET this would show up as unused. */
         LTC_UNUSED_PARAM(issuer_matches_next_subject);
      }
   }
check_next:
   for (n = num_certs; n --> 0;) {
      x509_free(&cert[n]);
   }
   if (XMEMCMP(cert, zero_cert_buf, sizeof(zero_cert_buf))) {
      DIE("cert buf not completely cleaned");
   }
   if (f != stdin) {
      fclose(f);
      argn++;
      if (argc > argn) {
         goto next;
      }
   }
   return 0;
}
