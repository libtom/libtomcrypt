/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include  <tomcrypt_test.h>

#if defined(LTC_BASE64) || defined(LTC_BASE64_URL)
enum { insane = 0, strict = 1, relaxed = 2, invalid = 666 };

int base64_test(void)
{
   unsigned char in[64], tmp[64];
   char out[256];
   unsigned long x, l1, l2, slen1;

   const unsigned char special_case[] = {
         0xbe, 0xe8, 0x92, 0x3c, 0xa2, 0x25, 0xf0, 0xf8,
         0x91, 0xe4, 0xef, 0xab, 0x0b, 0x8c, 0xfd, 0xff,
         0x14, 0xd0, 0x29, 0x9d, 0x00 };
   /* 3 A's are encoded as QUFB */
   const char *As_lf = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\nQUFB";
   const char *As_crlf = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\r\nQUFB";
   const char *As_ssh_lf = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\nQUFB";
   const char *As_ssh_crlf = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\r\nQUFB";

#if defined(LTC_BASE64)
   /*
    TEST CASES SOURCE:

    Network Working Group                                       S. Josefsson
    Request for Comments: 4648                                           SJD
    Obsoletes: 3548                                             October 2006
    Category: Standards Track
    */
   const struct {
     const char* s;
     const char* b64;
   } cases[] = {
       {"", ""              },
       {"f", "Zg=="         },
       {"fo", "Zm8="        },
       {"foo", "Zm9v"       },
       {"foob", "Zm9vYg=="  },
       {"fooba", "Zm9vYmE=" },
       {"foobar", "Zm9vYmFy"},
       {(char*)special_case,"vuiSPKIl8PiR5O+rC4z9/xTQKZ0="}
   };
#endif

#ifdef LTC_BASE64_URL
   const struct {
      const char* s;
      int flag;
   } url_cases[] = {
         {"vuiSPKIl8PiR5O-rC4z9_xTQKZ0", strict},                       /* 0 */
         {"vuiSPKIl8PiR5O-rC4z9_xTQKZ0=", strict},
         {"vuiS*PKIl8P*iR5O-rC4*z9_xTQKZ0", insane},
         {"vuiS*PKIl8P*iR5O-rC4*z9_xTQKZ0=", insane},
         {"vuiS*PKIl8P*iR5O-rC4*z9_xTQKZ0==", insane},
         {"vuiS*PKIl8P*iR5O-rC4*z9_xTQKZ0===", insane},                 /* 5 */
         {"vuiS*PKIl8P*iR5O-rC4*z9_xTQKZ0====", insane},
         {"vuiS*=PKIl8P*iR5O-rC4*z9_xTQKZ0=", insane},
         {"vuiS*==PKIl8P*iR5O-rC4*z9_xTQKZ0=", insane},
         {"vuiS*==\xffPKIl8P*iR5O-rC4*z9_xTQKZ0=", insane},
         {"vuiS PKIl8P\niR5O-rC4\tz9_xTQKZ0", relaxed},                 /* 10 */
         {"vuiS PKIl8P\niR5O-rC4\tz9_xTQKZ0=", relaxed},
         {"vuiS PKIl8P\niR5O-rC4\tz9_xTQKZ0==", relaxed},
         {"vuiS PKIl8P\niR5O-rC4\tz9_xTQKZ0===", relaxed},
         {"vuiS PKIl8P\niR5O-rC4\tz9_xTQKZ0====", relaxed},
         {"vuiS\rPKIl8P\niR5O-rC4\tz9_xTQKZ0=", relaxed},               /* 15 */
         {"vuiS\rPKIl8P\niR5O-rC4\tz9_xTQKZ0= = =\x00", relaxed},
         {"\nvuiS\rPKIl8P\niR5O-rC4\tz9_xTQKZ0=\n", relaxed},
         {"vuiSPKIl8PiR5O-rC4z9_xTQK", invalid},
   };

   for (x = 0; x < LTC_ARRAY_SIZE(url_cases); ++x) {
       slen1 = XSTRLEN(url_cases[x].s);
       l1 = sizeof(tmp);
       if(url_cases[x].flag == strict) {
          DO(base64url_strict_decode(url_cases[x].s, slen1, tmp, &l1));
          COMPARE_TESTVECTOR(tmp, l1, special_case, sizeof(special_case) - 1, "base64url_strict_decode", x);
          DO(base64url_sane_decode(url_cases[x].s, slen1, tmp, &l1));
          COMPARE_TESTVECTOR(tmp, l1, special_case, sizeof(special_case) - 1, "base64url_sane_decode/strict", x);
          DO(base64url_decode(url_cases[x].s, slen1, tmp, &l1));
          COMPARE_TESTVECTOR(tmp, l1, special_case, sizeof(special_case) - 1, "base64url_decode/strict", x);
       }
       else if(url_cases[x].flag == relaxed) {
          DO(base64url_strict_decode(url_cases[x].s, slen1, tmp, &l1) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
          DO(base64url_sane_decode(url_cases[x].s, slen1, tmp, &l1));
          COMPARE_TESTVECTOR(tmp, l1, special_case, sizeof(special_case) - 1, "base64url_sane_decode/relaxed", x);
          DO(base64url_decode(url_cases[x].s, slen1, tmp, &l1));
          COMPARE_TESTVECTOR(tmp, l1, special_case, sizeof(special_case) - 1, "base64url_decode/relaxed", x);
       }
       else if(url_cases[x].flag == insane) {
          DO(base64url_strict_decode(url_cases[x].s, slen1, tmp, &l1) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
          DO(base64url_sane_decode(url_cases[x].s, slen1, tmp, &l1) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
          DO(base64url_decode(url_cases[x].s, slen1, tmp, &l1));
          COMPARE_TESTVECTOR(tmp, l1, special_case, sizeof(special_case) - 1, "base64url_decode/insane", x);
       }
       else { /* invalid */
          DO(base64url_strict_decode(url_cases[x].s, slen1, tmp, &l1) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
          DO(base64url_sane_decode(url_cases[x].s, slen1, tmp, &l1) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
          DO(base64url_decode(url_cases[x].s, slen1, tmp, &l1) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
       }
       l2 = sizeof(out);
       if(x == 0) {
          DO(base64url_encode(tmp, l1, out, &l2));
          COMPARE_TESTVECTOR(out, l2, url_cases[x].s, XSTRLEN(url_cases[x].s), "base64url_encode", x);
       }
       if(x == 1) {
          DO(base64url_strict_encode(tmp, l1, out, &l2));
          COMPARE_TESTVECTOR(out, l2, url_cases[x].s, XSTRLEN(url_cases[x].s), "base64url_strict_encode", x);
       }
   }
#endif

#if defined(LTC_BASE64)
   for (x = 0; x < LTC_ARRAY_SIZE(cases); ++x) {
       memset(out, 0, sizeof(out));
       memset(tmp, 0, sizeof(tmp));
       slen1 = XSTRLEN(cases[x].s);
       l1 = sizeof(out);
       DO(base64_encode((unsigned char*)cases[x].s, slen1, out, &l1));
       COMPARE_TESTVECTOR(out, l1, cases[x].b64, XSTRLEN(cases[x].b64), "base64_encode", x);
       l2 = sizeof(tmp);
       DO(base64_strict_decode(out, l1, tmp, &l2));
       COMPARE_TESTVECTOR(tmp, l2, cases[x].s, slen1, "base64_strict_decode", x);
       DO(base64_sane_decode(out, l1, tmp, &l2));
       COMPARE_TESTVECTOR(tmp, l2, cases[x].s, slen1, "base64_sane_decode", x);
       DO(base64_decode(out, l1, tmp, &l2));
       COMPARE_TESTVECTOR(tmp, l2, cases[x].s, slen1, "base64_decode", x);
   }

   for  (x = 0; x < 64; x++) {
       ENSURE(yarrow_read(in, x, &yarrow_prng) == x);
       l1 = sizeof(out);
       DO(base64_encode(in, x, out, &l1));
       l2 = sizeof(tmp);
       DO(base64_decode(out, l1, tmp, &l2));
       COMPARE_TESTVECTOR(tmp, x, in, x, "random base64", x);
   }

   x--;
   memmove(&out[11], &out[10], l1 - 10);
   l1++;
   l2 = sizeof(tmp);

   out[10] = 0;
   DO(base64_decode(out, l1, tmp, &l2));
   COMPARE_TESTVECTOR(tmp, l2, in, l2, "insane base64 decoding (NUL)", 0);
   DO(base64_sane_decode(out, l1, tmp, &l2) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_INVALID_PACKET);
   DO(base64_strict_decode(out, l1, tmp, &l2) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_INVALID_PACKET);

   out[10] = 9; /* tab */
   DO(base64_decode(out, l1, tmp, &l2));
   COMPARE_TESTVECTOR(tmp, l2, in, l2, "insane base64 decoding (TAB)", 0);
   DO(base64_sane_decode(out, l1, tmp, &l2));
   COMPARE_TESTVECTOR(tmp, l2, in, l2, "relaxed base64 decoding (TAB)", 0);
   DO(base64_strict_decode(out, l1, tmp, &l2) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_INVALID_PACKET);

   memset(in, 'A', sizeof(in));
   l1 = strlen(As_lf);
   SHOULD_FAIL(base64_encode_pem(in, 51, out, &l1, 0));
   l1++;
   DO(base64_encode_pem(in, 51, out, &l1, 0));
   COMPARE_TESTVECTOR(out, l1, As_lf, strlen(As_lf), "PEM output with \\n", 0);
   l1 = strlen(As_crlf) + 1;
   DO(base64_encode_pem(in, 51, out, &l1, BASE64_PEM_CRLF));
   COMPARE_TESTVECTOR(out, l1, As_crlf, strlen(As_crlf), "PEM output with \\r\\n", 0);
   l1 = strlen(As_ssh_lf) + 1;
   DO(base64_encode_pem(in, 57, out, &l1, BASE64_PEM_SSH));
   COMPARE_TESTVECTOR(out, l1, As_ssh_lf, strlen(As_ssh_lf), "PEM SSH-style output with \\n", 0);
   l1 = strlen(As_ssh_crlf) + 1;
   DO(base64_encode_pem(in, 57, out, &l1, BASE64_PEM_SSH | BASE64_PEM_CRLF));
   COMPARE_TESTVECTOR(out, l1, As_ssh_crlf, strlen(As_ssh_crlf), "PEM SSH-style output with \\r\\n", 0);

   /* 150 bytes are 200 base64 chars, so every variant has to break more than one line */
   for (x = 0; x < 4; x++) {
      unsigned char big[150];
      char plain[201], stripped[201];
      unsigned long n, col = 0, linelen = (x & 2) ? 72 : 64, eol = (x & 1) ? 2 : 1;

      memset(big, 'A', sizeof(big));
      l2 = sizeof(plain);
      DO(base64_encode(big, sizeof(big), plain, &l2));
      l1 = sizeof(out);
      DO(base64_encode_pem(big, sizeof(big), out, &l1, ((x & 1) ? BASE64_PEM_CRLF : 0) | ((x & 2) ? BASE64_PEM_SSH : 0)));
      ENSURE(l1 == l2 + (l2 / linelen) * eol);
      for (n = 0, slen1 = 0; n < l1; n++) {
         if (out[n] == '\n') {
            ENSURE(col == linelen);
            col = 0;
         } else if (out[n] != '\r') {
            stripped[slen1++] = out[n];
            col++;
         }
      }
      COMPARE_TESTVECTOR(stripped, slen1, plain, l2, "PEM output with several lines", x);
   }
#endif

   return 0;
}
#endif
