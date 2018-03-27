/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
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

   for (x = 0; x < sizeof(url_cases)/sizeof(url_cases[0]); ++x) {
       slen1 = strlen(url_cases[x].s);
       l1 = sizeof(tmp);
       if(url_cases[x].flag == strict) {
          DO(base64url_strict_decode(url_cases[x].s, slen1, tmp, &l1));
          DO(do_compare_testvector(tmp, l1, special_case, sizeof(special_case) - 1, "base64url_strict_decode", x));
          DO(base64url_sane_decode(url_cases[x].s, slen1, tmp, &l1));
          DO(do_compare_testvector(tmp, l1, special_case, sizeof(special_case) - 1, "base64url_sane_decode/strict", x));
          DO(base64url_decode(url_cases[x].s, slen1, tmp, &l1));
          DO(do_compare_testvector(tmp, l1, special_case, sizeof(special_case) - 1, "base64url_decode/strict", x));
       }
       else if(url_cases[x].flag == relaxed) {
          DO(base64url_strict_decode(url_cases[x].s, slen1, tmp, &l1) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
          DO(base64url_sane_decode(url_cases[x].s, slen1, tmp, &l1));
          DO(do_compare_testvector(tmp, l1, special_case, sizeof(special_case) - 1, "base64url_sane_decode/relaxed", x));
          DO(base64url_decode(url_cases[x].s, slen1, tmp, &l1));
          DO(do_compare_testvector(tmp, l1, special_case, sizeof(special_case) - 1, "base64url_decode/relaxed", x));
       }
       else if(url_cases[x].flag == insane) {
          DO(base64url_strict_decode(url_cases[x].s, slen1, tmp, &l1) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
          DO(base64url_sane_decode(url_cases[x].s, slen1, tmp, &l1) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
          DO(base64url_decode(url_cases[x].s, slen1, tmp, &l1));
          DO(do_compare_testvector(tmp, l1, special_case, sizeof(special_case) - 1, "base64url_decode/insane", x));
       }
       else { /* invalid */
          DO(base64url_strict_decode(url_cases[x].s, slen1, tmp, &l1) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
          DO(base64url_sane_decode(url_cases[x].s, slen1, tmp, &l1) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
          DO(base64url_decode(url_cases[x].s, slen1, tmp, &l1) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
       }
       l2 = sizeof(out);
       if(x == 0) {
          DO(base64url_encode(tmp, l1, out, &l2));
          DO(do_compare_testvector(out, l2, url_cases[x].s, strlen(url_cases[x].s), "base64url_encode", x));
       }
       if(x == 1) {
          DO(base64url_strict_encode(tmp, l1, out, &l2));
          DO(do_compare_testvector(out, l2, url_cases[x].s, strlen(url_cases[x].s), "base64url_strict_encode", x));
       }
   }
#endif

#if defined(LTC_BASE64)
   for (x = 0; x < sizeof(cases)/sizeof(cases[0]); ++x) {
       memset(out, 0, sizeof(out));
       memset(tmp, 0, sizeof(tmp));
       slen1 = strlen(cases[x].s);
       l1 = sizeof(out);
       DO(base64_encode((unsigned char*)cases[x].s, slen1, out, &l1));
       DO(do_compare_testvector(out, l1, cases[x].b64, strlen(cases[x].b64), "base64_encode", x));
       l2 = sizeof(tmp);
       DO(base64_strict_decode(out, l1, tmp, &l2));
       DO(do_compare_testvector(tmp, l2, cases[x].s, slen1, "base64_strict_decode", x));
       DO(base64_sane_decode(out, l1, tmp, &l2));
       DO(do_compare_testvector(tmp, l2, cases[x].s, slen1, "base64_sane_decode", x));
       DO(base64_decode(out, l1, tmp, &l2));
       DO(do_compare_testvector(tmp, l2, cases[x].s, slen1, "base64_decode", x));
   }

   for  (x = 0; x < 64; x++) {
       yarrow_read(in, x, &yarrow_prng);
       l1 = sizeof(out);
       DO(base64_encode(in, x, out, &l1));
       l2 = sizeof(tmp);
       DO(base64_decode(out, l1, tmp, &l2));
       DO(do_compare_testvector(tmp, x, in, x, "random base64", x));
   }

   x--;
   memmove(&out[11], &out[10], l1 - 10);
   l1++;
   l2 = sizeof(tmp);

   out[10] = 0;
   DO(base64_decode(out, l1, tmp, &l2));
   DO(compare_testvector(tmp, l2, in, l2, "insane base64 decoding (NUL)", -1));
   DO(base64_sane_decode(out, l1, tmp, &l2) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_INVALID_PACKET);
   DO(base64_strict_decode(out, l1, tmp, &l2) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_INVALID_PACKET);

   out[10] = 9; /* tab */
   DO(base64_decode(out, l1, tmp, &l2));
   DO(compare_testvector(tmp, l2, in, l2, "insane base64 decoding (TAB)", -1));
   DO(base64_sane_decode(out, l1, tmp, &l2));
   DO(compare_testvector(tmp, l2, in, l2, "relaxed base64 decoding (TAB)", -1));
   DO(base64_strict_decode(out, l1, tmp, &l2) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_INVALID_PACKET);
#endif

   return 0;
}
#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
