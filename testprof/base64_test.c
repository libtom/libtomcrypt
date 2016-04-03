#include  <tomcrypt_test.h>

#ifdef LTC_BASE64
int base64_test(void)
{
   unsigned char in[64], out[256], tmp[64];
   unsigned long x, l1, l2, slen1;
   const char special_case[] =
      { 0xbe, 0xe8, 0x92, 0x3c, 0xa2, 0x25, 0xf0, 0xf8, 0x91, 0xe4, 0xef, 0xab,
            0x0b, 0x8c, 0xfd, 0xff, 0x14, 0xd0, 0x29, 0x9d };

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
       {special_case,"vuiSPKIl8PiR5O+rC4z9/xTQKZ0="}
   };

   const struct {
      const char* s;
      int mode;
   } url_cases[] = {
         {"vuiSPKIl8PiR5O-rC4z9_xTQKZ0", 0},
         {"vuiSPKIl8PiR5O-rC4z9_xTQKZ0=", 1},
         {"vuiS*PKIl8P*iR5O-rC4*z9_xTQKZ0", 0},
         {"vuiS*PKIl8P*iR5O-rC4*z9_xTQKZ0=", 0},
   };

   for (x = 0; x < sizeof(cases)/sizeof(cases[0]); ++x) {
       slen1 = strlen(cases[x].s);
       l1 = sizeof(out);
       DO(base64_encode((unsigned char*)cases[x].s, slen1, out, &l1));
       l2 = sizeof(tmp);
       DO(base64_decode(out, l1, tmp, &l2));
       if (l2 != slen1 || l1 != strlen(cases[x].b64) || memcmp(tmp, cases[x].s, l2) || memcmp(out, cases[x].b64, l1)) {
           fprintf(stderr, "\nbase64 failed case %lu", x);
           fprintf(stderr, "\nbase64 should: %s", cases[x].b64);
           out[sizeof(out)-1] = '\0';
           fprintf(stderr, "\nbase64 is:     %s", out);
           fprintf(stderr, "\nplain  should: %s", cases[x].s);
           tmp[sizeof(tmp)-1] = '\0';
           fprintf(stderr, "\nplain  is:     %s\n", tmp);
           return 1;
       }
   }

   for (x = 0; x < sizeof(url_cases)/sizeof(url_cases[0]); ++x) {
       slen1 = strlen(url_cases[x].s);
       l1 = sizeof(out);
       DO(base64url_decode_ex((unsigned char*)url_cases[x].s, slen1, out, &l1, url_cases[x].mode));
       if (l1 != sizeof(special_case) ||  memcmp(out, special_case, l1)) {
           fprintf(stderr, "\nbase64url failed case %lu: %s", x, url_cases[x].s);
           print_hex("\nbase64url should", special_case, sizeof(special_case));
           out[sizeof(out)-1] = '\0';
           print_hex("\nbase64url is", out, l1);
           return 1;
       }
   }


   for  (x = 0; x < 64; x++) {
       yarrow_read(in, x, &yarrow_prng);
       l1 = sizeof(out);
       DO(base64_encode(in, x, out, &l1));
       l2 = sizeof(tmp);
       DO(base64_decode(out, l1, tmp, &l2));
       if (l2 != x || memcmp(tmp, in, x)) {
           fprintf(stderr, "base64 failed %lu %lu %lu", x, l1, l2);
           return 1;
       }
   }

   x--;
   memmove(&out[11], &out[10], l1 - 10);
   out[10] = '\0';
   l1++;
   l2 = sizeof(tmp);
   DO(base64_decode_ex(out, l1, tmp, &l2, 0));
   if (l2 != x || memcmp(tmp, in, x)) {
       fprintf(stderr, "loose base64 decoding failed %lu %lu %lu", x, l1, l2);
       print_hex("is    ", tmp, l2);
       print_hex("should", in, x);
       print_hex("input ", out, l1);
       return 1;
   }
   l2 = sizeof(tmp);
   DO(base64_decode_ex(out, l1, tmp, &l2, 1) == CRYPT_INVALID_PACKET ? CRYPT_OK : CRYPT_INVALID_PACKET);
   return 0;
}
#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
