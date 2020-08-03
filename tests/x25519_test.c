/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_test.h"

/**
  @file x25519_test.c
  x25519 tests, Steffen Jaeckel
*/

#ifdef LTC_CURVE25519

static int s_rfc_7748_5_2_test(void)
{
   /* RFC 7748 Ch. 5.2 */
   const struct {
      unsigned char scalar[32];
      unsigned char u_in[32];
      unsigned char u_out[32];
   } rfc_7748_5_2[] = {
        {
           {  0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
              0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
              0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
              0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4 },
           {  0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
              0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
              0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
              0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c },
           {  0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90,
              0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
              0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7,
              0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52 }
        },
        {
           {  0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c,
              0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d, 0x6a, 0xf5,
              0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4,
              0x2c, 0xa4, 0x16, 0x9e, 0x79, 0x18, 0xba, 0x0d },
           {  0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3,
              0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38, 0xae, 0x2c,
              0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e,
              0xfc, 0x4c, 0xd5, 0x49, 0xc7, 0x15, 0xa4, 0x93 },
           {  0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d,
              0x7a, 0xad, 0xe4, 0x5c, 0xb4, 0xb8, 0x73, 0xf8,
              0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52,
              0xe6, 0xf8, 0xf7, 0x64, 0x7a, 0xac, 0x79, 0x57 }
        }
   };
   unsigned char out[32];
   unsigned long n;

   for (n = 0; n < sizeof(rfc_7748_5_2)/sizeof(rfc_7748_5_2[0]); ++n) {
      tweetnacl_crypto_scalarmult(out, rfc_7748_5_2[n].scalar, rfc_7748_5_2[n].u_in);
      if (compare_testvector(out, sizeof(out), rfc_7748_5_2[n].u_out, sizeof(rfc_7748_5_2[n].u_out), "x25519 RFC 7748 Ch. 5.2", n) != 0) {
         return CRYPT_FAIL_TESTVECTOR;
      }
   }
   return CRYPT_OK;
}

static int s_rfc_7748_6_test(void)
{
   /* RFC 7748 Ch. 6 */
   const unsigned char alice_private[] = {
      0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
      0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
      0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
      0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
   };
   const unsigned char alice_public[] = {
      0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
      0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
      0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
      0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
   };
   const unsigned char bob_private[] = {
      0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
      0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
      0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
      0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
   };
   const unsigned char bob_public[] = {
      0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
      0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
      0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
      0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
   };
   const unsigned char shared_secret[] = {
      0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
      0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
      0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
      0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
   };
   curve25519_key alice_priv, alice_pub, bob_priv, bob_pub;
   unsigned char buf[32];
   unsigned long buflen = sizeof(buf);

   DO(x25519_import_raw(alice_private, sizeof(alice_private), PK_PRIVATE, &alice_priv));
   DO(x25519_import_raw(bob_private, sizeof(bob_private), PK_PRIVATE, &bob_priv));
   DO(x25519_import_raw(alice_public, sizeof(alice_public), PK_PUBLIC, &alice_pub));
   DO(x25519_import_raw(bob_public, sizeof(bob_public), PK_PUBLIC, &bob_pub));

   DO(x25519_shared_secret(&alice_priv, &bob_pub, buf, &buflen));
   DO(compare_testvector(buf, buflen, shared_secret, sizeof(shared_secret), "x25519 - RFC 7748 Ch. 6", 0));

   XMEMSET(buf, 0, sizeof(buf));

   DO(x25519_shared_secret(&bob_priv, &alice_pub, buf, &buflen));
   DO(compare_testvector(buf, buflen, shared_secret, sizeof(shared_secret), "x25519 - RFC 7748 Ch. 6", 1));

   return CRYPT_OK;
}

static int s_rfc_8410_10_test(void)
{
   const struct {
      const char *b64;
   } rfc_8410_10[] = {
                         /* RFC 8410 - 10.2.  Example X25519 Certificate */
                       { "MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZX"
                         "N0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQD"
                         "DA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJj"
                         "ga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAg"
                         "BgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v"
                         "/BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cg"
                         "w1AH9efZBw=="
                       },
   };
   unsigned n;
   curve25519_key key;
   unsigned char buf[1024];
   unsigned long buflen;
   for (n = 0; n < sizeof(rfc_8410_10)/sizeof(rfc_8410_10[0]); ++n) {
      buflen = sizeof(buf);
      DO(base64_decode(rfc_8410_10[n].b64, XSTRLEN(rfc_8410_10[n].b64), buf, &buflen));
      DO(x25519_import_x509(buf, buflen, &key));
      zeromem(buf, sizeof(buf));
   }
   return CRYPT_OK;
}

static int s_x25519_pkcs8_test(void)
{
   const struct {
      const char *b64, *pass;
   } s_x25519_pkcs8[] = {
                          /* `openssl genpkey -algorithm x25519 -pass stdin -aes128` */
                          {
                            "MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAjG5kRkEihOvQICCAAw"
                            "DAYIKoZIhvcNAgkFADAdBglghkgBZQMEAQIEEHPLHLoCvesRyeToyMtGHWcEQM1+"
                            "FMpSO5DplX3d+YGTAvf0WxWaBff1q4bfKDn/7IoWQT1e4Fe6Psj62Vy9T69o3+Uy"
                            "VM6mdIOXGOkAtaMSsSk=",
                            "123456"
                          },
                          /* `openssl genpkey -algorithm x25519 -pass stdin` */
                          {
                            "MC4CAQAwBQYDK2VuBCIEIEAInaUdx+fQFfghpCzw/WdItRT3+FnPSkrU9TcIZTZW",
                            NULL
                          },
   };
   unsigned n;
   curve25519_key key;
   unsigned char buf[1024];
   unsigned long buflen, passlen;
   for (n = 0; n < sizeof(s_x25519_pkcs8)/sizeof(s_x25519_pkcs8[0]); ++n) {
      buflen = sizeof(buf);
      DO(base64_decode(s_x25519_pkcs8[n].b64, XSTRLEN(s_x25519_pkcs8[n].b64), buf, &buflen));
      if (s_x25519_pkcs8[n].pass != NULL) passlen = XSTRLEN(s_x25519_pkcs8[n].pass);
      else passlen = 0;
      DO(x25519_import_pkcs8(buf, buflen, s_x25519_pkcs8[n].pass, passlen, &key));
      zeromem(buf, sizeof(buf));
   }
   return CRYPT_OK;
}

static int s_x25519_compat_test(void)
{
   curve25519_key priv, pub, imported;
   unsigned char buf[1024];
   unsigned long buflen = sizeof(buf);
   int prng_idx = find_prng("yarrow");

   XMEMSET(&priv, 0, sizeof(priv));
   XMEMSET(&pub, 0, sizeof(pub));
   XMEMSET(&imported, 0, sizeof(imported));

   DO(x25519_make_key(&yarrow_prng, prng_idx, &priv));

   DO(x25519_export(buf, &buflen, PK_PRIVATE | PK_STD, &priv));
   DO(x25519_import_pkcs8(buf, buflen, NULL, 0, &imported));
   DO(do_compare_testvector(&priv, sizeof(priv), &imported, sizeof(imported), "priv after ex-&import", __LINE__));
   XMEMSET(&imported, 0, sizeof(imported));

   buflen = sizeof(buf);
   DO(x25519_export(buf, &buflen, PK_PUBLIC, &priv));
   DO(x25519_import_raw(buf, buflen, PK_PUBLIC, &pub));

   buflen = sizeof(buf);
   DO(x25519_export(buf, &buflen, PK_PUBLIC | PK_STD, &priv));
   DO(x25519_import(buf, buflen, &imported));

   DO(do_compare_testvector(&pub, sizeof(pub), &imported, sizeof(imported), "pub after private ex-&import", __LINE__));
   XMEMSET(&imported, 0, sizeof(imported));

   buflen = sizeof(buf);
   DO(x25519_export(buf, &buflen, PK_PUBLIC | PK_STD, &pub));
   DO(x25519_import(buf, buflen, &imported));

   DO(do_compare_testvector(&pub, sizeof(pub), &imported, sizeof(imported), "pub after public ex-&import", __LINE__));

   return CRYPT_OK;
}

/**
  Test the x25519 system
  @return CRYPT_OK if successful
*/
int x25519_test(void)
{
   int ret;

   if (ltc_mp.name == NULL) return CRYPT_NOP;

   if ((ret = s_rfc_7748_5_2_test()) != CRYPT_OK) {
      return ret;
   }
   if ((ret = s_rfc_7748_6_test()) != CRYPT_OK) {
      return ret;
   }
   if ((ret = s_rfc_8410_10_test()) != CRYPT_OK) {
      return ret;
   }
   if ((ret = s_x25519_pkcs8_test()) != CRYPT_OK) {
      return ret;
   }
   if ((ret = s_x25519_compat_test()) != CRYPT_OK) {
      return ret;
   }

   return ret;
}

#else

int x25519_test(void)
{
   return CRYPT_NOP;
}

#endif
