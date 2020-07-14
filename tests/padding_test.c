/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include  <tomcrypt_test.h>

#ifdef LTC_PADDING

typedef struct padding_testcase_ padding_testcase;

typedef int (*cmp_padding_testcase)(const padding_testcase*, const unsigned char*, unsigned long);

struct padding_testcase_ {
   unsigned long is, should, max, mode;
   const char* name;
   cmp_padding_testcase cmp;
};

#define EQ(a, b) s_eq((a), (b), #a, #b)

static int s_eq(unsigned long a, unsigned long b, const char* s_a, const char* s_b)
{
   if (a == b) return CRYPT_OK;
#if defined(LTC_TEST) && defined(LTC_TEST_DBG)
   else fprintf(stderr, "'%s == %s' failed, %lu is not equal to %lu\n", s_a, s_b, a, b);
#else
   LTC_UNUSED_PARAM(s_a);
   LTC_UNUSED_PARAM(s_b);
#endif
   return CRYPT_FAIL_TESTVECTOR;
}

static int s_cmp_pkcs7(const padding_testcase* t, const unsigned char* p, unsigned long len)
{
   unsigned long n, diff = len - t->is;
   DOX(EQ(len, t->should), t->name);
   for (n = len - diff; n < len; ++n) {
      DOX(EQ(p[n], diff), t->name);
   }
   return CRYPT_OK;
}

#ifdef LTC_RNG_GET_BYTES
static int s_cmp_iso_10126(const padding_testcase* t, const unsigned char* p, unsigned long len)
{
   LTC_UNUSED_PARAM(p);
   if (len < t->should || len > t->max) {
#if defined(LTC_TEST) && defined(LTC_TEST_DBG)
      fprintf(stderr, "(%lu < %lu || %lu > %lu) failed, %s\n", len, t->should, len, t->max, t->name);
#endif
      return CRYPT_FAIL_TESTVECTOR;
   }
   DOX(EQ(p[len - 1], len - t->is), t->name);
   return CRYPT_OK;
}
#endif

static int s_cmp_x923(const padding_testcase* t, const unsigned char* p, unsigned long len)
{
   unsigned long n, diff = len - t->is;
   DOX(EQ(len, t->should), t->name);
   for (n = len - diff; n < len - 1; ++n) {
      DOX(EQ(p[n], 0x0), t->name);
   }
   DOX(EQ(p[len - 1], diff), t->name);
   return CRYPT_OK;
}

static int s_cmp_oaz(const padding_testcase* t, const unsigned char* p, unsigned long len)
{
   unsigned long n, diff = len - t->is;
   DOX(EQ(len, t->should), t->name);
   n = len - diff;
   DOX(EQ(p[n], 0x80), t->name);
   n++;
   for (; n < len; ++n) {
      DOX(EQ(p[n], 0x0), t->name);
   }
   return CRYPT_OK;
}

static int s_cmp_zero(const padding_testcase* t, const unsigned char* p, unsigned long len)
{
   unsigned long n, diff = len - t->is;
   DOX(EQ(len, t->should), t->name);
   for (n = len - diff; n < len; ++n) {
      DOX(EQ(p[n], 0x0), t->name);
   }
   return CRYPT_OK;
}

static int s_padding_testrun(const padding_testcase* t)
{
   unsigned long len;
   unsigned char buf[1024];

   len = sizeof(buf);
   XMEMSET(buf, 0xAA, t->is);
   DO(padding_pad(buf, t->is, &len, t->mode));
   DO(t->cmp(t, buf, len));
   DO(padding_depad(buf, &len, t->mode));
   DO(EQ(len, t->is));
   return CRYPT_OK;
}

int padding_test(void)
{
   const padding_testcase cases[] = {
                             {   0,  16,   0, LTC_PAD_PKCS7 | 16, "0-pkcs7",     s_cmp_pkcs7 },
                             {   1,  16,   0, LTC_PAD_PKCS7 | 16, "1-pkcs7",     s_cmp_pkcs7 },
                             {  15,  16,   0, LTC_PAD_PKCS7 | 16, "15-pkcs7",    s_cmp_pkcs7 },
                             {  16,  32,   0, LTC_PAD_PKCS7 | 16, "16-pkcs7",    s_cmp_pkcs7 },
                             { 255, 256,   0, LTC_PAD_PKCS7 | 16, "255-pkcs7",   s_cmp_pkcs7 },
                             { 256, 272,   0, LTC_PAD_PKCS7 | 16, "256-pkcs7",   s_cmp_pkcs7 },
#ifdef LTC_RNG_GET_BYTES
                             {   0,  16, 256, LTC_PAD_ISO_10126 | 16, "0-rand",     s_cmp_iso_10126 },
                             {   1,  16, 272, LTC_PAD_ISO_10126 | 16, "1-rand",     s_cmp_iso_10126 },
                             {  15,  16, 272, LTC_PAD_ISO_10126 | 16, "15-rand",    s_cmp_iso_10126 },
                             {  16,  32, 288, LTC_PAD_ISO_10126 | 16, "16-rand",    s_cmp_iso_10126 },
                             { 255, 256, 512, LTC_PAD_ISO_10126 | 16, "255-rand",   s_cmp_iso_10126 },
                             { 256, 272, 528, LTC_PAD_ISO_10126 | 16, "256-rand",   s_cmp_iso_10126 },
#endif
                             {   0,  16,   0, LTC_PAD_ANSI_X923 | 16, "0-x923",   s_cmp_x923 },
                             {   1,  16,   0, LTC_PAD_ANSI_X923 | 16, "1-x923",   s_cmp_x923 },
                             {  15,  16,   0, LTC_PAD_ANSI_X923 | 16, "15-x923",  s_cmp_x923 },
                             {  16,  32,   0, LTC_PAD_ANSI_X923 | 16, "16-x923",  s_cmp_x923 },
                             { 255, 256,   0, LTC_PAD_ANSI_X923 | 16, "255-x923", s_cmp_x923 },
                             { 256, 272,   0, LTC_PAD_ANSI_X923 | 16, "256-x923", s_cmp_x923 },

                             {   0,  16,   0, LTC_PAD_ONE_AND_ZERO | 16, "0-one-and-zero",   s_cmp_oaz },
                             {   1,  16,   0, LTC_PAD_ONE_AND_ZERO | 16, "1-one-and-zero",   s_cmp_oaz },
                             {  15,  16,   0, LTC_PAD_ONE_AND_ZERO | 16, "15-one-and-zero",  s_cmp_oaz },
                             {  16,  32,   0, LTC_PAD_ONE_AND_ZERO | 16, "16-one-and-zero",  s_cmp_oaz },
                             { 255, 256,   0, LTC_PAD_ONE_AND_ZERO | 16, "255-one-and-zero", s_cmp_oaz },
                             { 256, 272,   0, LTC_PAD_ONE_AND_ZERO | 16, "256-one-and-zero", s_cmp_oaz },

                             {   0,   0,   0, LTC_PAD_ZERO | 16, "0-zero",   s_cmp_zero },
                             {   1,  16,   0, LTC_PAD_ZERO | 16, "1-zero",   s_cmp_zero },
                             {  15,  16,   0, LTC_PAD_ZERO | 16, "15-zero",  s_cmp_zero },
                             {  16,  16,   0, LTC_PAD_ZERO | 16, "16-zero",  s_cmp_zero },
                             { 255, 256,   0, LTC_PAD_ZERO | 16, "255-zero", s_cmp_zero },
                             { 256, 256,   0, LTC_PAD_ZERO | 16, "256-zero", s_cmp_zero },

                             {   0,  16,   0, LTC_PAD_ZERO_ALWAYS | 16, "0-zero-always",   s_cmp_zero },
                             {   1,  16,   0, LTC_PAD_ZERO_ALWAYS | 16, "1-zero-always",   s_cmp_zero },
                             {  15,  16,   0, LTC_PAD_ZERO_ALWAYS | 16, "15-zero-always",  s_cmp_zero },
                             {  16,  32,   0, LTC_PAD_ZERO_ALWAYS | 16, "16-zero-always",  s_cmp_zero },
                             { 255, 256,   0, LTC_PAD_ZERO_ALWAYS | 16, "255-zero-always", s_cmp_zero },
                             { 256, 272,   0, LTC_PAD_ZERO_ALWAYS | 16, "256-zero-always", s_cmp_zero },
   };
   unsigned i;
   /* Examples from https://en.wikipedia.org/w/index.php?title=Padding_(cryptography)&oldid=823057951#Byte_padding */
   const struct {
      unsigned char data[16];
      unsigned long len;
      unsigned long mode;
   } tv[] = {
      { { 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0x04, 0x04, 0x04, 0x04 }, 12, LTC_PAD_PKCS7 | 16 },
      { { 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0x00, 0x00, 0x00, 0x04 }, 12, LTC_PAD_ANSI_X923 | 16 },
#ifdef LTC_RNG_GET_BYTES
      { { 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0x81, 0xA6, 0x23, 0x04 }, 12, LTC_PAD_ISO_10126 | 16 },
#endif
      { { 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0x80, 0x00, 0x00, 0x00 }, 12, LTC_PAD_ONE_AND_ZERO | 16 },
      { { 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0x80 }, 15, LTC_PAD_ONE_AND_ZERO | 16 },
      { { 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0x00, 0x00, 0x00, 0x00 }, 12, LTC_PAD_ZERO | 16 },
   };
   /* we need a big buffer like that as LTC_PAD_ISO_10126
    * is allowed to add 1-255 bytes of padding
    */
   unsigned char buf[256 + 16];
   unsigned long l;

   for (i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
      DOX(s_padding_testrun(&cases[i]), cases[i].name);
   }

   for (i = 0; i < sizeof(tv)/sizeof(tv[0]); ++i) {
      XMEMCPY(buf, tv[i].data, sizeof(tv[i].data));
      l = sizeof(tv[i].data);
      DO(padding_depad(buf, &l, tv[i].mode));
      XMEMSET(buf, 0xDD, 16);
      l = sizeof(buf);
      DO(padding_pad(buf, tv[i].len, &l, tv[i].mode));
#ifdef LTC_RNG_GET_BYTES
      if ((tv[i].mode & LTC_PAD_MASK) != LTC_PAD_ISO_10126)
#endif
      {
         COMPARE_TESTVECTOR(tv[i].data, sizeof(tv[i].data), buf, l, "padding fixed TV", i);
      }
   }

   /* wycheproof failing test - https://github.com/libtom/libtomcrypt/pull/454 */
   {
      unsigned char data[] = { 0x47,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
      unsigned long len = sizeof(data);

      SHOULD_FAIL(padding_depad(data, &len, (LTC_PAD_PKCS7 | 16)));
   }

   return CRYPT_OK;
}
#endif
