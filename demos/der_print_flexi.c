/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/* DER flexi-decode a certificate */
#include "tomcrypt_private.h"
#include <wchar.h>

#define ASN1_FMTSTRING_FMT "line: %d, type=%d, size=%lu, data=%p, self=%p, next=%p, prev=%p, parent=%p, child=%p"
#define ASN1_FMTSTRING_VAL(l)  __LINE__, (l)->type, (l)->size, (l)->data, (l), (l)->next, (l)->prev, (l)->parent, (l)->child

static void* s_xmalloc(int l)
{
   void *r = XCALLOC(1, l);

#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 3
   fprintf(stderr, "ALLOC %9d to %p\n", l, r);
#endif
   if (!r) {
      fprintf(stderr, "Could not allocate %d bytes of memory\n", l);
      exit(EXIT_FAILURE);
   }
   return r;
}

#ifndef S_FREE
static void s_free(void *p)
{
#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 3
   fprintf(stderr, "FREE %p\n", p);
#endif
   XFREE(p);
}
#endif

static void s_der_print_flexi_i(const ltc_asn1_list* l, unsigned int level)
{
   char *buf = NULL;
   const char *name = NULL;
   const char *text = NULL;
   ltc_asn1_list *ostring = NULL;
   unsigned int n;
   int slen;
   const wchar_t *wtmp;

   switch (l->type)
   {
      case LTC_ASN1_EOL:
         name = "EOL";
         slen = snprintf(NULL, 0, ASN1_FMTSTRING_FMT "\n", ASN1_FMTSTRING_VAL(l));
         buf = s_xmalloc(slen);
         snprintf(buf, slen, ASN1_FMTSTRING_FMT "\n", ASN1_FMTSTRING_VAL(l));
         text = buf;
         break;
      case LTC_ASN1_BOOLEAN:
         name = "BOOLEAN";
         {
            if (*(int*) l->data)
               text = "true";
            else
               text = "false";
         }
         break;
      case LTC_ASN1_INTEGER:
         name = "INTEGER";
         buf = s_xmalloc(((ltc_mp_get_digit_count(l->data) + 1) * ltc_mp.bits_per_digit) / 3);
         ltc_mp_toradix(l->data, buf, 10);
         text = buf;
         break;
      case LTC_ASN1_SHORT_INTEGER:
         name = "SHORT INTEGER";
         break;
      case LTC_ASN1_BIT_STRING:
         name = "BIT STRING";
         if (l->size <= 16) {
            int r;
            int sz = l->size + 1;
            char *s = buf = s_xmalloc(sz);
            for (n = 0; n < l->size; ++n) {
               r = snprintf(s, sz, "%c", ((unsigned char*) l->data)[n] ? '1' : '0');
               if (r < 0 || r >= sz) {
                  fprintf(stderr, "%s boom\n", name);
                  exit(EXIT_FAILURE);
               }
               s += r;
               sz -= r;
            }
         } else {
            slen = snprintf(NULL, 0, "Length %lu", l->size);
            buf = s_xmalloc(slen);
            snprintf(buf, slen, "Length %lu", l->size);
         }
         text = buf;
         break;
      case LTC_ASN1_OCTET_STRING:
         name = "OCTET STRING";
         {
            unsigned long ostring_l = l->size;
            /* sometimes there's another sequence in an octet string...
             * try to decode that... if it fails print out the octet string
             */
            if (der_decode_sequence_flexi(l->data, &ostring_l, &ostring) == CRYPT_OK) {
               text = "";
            } else {
               int r;
               int sz = l->size * 2 + 1;
               char *s = buf = s_xmalloc(sz);
               for (n = 0; n < l->size; ++n) {
                  r = snprintf(s, sz, "%02X", ((unsigned char*) l->data)[n]);
                  if (r < 0 || r >= sz) {
                     fprintf(stderr, "%s boom\n", name);
                     exit(EXIT_FAILURE);
                  }
                  s += r;
                  sz -= r;
               }
               text = buf;
            }
         }
         break;
      case LTC_ASN1_NULL:
         name = "NULL";
         text = "";
         break;
      case LTC_ASN1_OBJECT_IDENTIFIER:
         name = "OBJECT IDENTIFIER";
         {
            unsigned long len = 0;
            if (pk_oid_num_to_str(l->data, l->size, buf, &len) != CRYPT_BUFFER_OVERFLOW) {
               fprintf(stderr, "%s WTF\n", name);
               exit(EXIT_FAILURE);
            }
            buf = s_xmalloc(len);
            if (pk_oid_num_to_str(l->data, l->size, buf, &len) != CRYPT_OK) {
               fprintf(stderr, "%s boom\n", name);
               exit(EXIT_FAILURE);
            }
            text = buf;
         }
         break;
      case LTC_ASN1_IA5_STRING:
         name = "IA5 STRING";
         text = l->data;
         break;
      case LTC_ASN1_PRINTABLE_STRING:
         name = "PRINTABLE STRING";
         text = l->data;
         break;
      case LTC_ASN1_UTF8_STRING:
         name = "UTF8 STRING";
         wtmp = l->data;
         slen = wcsrtombs(NULL, &wtmp, 0, NULL);
         if (slen != -1) {
            slen++;
            buf = s_xmalloc(slen);
            if (wcsrtombs(buf, &wtmp, slen, NULL) == (size_t)-1) {
               fprintf(stderr, "%s boom\n", name);
               exit(EXIT_FAILURE);
            }
            text = buf;
         }
         break;
      case LTC_ASN1_UTCTIME:
         name = "UTCTIME";
         {
            ltc_utctime *ut = l->data;
            slen = 32;
            buf = s_xmalloc(slen);
            snprintf(buf, slen, "%02d-%02d-%02d %02d:%02d:%02d %c%02d:%02d", ut->YY, ut->MM, ut->DD, ut->hh, ut->mm,
                     ut->ss, ut->off_dir ? '-' : '+', ut->off_hh, ut->off_mm);
            text = buf;
         }
         break;
      case LTC_ASN1_GENERALIZEDTIME:
         name = "GENERALIZED TIME";
         {
            ltc_generalizedtime *gt = l->data;
            slen = 32;
            buf = s_xmalloc(slen);
            if (gt->fs)
               snprintf(buf, slen, "%04d-%02d-%02d %02d:%02d:%02d.%02dZ", gt->YYYY, gt->MM, gt->DD, gt->hh, gt->mm,
                        gt->ss, gt->fs);
            else
               snprintf(buf, slen, "%04d-%02d-%02d %02d:%02d:%02dZ", gt->YYYY, gt->MM, gt->DD, gt->hh, gt->mm, gt->ss);
            text = buf;
         }
         break;
      case LTC_ASN1_CHOICE:
         name = "CHOICE";
         break;
      case LTC_ASN1_SEQUENCE:
         name = "SEQUENCE";
         text = "";
         break;
      case LTC_ASN1_SET:
         name = "SET";
         text = "";
         break;
      case LTC_ASN1_SETOF:
         name = "SETOF";
         text = "";
         break;
      case LTC_ASN1_RAW_BIT_STRING:
         name = "RAW BIT STRING";
         break;
      case LTC_ASN1_TELETEX_STRING:
         name = "TELETEX STRING";
         text = l->data;
         break;
      case LTC_ASN1_CUSTOM_TYPE:
         name = "NON STANDARD";
         {
            int r;
            int sz = 128;
            char *s = buf = s_xmalloc(sz);

            r = snprintf(s, sz, "[%s %s %llu]", der_asn1_class_to_string_map[l->klass],
                         der_asn1_pc_to_string_map[l->pc], l->tag);
            if (r < 0 || r >= sz) {
               fprintf(stderr, "%s boom\n", name);
               exit(EXIT_FAILURE);
            }

            text = buf;
         }
         break;
   }

   for (n = 0; n < level; ++n) {
      fprintf(stderr, "    ");
   }
   if (name) {
      if (text)
         fprintf(stderr, "%s %s\n", name, text);
      else
         fprintf(stderr, "%s <missing decoding>\n", name);
   } else
      fprintf(stderr, "WTF type=%i\n", l->type);

   if (buf) {
      s_free(buf);
      buf = NULL;
   }

   if (ostring) {
      s_der_print_flexi_i(ostring, level + 1);
      der_free_sequence_flexi(ostring);
   }

   if (l->child) s_der_print_flexi_i(l->child, level + 1);

   if (l->next) s_der_print_flexi_i(l->next, level);
}

#ifndef LTC_DER_PRINT_FLEXI_NO_MAIN

static void s_der_print_flexi(const ltc_asn1_list* l)
{
   fprintf(stderr, "\n\n");
   s_der_print_flexi_i(l, 0);
   fprintf(stderr, "\n\n");
}

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int fd;
static ltc_asn1_list *l;

static void print_err(const char *fmt, ...)
{
   va_list args;

   va_start(args, fmt);
   vfprintf(stderr, fmt, args);
   va_end(args);
}

static void die_(int err, int line)
{
   print_err("%3d: LTC sez %s\n", line, error_to_string(err));
   der_free_sequence_flexi(l);
   close(fd);
   exit(EXIT_FAILURE);
}

#define die(i) do { die_(i, __LINE__); } while(0)
#define DIE(s, ...) do { print_err("%3d: " s "\n", __LINE__, ##__VA_ARGS__); exit(EXIT_FAILURE); } while(0)

int main(int argc, char **argv)
{
   void *addr;
   int err, argn = 1;
   struct stat sb;
   unsigned long len;

   if ((err = register_all_hashes()) != CRYPT_OK) {
      die(err);
   }
   if ((err = crypt_mp_init("ltm")) != CRYPT_OK) {
      die(err);
   }
   if (argc > argn) fd = open(argv[argn], O_RDONLY);
   else fd = STDIN_FILENO;
   if (fd == -1) DIE("open sez no");
   if (fstat(fd, &sb) == -1) DIE("fstat");

   addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
   if (addr == MAP_FAILED) DIE("mmap");

   len = sb.st_size;

   if ((err = der_decode_sequence_flexi(addr, &len, &l)) != CRYPT_OK) {
      die(err);
   }

   s_der_print_flexi(l);

   der_free_sequence_flexi(l);
   close(fd);

   return 0;
}

#endif /* LTC_DER_PRINT_FLEXI_NO_MAIN */
