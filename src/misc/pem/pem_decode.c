/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pem_decode.c
  Decode and import a PEM file, Steffen Jaeckel
*/

#ifdef LTC_PEM

/* Encrypted PEM files */
#define PEM_DECODE_BUFSZ 72

int pem_get_char_from_file(struct get_char *g)
{
   return getc(g->f);
}

int pem_get_char_from_buf(struct get_char *g)
{
   int ret;
   if (g->buf.r == g->buf.end) {
      return -1;
   }
   ret = *g->buf.r;
   g->buf.r++;
   return ret;
}

static char* s_get_line(char *buf, unsigned long *buflen, struct get_char *g)
{
   unsigned long blen = 0;
   int c = -1, c_;
   while(blen < *buflen) {
      c_ = c;
      c = g->get(g);
      if (c == '\n') {
         buf[blen] = '\0';
         if (c_ == '\r') {
            buf[--blen] = '\0';
         }
         *buflen = blen;
         return buf;
      }
      if (c == -1 || c == '\0') {
         buf[blen] = '\0';
         *buflen = blen;
         return buf;
      }
      buf[blen] = c;
      blen++;
   }
   return NULL;
}

static LTC_INLINE int s_fits_buf(void *dest, unsigned long to_write, void *end)
{
   unsigned char *d = dest;
   unsigned char *e = end;
   unsigned char *w = d + to_write;
   if (w < d || w > e)
      return 0;
   return 1;
}

static int s_pem_decode_headers(struct pem_headers *hdr, struct get_char *g)
{
   return CRYPT_OK;
}

int pem_read(void *pem, unsigned long *w, struct pem_headers *hdr, struct get_char *g)
{
   char buf[PEM_DECODE_BUFSZ];
   char *wpem = pem;
   char *end = wpem + *w;
   unsigned long slen, linelen;
   int err, hdr_ok = 0;
   int would_overflow = 0;

   linelen = sizeof(buf);
   if (s_get_line(buf, &linelen, g) == NULL) {
      return CRYPT_INVALID_PACKET;
   }
   if (hdr->start.len != linelen || XMEMCMP(buf, hdr->start.p, hdr->start.len)) {
      return CRYPT_INVALID_PACKET;
   }

   if ((err = s_pem_decode_headers(hdr, g)) != CRYPT_OK)
      return err;

   /* Read the base64 encoded part of the PEM */
   slen = sizeof(buf);
   while (s_get_line(buf, &slen, g)) {
      if (slen == hdr->end.len && !XMEMCMP(buf, hdr->end.p, slen)) {
         hdr_ok = 1;
         break;
      }
      if (!would_overflow && s_fits_buf(wpem, slen, end)) {
         XMEMCPY(wpem, buf, slen);
      } else {
         would_overflow = 1;
      }
      wpem += slen;
      slen = sizeof(buf);
   }
   if (!hdr_ok)
      return CRYPT_INVALID_PACKET;

   if (would_overflow || !s_fits_buf(wpem, 1, end)) {
      /* NUL termination */
      wpem++;
      /* prevent a wrap-around */
      if (wpem < (char*)pem)
         return CRYPT_OVERFLOW;
      *w = wpem - (char*)pem;
      return CRYPT_BUFFER_OVERFLOW;
   }

   *w = wpem - (char*)pem;
   *wpem++ = '\0';

   if ((err = base64_strict_decode(pem, *w, pem, w)) != CRYPT_OK) {
      return err;
   }
   return CRYPT_OK;
}

#endif /* LTC_PEM */
