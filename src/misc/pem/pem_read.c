/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pem_read.c
  Read and interpret a PEM file, Steffen Jaeckel
*/

#ifdef LTC_PEM

extern const struct str pem_proc_type_encrypted;
#ifdef LTC_SSH
extern const struct str pem_ssh_comment;
#endif
extern const struct str pem_dek_info_start;
extern const struct blockcipher_info pem_dek_infos[];
extern const unsigned long pem_dek_infos_num;

static LTC_INLINE unsigned long s_bufp_alloc_len(struct bufp *buf)
{
   if (buf->start == NULL || buf->end == NULL)
      return 0;
   return buf->end - buf->start - 1;
}

static LTC_INLINE unsigned long s_bufp_used_len(struct bufp *buf)
{
   if (buf->start == NULL || buf->end == NULL)
      return 0;
   return buf->work - buf->start;
}

static LTC_INLINE int s_bufp_grow(struct bufp *buf)
{
   int err = CRYPT_OK;
   void *ret;
   unsigned long alloc_len = s_bufp_alloc_len(buf), realloc_len;
   unsigned long work_offset = s_bufp_used_len(buf);
   if (alloc_len == 0)
      realloc_len = LTC_PEM_READ_BUFSIZE;
   else
      realloc_len = alloc_len * 2;
   if (realloc_len < alloc_len)
      return CRYPT_OVERFLOW;
   ret = XREALLOC(buf->start, realloc_len);
   if (ret == NULL) {
      err = CRYPT_MEM;
   } else {
      UPDATE_BUFP((*buf), ret, work_offset, realloc_len);
   }
   return err;
}

static LTC_INLINE int s_bufp_fits(struct bufp *buf, unsigned long to_write)
{
   char *d = buf->work;
   char *e = buf->end;
   char *w = d + to_write;
   if (d == NULL || w < d || w > e)
      return 0;
   return 1;
}

static LTC_INLINE int s_bufp_add(struct bufp *buf, const void *src, unsigned long len)
{
   int err;
   if (!s_bufp_fits(buf, len)) {
      if ((err = s_bufp_grow(buf)) != CRYPT_OK) {
         return err;
      }
   }
   XMEMCPY(buf->work, src, len);
   buf->work += len;
   return CRYPT_OK;
}

#ifndef LTC_NO_FILE
static int s_pem_get_char_from_file(struct get_char *g)
{
   return getc(g->data.f.f);
}

static int s_pem_get_char_reset_file(struct get_char *g)
{
   if (g->data.f.original_pos == -1)
      return -1;
   return fseek(g->data.f.f, g->data.f.original_pos, SEEK_SET);
}

static unsigned long s_pem_get_char_len_file(struct get_char *g)
{
   FILE *f = g->data.f.f;
   long len, cur_pos = ftell(f);
   if (cur_pos != -1) {
      fseek(f, 0, SEEK_END);
      len = ftell(f);
      fseek(f, cur_pos, SEEK_SET);
      return len - cur_pos;
   }
   return LTC_PEM_READ_BUFSIZE * 2;
}

const struct get_char_api get_char_filehandle_api = {
                                                     .get = s_pem_get_char_from_file,
                                                     .reset = s_pem_get_char_reset_file,
                                                     .len = s_pem_get_char_len_file,
};
#endif /* LTC_NO_FILE */

static int s_pem_get_char_from_buf(struct get_char *g)
{
   int ret;
   if (g->data.buf.work == g->data.buf.end) {
      return -1;
   }
   ret = *g->data.buf.work;
   g->data.buf.work++;
   return ret;
}

static int s_pem_get_char_reset(struct get_char *g)
{
   g->data.buf.work = g->data.buf.start;
   return 0;
}



static unsigned long s_pem_get_char_len(struct get_char *g)
{
   return s_bufp_alloc_len(&g->data.buf);
}

const struct get_char_api get_char_buffer_api = {
                                                     .get = s_pem_get_char_from_buf,
                                                     .reset = s_pem_get_char_reset,
                                                     .len = s_pem_get_char_len,
};

static void s_unget_line(char *buf, unsigned long buflen, struct get_char *g)
{
   if (buflen > sizeof(g->unget_buf_))
      return;
   g->unget_buf.p = g->unget_buf_;
   COPY_STR(g->unget_buf, buf, buflen);
}

static void s_tts(char *buf, unsigned long *buflen)
{
   while(1) {
      unsigned long blen = *buflen;
      if (blen < 2)
         return;
      blen--;
      switch (buf[blen]) {
         case ' ':
         case '\t':
            buf[blen] = '\0';
            *buflen = blen;
            break;
         default:
            return;
      }
   }
}

static char* s_get_line_i(char *buf, unsigned long *buflen, struct get_char *g, int search_for_start)
{
   unsigned long blen = 0, wr = 0;
   int c_;
   if (g->unget_buf.p) {
      if (*buflen < g->unget_buf.len) {
         return NULL;
      }
      XMEMCPY(buf, g->unget_buf.p, g->unget_buf.len);
      *buflen = g->unget_buf.len;
      RESET_STR(g->unget_buf);
      return buf;
   }
   if (g->prev_get == -1) {
      return NULL;
   }
   while(blen < *buflen || search_for_start) {
      wr = blen < *buflen ? blen : *buflen - 1;
      c_ = g->prev_get;
      g->prev_get = g->api.get(g);
      if (g->prev_get == '\n') {
         buf[wr] = '\0';
         if (c_ == '\r') {
            buf[--wr] = '\0';
         }
         s_tts(buf, &wr);
         *buflen = wr;
         return buf;
      }
      if (g->prev_get == -1 || g->prev_get == '\0') {
         buf[wr] = '\0';
         s_tts(buf, &wr);
         *buflen = wr;
         return buf;
      }
      buf[wr] = g->prev_get;
      blen++;
   }
   return NULL;
}

static LTC_INLINE char* s_get_first_line(char *buf, unsigned long *buflen, struct get_char *g)
{
   return s_get_line_i(buf, buflen, g, 1);
}

static LTC_INLINE char* s_get_line(char *buf, unsigned long *buflen, struct get_char *g)
{
   return s_get_line_i(buf, buflen, g, 0);
}

static int s_pem_decode_headers(struct pem_headers *hdr, struct get_char *g)
{
   char buf[LTC_PEM_DECODE_BUFSZ], *alg_start;
   unsigned long slen, tmplen, n;
   int has_more_headers = hdr->id->has_more_headers == no ? 0 : 3;

   /* Make sure the PEM has the appropriate extension headers if required.
    *
    * ```
    * Proc-Type: 4,ENCRYPTED[\r]\n
    * DEK-Info: <algorithm>,<IV>[\r]\n
    * [\r]\n
    * ```
    */
   while (has_more_headers) {
      slen = sizeof(buf);
      if (!s_get_line(buf, &slen, g) || (has_more_headers > 1 && slen == 0)) {
         return CRYPT_INVALID_PACKET;
      }
      switch (has_more_headers) {
         case 3:
            if (XMEMCMP(buf, pem_proc_type_encrypted.p, pem_proc_type_encrypted.len)) {
#ifdef LTC_SSH
               if (XMEMCMP(buf, pem_ssh_comment.p, pem_ssh_comment.len))
#endif
                  s_unget_line(buf, slen, g);
               if (hdr->id->has_more_headers == maybe)
                  return CRYPT_OK;
               else
                  return CRYPT_INVALID_PACKET;
            }
            hdr->encrypted = 1;
            break;
         case 2:
            hdr->info.algo = NULL;
            if (XMEMCMP(buf, pem_dek_info_start.p, pem_dek_info_start.len))
               return CRYPT_INVALID_PACKET;
            alg_start = &buf[pem_dek_info_start.len];
            for (n = 0; n < pem_dek_infos_num; ++n) {
               unsigned long namelen = XSTRLEN(pem_dek_infos[n].name);
               if (slen >= namelen + pem_dek_info_start.len && !XMEMCMP(alg_start, pem_dek_infos[n].name, namelen)) {
                  char *iv = alg_start + namelen;
                  hdr->info = pem_dek_infos[n];
                  tmplen = XSTRLEN(iv);
                  if (tmplen > sizeof(hdr->info.iv))
                     return CRYPT_INVALID_KEYSIZE;
                  XMEMCPY(hdr->info.iv, iv, tmplen);
                  break;
               }
            }
            if (hdr->info.algo == NULL) {
               return CRYPT_INVALID_CIPHER;
            }
            break;
         case 1:
            /* Make sure that there's an empty line in between */
            if (buf[0] != '\0')
               return CRYPT_INVALID_PACKET;
            break;
         default:
            return CRYPT_INVALID_CIPHER;
      }
      has_more_headers--;
   }
   return CRYPT_OK;
}

int pem_read(void **dest, unsigned long *len, struct pem_headers *hdr, struct get_char *g)
{
   char line[LTC_PEM_DECODE_BUFSZ];
   struct bufp b_ = {0}, *b = &b_;
   const char pem_start[] = "----";
   unsigned long slen, linelen;
   int err, hdr_ok = 0;
   unsigned char empty_lines = 0;

   g->prev_get = 0;
   do {
      linelen = sizeof(line);
      if (s_get_first_line(line, &linelen, g) == NULL) {
         if (g->prev_get == -1)
            return CRYPT_NOP;
         else
            return CRYPT_INVALID_PACKET;
      }
      if (linelen < sizeof(pem_start) - 1)
         continue;
   } while(XMEMCMP(line, pem_start, sizeof(pem_start) - 1) != 0);
   if (hdr->id->start.len != linelen || XMEMCMP(line, hdr->id->start.p, hdr->id->start.len)) {
      s_unget_line(line, linelen, g);
      return CRYPT_UNKNOWN_PEM;
   }

   hdr->encrypted = hdr->id->flags & pf_encrypted;
   if ((err = s_pem_decode_headers(hdr, g)) != CRYPT_OK)
      return err;

   /* Read the base64 encoded part of the PEM */
   slen = sizeof(line);
   while (s_get_line(line, &slen, g)) {
      if (slen == hdr->id->end.len && !XMEMCMP(line, hdr->id->end.p, slen)) {
         hdr_ok = 1;
         break;
      }
      if (!slen) {
         if (empty_lines)
            break;
         empty_lines++;
      }
      if ((err = s_bufp_add(b, line, slen)) != CRYPT_OK) {
         goto error_out;
      }
      slen = sizeof(line);
   }
   if (!hdr_ok) {
      err = CRYPT_INVALID_PACKET;
   } else {
      slen = s_bufp_alloc_len(b);
      err = base64_strict_decode(b->start, s_bufp_used_len(b), (void*)b->start, &slen);
   }
   if (err == CRYPT_OK) {
      *dest = b->start;
      *len = slen;
   } else {
error_out:
      XFREE(b->start);
   }
   return err;
}

#endif /* LTC_PEM */
