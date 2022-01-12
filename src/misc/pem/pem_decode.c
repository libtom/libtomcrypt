/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pem_decode.c
  Decode and import a PEM file, Steffen Jaeckel
*/

#ifdef LTC_PEM

struct dek_info_from_str {
   const struct str id;
   struct dek_info info;
};

/* Encrypted PEM files */
static const struct str proc_type_encrypted = { SET_CSTR(, "Proc-Type: 4,ENCRYPTED") };
static const struct dek_info_from_str dek_infos[] =
   {
      { SET_CSTR(.id, "DEK-Info: AES-128-CBC,"),  .info.alg = "aes",  .info.keylen = 128 / 8, },
      { SET_CSTR(.id, "DEK-Info: AES-192-CBC,"),  .info.alg = "aes",  .info.keylen = 192 / 8, },
      { SET_CSTR(.id, "DEK-Info: AES-256-CBC,"),  .info.alg = "aes",  .info.keylen = 256 / 8, },
      { SET_CSTR(.id, "DEK-Info: CAMELLIA-128-CBC,"),  .info.alg = "camellia",  .info.keylen = 128 / 8, },
      { SET_CSTR(.id, "DEK-Info: CAMELLIA-192-CBC,"),  .info.alg = "camellia",  .info.keylen = 192 / 8, },
      { SET_CSTR(.id, "DEK-Info: CAMELLIA-256-CBC,"),  .info.alg = "camellia",  .info.keylen = 256 / 8, },
      { SET_CSTR(.id, "DEK-Info: DES-EDE3-CBC,"), .info.alg = "3des", .info.keylen = 192 / 8, },
      { SET_CSTR(.id, "DEK-Info: DES-CBC,"),      .info.alg = "des",  .info.keylen = 64 / 8, },
   };

static int s_decrypt_pem(unsigned char *pem, unsigned long *l, const struct pem_headers *hdr)
{
   unsigned char iv[MAXBLOCKSIZE], key[MAXBLOCKSIZE];
   unsigned long ivlen, klen;
   int err;
   symmetric_CBC cbc_ctx;

   if (hdr->info.keylen > sizeof(key)) {
      return CRYPT_BUFFER_OVERFLOW;
   }
   if (!hdr->pw->pw) {
      return CRYPT_INVALID_ARG;
   }

   ivlen = sizeof(iv);
   if ((err = base16_decode(hdr->info.iv, XSTRLEN(hdr->info.iv), iv, &ivlen)) != CRYPT_OK) {
      return err;
   }
   klen = hdr->info.keylen;
   if ((err = pkcs_5_alg1_openssl(hdr->pw->pw, hdr->pw->l, iv, 1, find_hash("md5"), key, &klen))) {
      return err;
   }

   if ((err = cbc_start(find_cipher(hdr->info.alg), iv, key, klen, 0, &cbc_ctx)) != CRYPT_OK) {
      goto error_out;
   }
   if ((err = cbc_decrypt(pem, pem, *l, &cbc_ctx)) != CRYPT_OK) {
      goto error_out;
   }
   if ((err = cbc_done(&cbc_ctx)) != CRYPT_OK) {
      goto error_out;
   }
   if ((err = padding_depad(pem, l, LTC_PAD_PKCS7 | cbc_ctx.blocklen)) != CRYPT_OK) {
      goto error_out;
   }

error_out:
   zeromem(key, sizeof(key));
   zeromem(iv, sizeof(iv));
   return err;
}

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

static void s_unget_line(char *buf, unsigned long buflen, struct get_char *g)
{
   if (buflen > sizeof(g->unget_buf_))
      return;
   g->unget_buf.p = g->unget_buf_;
   COPY_STR(g->unget_buf, buf, buflen);
}

static char* s_get_line(char *buf, unsigned long *buflen, struct get_char *g)
{
   unsigned long blen = 0;
   int c = -1, c_;
   if (g->unget_buf.p) {
      if (*buflen < g->unget_buf.len) {
         return NULL;
      }
      XMEMCPY(buf, g->unget_buf.p, g->unget_buf.len);
      *buflen = g->unget_buf.len;
      FREE_STR(g->unget_buf);
      return buf;
   }
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
   char buf[LTC_PEM_DECODE_BUFSZ];
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
            if (XMEMCMP(buf, proc_type_encrypted.p, proc_type_encrypted.len)) {
               s_unget_line(buf, slen, g);
               if (hdr->id->has_more_headers == maybe)
                  return CRYPT_OK;
               else
                  return CRYPT_INVALID_PACKET;
            }
            hdr->encrypted = 1;
            break;
         case 2:
            hdr->info.alg = NULL;
            for (n = 0; n < sizeof(dek_infos)/sizeof(dek_infos[0]); ++n) {
               if (slen >= dek_infos[n].id.len && !XMEMCMP(buf, dek_infos[n].id.p, dek_infos[n].id.len)) {
                  hdr->info = dek_infos[n].info;
                  tmplen = XSTRLEN(buf + dek_infos[n].id.len);
                  if (tmplen > sizeof(hdr->info.iv))
                     return CRYPT_INVALID_KEYSIZE;
                  XMEMCPY(hdr->info.iv, buf + dek_infos[n].id.len, tmplen);
                  break;
               }
            }
            if (hdr->info.alg == NULL) {
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

int pem_read(void *pem, unsigned long *w, struct pem_headers *hdr, struct get_char *g)
{
   char buf[LTC_PEM_DECODE_BUFSZ];
   char *wpem = pem;
   char *end = wpem + *w;
   unsigned long slen, linelen;
   int err, hdr_ok = 0;
   int would_overflow = 0;

   linelen = sizeof(buf);
   if (s_get_line(buf, &linelen, g) == NULL) {
      return CRYPT_INVALID_PACKET;
   }
   if (hdr->id->start.len != linelen || XMEMCMP(buf, hdr->id->start.p, hdr->id->start.len)) {
      s_unget_line(buf, linelen, g);
      return CRYPT_INVALID_PACKET;
   }

   hdr->encrypted = hdr->id->encrypted;
   if ((err = s_pem_decode_headers(hdr, g)) != CRYPT_OK)
      return err;

   /* Read the base64 encoded part of the PEM */
   slen = sizeof(buf);
   while (s_get_line(buf, &slen, g)) {
      if (slen == hdr->id->end.len && !XMEMCMP(buf, hdr->id->end.p, slen)) {
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

static const struct pem_header_id pem_std_headers[] = {
   {
     /* PKCS#8 encrypted */
     SET_CSTR(.start, "-----BEGIN ENCRYPTED PRIVATE KEY-----"),
     SET_CSTR(.end, "-----END ENCRYPTED PRIVATE KEY-----"),
     .has_more_headers = no,
     .encrypted = 1,
     .pkcs8 = 1,
   },
   {
     /* PKCS#8 plain */
     SET_CSTR(.start, "-----BEGIN PRIVATE KEY-----"),
     SET_CSTR(.end, "-----END PRIVATE KEY-----"),
     .has_more_headers = no,
     .pkcs8 = 1,
   },
   /* Regular plain or encrypted private keys */
   {
     SET_CSTR(.start, "-----BEGIN RSA PRIVATE KEY-----"),
     SET_CSTR(.end, "-----END RSA PRIVATE KEY-----"),
     .has_more_headers = maybe,
     .pka = LTC_PKA_RSA,
   },
   {
     SET_CSTR(.start, "-----BEGIN EC PRIVATE KEY-----"),
     SET_CSTR(.end, "-----END EC PRIVATE KEY-----"),
     .has_more_headers = maybe,
     .pka = LTC_PKA_EC,
   },
   {
     SET_CSTR(.start, "-----BEGIN DSA PRIVATE KEY-----"),
     SET_CSTR(.end, "-----END DSA PRIVATE KEY-----"),
     .has_more_headers = maybe,
     .pka = LTC_PKA_DSA,
   },
};
typedef int (*pkcs8_import)(const unsigned char *in, unsigned long inlen,
                                   password_ctx *pw_ctx,
                                           void *key);
typedef struct {
   enum ltc_oid_id id;
   pkcs8_import fn;
} p8_import_st;

static int s_decode(struct get_char *g, ltc_pka_key *k, password_ctx *pw_ctx)
{
   unsigned char *pem = NULL;
   unsigned long w, l, n;
   int err = CRYPT_ERROR;
   struct pem_headers hdr = { 0 };
   struct password pw;
   ltc_asn1_list *p8_asn1 = NULL;
   w = LTC_PEM_READ_BUFSIZE * 2;
retry:
   pem = XREALLOC(pem, w);
   for (n = 0; n < sizeof(pem_std_headers)/sizeof(pem_std_headers[0]); ++n) {
      hdr.id = &pem_std_headers[n];
      err = pem_read(pem, &w, &hdr, g);
      if (err == CRYPT_BUFFER_OVERFLOW) {
         goto retry;
      } else if (err == CRYPT_OK) {
         break;
      }
      hdr.id = NULL;
   }
   /* id not found */
   if (hdr.id == NULL)
      goto cleanup;
   l = w;
   if (hdr.id->pkcs8) {
      enum ltc_oid_id pka;
      ltc_asn1_list *alg_id, *priv_key;
      if ((err = pkcs8_decode_flexi(pem, l, pw_ctx, &p8_asn1)) != CRYPT_OK) {
         goto cleanup;
      }
      if ((err = pkcs8_get_children(p8_asn1, &pka, &alg_id, &priv_key)) != CRYPT_OK) {
         goto cleanup;
      }
      switch (pka) {
         case LTC_OID_RSA:
            err = rsa_import_pkcs8_asn1(alg_id, priv_key, &k->u.rsa);
            k->id = LTC_PKA_RSA;
            break;
         case LTC_OID_EC:
            err = ecc_import_pkcs8_asn1(alg_id, priv_key, &k->u.ecc);
            k->id = LTC_PKA_EC;
            break;
         case LTC_OID_ED25519:
            err = ed25519_import_pkcs8_asn1(alg_id, priv_key, &k->u.curve25519);
            k->id = LTC_PKA_CURVE25519;
            break;
         case LTC_OID_X25519:
            err = x25519_import_pkcs8_asn1(alg_id, priv_key, &k->u.curve25519);
            k->id = LTC_PKA_CURVE25519;
            break;
         default:
            err = CRYPT_PK_INVALID_TYPE;
      }
      goto cleanup;
   } else if (hdr.encrypted) {
      LTC_ARGCHK(pw_ctx           != NULL);
      LTC_ARGCHK(pw_ctx->callback != NULL);

      hdr.pw = &pw;
      if (pw_ctx->callback(&hdr.pw->pw, &hdr.pw->l, pw_ctx->userdata)) {
         err = CRYPT_ERROR;
         goto cleanup;
      }

      if ((err = s_decrypt_pem(pem, &l, &hdr)) != CRYPT_OK) {
         goto cleanup;
      }
   }
   switch (hdr.id->pka) {
      case LTC_OID_RSA:
         err = rsa_import(pem, l, &k->u.rsa);
         k->id = LTC_PKA_RSA;
         break;
      case LTC_OID_EC:
         err = ecc_import_openssl(pem, l, &k->u.ecc);
         k->id = LTC_PKA_EC;
         break;
      default:
         err = CRYPT_PK_INVALID_TYPE;
         goto cleanup;
   }

cleanup:
   if (p8_asn1) {
      der_sequence_free(p8_asn1);
   }
   if (hdr.pw) {
      zeromem(hdr.pw->pw, hdr.pw->l);
      XFREE(hdr.pw->pw);
   }
   XFREE(pem);
   return err;
}

int pem_decode_filehandle(FILE *f, ltc_pka_key *k, password_ctx *pw_ctx)
{
   struct get_char g = { .get = pem_get_char_from_file, .f = f };
   return s_decode(&g, k, pw_ctx);
}

int pem_decode(const void *buf, unsigned long len, ltc_pka_key *k, password_ctx *pw_ctx)
{
   struct get_char g = { .get = pem_get_char_from_buf, SET_BUFP(.buf, buf, len) };
   return s_decode(&g, k, pw_ctx);

}

#endif /* LTC_PEM */
