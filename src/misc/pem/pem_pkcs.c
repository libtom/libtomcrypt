/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pem_decode.c
  Decode a PEM file, Steffen Jaeckel
*/

#ifdef LTC_PEM

extern const struct pem_header_id pem_std_headers[];
extern const unsigned long pem_std_headers_num;

static int s_decrypt_pem(unsigned char *pem, unsigned long *l, const struct pem_headers *hdr)
{
   unsigned char iv[MAXBLOCKSIZE], key[MAXBLOCKSIZE];
   unsigned long ivlen, klen;
   int err, cipher;

   cipher = find_cipher(hdr->info.algo);
   if (cipher == -1) {
      return CRYPT_INVALID_CIPHER;
   }
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

   err = pem_decrypt(pem, l, key, klen, iv, ivlen, &hdr->info, LTC_PAD_PKCS7);

   zeromem(key, sizeof(key));
   zeromem(iv, sizeof(iv));
   return err;
}
typedef int (*pkcs8_import)(const unsigned char *in, unsigned long inlen,
                                   password_ctx *pw_ctx,
                                           void *key);
typedef struct {
   enum ltc_oid_id id;
   pkcs8_import fn;
} p8_import_st;

static int s_decode(struct get_char *g, ltc_pka_key *k, const password_ctx *pw_ctx)
{
   unsigned char *pem = NULL;
   unsigned long w, l, n;
   int err = CRYPT_ERROR;
   struct pem_headers hdr = { 0 };
   struct password pw;
   ltc_asn1_list *p8_asn1 = NULL;
   XMEMSET(k, 0, sizeof(*k));
   w = LTC_PEM_READ_BUFSIZE * 2;
retry:
   pem = XREALLOC(pem, w);
   for (n = 0; n < pem_std_headers_num; ++n) {
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
#ifdef LTC_MDH
         case LTC_OID_DH:
            err = dh_import_pkcs8_asn1(alg_id, priv_key, &k->u.dh);
            k->id = LTC_PKA_DH;
            break;
#endif
#ifdef LTC_MDSA
         case LTC_OID_DSA:
            err = dsa_import_pkcs8_asn1(alg_id, priv_key, &k->u.dsa);
            k->id = LTC_PKA_DSA;
            break;
#endif
#ifdef LTC_MRSA
         case LTC_OID_RSA:
            err = rsa_import_pkcs8_asn1(alg_id, priv_key, &k->u.rsa);
            k->id = LTC_PKA_RSA;
            break;
#endif
#ifdef LTC_MECC
         case LTC_OID_EC:
            err = ecc_import_pkcs8_asn1(alg_id, priv_key, &k->u.ecc);
            k->id = LTC_PKA_EC;
            break;
#endif
#ifdef LTC_CURVE25519
         case LTC_OID_X25519:
            err = x25519_import_pkcs8_asn1(alg_id, priv_key, &k->u.x25519);
            k->id = LTC_PKA_X25519;
            break;
         case LTC_OID_ED25519:
            err = ed25519_import_pkcs8_asn1(alg_id, priv_key, &k->u.ed25519);
            k->id = LTC_PKA_ED25519;
            break;
#endif
         default:
            err = CRYPT_PK_INVALID_TYPE;
      }
      goto cleanup;
   } else if (hdr.encrypted) {
      if ((pw_ctx == NULL) || (pw_ctx->callback == NULL)) {
         err = CRYPT_PW_CTX_MISSING;
         goto cleanup;
      }

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
#ifdef LTC_MDSA
      case LTC_OID_DSA:
         err = dsa_import(pem, l, &k->u.dsa);
         k->id = LTC_PKA_DSA;
         break;
#endif
#ifdef LTC_MRSA
      case LTC_OID_RSA:
         err = rsa_import(pem, l, &k->u.rsa);
         k->id = LTC_PKA_RSA;
         break;
#endif
#ifdef LTC_MECC
      case LTC_OID_EC:
         err = ecc_import_openssl(pem, l, &k->u.ecc);
         k->id = LTC_PKA_EC;
         break;
#endif
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

#ifndef LTC_NO_FILE
int pem_decode_pkcs_filehandle(FILE *f, ltc_pka_key *k, const password_ctx *pw_ctx)
{
   LTC_ARGCHK(f != NULL);
   LTC_ARGCHK(k != NULL);
   {
      struct get_char g = { .get = pem_get_char_from_file, .f = f };
      return s_decode(&g, k, pw_ctx);
   }
}
#endif /* LTC_NO_FILE */

int pem_decode_pkcs(const void *buf, unsigned long len, ltc_pka_key *k, const password_ctx *pw_ctx)
{
   LTC_ARGCHK(buf != NULL);
   LTC_ARGCHK(len != 0);
   LTC_ARGCHK(k != NULL);
   {
      struct get_char g = { .get = pem_get_char_from_buf, SET_BUFP(.buf, buf, len) };
      return s_decode(&g, k, pw_ctx);
   }
}

#endif /* LTC_PEM */
