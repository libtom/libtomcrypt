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
   int err;

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

   err = pem_decrypt(pem, l, key, klen, iv, ivlen, NULL, 0, &hdr->info, LTC_PAD_PKCS7);

   zeromem(key, sizeof(key));
   zeromem(iv, sizeof(iv));
   return err;
}

static int s_get_pka(ltc_asn1_list *pub, enum ltc_pka_id *pka)
{
   der_flexi_check flexi_should[4];
   ltc_asn1_list *seqid, *id;
   enum ltc_oid_id oid_id;
   int err;
   unsigned long n = 0;
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_SEQUENCE, &seqid);
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_BIT_STRING, NULL);
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n, LTC_ASN1_EOL, NULL);
   if ((err = der_flexi_sequence_cmp(pub, flexi_should)) != CRYPT_OK) {
      return err;
   }
   n = 0;
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_OBJECT_IDENTIFIER, &id);
   LTC_SET_DER_FLEXI_CHECK(flexi_should, n, LTC_ASN1_EOL, NULL);
   err = der_flexi_sequence_cmp(seqid, flexi_should);
   if (err != CRYPT_OK && err != CRYPT_INPUT_TOO_LONG) {
      return err;
   }
   if ((err = pk_get_oid_from_asn1(id, &oid_id)) != CRYPT_OK) {
      return err;
   }
   return pk_get_pka_id(oid_id, pka);
}

typedef int (*import_fn)(const unsigned char *, unsigned long, void*);

static const import_fn s_import_x509_fns[LTC_PKA_NUM] = {
#ifdef LTC_MRSA
                                                [LTC_PKA_RSA] = (import_fn)rsa_import_x509,
#endif
#ifdef LTC_MECC
                                                [LTC_PKA_EC] = (import_fn)ecc_import_x509,
#endif
#ifdef LTC_CURVE25519
                                                [LTC_PKA_X25519] = (import_fn)x25519_import_x509,
                                                [LTC_PKA_ED25519] = (import_fn)ed25519_import_x509,
#endif
};

static int s_import_x509(unsigned char *pem, unsigned long l, ltc_pka_key *k)
{
   enum ltc_pka_id pka = LTC_PKA_UNDEF;
   ltc_asn1_list *d, *spki;
   int err;
   if ((err = x509_decode_spki(pem, l, &d, &spki)) != CRYPT_OK) {
      return err;
   }
   err = s_get_pka(spki, &pka);
   der_free_sequence_flexi(d);
   if (err != CRYPT_OK) {
      return err;
   }
   if (pka < 0
         || pka > sizeof(s_import_x509_fns)/sizeof(s_import_x509_fns[0])
         || s_import_x509_fns[pka] == NULL) {
      return CRYPT_PK_INVALID_TYPE;
   }
   if ((err = s_import_x509_fns[pka](pem, l, &k->u)) == CRYPT_OK) {
      k->id = pka;
   }
   return err;
}

static int s_import_pkcs8(unsigned char *pem, unsigned long l, ltc_pka_key *k, const password_ctx *pw_ctx)
{
   int err;
   enum ltc_oid_id pka;
   ltc_asn1_list *alg_id, *priv_key;
   ltc_asn1_list *p8_asn1 = NULL;
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

cleanup:
   if (p8_asn1) {
      der_sequence_free(p8_asn1);
   }
   return err;
}

static int s_extract_pka(unsigned char *pem, unsigned long w, enum ltc_pka_id *pka)
{
   ltc_asn1_list *pub;
   int err = CRYPT_ERROR;
   if ((err = der_decode_sequence_flexi(pem, &w, &pub)) != CRYPT_OK) {
      return err;
   }
   err = s_get_pka(pub, pka);
   der_sequence_free(pub);
   return err;
}

static const import_fn s_import_openssl_fns[LTC_PKA_NUM] = {
#ifdef LTC_MRSA
                                                [LTC_PKA_RSA] = (import_fn)rsa_import,
#endif
#ifdef LTC_MDSA
                                                [LTC_PKA_DSA] = (import_fn)dsa_import,
#endif
#ifdef LTC_MECC
                                                [LTC_PKA_EC] = (import_fn)ecc_import_openssl,
#endif
#ifdef LTC_CURVE25519
                                                [LTC_PKA_X25519] = (import_fn)x25519_import,
                                                [LTC_PKA_ED25519] = (import_fn)ed25519_import,
#endif
};

static int s_decode(struct get_char *g, ltc_pka_key *k, const password_ctx *pw_ctx)
{
   unsigned char *pem = NULL;
   unsigned long w, l, n;
   int err = CRYPT_ERROR;
   struct pem_headers hdr = { 0 };
   struct password pw = { 0 };
   enum ltc_pka_id pka;
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
      } else if (err != CRYPT_UNKNOWN_PEM) {
         goto cleanup;
      }
      hdr.id = NULL;
   }
   /* id not found */
   if (hdr.id == NULL)
      goto cleanup;
   l = w;
   if (hdr.id->flags & pf_pkcs8) {
      err = s_import_pkcs8(pem, l, k, pw_ctx);
      goto cleanup;
   } else if (hdr.id->flags == pf_x509) {
      err = s_import_x509(pem, l, k);
      goto cleanup;
   } else if ((hdr.id->flags & pf_public) && hdr.id->pka == LTC_PKA_UNDEF) {
      if ((err = s_extract_pka(pem, w, &pka)) != CRYPT_OK) {
         goto cleanup;
      }
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
      pka = hdr.id->pka;
   } else {
      pka = hdr.id->pka;
   }

   if (pka < 0
         || pka > sizeof(s_import_openssl_fns)/sizeof(s_import_openssl_fns[0])
         || s_import_openssl_fns[pka] == NULL) {
      err = CRYPT_PK_INVALID_TYPE;
      goto cleanup;
   }
   if ((err = s_import_openssl_fns[pka](pem, l, &k->u)) == CRYPT_OK) {
      k->id = pka;
   }

cleanup:
   password_free(hdr.pw, pw_ctx);
   XFREE(pem);
   return err;
}

#ifndef LTC_NO_FILE
int pem_decode_pkcs_filehandle(FILE *f, ltc_pka_key *k, const password_ctx *pw_ctx)
{
   LTC_ARGCHK(f != NULL);
   LTC_ARGCHK(k != NULL);
   {
      struct get_char g = { .get = pem_get_char_from_file, .data.f = f };
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
      struct get_char g = { .get = pem_get_char_from_buf, SET_BUFP(.data.buf, buf, len) };
      return s_decode(&g, k, pw_ctx);
   }
}

#endif /* LTC_PEM */
