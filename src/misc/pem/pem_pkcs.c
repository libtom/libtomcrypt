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

static int s_decrypt_pem(unsigned char *asn1_cert, unsigned long *asn1_len, const struct pem_headers *hdr)
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

   err = pem_decrypt(asn1_cert, asn1_len, key, klen, iv, ivlen, NULL, 0, &hdr->info, LTC_PAD_PKCS7);

   zeromem(key, sizeof(key));
   zeromem(iv, sizeof(iv));
   return err;
}

typedef int (*pkcs8_import_fn)(ltc_asn1_list *, ltc_asn1_list *, void*);

static const struct {
   enum ltc_pka_id id;
   pkcs8_import_fn fn;
} s_import_pkcs8_map[LTC_OID_NUM] = {
#ifdef LTC_MDH
                                                [LTC_OID_DH] = { LTC_PKA_DH, (pkcs8_import_fn)dh_import_pkcs8_asn1 },
#endif
#ifdef LTC_MDSA
                                                [LTC_OID_DSA] = { LTC_PKA_DSA, (pkcs8_import_fn)dsa_import_pkcs8_asn1 },
#endif
#ifdef LTC_MRSA
                                                [LTC_OID_RSA] = { LTC_PKA_RSA, (pkcs8_import_fn)rsa_import_pkcs8_asn1 },
#endif
#ifdef LTC_MECC
                                                [LTC_OID_EC] = { LTC_PKA_EC, (pkcs8_import_fn)ecc_import_pkcs8_asn1 },
#endif
#ifdef LTC_CURVE25519
                                                [LTC_OID_X25519] =  { LTC_PKA_X25519, (pkcs8_import_fn)x25519_import_pkcs8_asn1 },
                                                [LTC_OID_ED25519] = { LTC_PKA_ED25519, (pkcs8_import_fn)ed25519_import_pkcs8_asn1 },
#endif
};

static int s_import_pkcs8(unsigned char *asn1_cert, unsigned long asn1_len, ltc_pka_key *k, const password_ctx *pw_ctx)
{
   int err;
   enum ltc_oid_id oid_id;
   ltc_asn1_list *alg_id, *priv_key;
   ltc_asn1_list *p8_asn1 = NULL;
   if ((err = pkcs8_decode_flexi(asn1_cert, asn1_len, pw_ctx, &p8_asn1)) != CRYPT_OK) {
      goto cleanup;
   }
   if ((err = pkcs8_get_children(p8_asn1, &oid_id, &alg_id, &priv_key)) != CRYPT_OK) {
      goto cleanup;
   }
   if (oid_id < 0
         || oid_id > LTC_ARRAY_SIZE(s_import_pkcs8_map)
         || s_import_pkcs8_map[oid_id].fn == NULL) {
      err = CRYPT_PK_INVALID_TYPE;
      goto cleanup;
   }
   if ((err = s_import_pkcs8_map[oid_id].fn(alg_id, priv_key, &k->u)) == CRYPT_OK) {
      k->id = s_import_pkcs8_map[oid_id].id;
   }

cleanup:
   if (p8_asn1) {
      der_sequence_free(p8_asn1);
   }
   return err;
}

static int s_extract_pka(unsigned char *asn1_cert, unsigned long asn1_len, enum ltc_pka_id *pka)
{
   ltc_asn1_list *pub;
   int err = CRYPT_ERROR;
   if ((err = der_decode_sequence_flexi(asn1_cert, &asn1_len, &pub)) != CRYPT_OK) {
      return err;
   }
   err = x509_get_pka(pub, pka);
   der_sequence_free(pub);
   return err;
}

typedef int (*import_fn)(const unsigned char *, unsigned long, void*);

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
   unsigned char *asn1_cert = NULL;
   unsigned long w = 0, asn1_len, n;
   int err = CRYPT_ERROR;
   struct pem_headers hdr = { 0 };
   struct password pw = { 0 };
   enum ltc_pka_id pka;
   XMEMSET(k, 0, sizeof(*k));
   for (n = 0; n < pem_std_headers_num; ++n) {
      hdr.id = &pem_std_headers[n];
      err = pem_read((void**)&asn1_cert, &w, &hdr, g);
      if (err == CRYPT_OK) {
         break;
      } else if (err != CRYPT_UNKNOWN_PEM) {
         goto cleanup;
      }
      hdr.id = NULL;
   }
   /* id not found */
   if (hdr.id == NULL)
      goto cleanup;
   asn1_len = w;
   if (hdr.id->flags & pf_pkcs8) {
      err = s_import_pkcs8(asn1_cert, asn1_len, k, pw_ctx);
      goto cleanup;
   } else if (hdr.id->flags == pf_x509) {
      err = x509_import_spki(asn1_cert, asn1_len, k, NULL);
      goto cleanup;
   } else if ((hdr.id->flags & pf_public) && hdr.id->pka == LTC_PKA_UNDEF) {
      if ((err = s_extract_pka(asn1_cert, asn1_len, &pka)) != CRYPT_OK) {
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

      if ((err = s_decrypt_pem(asn1_cert, &asn1_len, &hdr)) != CRYPT_OK) {
         goto cleanup;
      }
      pka = hdr.id->pka;
   } else {
      pka = hdr.id->pka;
   }

   if (pka < 0
         || pka > LTC_ARRAY_SIZE(s_import_openssl_fns)
         || s_import_openssl_fns[pka] == NULL) {
      err = CRYPT_PK_INVALID_TYPE;
      goto cleanup;
   }
   if ((err = s_import_openssl_fns[pka](asn1_cert, asn1_len, &k->u)) == CRYPT_OK) {
      k->id = pka;
   }

cleanup:
   password_free(hdr.pw, pw_ctx);
   XFREE(asn1_cert);
   return err;
}

#ifndef LTC_NO_FILE
int pem_decode_pkcs_filehandle(FILE *f, ltc_pka_key *k, const password_ctx *pw_ctx)
{
   LTC_ARGCHK(f != NULL);
   LTC_ARGCHK(k != NULL);
   {
      struct get_char g = pem_get_char_init_filehandle(f);
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
      struct get_char g = pem_get_char_init(buf, len);
      return s_decode(&g, k, pw_ctx);
   }
}

#endif /* LTC_PEM */
