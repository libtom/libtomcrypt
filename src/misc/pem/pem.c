/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file pem.c
  Const declarations for PEM, Steffen Jaeckel
*/

#ifdef LTC_PEM

const struct pem_header_id pem_std_headers[] = {
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
const unsigned long pem_std_headers_num = sizeof(pem_std_headers)/sizeof(pem_std_headers[0]);


/* Encrypted PEM files */
const struct str pem_proc_type_encrypted = { SET_CSTR(, "Proc-Type: 4,ENCRYPTED") };
const struct str pem_dek_info_start = { SET_CSTR(, "DEK-Info: ") };
const struct dek_info_from_str pem_dek_infos[] =
   {
      { SET_CSTR(.id, "AES-128-CBC,"),      .info.alg = "aes",      .info.keylen = 128 / 8, },
      { SET_CSTR(.id, "AES-192-CBC,"),      .info.alg = "aes",      .info.keylen = 192 / 8, },
      { SET_CSTR(.id, "AES-256-CBC,"),      .info.alg = "aes",      .info.keylen = 256 / 8, },
      { SET_CSTR(.id, "CAMELLIA-128-CBC,"), .info.alg = "camellia", .info.keylen = 128 / 8, },
      { SET_CSTR(.id, "CAMELLIA-192-CBC,"), .info.alg = "camellia", .info.keylen = 192 / 8, },
      { SET_CSTR(.id, "CAMELLIA-256-CBC,"), .info.alg = "camellia", .info.keylen = 256 / 8, },
      { SET_CSTR(.id, "DES-EDE3-CBC,"),     .info.alg = "3des",     .info.keylen = 192 / 8, },
      { SET_CSTR(.id, "DES-CBC,"),          .info.alg = "des",      .info.keylen = 64 / 8, },
   };
const unsigned long pem_dek_infos_num = sizeof(pem_dek_infos)/sizeof(pem_dek_infos[0]);

#endif /* LTC_PEM */
