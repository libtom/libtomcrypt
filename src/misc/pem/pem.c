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
     .flags = pf_encrypted_pkcs8,
   },
   {
     /* PKCS#8 plain */
     SET_CSTR(.start, "-----BEGIN PRIVATE KEY-----"),
     SET_CSTR(.end, "-----END PRIVATE KEY-----"),
     .has_more_headers = no,
     .flags = pf_pkcs8,
   },
   {
     /* X.509 Certificates */
     SET_CSTR(.start, "-----BEGIN CERTIFICATE-----"),
     SET_CSTR(.end, "-----END CERTIFICATE-----"),
     .has_more_headers = no,
     .flags = pf_x509,
   },
   {
     /* Regular (plain) public keys */
     SET_CSTR(.start, "-----BEGIN PUBLIC KEY-----"),
     SET_CSTR(.end, "-----END PUBLIC KEY-----"),
     .has_more_headers = no,
     .flags = pf_public,
   },
   {
     SET_CSTR(.start, "-----BEGIN RSA PUBLIC KEY-----"),
     SET_CSTR(.end, "-----END RSA PUBLIC KEY-----"),
     .has_more_headers = no,
     .pka = LTC_PKA_RSA,
     .flags = pf_public,
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
#if defined(LTC_SSH)
const struct str pem_ssh_comment = { SET_CSTR(, "Comment: ") };
#endif
const struct str pem_dek_info_start = { SET_CSTR(, "DEK-Info: ") };
const struct blockcipher_info pem_dek_infos[] =
   {
      { .name = "AES-128-CBC,",      .algo = "aes",      .keylen = 128 / 8, .mode = cm_cbc, },
      { .name = "AES-192-CBC,",      .algo = "aes",      .keylen = 192 / 8, .mode = cm_cbc, },
      { .name = "AES-256-CBC,",      .algo = "aes",      .keylen = 256 / 8, .mode = cm_cbc, },
      { .name = "AES-128-CFB,",      .algo = "aes",      .keylen = 128 / 8, .mode = cm_cfb, },
      { .name = "AES-192-CFB,",      .algo = "aes",      .keylen = 192 / 8, .mode = cm_cfb, },
      { .name = "AES-256-CFB,",      .algo = "aes",      .keylen = 256 / 8, .mode = cm_cfb, },
      { .name = "AES-128-CTR,",      .algo = "aes",      .keylen = 128 / 8, .mode = cm_ctr, },
      { .name = "AES-192-CTR,",      .algo = "aes",      .keylen = 192 / 8, .mode = cm_ctr, },
      { .name = "AES-256-CTR,",      .algo = "aes",      .keylen = 256 / 8, .mode = cm_ctr, },
      { .name = "AES-128-OFB,",      .algo = "aes",      .keylen = 128 / 8, .mode = cm_ofb, },
      { .name = "AES-192-OFB,",      .algo = "aes",      .keylen = 192 / 8, .mode = cm_ofb, },
      { .name = "AES-256-OFB,",      .algo = "aes",      .keylen = 256 / 8, .mode = cm_ofb, },
      { .name = "BF-CBC,",           .algo = "blowfish", .keylen = 128 / 8, .mode = cm_cbc, },
      { .name = "BF-CFB,",           .algo = "blowfish", .keylen = 128 / 8, .mode = cm_cfb, },
      { .name = "BF-OFB,",           .algo = "blowfish", .keylen = 128 / 8, .mode = cm_ofb, },
      { .name = "CAMELLIA-128-CBC,", .algo = "camellia", .keylen = 128 / 8, .mode = cm_cbc, },
      { .name = "CAMELLIA-192-CBC,", .algo = "camellia", .keylen = 192 / 8, .mode = cm_cbc, },
      { .name = "CAMELLIA-256-CBC,", .algo = "camellia", .keylen = 256 / 8, .mode = cm_cbc, },
      { .name = "CAMELLIA-128-CFB,", .algo = "camellia", .keylen = 128 / 8, .mode = cm_cfb, },
      { .name = "CAMELLIA-192-CFB,", .algo = "camellia", .keylen = 192 / 8, .mode = cm_cfb, },
      { .name = "CAMELLIA-256-CFB,", .algo = "camellia", .keylen = 256 / 8, .mode = cm_cfb, },
      { .name = "CAMELLIA-128-CTR,", .algo = "camellia", .keylen = 128 / 8, .mode = cm_ctr, },
      { .name = "CAMELLIA-192-CTR,", .algo = "camellia", .keylen = 192 / 8, .mode = cm_ctr, },
      { .name = "CAMELLIA-256-CTR,", .algo = "camellia", .keylen = 256 / 8, .mode = cm_ctr, },
      { .name = "CAMELLIA-128-OFB,", .algo = "camellia", .keylen = 128 / 8, .mode = cm_ofb, },
      { .name = "CAMELLIA-192-OFB,", .algo = "camellia", .keylen = 192 / 8, .mode = cm_ofb, },
      { .name = "CAMELLIA-256-OFB,", .algo = "camellia", .keylen = 256 / 8, .mode = cm_ofb, },
      { .name = "CAST5-CBC,",        .algo = "cast5",    .keylen = 128 / 8, .mode = cm_cbc, },
      { .name = "CAST5-CFB,",        .algo = "cast5",    .keylen = 128 / 8, .mode = cm_cfb, },
      { .name = "CAST5-OFB,",        .algo = "cast5",    .keylen = 128 / 8, .mode = cm_ofb, },
      { .name = "DES-EDE3-CBC,",     .algo = "3des",     .keylen = 192 / 8, .mode = cm_cbc, },
      { .name = "DES-EDE3-CFB,",     .algo = "3des",     .keylen = 192 / 8, .mode = cm_cfb, },
      { .name = "DES-EDE3-OFB,",     .algo = "3des",     .keylen = 192 / 8, .mode = cm_ofb, },
      { .name = "DES-CBC,",          .algo = "des",      .keylen =  64 / 8, .mode = cm_cbc, },
      { .name = "DES-CFB,",          .algo = "des",      .keylen =  64 / 8, .mode = cm_cfb, },
      { .name = "DES-OFB,",          .algo = "des",      .keylen =  64 / 8, .mode = cm_ofb, },
      { .name = "IDEA-CBC,",         .algo = "idea",     .keylen = 128 / 8, .mode = cm_cbc, },
      { .name = "IDEA-CFB,",         .algo = "idea",     .keylen = 128 / 8, .mode = cm_cfb, },
      { .name = "IDEA-OFB,",         .algo = "idea",     .keylen = 128 / 8, .mode = cm_ofb, },
      { .name = "RC5-CBC,",          .algo = "rc5",      .keylen = 128 / 8, .mode = cm_cbc, },
      { .name = "RC5-CFB,",          .algo = "rc5",      .keylen = 128 / 8, .mode = cm_cfb, },
      { .name = "RC5-OFB,",          .algo = "rc5",      .keylen = 128 / 8, .mode = cm_ofb, },
      { .name = "RC2-40-CBC,",       .algo = "rc2",      .keylen =  40 / 8, .mode = cm_cbc, },
      { .name = "RC2-64-CBC,",       .algo = "rc2",      .keylen =  64 / 8, .mode = cm_cbc, },
      { .name = "RC2-CBC,",          .algo = "rc2",      .keylen = 128 / 8, .mode = cm_cbc, },
      { .name = "RC2-CFB,",          .algo = "rc2",      .keylen = 128 / 8, .mode = cm_cfb, },
      { .name = "RC2-OFB,",          .algo = "rc2",      .keylen = 128 / 8, .mode = cm_ofb, },
      { .name = "SEED-CBC,",         .algo = "seed",     .keylen = 128 / 8, .mode = cm_cbc, },
      { .name = "SEED-CFB,",         .algo = "seed",     .keylen = 128 / 8, .mode = cm_cfb, },
      { .name = "SEED-OFB,",         .algo = "seed",     .keylen = 128 / 8, .mode = cm_ofb, },
   };
const unsigned long pem_dek_infos_num = sizeof(pem_dek_infos)/sizeof(pem_dek_infos[0]);

int pem_decrypt(unsigned char *data, unsigned long *datalen,
                unsigned char *key,  unsigned long keylen,
                unsigned char *iv,   unsigned long ivlen,
                const struct blockcipher_info *info,
                enum padding_type padding)
{
   int err, cipher;
   struct {
      union {
#ifdef LTC_CBC_MODE
         symmetric_CBC cbc;
#endif
#ifdef LTC_CFB_MODE
         symmetric_CFB cfb;
#endif
#ifdef LTC_CTR_MODE
         symmetric_CTR ctr;
#endif
#ifdef LTC_OFB_MODE
         symmetric_OFB ofb;
#endif
      } ctx;
   } s;

   cipher = find_cipher(info->algo);
   if (cipher == -1) {
      return CRYPT_INVALID_CIPHER;
   }

   switch (info->mode) {
      case cm_cbc:
#ifdef LTC_CBC_MODE
         LTC_ARGCHK(ivlen == (unsigned long)cipher_descriptor[cipher].block_length);

         if ((err = cbc_start(cipher, iv, key, keylen, 0, &s.ctx.cbc)) != CRYPT_OK) {
            goto error_out;
         }
         if ((err = cbc_decrypt(data, data, *datalen, &s.ctx.cbc)) != CRYPT_OK) {
            goto error_out;
         }
         if ((err = cbc_done(&s.ctx.cbc)) != CRYPT_OK) {
            goto error_out;
         }

         if ((err = padding_depad(data, datalen, padding | s.ctx.cbc.blocklen)) != CRYPT_OK) {
            goto error_out;
         }
#else
         return CRYPT_INVALID_CIPHER;
#endif
         break;
      case cm_cfb:
#ifdef LTC_CFB_MODE
         if ((err = cfb_start(cipher, iv, key, keylen, 0, &s.ctx.cfb)) != CRYPT_OK) {
            goto error_out;
         }
         if ((err = cfb_decrypt(data, data, *datalen, &s.ctx.cfb)) != CRYPT_OK) {
            goto error_out;
         }
         if ((err = cfb_done(&s.ctx.cfb)) != CRYPT_OK) {
            goto error_out;
         }
#else
         return CRYPT_INVALID_CIPHER;
#endif
         break;
      case cm_ctr:
#ifdef LTC_CTR_MODE
         if ((err = ctr_start(cipher, iv, key, keylen, 0, CTR_COUNTER_BIG_ENDIAN, &s.ctx.ctr)) != CRYPT_OK) {
            goto error_out;
         }
         if ((err = ctr_decrypt(data, data, *datalen, &s.ctx.ctr)) != CRYPT_OK) {
            goto error_out;
         }
         if ((err = ctr_done(&s.ctx.ctr)) != CRYPT_OK) {
            goto error_out;
         }
#else
         return CRYPT_INVALID_CIPHER;
#endif
         break;
      case cm_ofb:
#ifdef LTC_OFB_MODE
         if ((err = ofb_start(cipher, iv, key, keylen, 0, &s.ctx.ofb)) != CRYPT_OK) {
            goto error_out;
         }
         if ((err = ofb_decrypt(data, data, *datalen, &s.ctx.ofb)) != CRYPT_OK) {
            goto error_out;
         }
         if ((err = ofb_done(&s.ctx.ofb)) != CRYPT_OK) {
            goto error_out;
         }
#else
         return CRYPT_INVALID_CIPHER;
#endif
         break;
      default:
         err = CRYPT_INVALID_ARG;
         break;
   }

error_out:
   return err;
}

#endif /* LTC_PEM */
