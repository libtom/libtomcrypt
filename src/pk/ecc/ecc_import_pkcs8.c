/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

static int _pkcs_5_alg1_wrap(const unsigned char *password, unsigned long password_len,
                              const unsigned char *salt,     unsigned long salt_len,
                              int iteration_count,  int hash_idx,
                              unsigned char *out,   unsigned long *outlen)
{
   LTC_UNUSED_PARAM(salt_len);
   return pkcs_5_alg1(password, password_len, salt, iteration_count, hash_idx, out, outlen);
}

static int _pkcs_12_wrap(const unsigned char *password, unsigned long password_len,
                              const unsigned char *salt,     unsigned long salt_len,
                              int iteration_count,  int hash_idx,
                              unsigned char *out,   unsigned long *outlen)
{
   int err;
   /* convert password to unicode/utf16-be */
   unsigned long pwlen = password_len * 2;
   unsigned char* pw;
   if (*outlen < 32) return CRYPT_INVALID_ARG;
   pw = XMALLOC(pwlen + 2);
   if (pw == NULL) return CRYPT_MEM;
   if ((err = pkcs12_utf8_to_utf16(password, password_len, pw, &pwlen) != CRYPT_OK)) goto LBL_ERROR;
   pw[pwlen++] = 0;
   pw[pwlen++] = 0;
   /* derive KEY */
   if ((err = pkcs12_kdf(hash_idx, pw, pwlen, salt, salt_len, iteration_count, 1, out, 24)) != CRYPT_OK) goto LBL_ERROR;
   /* derive IV */
   if ((err = pkcs12_kdf(hash_idx, pw, pwlen, salt, salt_len, iteration_count, 2, out+24, 8)) != CRYPT_OK) goto LBL_ERROR;

   *outlen = 32;
LBL_ERROR:
   zeromem(pw, pwlen);
   XFREE(pw);
   return err;
}

typedef int (*fn_kdf_t)(const unsigned char *password, unsigned long password_len,
                              const unsigned char *salt,     unsigned long salt_len,
                              int iteration_count,  int hash_idx,
                              unsigned char *out,   unsigned long *outlen);

typedef struct {
   /* KDF */
   fn_kdf_t kdf;
   /* Hash or HMAC */
   const char* h;
   /* cipher */
   const char* c;
   unsigned long keylen;
   /* not used for pbkdf2 */
   unsigned long blocklen;
} _pbes_type;

typedef struct {
   const _pbes_type *data;
   const char *oid;
} oid_pbes_type;

/* PBES1-related structs */

static const _pbes_type _pbes1_types[] = {
   { _pkcs_5_alg1_wrap, "md2",   "des",   8, 8 },
   { _pkcs_5_alg1_wrap, "md2",   "rc2",   8, 8 },
   { _pkcs_5_alg1_wrap, "md5",   "des",   8, 8 },
   { _pkcs_5_alg1_wrap, "md5",   "rc2",   8, 8 },
   { _pkcs_5_alg1_wrap, "sha1",  "des",   8, 8 },
   { _pkcs_5_alg1_wrap, "sha1",  "rc2",   8, 8 },
   { _pkcs_12_wrap,     "sha1",  "3des", 24, 8 },
};

static const oid_pbes_type _pbes1_list[] = {
   { &_pbes1_types[0], "1.2.840.113549.1.5.1"    },  /* http://www.oid-info.com/get/1.2.840.113549.1.5.1    pbeWithMD2AndDES-CBC */
   { &_pbes1_types[1], "1.2.840.113549.1.5.4"    },  /* http://www.oid-info.com/get/1.2.840.113549.1.5.4    pbeWithMD2AndRC2-CBC */
   { &_pbes1_types[2], "1.2.840.113549.1.5.3"    },  /* http://www.oid-info.com/get/1.2.840.113549.1.5.3    pbeWithMD5AndDES-CBC */
   { &_pbes1_types[3], "1.2.840.113549.1.5.6"    },  /* http://www.oid-info.com/get/1.2.840.113549.1.5.6    pbeWithMD5AndRC2-CBC */
   { &_pbes1_types[4], "1.2.840.113549.1.5.10"   },  /* http://www.oid-info.com/get/1.2.840.113549.1.5.10   pbeWithSHA1AndDES-CBC */
   { &_pbes1_types[5], "1.2.840.113549.1.5.11"   },  /* http://www.oid-info.com/get/1.2.840.113549.1.5.11   pbeWithSHA1AndRC2-CBC */
   { &_pbes1_types[6], "1.2.840.113549.1.12.1.3" },  /* http://www.oid-info.com/get/1.2.840.113549.1.12.1.3 pbeWithSHAAnd3-KeyTripleDES-CBC */
   { 0 },
};

/* PBES2-related structs */

typedef struct {
   const char *oid;
   const char *id;
} oid_id_st;

static const oid_id_st _hmac_oid_names[] = {
   { "1.2.840.113549.2.7",  "sha1" },
   { "1.2.840.113549.2.8",  "sha224" },
   { "1.2.840.113549.2.9",  "sha256" },
   { "1.2.840.113549.2.10", "sha384" },
   { "1.2.840.113549.2.11", "sha512" },
   { "1.2.840.113549.2.12", "sha512-224" },
   { "1.2.840.113549.2.13", "sha512-256" },
};

static const _pbes_type _pbes2_default_types[] = {
   { pkcs_5_alg2, "sha1",   "des",   8, 0 },
   { pkcs_5_alg2, "sha1",   "rc2",   4, 0 },
   { pkcs_5_alg2, "sha1",   "3des", 24, 0 },
   { pkcs_5_alg2, "sha1",   "aes",  16, 0 },
   { pkcs_5_alg2, "sha1",   "aes",  24, 0 },
   { pkcs_5_alg2, "sha1",   "aes",  32, 0 },
};

typedef struct {
   const _pbes_type *def;
   const char* oid;
} _pbes2_cipher_hmac_map;

static const _pbes2_cipher_hmac_map _pbes2_ciphers[] = {
   { &_pbes2_default_types[0], "1.3.14.3.2.7"            },  /* http://www.oid-info.com/get/1.3.14.3.2.7            desCBC */
   { &_pbes2_default_types[1], "1.2.840.113549.3.2"      },  /* http://www.oid-info.com/get/1.2.840.113549.3.2      rc2CBC */
   { &_pbes2_default_types[2], "1.2.840.113549.3.7"      },  /* http://www.oid-info.com/get/1.2.840.113549.3.7      des-EDE3-CBC */
   { &_pbes2_default_types[3], "2.16.840.1.101.3.4.1.2"  },  /* http://www.oid-info.com/get/2.16.840.1.101.3.4.1.2  aes128-CBC */
   { &_pbes2_default_types[4], "2.16.840.1.101.3.4.1.22" },  /* http://www.oid-info.com/get/2.16.840.1.101.3.4.1.22 aes192-CBC */
   { &_pbes2_default_types[5], "2.16.840.1.101.3.4.1.42" },  /* http://www.oid-info.com/get/2.16.840.1.101.3.4.1.42 aes256-CBC */
};

static const char *_oid_pbkdf2 = "1.2.840.113549.1.5.12";
static const char *_oid_pbes2 =  "1.2.840.113549.1.5.13";

static int _oid_to_pbe(const ltc_asn1_list *oidA, const ltc_asn1_list *oidB, _pbes_type *res)
{
   unsigned int i;
   if (oidB != NULL) {
      for (i = 0; i < sizeof(_pbes2_ciphers)/sizeof(_pbes2_ciphers[0]); ++i) {
         if (pk_oid_cmp_with_asn1(_pbes2_ciphers[i].oid, oidB) == CRYPT_OK) {
            *res = *_pbes2_ciphers[i].def;
            break;
         }
      }
      if (res->c == NULL) return CRYPT_INVALID_CIPHER;
      if (oidA != NULL) {
         for (i = 0; i < sizeof(_hmac_oid_names)/sizeof(_hmac_oid_names[0]); ++i) {
            if (pk_oid_cmp_with_asn1(_hmac_oid_names[i].oid, oidA) == CRYPT_OK) {
               res->h = _hmac_oid_names[i].id;
               return CRYPT_OK;
            }
         }
         return CRYPT_INVALID_HASH;
      }
      return CRYPT_OK;
   } else {
      for (i = 0; _pbes1_list[i].data != NULL; ++i) {
         if (pk_oid_cmp_with_asn1(_pbes1_list[i].oid, oidA) == CRYPT_OK) {
            *res = *_pbes1_list[i].data;
            return CRYPT_OK;
         }
      }
   }
   return CRYPT_INVALID_ARG;
}

typedef struct
{
   _pbes_type type;
   const void *pwd;
   unsigned long pwdlen;
   ltc_asn1_list *enc_data;
   ltc_asn1_list *salt;
   ltc_asn1_list *iv;
   unsigned long iterations;
   int klen;
} _pbesX_arg_t;

static int _pbesX_decrypt(const _pbesX_arg_t  *arg,
                                unsigned char *dec_data, unsigned long *dec_size)
{
   int err, hid = -1, cid = -1;
   unsigned char k[32], *iv;
   unsigned long klen, keylen, ivlen, dlen;
   long diff;
   symmetric_CBC cbc;

   hid = find_hash(arg->type.h);
   if (hid == -1) return CRYPT_INVALID_ARG;
   cid = find_cipher(arg->type.c);
   if (cid == -1) return CRYPT_INVALID_ARG;

   klen = arg->type.keylen;

   /* rc2 special case */
   if (arg->klen != 0) {
      if (arg->klen == 160)  klen = 5;
      if (arg->klen == 120)  klen = 8;
      if (arg->klen == 58)   klen = 16;
      if (arg->klen >= 256)  klen = arg->klen / 8;
   }
   keylen = klen;

   if (arg->iv != NULL) {
      iv = arg->iv->data;
      ivlen = arg->iv->size;
   } else {
      iv = k + klen;
      ivlen = arg->type.blocklen;
      klen += ivlen;
   }

   if (klen > sizeof(k)) return CRYPT_INVALID_ARG;

   if ((err = arg->type.kdf(arg->pwd, arg->pwdlen, arg->salt->data, arg->salt->size, arg->iterations, hid, k, &klen)) != CRYPT_OK) goto LBL_ERROR;
   if ((err = cbc_start(cid, iv, k, keylen, 0, &cbc)) != CRYPT_OK) goto LBL_ERROR;
   if ((err = cbc_decrypt(arg->enc_data->data, dec_data, arg->enc_data->size, &cbc)) != CRYPT_OK) goto LBL_ERROR;
   if ((err = cbc_done(&cbc)) != CRYPT_OK) goto LBL_ERROR;
   dlen = arg->enc_data->size;
   if ((err = padding_depad(dec_data, &dlen, LTC_PAD_PKCS7)) != CRYPT_OK) goto LBL_ERROR;
   diff = (long)arg->enc_data->size - (long)dlen;
   if ((diff <= 0) || (diff > cipher_descriptor[cid].block_length)) {
      err = CRYPT_PK_INVALID_PADDING;
      goto LBL_ERROR;
   }
   *dec_size = dlen;
   return CRYPT_OK;

LBL_ERROR:
   zeromem(k, sizeof(k));
   zeromem(dec_data, *dec_size);
   return err;
}

static int _der_decode_pkcs8_flexi(const unsigned char *in,  unsigned long inlen,
                                   const void *pwd, unsigned long pwdlen,
                                   ltc_asn1_list **decoded_list)
{
   unsigned long len = inlen;
   unsigned long dec_size;
   unsigned char *dec_data = NULL;
   ltc_asn1_list *l = NULL;
   int err;

   *decoded_list = NULL;
   if ((err = der_decode_sequence_flexi(in, &len, &l)) == CRYPT_OK) {
      /* the following "if" detects whether it is encrypted or not */
      if (l->type == LTC_ASN1_SEQUENCE &&
          LTC_ASN1_IS_TYPE(l->child, LTC_ASN1_SEQUENCE) &&
          LTC_ASN1_IS_TYPE(l->child->child, LTC_ASN1_OBJECT_IDENTIFIER) &&
          LTC_ASN1_IS_TYPE(l->child->child->next, LTC_ASN1_SEQUENCE) &&
          LTC_ASN1_IS_TYPE(l->child->next, LTC_ASN1_OCTET_STRING)) {
         ltc_asn1_list *lalgoid = l->child->child;
         ltc_asn1_list *lalgparam = l->child->child->next;
         _pbesX_arg_t pbes_arg = {0};
         pbes_arg.enc_data = l->child->next;
         pbes_arg.pwd = pwd;
         pbes_arg.pwdlen = pwdlen;
         dec_size = pbes_arg.enc_data->size;
         if ((dec_data = XMALLOC(dec_size)) == NULL) {
            err = CRYPT_MEM;
            goto LBL_DONE;
         }
         if (LTC_ASN1_IS_TYPE(lalgparam->child, LTC_ASN1_OCTET_STRING) &&
             LTC_ASN1_IS_TYPE(lalgparam->child->next, LTC_ASN1_INTEGER)) {
            /* PBES1: encrypted pkcs8 - pbeWithMD5AndDES-CBC:
             *  0:d=0  hl=4 l= 329 cons: SEQUENCE
             *  4:d=1  hl=2 l=  27 cons:   SEQUENCE             (== *lalg)
             *  6:d=2  hl=2 l=   9 prim:     OBJECT             :pbeWithMD5AndDES-CBC (== 1.2.840.113549.1.5.3)
             * 17:d=2  hl=2 l=  14 cons:     SEQUENCE           (== *lalgparam)
             * 19:d=3  hl=2 l=   8 prim:       OCTET STRING     [HEX DUMP]:8EDF749A06CCDE51 (== salt)
             * 29:d=3  hl=2 l=   2 prim:       INTEGER          :0800  (== iterations)
             * 33:d=1  hl=4 l= 296 prim:   OCTET STRING         :bytes (== encrypted data)
             */
            pbes_arg.iterations = mp_get_int(lalgparam->child->next->data);
            pbes_arg.salt = lalgparam->child;
            if ((err = _oid_to_pbe(lalgoid, NULL, &pbes_arg.type)) != CRYPT_OK) goto LBL_DONE;
            err = _pbesX_decrypt(&pbes_arg, dec_data, &dec_size);
            if (err != CRYPT_OK) goto LBL_DONE;
         }
         else if (pk_oid_cmp_with_asn1(_oid_pbes2, lalgoid) == CRYPT_OK &&
                  LTC_ASN1_IS_TYPE(lalgparam->child, LTC_ASN1_SEQUENCE) &&
                  LTC_ASN1_IS_TYPE(lalgparam->child->child, LTC_ASN1_OBJECT_IDENTIFIER) &&
                  LTC_ASN1_IS_TYPE(lalgparam->child->child->next, LTC_ASN1_SEQUENCE) &&
                  LTC_ASN1_IS_TYPE(lalgparam->child->next, LTC_ASN1_SEQUENCE) &&
                  LTC_ASN1_IS_TYPE(lalgparam->child->next->child, LTC_ASN1_OBJECT_IDENTIFIER)) {
            /* PBES2: encrypted pkcs8 - PBES2+PBKDF2+des-ede3-cbc:
             *  0:d=0  hl=4 l= 380 cons: SEQUENCE
             *  4:d=1  hl=2 l=  78 cons:   SEQUENCE             (== *lalg)
             *  6:d=2  hl=2 l=   9 prim:     OBJECT             :PBES2 (== 1.2.840.113549.1.5.13)
             * 17:d=2  hl=2 l=  65 cons:     SEQUENCE           (== *lalgparam)
             * 19:d=3  hl=2 l=  41 cons:       SEQUENCE
             * 21:d=4  hl=2 l=   9 prim:         OBJECT         :PBKDF2
             * 32:d=4  hl=2 l=  28 cons:         SEQUENCE
             * 34:d=5  hl=2 l=   8 prim:           OCTET STRING [HEX DUMP]:28BA4ABF6AA76A3D (== salt)
             * 44:d=5  hl=2 l=   2 prim:           INTEGER      :0800 (== iterations)
             * 48:d=5  hl=2 l=  12 cons:           SEQUENCE     (this sequence is optional, may be missing)
             * 50:d=6  hl=2 l=   8 prim:             OBJECT     :hmacWithSHA256
             * 60:d=6  hl=2 l=   0 prim:             NULL
             * 62:d=3  hl=2 l=  20 cons:       SEQUENCE
             * 64:d=4  hl=2 l=   8 prim:         OBJECT         :des-ede3-cbc
             * 74:d=4  hl=2 l=   8 prim:         OCTET STRING   [HEX DUMP]:B1404C4688DC9A5A
             * 84:d=1  hl=4 l= 296 prim:   OCTET STRING         :bytes (== encrypted data)
             */
            ltc_asn1_list *lkdf = lalgparam->child->child;
            ltc_asn1_list *lenc = lalgparam->child->next->child;
            if (pk_oid_cmp_with_asn1(_oid_pbkdf2, lkdf) == CRYPT_OK &&
                LTC_ASN1_IS_TYPE(lkdf->next, LTC_ASN1_SEQUENCE) &&
                LTC_ASN1_IS_TYPE(lkdf->next->child, LTC_ASN1_OCTET_STRING) &&
                LTC_ASN1_IS_TYPE(lkdf->next->child->next, LTC_ASN1_INTEGER)) {
               ltc_asn1_list *loptseq = lkdf->next->child->next->next;
               pbes_arg.iterations = mp_get_int(lkdf->next->child->next->data);
               pbes_arg.salt = lkdf->next->child;
               if (LTC_ASN1_IS_TYPE(loptseq, LTC_ASN1_SEQUENCE) &&
                   LTC_ASN1_IS_TYPE(loptseq->child, LTC_ASN1_OBJECT_IDENTIFIER)) {
                  /* this sequence is optional */
                  if ((err = _oid_to_pbe(loptseq->child, lenc, &pbes_arg.type)) != CRYPT_OK) goto LBL_DONE;
               } else {
                  if ((err = _oid_to_pbe(NULL, lenc, &pbes_arg.type)) != CRYPT_OK) goto LBL_DONE;
               }

               if (LTC_ASN1_IS_TYPE(lenc->next, LTC_ASN1_OCTET_STRING)) {
                  /* DES-CBC + DES_EDE3_CBC */
                  pbes_arg.iv = lenc->next;
               } else if (LTC_ASN1_IS_TYPE(lenc->next, LTC_ASN1_SEQUENCE) &&
                        LTC_ASN1_IS_TYPE(lenc->next->child, LTC_ASN1_INTEGER) &&
                        LTC_ASN1_IS_TYPE(lenc->next->child->next, LTC_ASN1_OCTET_STRING)) {
                  /* RC2-CBC is a bit special */
                  pbes_arg.iv = lenc->next->child->next;
                  pbes_arg.klen = mp_get_int(lenc->next->child->data);
               }
               err = _pbesX_decrypt(&pbes_arg, dec_data, &dec_size);
               if (err != CRYPT_OK) goto LBL_DONE;
            }
            else {
               /* non-PBKDF2 algorithms are not supported */
               err = CRYPT_INVALID_PACKET;
               goto LBL_DONE;
            }
         }
         else {
            /* unsupported encryption */
            err = CRYPT_INVALID_PACKET;
            goto LBL_DONE;
         }
         der_free_sequence_flexi(l);
         l = NULL;
         err = der_decode_sequence_flexi(dec_data, &dec_size, &l);
         if (err != CRYPT_OK) goto LBL_DONE;
         *decoded_list = l;
      }
      else {
         /* not encrypted */
         err = CRYPT_OK;
         *decoded_list = l;
      }
      l = NULL;
   }

LBL_DONE:
   der_free_sequence_flexi(l);
   if (dec_data) XFREE(dec_data);
   return err;
}

typedef struct {
   ltc_asn1_type t;
   ltc_asn1_list **pp;
} der_flexi_check;

#define LTC_SET_DER_FLEXI_CHECK(list, index, Type, P)    \
   do {                                         \
      int LTC_SDFC_temp##__LINE__ = (index);   \
      list[LTC_SDFC_temp##__LINE__].t = Type;  \
      list[LTC_SDFC_temp##__LINE__].pp = P;    \
   } while (0)

static int _der_flexi_sequence_cmp(const ltc_asn1_list *flexi, der_flexi_check *check)
{
   const ltc_asn1_list *cur;
   if (flexi->type != LTC_ASN1_SEQUENCE)
      return CRYPT_INVALID_PACKET;
   cur = flexi->child;
   while(check->t != LTC_ASN1_EOL) {
      if (!LTC_ASN1_IS_TYPE(cur, check->t))
         return CRYPT_INVALID_PACKET;
      if (check->pp != NULL) *check->pp = (ltc_asn1_list*)cur;
      cur = cur->next;
      check++;
   }
   return CRYPT_OK;
}

/* NOTE: _der_decode_pkcs8_flexi & related stuff can be shared with rsa_import_pkcs8() */

int ecc_import_pkcs8(const unsigned char *in, unsigned long inlen,
                     const void *pwd, unsigned long pwdlen,
                     ecc_key *key)
{
   void          *a, *b, *gx, *gy;
   unsigned long len, cofactor, n;
   const char    *pka_ec_oid;
   int           err;
   char          OID[256];
   const ltc_ecc_curve *curve;
   ltc_asn1_list *p = NULL, *l = NULL;
   der_flexi_check flexi_should[7];
   ltc_asn1_list *seq, *priv_key;

   LTC_ARGCHK(in          != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* get EC alg oid */
   err = pk_get_oid(PKA_EC, &pka_ec_oid);
   if (err != CRYPT_OK) return err;

   /* init key */
   err = mp_init_multi(&a, &b, &gx, &gy, NULL);
   if (err != CRYPT_OK) return err;


   if ((err = _der_decode_pkcs8_flexi(in, inlen, pwd, pwdlen, &l)) == CRYPT_OK) {

      /* Setup for basic structure */
      n=0;
      LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_INTEGER, NULL);
      LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_SEQUENCE, &seq);
      LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_OCTET_STRING, &priv_key);
      LTC_SET_DER_FLEXI_CHECK(flexi_should, n, LTC_ASN1_EOL, NULL);

      if (((err = _der_flexi_sequence_cmp(l, flexi_should)) == CRYPT_OK) &&
            (pk_oid_cmp_with_asn1(pka_ec_oid, seq->child) == CRYPT_OK)) {
         ltc_asn1_list *version, *field, *point, *point_g, *order, *p_cofactor;

         err = CRYPT_INVALID_PACKET;

         /* Setup for CASE 2 */
         n=0;
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_INTEGER, &version);
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_SEQUENCE, &field);
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_SEQUENCE, &point);
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_OCTET_STRING, &point_g);
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_INTEGER, &order);
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_INTEGER, &p_cofactor);
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n, LTC_ASN1_EOL, NULL);

         if (LTC_ASN1_IS_TYPE(seq->child->next, LTC_ASN1_OBJECT_IDENTIFIER)) {
            /* CASE 1: curve by OID (AKA short variant):
             *   0:d=0  hl=2 l= 100 cons: SEQUENCE
             *   2:d=1  hl=2 l=   1 prim:   INTEGER        :00
             *   5:d=1  hl=2 l=  16 cons:   SEQUENCE       (== *seq)
             *   7:d=2  hl=2 l=   7 prim:     OBJECT       :id-ecPublicKey
             *  16:d=2  hl=2 l=   5 prim:     OBJECT       :(== *curve_oid (e.g. secp256k1 (== 1.3.132.0.10)))
             *  23:d=1  hl=2 l=  77 prim:   OCTET STRING   :bytes (== *priv_key)
             */
            ltc_asn1_list *curve_oid = seq->child->next;
            len = sizeof(OID);
            if ((err = pk_oid_num_to_str(curve_oid->data, curve_oid->size, OID, &len)) != CRYPT_OK) { goto LBL_DONE; }
            if ((err = ecc_find_curve(OID, &curve)) != CRYPT_OK)                          { goto LBL_DONE; }
            if ((err = ecc_set_curve(curve, key)) != CRYPT_OK)                            { goto LBL_DONE; }
         }
         else if ((err = _der_flexi_sequence_cmp(seq->child->next, flexi_should)) == CRYPT_OK) {
            /* CASE 2: explicit curve parameters (AKA long variant):
             *   0:d=0  hl=3 l= 227 cons: SEQUENCE
             *   3:d=1  hl=2 l=   1 prim:   INTEGER              :00
             *   6:d=1  hl=3 l= 142 cons:   SEQUENCE             (== *seq)
             *   9:d=2  hl=2 l=   7 prim:     OBJECT             :id-ecPublicKey
             *  18:d=2  hl=3 l= 130 cons:     SEQUENCE
             *  21:d=3  hl=2 l=   1 prim:       INTEGER          :01
             *  24:d=3  hl=2 l=  44 cons:       SEQUENCE         (== *field)
             *  26:d=4  hl=2 l=   7 prim:         OBJECT         :prime-field
             *  35:d=4  hl=2 l=  33 prim:         INTEGER        :(== *prime / curve.prime)
             *  70:d=3  hl=2 l=   6 cons:       SEQUENCE         (== *point)
             *  72:d=4  hl=2 l=   1 prim:         OCTET STRING   :bytes (== curve.A)
             *  75:d=4  hl=2 l=   1 prim:         OCTET STRING   :bytes (== curve.B)
             *  78:d=3  hl=2 l=  33 prim:       OCTET STRING     :bytes (== *g_point / curve.G-point)
             * 113:d=3  hl=2 l=  33 prim:       INTEGER          :(== *order / curve.order)
             * 148:d=3  hl=2 l=   1 prim:       INTEGER          :(== curve.cofactor)
             * 151:d=1  hl=2 l=  77 prim:   OCTET STRING         :bytes (== *priv_key)
             */

            if (mp_get_int(version->data) != 1) {
               goto LBL_DONE;
            }
            cofactor = mp_get_int(p_cofactor->data);

            if (LTC_ASN1_IS_TYPE(field->child, LTC_ASN1_OBJECT_IDENTIFIER) &&
                LTC_ASN1_IS_TYPE(field->child->next, LTC_ASN1_INTEGER) &&
                LTC_ASN1_IS_TYPE(point->child, LTC_ASN1_OCTET_STRING) &&
                LTC_ASN1_IS_TYPE(point->child->next, LTC_ASN1_OCTET_STRING)) {

               ltc_asn1_list *prime = field->child->next;
               if ((err = mp_read_unsigned_bin(a, point->child->data, point->child->size)) != CRYPT_OK) {
                  goto LBL_DONE;
               }
               if ((err = mp_read_unsigned_bin(b, point->child->next->data, point->child->next->size)) != CRYPT_OK) {
                  goto LBL_DONE;
               }
               if ((err = ltc_ecc_import_point(point_g->data, point_g->size, prime->data, a, b, gx, gy)) != CRYPT_OK) {
                  goto LBL_DONE;
               }
               if ((err = ecc_set_curve_from_mpis(a, b, prime->data, order->data, gx, gy, cofactor, key)) != CRYPT_OK) {
                  goto LBL_DONE;
               }
            }
         }
         else {
            err = CRYPT_INVALID_PACKET;
            goto LBL_DONE;
         }

         /* load private key value 'k' */
         len = priv_key->size;
         if ((err = der_decode_sequence_flexi(priv_key->data, &len, &p)) == CRYPT_OK) {
            if (p->type == LTC_ASN1_SEQUENCE &&
                LTC_ASN1_IS_TYPE(p->child, LTC_ASN1_INTEGER) &&
                LTC_ASN1_IS_TYPE(p->child->next, LTC_ASN1_OCTET_STRING)) {
               ltc_asn1_list *lk = p->child->next;
               if (mp_cmp_d(p->child->data, 1) != LTC_MP_EQ) {
                  err = CRYPT_INVALID_PACKET;
                  goto LBL_ECCFREE;
               }
               if ((err = ecc_set_key(lk->data, lk->size, PK_PRIVATE, key)) != CRYPT_OK) {
                  goto LBL_ECCFREE;
               }
               goto LBL_DONE; /* success */
            }
         }
      }
   }
   err = CRYPT_INVALID_PACKET;
   goto LBL_DONE;

LBL_ECCFREE:
   ecc_free(key);
LBL_DONE:
   mp_clear_multi(a, b, gx, gy, NULL);
   if (l) der_free_sequence_flexi(l);
   if (p) der_free_sequence_flexi(p);
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
