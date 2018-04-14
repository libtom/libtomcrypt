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

enum algorithm_oid {
   PBE_MD2_DES,         /* 0 */
   PBE_MD2_RC2,
   PBE_MD5_DES,
   PBE_MD5_RC2,
   PBE_SHA1_DES,
   PBE_SHA1_RC2,        /* 5 */
   PBES2,
   PBKDF2,
   DES_CBC,
   RC2_CBC,
   DES_EDE3_CBC,        /* 10 */
   HMAC_WITH_SHA1,
   HMAC_WITH_SHA224,
   HMAC_WITH_SHA256,
   HMAC_WITH_SHA384,
   HMAC_WITH_SHA512,    /* 15 */
   PBE_SHA1_3DES
};

static const oid_st oid_list[] = {
   { { 1,2,840,113549,1,5,1     }, 7 }, /* [0]  http://www.oid-info.com/get/1.2.840.113549.1.5.1    pbeWithMD2AndDES-CBC */
   { { 1,2,840,113549,1,5,4     }, 7 }, /* [1]  http://www.oid-info.com/get/1.2.840.113549.1.5.4    pbeWithMD2AndRC2-CBC */
   { { 1,2,840,113549,1,5,3     }, 7 }, /* [2]  http://www.oid-info.com/get/1.2.840.113549.1.5.3    pbeWithMD5AndDES-CBC */
   { { 1,2,840,113549,1,5,6     }, 7 }, /* [3]  http://www.oid-info.com/get/1.2.840.113549.1.5.6    pbeWithMD5AndRC2-CBC */
   { { 1,2,840,113549,1,5,10    }, 7 }, /* [4]  http://www.oid-info.com/get/1.2.840.113549.1.5.10   pbeWithSHA1AndDES-CBC */
   { { 1,2,840,113549,1,5,11    }, 7 }, /* [5]  http://www.oid-info.com/get/1.2.840.113549.1.5.11   pbeWithSHA1AndRC2-CBC */
   { { 1,2,840,113549,1,5,13    }, 7 }, /* [6]  http://www.oid-info.com/get/1.2.840.113549.1.5.13   pbes2 */
   { { 1,2,840,113549,1,5,12    }, 7 }, /* [7]  http://www.oid-info.com/get/1.2.840.113549.1.5.12   pBKDF2 */
   { { 1,3,14,3,2,7             }, 6 }, /* [8]  http://www.oid-info.com/get/1.3.14.3.2.7            desCBC */
   { { 1,2,840,113549,3,2       }, 6 }, /* [9]  http://www.oid-info.com/get/1.2.840.113549.3.2      rc2CBC */
   { { 1,2,840,113549,3,7       }, 6 }, /* [10] http://www.oid-info.com/get/1.2.840.113549.3.7      des-EDE3-CBC */
   { { 1,2,840,113549,2,7       }, 6 }, /* [11] http://www.oid-info.com/get/1.2.840.113549.2.7      hmacWithSHA1 */
   { { 1,2,840,113549,2,8       }, 6 }, /* [12] http://www.oid-info.com/get/1.2.840.113549.2.8      hmacWithSHA224 */
   { { 1,2,840,113549,2,9       }, 6 }, /* [13] http://www.oid-info.com/get/1.2.840.113549.2.9      hmacWithSHA256 */
   { { 1,2,840,113549,2,10      }, 6 }, /* [14] http://www.oid-info.com/get/1.2.840.113549.2.10     hmacWithSHA384 */
   { { 1,2,840,113549,2,11      }, 6 }, /* [15] http://www.oid-info.com/get/1.2.840.113549.2.11     hmacWithSHA512 */
   { { 1,2,840,113549,1,12,1,3  }, 8 }, /* [16] http://www.oid-info.com/get/1.2.840.113549.1.12.1.3 pbeWithSHAAnd3-KeyTripleDES-CBC */
   { { 0 }, 0 },
};

static int _simple_utf8_to_utf16(const unsigned char *in, unsigned long inlen,
                                 unsigned char *out, unsigned long *outlen) {
   unsigned long len = 0;
   const unsigned char* in_end = in + inlen;
   const ulong32 offset[6] = {
      0x00000000UL, 0x00003080UL, 0x000E2080UL,
      0x03C82080UL, 0xFA082080UL, 0x82082080UL
   };
   int err = CRYPT_ERROR;

   while (in < in_end) {
      ulong32 ch = 0;
      unsigned short extra = 0; /* 0 */
      if (*in >= 192) extra++;  /* 1 */
      if (*in >= 224) extra++;  /* 2 */
      if (*in >= 240) extra++;  /* 3 */
      if (*in >= 248) extra++;  /* 4 */
      if (*in >= 252) extra++;  /* 5 */
      if (in + extra >= in_end) goto ERROR;
      switch (extra) {
         case 5: ch += *in++; ch <<= 6;
         case 4: ch += *in++; ch <<= 6;
         case 3: ch += *in++; ch <<= 6;
         case 2: ch += *in++; ch <<= 6;
         case 1: ch += *in++; ch <<= 6;
         case 0: ch += *in++;
      }
      ch -= offset[extra];
      if (ch > 0xFFFF) goto ERROR;
      if (*outlen >= len + 2) {
         out[len] = (unsigned short)((ch >> 8) & 0xFF);
         out[len + 1] = (unsigned char)(ch & 0xFF);
      }
      len += 2;
   }

   err = len > *outlen ? CRYPT_BUFFER_OVERFLOW : CRYPT_OK;
   *outlen = len;
ERROR:
   return err;
}

static int _kdf_pkcs12(int hash_id, const unsigned char *pw, unsigned long pwlen,
                                    const unsigned char *salt, unsigned long saltlen,
                                    unsigned int iterations, unsigned char purpose,
                                    unsigned char *out, unsigned long outlen)
{
   unsigned long u = hash_descriptor[hash_id].hashsize;
   unsigned long v = hash_descriptor[hash_id].blocksize;
   unsigned long c = (outlen + u - 1) / u;
   unsigned long Slen = ((saltlen + v - 1) / v) * v;
   unsigned long Plen = ((pwlen + v - 1) / v) * v;
   unsigned long k = (Plen + Slen) / v;
   unsigned long Alen, keylen = 0;
   unsigned int tmp, i, j, n;
   unsigned char ch;
   unsigned char D[MAXBLOCKSIZE], A[MAXBLOCKSIZE], B[MAXBLOCKSIZE];
   unsigned char *I = NULL, *key = NULL;
   int err = CRYPT_ERROR;

   key = XMALLOC(u * c);
   I   = XMALLOC(Plen + Slen);
   if (key == NULL || I == NULL) goto DONE;
   zeromem(key, u * c);

   for (i = 0; i < v;    i++) D[i] = purpose;              /* D - diversifier */
   for (i = 0; i < Slen; i++) I[i] = salt[i % saltlen];
   for (i = 0; i < Plen; i++) I[Slen + i] = pw[i % pwlen]; /* I = Salt || Pass */

   for (i = 0; i < c; i++) {
      Alen = u; /* hash size */
      err = hash_memory_multi(hash_id, A, &Alen, D, v, I, Slen + Plen, NULL); /* A = HASH(D || I) */
      if (err != CRYPT_OK) goto DONE;
      for (j = 1; j < iterations; j++) {
         err = hash_memory(hash_id, A, Alen, A, &Alen); /* A = HASH(A) */
         if (err != CRYPT_OK) goto DONE;
      }
      /* fill buffer B with A */
      for (j = 0; j < v; j++) B[j] = A[j % Alen];
      /* B += 1 */
      for (j = v; j > 0; j--) {
         if (++B[j - 1] != 0) break;
      }
      /* I_n += B */
      for (n = 0; n < k; n++) {
         ch = 0;
         for (j = v; j > 0; j--) {
            tmp = I[n * v + j - 1] + B[j - 1] + ch;
            ch = (unsigned char)((tmp >> 8) & 0xFF);
            I[n * v + j - 1] = (unsigned char)(tmp & 0xFF);
         }
      }
      /* store derived key block */
      for (j = 0; j < Alen; j++) key[keylen++] = A[j];
   }

   for (i = 0; i < outlen; i++) out[i] = key[i];
   err = CRYPT_OK;
DONE:
   if (I) XFREE(I);
   if (key) XFREE(key);
   return err;
}

static int _oid_to_id(const unsigned long *oid, unsigned long oid_size)
{
   int i, j;
   for (j = 0; oid_list[j].OIDlen > 0; j++) {
     int match = 1;
     if (oid_list[j].OIDlen != oid_size) continue;
     for (i = 0; i < (int)oid_size && match; i++) if (oid_list[j].OID[i] != oid[i]) match = 0;
     if (match) return j;
   }
   return -1;
}

static int _pbes1_decrypt(const unsigned char *enc_data, unsigned long enc_size,
                          const unsigned char *pass,     unsigned long pass_size,
                          const unsigned char *salt,     unsigned long salt_size,
                                unsigned long iterations,
                          const unsigned long *oid,      unsigned long oid_size,
                                unsigned char *dec_data, unsigned long *dec_size)
{
   int id = _oid_to_id(oid, oid_size);
   int err, hid = -1, cid = -1;
   unsigned int keylen, blklen;
   unsigned char key_iv[32] = { 0 }, pad;
   unsigned long len = sizeof(key_iv), pwlen = pass_size;
   symmetric_CBC cbc;
   unsigned char *pw = NULL;

   /* https://tools.ietf.org/html/rfc8018#section-6.1.2 */
   if (id == PBE_MD2_DES  || id == PBE_MD2_RC2) hid = find_hash("md2");
   if (id == PBE_MD5_DES  || id == PBE_MD5_RC2) hid = find_hash("md5");
   if (id == PBE_SHA1_DES || id == PBE_SHA1_RC2 || id == PBE_SHA1_3DES) hid = find_hash("sha1");

   if (id == PBE_MD2_RC2 || id == PBE_MD5_RC2 || id == PBE_SHA1_RC2) {
      cid = find_cipher("rc2");
      keylen = 8;
      blklen = 8;
   }
   if (id == PBE_MD2_DES || id == PBE_MD5_DES || id == PBE_SHA1_DES) {
      cid = find_cipher("des");
      keylen = 8;
      blklen = 8;
   }
   if (id == PBE_SHA1_3DES) {
      cid = find_cipher("3des");
      keylen = 24;
      blklen = 8;
   }

   if (id == PBE_SHA1_3DES) {
      /* convert password to unicode/utf16-be */
      pwlen = pass_size * 2;
      pw = XMALLOC(pwlen + 2);
      if (pw == NULL) goto LBL_ERROR;
      if ((err = _simple_utf8_to_utf16(pass, pass_size, pw, &pwlen) != CRYPT_OK)) goto LBL_ERROR;
      pw[pwlen++] = 0;
      pw[pwlen++] = 0;
      /* derive KEY */
      if ((err = _kdf_pkcs12(hid, pw, pwlen, salt, salt_size, iterations, 1, key_iv, keylen)) != CRYPT_OK) goto LBL_ERROR;
      /* derive IV */
      if ((err = _kdf_pkcs12(hid, pw, pwlen, salt, salt_size, iterations, 2, key_iv+24, blklen)) != CRYPT_OK) goto LBL_ERROR;
   }
   else {
      if ((err = pkcs_5_alg1(pass, pass_size, salt, iterations, hid, key_iv, &len)) != CRYPT_OK) goto LBL_ERROR;
      /* the output has 16 bytes: [KEY-8-bytes][IV-8-bytes] */
   }

   if (hid != -1 && cid != -1) {
      if (salt_size != 8 || enc_size < blklen) goto LBL_ERROR;
      if ((err = cbc_start(cid, key_iv + keylen, key_iv, keylen, 0, &cbc)) != CRYPT_OK) goto LBL_ERROR;
      if ((err = cbc_decrypt(enc_data, dec_data, enc_size, &cbc)) != CRYPT_OK) goto LBL_ERROR;
      if ((err = cbc_done(&cbc)) != CRYPT_OK) goto LBL_ERROR;
      pad = dec_data[enc_size-1];
      if (pad < 1 || pad > blklen) goto LBL_ERROR;
      *dec_size = enc_size - pad;
      err = CRYPT_OK;
      goto LBL_DONE;
   }

LBL_ERROR:
   err = CRYPT_INVALID_ARG;
LBL_DONE:
   zeromem(key_iv, sizeof(key_iv));
   if (pw) { zeromem(pw, pwlen); XFREE(pw); }
   return err;
}

static int _pbes2_pbkdf2_decrypt(const unsigned char *enc_data, unsigned long enc_size,
                                 const unsigned char *pass,     unsigned long pass_size,
                                 const unsigned char *salt,     unsigned long salt_size,
                                 const unsigned char *iv,       unsigned long iv_size,
                                       unsigned long iterations,
                                                 int hmacid,
                                                 int encid,
                                                 int extra_arg,
                                       unsigned char *dec_data, unsigned long *dec_size)
{
   int err, hid = -1, cid = -1;
   unsigned char k[32], pad;
   unsigned long klen = sizeof(k);
   symmetric_CBC cbc;

   /* https://tools.ietf.org/html/rfc8018#section-6.2.2 */

   if (hmacid == HMAC_WITH_SHA1)   hid = find_hash("sha1");
   if (hmacid == HMAC_WITH_SHA224) hid = find_hash("sha224");
   if (hmacid == HMAC_WITH_SHA256) hid = find_hash("sha256");
   if (hmacid == HMAC_WITH_SHA384) hid = find_hash("sha384");
   if (hmacid == HMAC_WITH_SHA512) hid = find_hash("sha512");
   if (hid == -1) return CRYPT_INVALID_ARG;

   if (encid == DES_EDE3_CBC) {
      /* https://tools.ietf.org/html/rfc8018#appendix-B.2.2 */
      cid = find_cipher("3des");
      klen = 24;
      if (klen > sizeof(k) || iv_size != 8 || iv == NULL || cid == -1) goto LBL_ERROR;
      if ((err = pkcs_5_alg2(pass, pass_size, salt, salt_size, iterations, hid, k, &klen)) != CRYPT_OK) goto LBL_ERROR;
      if ((err = cbc_start(cid, iv, k, klen, 0, &cbc)) != CRYPT_OK) goto LBL_ERROR;
      if ((err = cbc_decrypt(enc_data, dec_data, enc_size, &cbc)) != CRYPT_OK) goto LBL_ERROR;
      if ((err = cbc_done(&cbc)) != CRYPT_OK) goto LBL_ERROR;
      pad = dec_data[enc_size-1];
      if (pad < 1 || pad > 8) goto LBL_ERROR;
      *dec_size = enc_size - pad;
      return CRYPT_OK;
   }

   if (encid == DES_CBC) {
      /* https://tools.ietf.org/html/rfc8018#appendix-B.2.1 */
      cid = find_cipher("des");
      klen = 8; /* 64 bits */
      if (klen > sizeof(k) || iv_size != 8 || iv == NULL || cid == -1) goto LBL_ERROR;
      if ((err = pkcs_5_alg2(pass, pass_size, salt, salt_size, iterations, hid, k, &klen)) != CRYPT_OK) goto LBL_ERROR;
      if ((err = cbc_start(cid, iv, k, klen, 0, &cbc)) != CRYPT_OK) goto LBL_ERROR;
      if ((err = cbc_decrypt(enc_data, dec_data, enc_size, &cbc)) != CRYPT_OK) goto LBL_ERROR;
      if ((err = cbc_done(&cbc)) != CRYPT_OK) goto LBL_ERROR;
      pad = dec_data[enc_size-1];
      if (pad < 1 || pad > 8) goto LBL_ERROR;
      *dec_size = enc_size - pad;
      return CRYPT_OK;
   }

   if (encid == RC2_CBC) {
     /* https://tools.ietf.org/html/rfc8018#appendix-B.2.3 */
      cid = find_cipher("rc2");
      klen = 4; /* default: 32 bits */
      if (extra_arg == 160)  klen = 5;
      if (extra_arg == 120)  klen = 8;
      if (extra_arg == 58)   klen = 16;
      if (extra_arg >= 256)  klen = extra_arg / 8;
      if (klen > sizeof(k) || iv_size != 8 || iv == NULL || cid == -1) goto LBL_ERROR;
      if ((err = pkcs_5_alg2(pass, pass_size, salt, salt_size, iterations, hid, k, &klen)) != CRYPT_OK) goto LBL_ERROR;
      if ((err = cbc_start(cid, iv, k, klen, 0, &cbc)) != CRYPT_OK) goto LBL_ERROR;
      if ((err = cbc_decrypt(enc_data, dec_data, enc_size, &cbc)) != CRYPT_OK) goto LBL_ERROR;
      if ((err = cbc_done(&cbc)) != CRYPT_OK) goto LBL_ERROR;
      pad = dec_data[enc_size-1];
      if (pad < 1 || pad > 8) goto LBL_ERROR;
      *dec_size = enc_size - pad;
      return CRYPT_OK;
   }

LBL_ERROR:
   zeromem(k, sizeof(k));
   return CRYPT_INVALID_ARG;
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
         unsigned char *enc_data = l->child->next->data;
         unsigned long enc_size = l->child->next->size;
         dec_size = enc_size;
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
            unsigned long iter = mp_get_int(lalgparam->child->next->data);
            unsigned long salt_size = lalgparam->child->size;
            unsigned char *salt = lalgparam->child->data;
            err = _pbes1_decrypt(enc_data, enc_size, pwd, pwdlen, salt, salt_size, iter, lalgoid->data, lalgoid->size, dec_data, &dec_size);
            if (err != CRYPT_OK) goto LBL_DONE;
         }
         else if (PBES2 == _oid_to_id(lalgoid->data, lalgoid->size) &&
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
            int kdfid = _oid_to_id(lkdf->data, lkdf->size);
            int encid = _oid_to_id(lenc->data, lenc->size);
            if (PBKDF2 == kdfid &&
                LTC_ASN1_IS_TYPE(lkdf->next, LTC_ASN1_SEQUENCE) &&
                LTC_ASN1_IS_TYPE(lkdf->next->child, LTC_ASN1_OCTET_STRING) &&
                LTC_ASN1_IS_TYPE(lkdf->next->child->next, LTC_ASN1_INTEGER)) {
               unsigned long iter = mp_get_int(lkdf->next->child->next->data);
               unsigned long salt_size = lkdf->next->child->size;
               unsigned char *salt = lkdf->next->child->data;
               unsigned char *iv = NULL;
               unsigned long iv_size = 0;
               unsigned long arg = 0;
               ltc_asn1_list *loptseq = lkdf->next->child->next->next;
               int hmacid = HMAC_WITH_SHA1; /* this is default */
               if (LTC_ASN1_IS_TYPE(loptseq, LTC_ASN1_SEQUENCE) &&
                   LTC_ASN1_IS_TYPE(loptseq->child, LTC_ASN1_OBJECT_IDENTIFIER)) {
                  /* this sequence is optional */
                  hmacid = _oid_to_id(loptseq->child->data, loptseq->child->size);
               }
               if (LTC_ASN1_IS_TYPE(lenc->next, LTC_ASN1_OCTET_STRING)) {
                  /* DES-CBC + DES_EDE3_CBC */
                  iv = lenc->next->data;
                  iv_size = lenc->next->size;
               }
               else if (LTC_ASN1_IS_TYPE(lenc->next, LTC_ASN1_SEQUENCE) &&
                        LTC_ASN1_IS_TYPE(lenc->next->child, LTC_ASN1_INTEGER) &&
                        LTC_ASN1_IS_TYPE(lenc->next->child->next, LTC_ASN1_OCTET_STRING)) {
                  /* RC2-CBC is a bit special */
                  iv = lenc->next->child->next->data;
                  iv_size = lenc->next->child->next->size;
                  arg = mp_get_int(lenc->next->child->data);
               }
               err = _pbes2_pbkdf2_decrypt(enc_data, enc_size, pwd, pwdlen, salt, salt_size, iv, iv_size, iter, hmacid, encid, arg, dec_data, &dec_size);
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
   }

LBL_DONE:
   if (dec_data) XFREE(dec_data);
   return err;
}

/* NOTE: _der_decode_pkcs8_flexi & related stuff can be shared with rsa_import_pkcs8() */

int ecc_import_pkcs8(const unsigned char *in, unsigned long inlen,
                     const void *pwd, unsigned long pwdlen,
                     ecc_key *key)
{
   void          *a, *b, *gx, *gy;
   unsigned long len, cofactor;
   oid_st        ecoid;
   int           err;
   char          OID[256];
   const ltc_ecc_curve *curve;
   ltc_asn1_list *p = NULL, *l = NULL;

   LTC_ARGCHK(in          != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* get EC alg oid */
   err = pk_get_oid(PKA_EC, &ecoid);
   if (err != CRYPT_OK) return err;

   /* init key */
   err = mp_init_multi(&a, &b, &gx, &gy, NULL);
   if (err != CRYPT_OK) return err;

   if ((err = _der_decode_pkcs8_flexi(in, inlen, pwd, pwdlen, &l)) == CRYPT_OK) {
      if (l->type == LTC_ASN1_SEQUENCE &&
          LTC_ASN1_IS_TYPE(l->child, LTC_ASN1_INTEGER) &&
          LTC_ASN1_IS_TYPE(l->child->next, LTC_ASN1_SEQUENCE) &&
          LTC_ASN1_IS_TYPE(l->child->next->child, LTC_ASN1_OBJECT_IDENTIFIER) &&
          LTC_ASN1_IS_TYPE(l->child->next->next, LTC_ASN1_OCTET_STRING)) {
         ltc_asn1_list *lseq = l->child->next;
         ltc_asn1_list *lpri = l->child->next->next;
         ltc_asn1_list *lecoid = l->child->next->child;

         if ((lecoid->size != ecoid.OIDlen) ||
            XMEMCMP(ecoid.OID, lecoid->data, ecoid.OIDlen * sizeof(ecoid.OID[0]))) {
            err = CRYPT_PK_INVALID_TYPE;
            goto LBL_DONE;
         }

         if (LTC_ASN1_IS_TYPE(lseq->child->next, LTC_ASN1_OBJECT_IDENTIFIER)) {
            /* CASE 1: curve by OID (AKA short variant):
             *  0:d=0  hl=2 l= 100 cons: SEQUENCE
             *  2:d=1  hl=2 l=   1 prim:   INTEGER        :00
             *  5:d=1  hl=2 l=  16 cons:   SEQUENCE       (== *lseq)
             *  7:d=2  hl=2 l=   7 prim:     OBJECT       :id-ecPublicKey
             * 16:d=2  hl=2 l=   5 prim:     OBJECT       :secp256k1 (== 1.3.132.0.10)
             * 23:d=1  hl=2 l=  77 prim:   OCTET STRING   :bytes (== privatekey)
             */
            ltc_asn1_list *loid = lseq->child->next;
            len = sizeof(OID);
            if ((err = pk_oid_num_to_str(loid->data, loid->size, OID, &len)) != CRYPT_OK) { goto LBL_DONE; }
            if ((err = ecc_get_curve(OID, &curve)) != CRYPT_OK)                           { goto LBL_DONE; }
            if ((err = ecc_set_dp(curve, key)) != CRYPT_OK)                               { goto LBL_DONE; }
         }
         else if (LTC_ASN1_IS_TYPE(lseq->child->next, LTC_ASN1_SEQUENCE)) {
            /* CASE 2: explicit curve parameters (AKA long variant):
             *   0:d=0  hl=3 l= 227 cons: SEQUENCE
             *   3:d=1  hl=2 l=   1 prim:   INTEGER              :00
             *   6:d=1  hl=3 l= 142 cons:   SEQUENCE             (== *lseq)
             *   9:d=2  hl=2 l=   7 prim:     OBJECT             :id-ecPublicKey
             *  18:d=2  hl=3 l= 130 cons:     SEQUENCE           (== *lcurve)
             *  21:d=3  hl=2 l=   1 prim:       INTEGER          :01
             *  24:d=3  hl=2 l=  44 cons:       SEQUENCE         (== *lfield)
             *  26:d=4  hl=2 l=   7 prim:         OBJECT         :prime-field
             *  35:d=4  hl=2 l=  33 prim:         INTEGER        :(== curve.prime)
             *  70:d=3  hl=2 l=   6 cons:       SEQUENCE         (== *lpoint)
             *  72:d=4  hl=2 l=   1 prim:         OCTET STRING   :bytes (== curve.A)
             *  75:d=4  hl=2 l=   1 prim:         OCTET STRING   :bytes (== curve.B)
             *  78:d=3  hl=2 l=  33 prim:       OCTET STRING     :bytes (== curve.G-point)
             * 113:d=3  hl=2 l=  33 prim:       INTEGER          :(== curve.order)
             * 148:d=3  hl=2 l=   1 prim:       INTEGER          :(== curve.cofactor)
             * 151:d=1  hl=2 l=  77 prim:   OCTET STRING         :bytes (== privatekey)
             */
            ltc_asn1_list *lcurve = lseq->child->next;

            if (LTC_ASN1_IS_TYPE(lcurve->child, LTC_ASN1_INTEGER) &&
                LTC_ASN1_IS_TYPE(lcurve->child->next, LTC_ASN1_SEQUENCE) &&
                LTC_ASN1_IS_TYPE(lcurve->child->next->next, LTC_ASN1_SEQUENCE) &&
                LTC_ASN1_IS_TYPE(lcurve->child->next->next->next, LTC_ASN1_OCTET_STRING) &&
                LTC_ASN1_IS_TYPE(lcurve->child->next->next->next->next, LTC_ASN1_INTEGER) &&
                LTC_ASN1_IS_TYPE(lcurve->child->next->next->next->next->next, LTC_ASN1_INTEGER)) {

               ltc_asn1_list *lfield = lcurve->child->next;
               ltc_asn1_list *lpoint = lcurve->child->next->next;
               ltc_asn1_list *lg     = lcurve->child->next->next->next;
               ltc_asn1_list *lorder = lcurve->child->next->next->next->next;
               cofactor = mp_get_int(lcurve->child->next->next->next->next->next->data);

               if (LTC_ASN1_IS_TYPE(lfield->child, LTC_ASN1_OBJECT_IDENTIFIER) &&
                   LTC_ASN1_IS_TYPE(lfield->child->next, LTC_ASN1_INTEGER) &&
                   LTC_ASN1_IS_TYPE(lpoint->child, LTC_ASN1_OCTET_STRING) &&
                   LTC_ASN1_IS_TYPE(lpoint->child->next, LTC_ASN1_OCTET_STRING)) {

                  ltc_asn1_list *lprime = lfield->child->next;
                  if ((err = mp_read_unsigned_bin(a, lpoint->child->data, lpoint->child->size)) != CRYPT_OK) {
                     goto LBL_DONE;
                  }
                  if ((err = mp_read_unsigned_bin(b, lpoint->child->next->data, lpoint->child->next->size)) != CRYPT_OK) {
                     goto LBL_DONE;
                  }
                  if ((err = ltc_ecc_import_point(lg->data, lg->size, lprime->data, a, b, gx, gy)) != CRYPT_OK) {
                     goto LBL_DONE;
                  }
                  if ((err = ecc_set_dp_from_mpis(a, b, lprime->data, lorder->data, gx, gy, cofactor, key)) != CRYPT_OK) {
                     goto LBL_DONE;
                  }
               }
            }
         }
         else {
            err = CRYPT_INVALID_PACKET;
            goto LBL_DONE;
         }

         /* load private key value 'k' */
         len = lpri->size;
         if ((err = der_decode_sequence_flexi(lpri->data, &len, &p)) == CRYPT_OK) {
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
