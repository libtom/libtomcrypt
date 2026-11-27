/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file siv.c
  RFC 5297  SIV - Synthetic Initialization Vector, Steffen Jaeckel
*/

#ifdef LTC_SIV_MODE

/* RFC 5297 - Chapter 7 - Security Considerations
 *
 * [...] S2V must not be
 * passed more than 127 components.  Since SIV includes the plaintext as
 * a component to S2V, that limits the number of components of
 * associated data that can be safely passed to SIV to 126.
 */
static const unsigned long s_siv_max_aad_components = 126;

LTC_ALIGN_MSVC(16)
typedef struct siv_buf_t {
   union {
#ifdef LTC_FAST
      LTC_FAST_TYPE word[16/sizeof(LTC_FAST_TYPE)];
#endif
      unsigned char byte[16];
   } u;
} siv_buf_t LTC_ALIGN(16);

LTC_STATIC_ASSERT(size_of_siv_buf_t_is_16_bytes, sizeof(siv_buf_t) == 16);

static LTC_INLINE void s_siv_dbl(siv_buf_t *D_)
{
   unsigned char *D = D_->u.byte;
   unsigned int y, mask, msb, len;

   /* setup the system */
   mask = 0x87;
   len = 16;

   /* if msb(L * u^(x+1)) = 0 then just shift, otherwise shift and xor constant mask */
   msb = D[0] >> 7;

   /* shift left */
   for (y = 0; y < (len - 1); y++) {
      D[y] = ((D[y] << 1) | (D[y + 1] >> 7)) & 255;
   }
   D[len - 1] = ((D[len - 1] << 1) ^ (msb ? mask : 0)) & 255;
}

typedef struct siv_omac_ctx_t {
   omac_state omac;
   int cipher;
} siv_omac_ctx_t;

static LTC_INLINE void s_siv_xor_buf(const siv_buf_t *a, siv_buf_t *b)
{
   unsigned int n;
#ifdef LTC_FAST
#ifdef ENDIAN_64BITWORD
   LTC_UNUSED_PARAM(n);
   b->u.word[0] ^= a->u.word[0];
   b->u.word[1] ^= a->u.word[1];
#else
   for (n = 0; n < LTC_ARRAY_SIZE(a->u.word); ++n) {
      b->u.word[n] ^= a->u.word[n];
   }
#endif
#else
   for (n = 0; n < LTC_ARRAY_SIZE(a->u.byte); ++n) {
      b->u.byte[n] ^= a->u.byte[n];
   }
#endif
}

static LTC_INLINE int s_siv_ctx_init(int cipher,
                     const unsigned char *key,    unsigned long keylen,
                          siv_omac_ctx_t *ctx)
{
   ctx->cipher = cipher;
   return omac_init(&ctx->omac, cipher, key, keylen);
}

static LTC_INLINE int s_siv_omac_memory(siv_omac_ctx_t *ctx,
                                   const unsigned char *in,  unsigned long inlen,
                                             siv_buf_t *out)
{
   int err;
   unsigned long len = sizeof(*out);
   omac_state omac = ctx->omac;
   if ((err = omac_process(&omac, in, inlen)) != CRYPT_OK) {
      return err;
   }
   err = omac_done(&omac, out->u.byte, &len);
   zeromem(&omac, sizeof(omac));
   return err;
}

static LTC_INLINE int s_siv_S2V_zero(siv_omac_ctx_t *ctx, siv_buf_t *D)
{
   /* D = AES-CMAC(K, <zero>) */
   const siv_buf_t zero = {0};
   return s_siv_omac_memory(ctx, zero.u.byte, sizeof(zero), D);
}

static LTC_INLINE int s_siv_S2V_dbl_xor_cmac(siv_omac_ctx_t *ctx,
                                        const unsigned char *aad, unsigned long aadlen,
                                                  siv_buf_t *D)
{
   /* for i = 1 to n-1 do
    *   D = dbl(D) xor AES-CMAC(K, Si)
    * done
    */
   int err;
   siv_buf_t TMP;
   if ((err = s_siv_omac_memory(ctx, aad, aadlen, &TMP)) != CRYPT_OK) {
      return err;
   }
   s_siv_dbl(D);
   s_siv_xor_buf(&TMP, D);
   return err;
}

static LTC_INLINE int s_siv_omac_memory_multi(siv_omac_ctx_t *ctx,
                                                   siv_buf_t *out,
                                         const unsigned char *in,  unsigned long inlen,
                                                              ...)
{
   int err;
   va_list args;
   unsigned long len = sizeof(*out);
   omac_state omac = ctx->omac;
   va_start(args, inlen);

   if ((err = omac_vprocess(&omac, in, inlen, args)) != CRYPT_OK) {
      return err;
   }
   err = omac_done(&omac, out->u.byte, &len);
   zeromem(&omac, sizeof(omac));
   return err;
}

static LTC_INLINE int s_siv_S2V_T(siv_omac_ctx_t *ctx,
                             const unsigned char *in,  unsigned long inlen,
                                       siv_buf_t *D,       siv_buf_t *V)
{
   siv_buf_t T;
   int err;

   /* if len(Sn) >= 128 then
    *   T = Sn xorend D
    * else
    *   T = dbl(D) xor pad(Sn)
    * fi
    */
   if (inlen >= 16) {
      XMEMCPY(&T, &in[inlen - 16], 16);
      s_siv_xor_buf(D, &T);
      err = s_siv_omac_memory_multi(ctx, V, in, inlen - 16, &T, sizeof(T), LTC_NULL);
   } else {
      s_siv_dbl(D);
      XMEMSET(&T, 0, sizeof(T));
      if (inlen != 0) XMEMCPY(&T, in, inlen);
      T.u.byte[inlen] = 0x80;
      s_siv_xor_buf(D, &T);

      err = s_siv_omac_memory(ctx, T.u.byte, sizeof(T), V);
   }
   return err;
}

static int s_siv_S2V(int cipher,
    const unsigned char *key,    unsigned long keylen,
          unsigned long  adnum,
    const unsigned char **ad,    unsigned long *adlen,
    const unsigned char *in,     unsigned long inlen,
              siv_buf_t *V)
{
   int err;
   siv_buf_t D;
   unsigned long n = 0;
   siv_omac_ctx_t ctx;

   if ((err = s_siv_ctx_init(cipher, key, keylen, &ctx)) != CRYPT_OK) {
      return err;
   }
   /* RFC 5297 sec 2.6: S2V(K1, AD1..ADm, P). With zero ADs this is n=1
    * (P only), not n=0 - the plaintext must still be folded into V. */
   if ((err = s_siv_S2V_zero(&ctx, &D)) != CRYPT_OK) {
      return err;
   }

   /* With zero AD components the loop runs zero times. */
   while (n < adnum) {
      if (n >= s_siv_max_aad_components) {
         return CRYPT_INPUT_TOO_LONG;
      }
      if ((err = s_siv_S2V_dbl_xor_cmac(&ctx, ad ? ad[n] : NULL, adlen ? adlen[n] : 0, &D)) != CRYPT_OK) {
         return err;
      }
      n++;
   }

   return s_siv_S2V_T(&ctx, in, inlen, &D, V);
}

static LTC_INLINE void s_siv_bitand(const void* V, siv_buf_t* Q)
{
   XMEMCPY(Q, V, sizeof(*Q));
   Q->u.byte[8] &= 0x7F;
   Q->u.byte[12] &= 0x7F;
}

static LTC_INLINE int s_ctr_crypt_memory(int   cipher,
                          const unsigned char *IV,
                          const unsigned char *key,           int keylen,
                          const unsigned char *in,
                                unsigned char *out, unsigned long len)
{
   int err;
   symmetric_CTR ctr;

   if ((err = ctr_start(cipher, IV, key, keylen, 0, CTR_COUNTER_BIG_ENDIAN | 16, &ctr)) != CRYPT_OK) {
      goto out;
   }
   if ((err = ctr_encrypt(in, out, len, &ctr)) != CRYPT_OK) {
      goto out;
   }
   if ((err = ctr_done(&ctr)) != CRYPT_OK) {
      goto out;
   }

out:
#ifdef LTC_CLEAN_STACK
   zeromem(&ctr, sizeof(ctr));
#endif
   return err;
}

typedef struct {
   siv_buf_t Q, V;
} siv_state;

/**
   SIV encrypt

   @param cipher     The index of the cipher desired
   @param key        The secret key to use
   @param keylen     The length of the secret key (octets)
   @param ad         An array of Associated Data pointers (must be NULL terminated)
   @param adlen      An array with the lengths of the Associated Data
   @param pt         The plaintext
   @param ptlen      The length of the plaintext
   @param ct         The ciphertext
   @param ctlen      [in/out] The length of the ciphertext
   @return CRYPT_OK if successful
*/
int siv_encrypt_memory(                int  cipher,
                       const unsigned char *key,    unsigned long  keylen,
                             unsigned long adnum,
                       const unsigned char *ad[],   unsigned long  adlen[],
                       const unsigned char *pt,     unsigned long  ptlen,
                             unsigned char *ct,     unsigned long *ctlen)
{
   int err;
   const unsigned char *K1, *K2;
   void *work = NULL;
   siv_state siv;

   LTC_ARGCHK(key    != NULL);
   LTC_ARGCHK(ad     != NULL || adnum == 0);
   LTC_ARGCHK(adlen  != NULL || adnum == 0);
   LTC_ARGCHK(pt     != NULL || ptlen == 0);
   LTC_ARGCHK(ct     != NULL);
   LTC_ARGCHK(ctlen  != NULL);

   if (ptlen + 16 < ptlen) {
      return CRYPT_OVERFLOW;
   }
   if (*ctlen < ptlen + 16) {
      *ctlen = ptlen + 16;
      return CRYPT_BUFFER_OVERFLOW;
   }
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }

   work = XMALLOC(ptlen + 16);
   if (work == NULL) {
      return CRYPT_MEM;
   }

   K1 = key;
   K2 = &key[keylen/2];

   if ((err = s_siv_S2V(cipher, K1, keylen/2, adnum, ad, adlen, pt, ptlen, &siv.V)) != CRYPT_OK) {
      goto out;
   }

   s_siv_bitand(&siv.V, &siv.Q);

   if ((err = s_ctr_crypt_memory(cipher, siv.Q.u.byte, K2, keylen/2, pt, work, ptlen)) != CRYPT_OK) {
      goto out;
   }
   XMEMCPY(ct, &siv.V, 16);
   XMEMCPY(ct + 16, work, ptlen);
   *ctlen = ptlen + 16;

out:
#ifdef LTC_CLEAN_STACK
   zeromem(&siv, sizeof(siv));
#endif
   zeromem(work, ptlen + 16);
   XFREE(work);

   return err;
}

/**
   SIV decrypt

   @param cipher     The index of the cipher desired
   @param key        The secret key to use
   @param keylen     The length of the secret key (octets)
   @param ad         An array of Associated Data pointers (must be NULL terminated)
   @param adlen      An array with the lengths of the Associated Data
   @param ct         The ciphertext
   @param ctlen      The length of the ciphertext
   @param pt         The plaintext
   @param ptlen      [in/out] The length of the plaintext
   @return CRYPT_OK if successful
*/
int siv_decrypt_memory(                int  cipher,
                       const unsigned char *key,    unsigned long  keylen,
                             unsigned long adnum,
                       const unsigned char *ad[],   unsigned long  adlen[],
                       const unsigned char *ct,     unsigned long  ctlen,
                             unsigned char *pt,     unsigned long *ptlen)
{
   int err;
   unsigned char *pt_work;
   const unsigned char *K1, *K2, *ct_work;
   siv_state siv;

   LTC_ARGCHK(key    != NULL);
   LTC_ARGCHK(ad     != NULL || adnum == 0);
   LTC_ARGCHK(adlen  != NULL || adnum == 0);
   LTC_ARGCHK(ct     != NULL);
   LTC_ARGCHK(pt     != NULL);
   LTC_ARGCHK(ptlen  != NULL);

   if (ctlen < 16) {
      return CRYPT_INVALID_ARG;
   }
   if (*ptlen < (ctlen - 16)) {
      *ptlen = ctlen - 16;
      return CRYPT_BUFFER_OVERFLOW;
   }

   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }
   *ptlen = ctlen - 16;
   pt_work = XMALLOC(*ptlen ? *ptlen : 1); /* XMALLOC(0) may return NULL */
   if (pt_work == NULL) {
      return CRYPT_MEM;
   }

   K1 = key;
   K2 = &key[keylen/2];

   ct_work = ct;
   s_siv_bitand(ct_work, &siv.Q);
   ct_work += 16;

   if ((err = s_ctr_crypt_memory(cipher, siv.Q.u.byte, K2, keylen/2, ct_work, pt_work, *ptlen)) != CRYPT_OK) {
      goto out;
   }
   if ((err = s_siv_S2V(cipher, K1, keylen/2, adnum, ad, adlen, pt_work, *ptlen, &siv.V)) != CRYPT_OK) {
      goto out;
   }

   err = XMEM_NEQ(&siv.V, ct, sizeof(siv.V));
   copy_or_zeromem(pt_work, pt, *ptlen, err);
out:
#ifdef LTC_CLEAN_STACK
   zeromem(&siv, sizeof(siv));
#endif
   zeromem(pt_work, *ptlen);
   XFREE(pt_work);

   return err;
}

/**
  Process an entire SIV packet in one call.

  @param cipher            The index of the cipher desired
  @param direction         Encrypt or Decrypt mode (LTC_ENCRYPT or LTC_DECRYPT)
  @param key               The secret key to use
  @param keylen            The length of the secret key (octets)
  @param in                The input
  @param inlen             The length of the input
  @param out               The output
  @param outlen            [in/out]  The max size and resulting size of the output
  @remark <...> is of the form <pointer, length> (void*, unsigned long) and contains the Associated Data
  @return CRYPT_OK on success
 */
int siv_memory(                int  cipher,           int  direction,
               const unsigned char *key,    unsigned long  keylen,
               const unsigned char *in,     unsigned long  inlen,
                     unsigned char *out,    unsigned long *outlen,
                     unsigned long adnum,
                                   ...)
{
   int err;
   va_list args;
   siv_omac_ctx_t ctx;
   siv_state siv;
   siv_buf_t D;
   unsigned char *buf = NULL;
   const unsigned char *aad, *K1, *K2, *in_work;
   unsigned long n = 0, aadlen, in_work_len, buf_len;

   LTC_ARGCHK(key    != NULL);
   LTC_ARGCHK(in     != NULL || inlen == 0);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }
   if (direction == LTC_ENCRYPT && *outlen < inlen + 16) {
      *outlen = inlen + 16;
      return CRYPT_BUFFER_OVERFLOW;
   } else if (direction == LTC_DECRYPT && (inlen < 16 || *outlen < inlen - 16)) {
      *outlen = inlen - 16;
      return CRYPT_BUFFER_OVERFLOW;
   }

   K1 = key;
   K2 = &key[keylen/2];
   in_work = in;
   in_work_len = inlen;

   if (direction == LTC_DECRYPT) {
      in_work_len -= 16;
      buf_len = in_work_len;
   } else {
      buf_len = inlen;
   }
   buf = XMALLOC(buf_len ? buf_len : 1); /* XMALLOC(0) may return NULL */
   if (buf == NULL)
      return CRYPT_MEM;

   if (direction == LTC_DECRYPT) {
      s_siv_bitand(in_work, &siv.Q);
      in_work += 16;

      if ((err = s_ctr_crypt_memory(cipher, siv.Q.u.byte, K2, keylen/2, in_work, buf, in_work_len)) != CRYPT_OK) {
         goto err_out;
      }
      in_work = buf;
   }

   if ((err = s_siv_ctx_init(cipher, K1, keylen/2, &ctx)) != CRYPT_OK) {
      goto err_out;
   }
   if ((err = s_siv_S2V_zero(&ctx, &D)) != CRYPT_OK) {
      goto err_out;
   }
   va_start(args, adnum);
   /* With zero AD components the loop runs zero times. */
   while (n < adnum) {
      if (n >= s_siv_max_aad_components) {
         err = CRYPT_INPUT_TOO_LONG;
         goto err_out2;
      }
      aad = va_arg(args, const unsigned char*);
      aadlen = va_arg(args, unsigned long);
      if ((err = s_siv_S2V_dbl_xor_cmac(&ctx, aad, aadlen, &D)) != CRYPT_OK) {
         goto err_out2;
      }
      n++;
   }

   if ((err = s_siv_S2V_T(&ctx, in_work, in_work_len, &D, &siv.V)) != CRYPT_OK) {
      goto err_out2;
   }

   if (direction == LTC_DECRYPT) {
      err = XMEM_NEQ(&siv.V, in, sizeof(siv.V));
      copy_or_zeromem(in_work, out, in_work_len, err);
      *outlen = in_work_len;
   } else {
      s_siv_bitand(&siv.V, &siv.Q);

      if ((err = s_ctr_crypt_memory(cipher, siv.Q.u.byte, K2, keylen/2, in_work, buf, inlen)) != CRYPT_OK) {
         goto err_out2;
      }
      XMEMCPY(out, &siv.V, 16);
      XMEMCPY(out + 16, buf, inlen);
      *outlen = inlen + 16;
   }
err_out2:
   va_end(args);
err_out:
#ifdef LTC_CLEAN_STACK
   zeromem(&ctx, sizeof(ctx));
   zeromem(&siv, sizeof(siv));
   zeromem(&D, sizeof(D));
#endif
   zeromem(buf, in_work_len);
   XFREE(buf);
   return err;
}

int siv_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   /*
    * RFC5297 - A.1.  Deterministic Authenticated Encryption Example
    */
   const unsigned char Key_A1[] =
      { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
   const unsigned char AD_A1[] =
      { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 };
   const unsigned char Plaintext_A1[] =
      { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
   const unsigned char output_A1[] =
      { 0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f,
        0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93,
        0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04,
        0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c };
   const unsigned char *ad_A1[] =
      { AD_A1, NULL };
   unsigned long adlen_A1[] =
      { sizeof(AD_A1), 0 };

   const unsigned char Key_A2[] =
      { 0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78,
        0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f };
   const unsigned char AD1_A2[] =
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xde, 0xad, 0xda, 0xda, 0xde, 0xad, 0xda, 0xda,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
   const unsigned char AD2_A2[] =
      { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0 };
   const unsigned char AD3_A2[] =
      { 0x09, 0xf9, 0x11, 0x02, 0x9d, 0x74, 0xe3, 0x5b,
        0xd8, 0x41, 0x56, 0xc5, 0x63, 0x56, 0x88, 0xc0 };
   const unsigned char Plaintext_A2[] =
      { 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x73, 0x6f, 0x6d, 0x65, 0x20, 0x70, 0x6c, 0x61,
        0x69, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x20, 0x74,
        0x6f, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70,
        0x74, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20,
        0x53, 0x49, 0x56, 0x2d, 0x41, 0x45, 0x53 };
   const unsigned char output_A2[] =
      { 0x7b, 0xdb, 0x6e, 0x3b, 0x43, 0x26, 0x67, 0xeb,
        0x06, 0xf4, 0xd1, 0x4b, 0xff, 0x2f, 0xbd, 0x0f,
        0xcb, 0x90, 0x0f, 0x2f, 0xdd, 0xbe, 0x40, 0x43,
        0x26, 0x60, 0x19, 0x65, 0xc8, 0x89, 0xbf, 0x17,
        0xdb, 0xa7, 0x7c, 0xeb, 0x09, 0x4f, 0xa6, 0x63,
        0xb7, 0xa3, 0xf7, 0x48, 0xba, 0x8a, 0xf8, 0x29,
        0xea, 0x64, 0xad, 0x54, 0x4a, 0x27, 0x2e, 0x9c,
        0x48, 0x5b, 0x62, 0xa3, 0xfd, 0x5c, 0x0d };
   const unsigned char *ad_A2[] =
      { AD1_A2, AD2_A2, AD3_A2, NULL };
   unsigned long adlen_A2[] =
      { sizeof(AD1_A2), sizeof(AD2_A2), sizeof(AD3_A2), 0 };
   const unsigned char *ad_ossl0[] =
      { AD1_A2, NULL, AD3_A2, NULL };
   unsigned long adlen_ossl0[] =
      { sizeof(AD1_A2), 0, sizeof(AD3_A2), 0 };
   const unsigned char output_ossl0[] =
      { 0x83, 0xce, 0x65, 0x93, 0xa8, 0xfa, 0x67, 0xeb,
        0x6f, 0xcd, 0x28, 0x19, 0xce, 0xdf, 0xc0, 0x11,
        0x30, 0xd9, 0x37, 0xb4, 0x2f, 0x71, 0xf7, 0x1f,
        0x93, 0xfc, 0x2d, 0x8d, 0x70, 0x2d, 0x3e, 0xac,
        0x8d, 0xc7, 0x65, 0x1e, 0xef, 0xcd, 0x81, 0x12,
        0x00, 0x81, 0xff, 0x29, 0xd6, 0x26, 0xf9, 0x7f,
        0x3d, 0xe1, 0x7f, 0x29, 0x69, 0xb6, 0x91, 0xc9,
        0x1b, 0x69, 0xb6, 0x52, 0xbf, 0x3a, 0x6d };
   const unsigned char *ad_ossl1[] =
      { NULL, AD1_A2, AD3_A2, NULL };
   unsigned long adlen_ossl1[] =
      { 0, sizeof(AD1_A2), sizeof(AD3_A2), 0 };
   const unsigned char output_ossl1[] =
      { 0x77, 0xdd, 0x4a, 0x44, 0xf5, 0xa6, 0xb4, 0x13,
        0x02, 0x12, 0x1e, 0xe7, 0xf3, 0x78, 0xde, 0x25,
        0x0f, 0xcd, 0x66, 0x4c, 0x92, 0x24, 0x64, 0xc8,
        0x89, 0x39, 0xd7, 0x1f, 0xad, 0x7a, 0xef, 0xb8,
        0x64, 0xe5, 0x01, 0xb0, 0x84, 0x8a, 0x07, 0xd3,
        0x92, 0x01, 0xc1, 0x06, 0x7a, 0x72, 0x88, 0xf3,
        0xda, 0xdf, 0x01, 0x31, 0xa8, 0x23, 0xa0, 0xbc,
        0x3d, 0x58, 0x8e, 0x85, 0x64, 0xa5, 0xfe };


   /* Zero AD components vs. a single *empty* AD component (vectors were cross-checked against OpenSSL 3.5.6) */
   const unsigned char output_A1_zeroad[] =
      { 0xf1, 0xc5, 0xfd, 0xea, 0xc1, 0xf1, 0x5a, 0x26,
        0x77, 0x9c, 0x15, 0x01, 0xf9, 0xfb, 0x75, 0x88,
        0x27, 0xe9, 0x46, 0xc6, 0x69, 0x08, 0x8a, 0xb0,
        0x6d, 0xa5, 0x8c, 0x5c, 0x83, 0x1c };
   const unsigned char output_A1_emptyad[] =
      { 0xd1, 0x02, 0x2f, 0x5b, 0x36, 0x64, 0xe5, 0xa4,
        0xdf, 0xaf, 0x90, 0xf8, 0x5b, 0xe6, 0xf2, 0x8a,
        0xb6, 0x6c, 0xff, 0x6b, 0x8e, 0xca, 0x0b, 0x79,
        0xf0, 0x83, 0xb3, 0x9a, 0x09, 0x01 };
   const unsigned char *ad_emptyad[] = { NULL, NULL };
   unsigned long adlen_emptyad[] = { 0, 0 };

#define PL_PAIR(n) n, sizeof(n)
   struct {
      const unsigned char* Key;
            unsigned long  Keylen;
      const unsigned char* Plaintext;
            unsigned long  Plaintextlen;
            unsigned long  ADnum;
      const          void* ADs;
                     void* ADlens;
      const unsigned char* output;
            unsigned long  outputlen;
      const          char* name;
   } siv_tests[] = {
     { PL_PAIR(Key_A1), PL_PAIR(Plaintext_A1), 1, &ad_A1, &adlen_A1, PL_PAIR(output_A1), "RFC5297 - A.1.  Deterministic Authenticated Encryption Example" },
     { PL_PAIR(Key_A2), PL_PAIR(Plaintext_A2), 3, &ad_A2, &adlen_A2, PL_PAIR(output_A2), "RFC5297 - A.2.  Nonce-Based Authenticated Encryption Example" },
     { PL_PAIR(Key_A2), PL_PAIR(Plaintext_A2), 3, &ad_ossl0, &adlen_ossl0, PL_PAIR(output_ossl0), "OpenSSL based example 0" },
     { PL_PAIR(Key_A2), PL_PAIR(Plaintext_A2), 3, &ad_ossl1, &adlen_ossl1, PL_PAIR(output_ossl1), "OpenSSL based example 1" },
     { PL_PAIR(Key_A1), PL_PAIR(Plaintext_A1), 0, NULL, NULL, PL_PAIR(output_A1_zeroad), "Zero AD components (ad = adlen = NULL)" },
     { PL_PAIR(Key_A1), PL_PAIR(Plaintext_A1), 1, &ad_emptyad, &adlen_emptyad, PL_PAIR(output_A1_emptyad), "One empty AD component" },
   };
#undef PL_PAIR

   int err, cipher;
   unsigned n;
   unsigned long buflen, tmplen;
   unsigned char buf[MAX(sizeof(output_A1), sizeof(output_A2))];
   const unsigned long niter = 1000;
   unsigned char *tmp[3] = {0};
   const unsigned long tmpmax = 16 + niter * 16;

   cipher = find_cipher("aes");

   for (n = 0; n < LTC_ARRAY_SIZE(siv_tests); ++n) {
      buflen = sizeof(buf);
      if ((err = siv_encrypt_memory(cipher,
                             siv_tests[n].Key, siv_tests[n].Keylen,
                             siv_tests[n].ADnum,
                             (const unsigned char **)siv_tests[n].ADs, siv_tests[n].ADlens,
                             siv_tests[n].Plaintext, siv_tests[n].Plaintextlen,
                             buf, &buflen)) != CRYPT_OK) {
         return err;
      }
      if (ltc_compare_testvector(buf, buflen, siv_tests[n].output, siv_tests[n].outputlen, siv_tests[n].name, n) != 0) {
         return CRYPT_FAIL_TESTVECTOR;
      }
      buflen = sizeof(buf);
      if ((err = siv_decrypt_memory(cipher,
                             siv_tests[n].Key, siv_tests[n].Keylen,
                             siv_tests[n].ADnum,
                             (const unsigned char **)siv_tests[n].ADs, siv_tests[n].ADlens,
                             siv_tests[n].output, siv_tests[n].outputlen,
                             buf, &buflen)) != CRYPT_OK) {
         return err;
      }
      if (ltc_compare_testvector(buf, buflen, siv_tests[n].Plaintext, siv_tests[n].Plaintextlen, siv_tests[n].name, n + 0x1000) != 0) {
         return CRYPT_FAIL_TESTVECTOR;
      }
   }

   /* Testcase 0x2 */
   buflen = sizeof(buf);
   if ((err = siv_memory(cipher, LTC_ENCRYPT,
                         siv_tests[0].Key, siv_tests[0].Keylen,
                         siv_tests[0].Plaintext, siv_tests[0].Plaintextlen,
                         buf, &buflen,
                         1,
                         AD_A1, sizeof(AD_A1),
                         NULL)) != CRYPT_OK) {
      return err;
   }
   if (ltc_compare_testvector(buf, buflen, siv_tests[0].output, siv_tests[0].outputlen, siv_tests[0].name, n) != 0) {
      return CRYPT_FAIL_TESTVECTOR;
   }
   /* Testcase 0x1002 */
   buflen = sizeof(buf);
   if ((err = siv_memory(cipher, LTC_DECRYPT,
                         siv_tests[0].Key, siv_tests[0].Keylen,
                         siv_tests[0].output, siv_tests[0].outputlen,
                         buf, &buflen,
                         1,
                         AD_A1, sizeof(AD_A1),
                         NULL)) != CRYPT_OK) {
      return err;
   }
   if (ltc_compare_testvector(buf, buflen, siv_tests[0].Plaintext, siv_tests[0].Plaintextlen, siv_tests[0].name, n + 0x1000) != 0) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   n++;

   /* Testcase 0x3 */
   buflen = sizeof(buf);
   if ((err = siv_memory(cipher, LTC_ENCRYPT,
                         siv_tests[1].Key, siv_tests[1].Keylen,
                         siv_tests[1].Plaintext, siv_tests[1].Plaintextlen,
                         buf, &buflen,
                         3,
                         ad_A2[0], adlen_A2[0],
                         ad_A2[1], adlen_A2[1],
                         ad_A2[2], adlen_A2[2],
                         NULL)) != CRYPT_OK) {
      return err;
   }
   if (ltc_compare_testvector(buf, buflen, siv_tests[1].output, siv_tests[1].outputlen, siv_tests[1].name, n) != 0) {
      return CRYPT_FAIL_TESTVECTOR;
   }
   /* Testcase 0x1003 */
   buflen = sizeof(buf);
   if ((err = siv_memory(cipher, LTC_DECRYPT,
                         siv_tests[1].Key, siv_tests[1].Keylen,
                         siv_tests[1].output, siv_tests[1].outputlen,
                         buf, &buflen,
                         3,
                         ad_A2[0], adlen_A2[0],
                         ad_A2[1], adlen_A2[1],
                         ad_A2[2], adlen_A2[2],
                         NULL)) != CRYPT_OK) {
      return err;
   }
   if (ltc_compare_testvector(buf, buflen, siv_tests[1].Plaintext, siv_tests[1].Plaintextlen, siv_tests[1].name, n + 0x1000) != 0) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   n++;

   /* Testcase 0x4 - siv_memory() - zero AD components - encrypt */
   buflen = sizeof(buf);
   if ((err = siv_memory(cipher, LTC_ENCRYPT, Key_A1, sizeof(Key_A1), Plaintext_A1, sizeof(Plaintext_A1), buf, &buflen, 0, NULL)) != CRYPT_OK) {
      return err;
   }
   if (ltc_compare_testvector(buf, buflen, output_A1_zeroad, sizeof(output_A1_zeroad), "siv_memory() - zero AD components", n) != 0) {
      return CRYPT_FAIL_TESTVECTOR;
   }
   /* Testcase 0x1004 - siv_memory() - zero AD components - decrypt */
   buflen = sizeof(buf);
   if ((err = siv_memory(cipher, LTC_DECRYPT, Key_A1, sizeof(Key_A1), output_A1_zeroad, sizeof(output_A1_zeroad), buf, &buflen, 0, NULL)) != CRYPT_OK) {
      return err;
   }
   if (ltc_compare_testvector(buf, buflen, Plaintext_A1, sizeof(Plaintext_A1), "siv_memory() - zero AD components", n + 0x1000) != 0) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   n++;

   /* Testcase 0x5 - siv_memory() - one empty AD component - encrypt */
   buflen = sizeof(buf);
   if ((err = siv_memory(cipher, LTC_ENCRYPT, Key_A1, sizeof(Key_A1), Plaintext_A1, sizeof(Plaintext_A1), buf, &buflen, 1, NULL, 0UL, NULL)) != CRYPT_OK) {
      return err;
   }
   if (ltc_compare_testvector(buf, buflen, output_A1_emptyad, sizeof(output_A1_emptyad), "siv_memory() - one empty AD component", n) != 0) {
      return CRYPT_FAIL_TESTVECTOR;
   }
   /* Testcase 0x1005 - siv_memory() - one empty AD component - decrypt */
   buflen = sizeof(buf);
   if ((err = siv_memory(cipher, LTC_DECRYPT, Key_A1, sizeof(Key_A1), output_A1_emptyad, sizeof(output_A1_emptyad), buf, &buflen, 1, NULL, 0UL, NULL)) != CRYPT_OK) {
      return err;
   }
   if (ltc_compare_testvector(buf, buflen, Plaintext_A1, sizeof(Plaintext_A1), "siv_memory() - one empty AD component", n + 0x1000) != 0) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   for (n = 0; n < LTC_ARRAY_SIZE(tmp); ++n) {
      tmp[n] = XCALLOC(1, tmpmax);
      if (tmp[n] == NULL) {
         err = CRYPT_MEM;
         goto out;
      }

   }
   tmplen = 16;
   for (n = 0; n < niter; ++n) {
      buflen = tmpmax;
      if ((err = siv_encrypt_memory(cipher,
                                    siv_tests[0].Key, siv_tests[0].Keylen,
                                    0,
                                    NULL, NULL,
                                    tmp[0], tmplen,
                                    tmp[0], &buflen)) != CRYPT_OK) {
         goto out;
      }
      tmplen = buflen;
   }
   if (ltc_compare_testvector(&buflen, sizeof(buflen), &tmpmax, sizeof(tmpmax), "Multiple encrypt length", -(int)niter)) {
      err = CRYPT_FAIL_TESTVECTOR;
      goto out;
   }
   XMEMCPY(tmp[1], tmp[0], buflen);
   for (n = 0; n < niter; ++n) {
      buflen = tmpmax;
      if ((err = siv_decrypt_memory(cipher,
                                    siv_tests[0].Key, siv_tests[0].Keylen,
                                    0,
                                    NULL, NULL,
                                    tmp[1], tmplen,
                                    tmp[1], &buflen)) != CRYPT_OK) {
         goto out;
      }
      tmplen = buflen;
   }
   if (ltc_compare_testvector(tmp[1], tmplen, tmp[2], tmplen, "Multi decrypt", niter + 0x2000)) {
      err = CRYPT_FAIL_TESTVECTOR;
   }
   tmplen = 16;
   XMEMSET(tmp[0], 0, tmplen);
   for (n = 0; n < niter; ++n) {
      buflen = tmpmax;
      if ((err = siv_memory(cipher, LTC_ENCRYPT,
                            siv_tests[0].Key, siv_tests[0].Keylen,
                            tmp[0], tmplen,
                            tmp[0], &buflen,
                            0,
                            NULL)) != CRYPT_OK) {
         goto out;
      }
      tmplen = buflen;
   }
   if (ltc_compare_testvector(&buflen, sizeof(buflen), &tmpmax, sizeof(tmpmax), "Multiple encrypt length", -(int)(niter + 0x4000))) {
      err = CRYPT_FAIL_TESTVECTOR;
      goto out;
   }
   XMEMCPY(tmp[1], tmp[0], buflen);
   for (n = 0; n < niter; ++n) {
      buflen = tmpmax;
      if ((err = siv_memory(cipher, LTC_DECRYPT,
                            siv_tests[0].Key, siv_tests[0].Keylen,
                            tmp[1], tmplen,
                            tmp[1], &buflen,
                            0,
                            NULL)) != CRYPT_OK) {
         goto out;
      }
      tmplen = buflen;
   }
   if (ltc_compare_testvector(tmp[1], tmplen, tmp[2], tmplen, "Multi decrypt", niter + 0x4000)) {
      err = CRYPT_FAIL_TESTVECTOR;
   }

out:
   for (n = LTC_ARRAY_SIZE(tmp); n --> 0;) {
      XFREE(tmp[n]);
   }

   return err;
#endif
}

#endif
