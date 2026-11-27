/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/**
  @file mlkem.c
  ML-KEM (FIPS 203) implementation: polynomial arithmetic, IND-CPA scheme,
  KEM operations, and public API.
  Based on the CRYSTALS-Kyber reference implementation (public domain).
*/

#include "tomcrypt_private.h"

#ifdef LTC_MLKEM

/* Exact 16-bit types for lattice arithmetic. Assumes short is 16-bit, which holds on all platforms libtomcrypt targets. */
typedef signed short   ishort16;
typedef unsigned short ushort16;

/* ---- ML-KEM constants ---- */
#define MLKEM_N              256
#define MLKEM_Q              3329
#define MLKEM_SYMBYTES       32
#define MLKEM_SSBYTES        32
#define MLKEM_POLYBYTES      384
#define MLKEM_K_MAX          4
#define MLKEM_QINV           (-3327)  /* q^{-1} mod 2^16 */
#define MLKEM_XOF_BLOCKBYTES 168      /* SHAKE128 rate */

LTC_STATIC_ASSERT(mlkem_keygen_seed_size, LTC_MLKEM_KEYGEN_SEED_BYTES == 2 * MLKEM_SYMBYTES)
LTC_STATIC_ASSERT(mlkem_shared_secret_size, LTC_MLKEM_SHARED_SECRET_BYTES == MLKEM_SSBYTES)
LTC_STATIC_ASSERT(mlkem_encaps_entropy_size, LTC_MLKEM_M_BYTES == MLKEM_SYMBYTES)

/* ---- Runtime parameter set ---- */
typedef struct {
   int k, eta1, eta2, du, dv;
   unsigned long polyvec_bytes, polyvec_compressed_bytes, poly_compressed_bytes;
   unsigned long indcpa_pk_bytes, indcpa_sk_bytes, indcpa_ct_bytes;
   unsigned long pk_bytes, sk_bytes, ct_bytes;
} mlkem_params;

/* ---- Polynomial types ---- */
typedef struct {
   ishort16 coeffs[MLKEM_N];
} mlkem_poly;

typedef struct {
   mlkem_poly vec[MLKEM_K_MAX];
} mlkem_polyvec;

/* Montgomery / Barrett reduction */

static ishort16 s_mlkem_montgomery_reduce(int a)
{
   ishort16 t;
   t = (ishort16)a * MLKEM_QINV;
   t = (a - (int)t * MLKEM_Q) >> 16;
   return t;
}

static ishort16 s_mlkem_barrett_reduce(ishort16 a)
{
   ishort16 t;
   const ishort16 v = ((1 << 26) + MLKEM_Q / 2) / MLKEM_Q;
   t  = ((int)v * a + (1 << 25)) >> 26;
   t *= MLKEM_Q;
   return a - t;
}

static ishort16 s_mlkem_fqmul(ishort16 a, ishort16 b)
{
   return s_mlkem_montgomery_reduce((int)a * b);
}

/* NTT */

static const ishort16 s_mlkem_zetas[128] = {
   -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
    -171,   622,  1577,   182,   962, -1202, -1474,  1468,
     573, -1325,   264,   383,  -829,  1458, -1602,  -130,
    -681,  1017,   732,   608, -1542,   411,  -205, -1571,
    1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
     516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
    -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
    -398,   961, -1508,  -725,   448, -1065,   677, -1275,
   -1103,   430,   555,   843, -1251,   871,  1550,   105,
     422,   587,   177,  -235,  -291,  -460,  1574,  1653,
    -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
   -1590,   644,  -872,   349,   418,   329,  -156,   -75,
     817,  1097,   603,   610,  1322, -1285, -1465,   384,
   -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
   -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
    -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

static void s_mlkem_ntt(ishort16 r[256])
{
   unsigned int len, start, j, k;
   ishort16 t, zeta;

   k = 1;
   for (len = 128; len >= 2; len >>= 1) {
      for (start = 0; start < 256; start = j + len) {
         zeta = s_mlkem_zetas[k++];
         for (j = start; j < start + len; j++) {
            t = s_mlkem_fqmul(zeta, r[j + len]);
            r[j + len] = r[j] - t;
            r[j] = r[j] + t;
         }
      }
   }
}

static void s_mlkem_invntt(ishort16 r[256])
{
   unsigned int start, len, j, k;
   ishort16 t, zeta;
   const ishort16 f = 1441; /* mont^2/128 */

   k = 127;
   for (len = 2; len <= 128; len <<= 1) {
      for (start = 0; start < 256; start = j + len) {
         zeta = s_mlkem_zetas[k--];
         for (j = start; j < start + len; j++) {
            t = r[j];
            r[j] = s_mlkem_barrett_reduce(t + r[j + len]);
            r[j + len] = r[j + len] - t;
            r[j + len] = s_mlkem_fqmul(zeta, r[j + len]);
         }
      }
   }

   for (j = 0; j < 256; j++)
      r[j] = s_mlkem_fqmul(r[j], f);
}

static void s_mlkem_basemul(ishort16 r[2], const ishort16 a[2], const ishort16 b[2], ishort16 zeta)
{
   r[0]  = s_mlkem_fqmul(a[1], b[1]);
   r[0]  = s_mlkem_fqmul(r[0], zeta);
   r[0] += s_mlkem_fqmul(a[0], b[0]);
   r[1]  = s_mlkem_fqmul(a[0], b[1]);
   r[1] += s_mlkem_fqmul(a[1], b[0]);
}

/* CBD (Centered Binomial Distribution) */

static ulong32 s_mlkem_load32_le(const unsigned char *x)
{
   ulong32 r;
   LOAD32L(r, x);
   return r;
}

static ulong32 s_mlkem_load24_le(const unsigned char *x)
{
   return ((ulong32)(x[0] & 255))
        | ((ulong32)(x[1] & 255) << 8)
        | ((ulong32)(x[2] & 255) << 16);
}

static void s_mlkem_cbd2(mlkem_poly *r, const unsigned char *buf)
{
   unsigned int i, j;
   ulong32 t, d;
   ishort16 a, b;

   for (i = 0; i < MLKEM_N / 8; i++) {
      t  = s_mlkem_load32_le(buf + 4 * i);
      d  = t & 0x55555555u;
      d += (t >> 1) & 0x55555555u;

      for (j = 0; j < 8; j++) {
         a = (d >> (4 * j + 0)) & 0x3;
         b = (d >> (4 * j + 2)) & 0x3;
         r->coeffs[8 * i + j] = a - b;
      }
   }
}

static void s_mlkem_cbd3(mlkem_poly *r, const unsigned char *buf)
{
   unsigned int i, j;
   ulong32 t, d;
   ishort16 a, b;

   for (i = 0; i < MLKEM_N / 4; i++) {
      t  = s_mlkem_load24_le(buf + 3 * i);
      d  = t & 0x00249249u;
      d += (t >> 1) & 0x00249249u;
      d += (t >> 2) & 0x00249249u;

      for (j = 0; j < 4; j++) {
         a = (d >> (6 * j + 0)) & 0x7;
         b = (d >> (6 * j + 3)) & 0x7;
         r->coeffs[4 * i + j] = a - b;
      }
   }
}

static void s_mlkem_poly_cbd_eta(mlkem_poly *r, const unsigned char *buf, int eta)
{
   if (eta == 3) {
      s_mlkem_cbd3(r, buf);
   }
   else {
      s_mlkem_cbd2(r, buf);
   }
}

/* Constant-time operations */

static int s_mlkem_ct_verify(const unsigned char *a, const unsigned char *b, unsigned long len)
{
   unsigned long i;
   unsigned char r = 0;

   for (i = 0; i < len; i++)
      r |= a[i] ^ b[i];

   return (-(ulong64)r) >> 63;
}

static void s_mlkem_cmov(unsigned char *r, const unsigned char *x, unsigned long len, unsigned char b)
{
   unsigned long i;

#if defined(__GNUC__) || defined(__clang__)
   __asm__("" : "+r"(b) : /* no inputs */);
#endif

   b = -b;
   for (i = 0; i < len; i++)
      r[i] ^= b & (r[i] ^ x[i]);
}

static void s_mlkem_cmov_int16(ishort16 *r, ishort16 v, ushort16 b)
{
#if defined(__GNUC__) || defined(__clang__)
   __asm__("" : "+r"(b) : /* no inputs */);
#endif

   b = -b;
   *r ^= b & ((*r) ^ v);
}

/* Parameter lookup */

static int s_mlkem_get_params(int alg, mlkem_params *p)
{
   LTC_ARGCHK(p != NULL);

   XMEMSET(p, 0, sizeof(*p));

   switch (alg) {
      case LTC_MLKEM_512:
         p->k = 2; p->eta1 = 3; p->eta2 = 2; p->du = 10; p->dv = 4;
         break;
      case LTC_MLKEM_768:
         p->k = 3; p->eta1 = 2; p->eta2 = 2; p->du = 10; p->dv = 4;
         break;
      case LTC_MLKEM_1024:
         p->k = 4; p->eta1 = 2; p->eta2 = 2; p->du = 11; p->dv = 5;
         break;
      default:
         return CRYPT_INVALID_ARG;
   }

   p->polyvec_bytes = (unsigned long)p->k * MLKEM_POLYBYTES;
   p->polyvec_compressed_bytes = (unsigned long)p->k * (p->du == 11 ? 352 : 320);
   p->poly_compressed_bytes = p->dv == 5 ? 160 : 128;
   p->indcpa_pk_bytes = p->polyvec_bytes + MLKEM_SYMBYTES;
   p->indcpa_sk_bytes = p->polyvec_bytes;
   p->indcpa_ct_bytes = p->polyvec_compressed_bytes + p->poly_compressed_bytes;
   p->pk_bytes = p->indcpa_pk_bytes;
   p->sk_bytes = p->indcpa_sk_bytes + p->indcpa_pk_bytes + 2 * MLKEM_SYMBYTES;
   p->ct_bytes = p->indcpa_ct_bytes;

   return CRYPT_OK;
}

/* Symmetric primitives using libtomcrypt SHA3 */

static int s_mlkem_hash_h(unsigned char out[32], const unsigned char *in, unsigned long inlen)
{
   hash_state md;
   int err;

   if ((err = sha3_256_init(&md)) == CRYPT_OK) {
      if ((err = sha3_process(&md, in, inlen)) == CRYPT_OK) {
         err = sha3_done(&md, out);
      }
   }
   zeromem(&md, sizeof(md));

   return err;
}

/* in and out may overlap, the input is fully absorbed before the digest is written */
static int s_mlkem_hash_g(unsigned char out[64], const unsigned char *in, unsigned long inlen)
{
   hash_state md;
   int err;

   if ((err = sha3_512_init(&md)) == CRYPT_OK) {
      if ((err = sha3_process(&md, in, inlen)) == CRYPT_OK) {
         err = sha3_done(&md, out);
      }
   }
   /* the sponge absorbed m, wipe it */
   zeromem(&md, sizeof(md));

   return err;
}

static int s_mlkem_xof_absorb(hash_state *state, const unsigned char seed[MLKEM_SYMBYTES],
                     unsigned char x, unsigned char y)
{
   int err;
   unsigned char extseed[MLKEM_SYMBYTES + 2];

   XMEMCPY(extseed, seed, MLKEM_SYMBYTES);
   extseed[MLKEM_SYMBYTES + 0] = x;
   extseed[MLKEM_SYMBYTES + 1] = y;

   if ((err = sha3_shake_init(state, 128)) != CRYPT_OK) return err;
   return sha3_shake_process(state, extseed, sizeof(extseed));
}

static int s_mlkem_xof_squeeze(hash_state *state, unsigned char *out, unsigned long outlen)
{
   return sha3_shake_done(state, out, outlen);
}

static int s_mlkem_prf(unsigned char *out, unsigned long outlen,
              const unsigned char key[MLKEM_SYMBYTES], unsigned char nonce)
{
   int err;
   hash_state md;
   unsigned char extkey[MLKEM_SYMBYTES + 1];

   XMEMCPY(extkey, key, MLKEM_SYMBYTES);
   extkey[MLKEM_SYMBYTES] = nonce;

   if ((err = sha3_shake_init(&md, 256)) == CRYPT_OK) {
      if ((err = sha3_shake_process(&md, extkey, sizeof(extkey))) == CRYPT_OK) {
         err = sha3_shake_done(&md, out, outlen);
      }
   }

   /* the sponge is a permutation, its state still yields the absorbed secret */
   zeromem(&md, sizeof(md));
   zeromem(extkey, sizeof(extkey));

   return err;
}

static int s_mlkem_rkprf(unsigned char out[MLKEM_SSBYTES],
                const unsigned char key[MLKEM_SYMBYTES],
                const unsigned char *ct, unsigned long ctlen)
{
   int err;
   hash_state md;

   if ((err = sha3_shake_init(&md, 256)) == CRYPT_OK) {
      if ((err = sha3_shake_process(&md, key, MLKEM_SYMBYTES)) == CRYPT_OK) {
         if ((err = sha3_shake_process(&md, ct, ctlen)) == CRYPT_OK) {
            err = sha3_shake_done(&md, out, MLKEM_SSBYTES);
         }
      }
   }

   /* the sponge absorbed z, wipe it along with everything else */
   zeromem(&md, sizeof(md));

   return err;
}

/* Polynomial operations */

static void s_mlkem_poly_compress(unsigned char *r, const mlkem_poly *a, int dv)
{
   unsigned int i, j;
   ishort16 u;
   ulong32 d0;
   unsigned char t[8];

   if (dv == 4) {
      for (i = 0; i < MLKEM_N / 8; i++) {
         for (j = 0; j < 8; j++) {
            u  = a->coeffs[8 * i + j];
            u += (u >> 15) & MLKEM_Q;
            d0 = u << 4;
            d0 += 1665;
            d0 *= 80635;
            d0 >>= 28;
            t[j] = d0 & 0xf;
         }
         r[0] = t[0] | (t[1] << 4);
         r[1] = t[2] | (t[3] << 4);
         r[2] = t[4] | (t[5] << 4);
         r[3] = t[6] | (t[7] << 4);
         r += 4;
      }
   }
   else { /* dv == 5 */
      for (i = 0; i < MLKEM_N / 8; i++) {
         for (j = 0; j < 8; j++) {
            u  = a->coeffs[8 * i + j];
            u += (u >> 15) & MLKEM_Q;
            d0 = u << 5;
            d0 += 1664;
            d0 *= 40318;
            d0 >>= 27;
            t[j] = d0 & 0x1f;
         }
         r[0] = (t[0] >> 0) | (t[1] << 5);
         r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
         r[2] = (t[3] >> 1) | (t[4] << 4);
         r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
         r[4] = (t[6] >> 2) | (t[7] << 3);
         r += 5;
      }
   }
}

static void s_mlkem_poly_decompress(mlkem_poly *r, const unsigned char *a, int dv)
{
   unsigned int i;

   if (dv == 4) {
      for (i = 0; i < MLKEM_N / 2; i++) {
         r->coeffs[2 * i + 0] = (((ushort16)(a[0] & 15) * MLKEM_Q) + 8) >> 4;
         r->coeffs[2 * i + 1] = (((ushort16)(a[0] >> 4) * MLKEM_Q) + 8) >> 4;
         a += 1;
      }
   }
   else { /* dv == 5 */
      unsigned int j;
      unsigned char t[8];
      for (i = 0; i < MLKEM_N / 8; i++) {
         t[0] = (a[0] >> 0);
         t[1] = (a[0] >> 5) | (a[1] << 3);
         t[2] = (a[1] >> 2);
         t[3] = (a[1] >> 7) | (a[2] << 1);
         t[4] = (a[2] >> 4) | (a[3] << 4);
         t[5] = (a[3] >> 1);
         t[6] = (a[3] >> 6) | (a[4] << 2);
         t[7] = (a[4] >> 3);
         a += 5;

         for (j = 0; j < 8; j++)
            r->coeffs[8 * i + j] = ((ulong32)(t[j] & 31) * MLKEM_Q + 16) >> 5;
      }
   }
}

static void s_mlkem_poly_tobytes(unsigned char *r, const mlkem_poly *a)
{
   unsigned int i;
   ushort16 t0, t1;

   for (i = 0; i < MLKEM_N / 2; i++) {
      t0  = a->coeffs[2 * i];
      t0 += ((ishort16)t0 >> 15) & MLKEM_Q;
      t1 = a->coeffs[2 * i + 1];
      t1 += ((ishort16)t1 >> 15) & MLKEM_Q;
      r[3 * i + 0] = (t0 >> 0);
      r[3 * i + 1] = (t0 >> 8) | (t1 << 4);
      r[3 * i + 2] = (t1 >> 4);
   }
}

static void s_mlkem_poly_frombytes(mlkem_poly *r, const unsigned char *a)
{
   unsigned int i;
   for (i = 0; i < MLKEM_N / 2; i++) {
      r->coeffs[2 * i]     = ((a[3 * i + 0] >> 0) | ((ushort16)a[3 * i + 1] << 8)) & 0xFFF;
      r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((ushort16)a[3 * i + 2] << 4)) & 0xFFF;
   }
}

static void s_mlkem_poly_frommsg(mlkem_poly *r, const unsigned char msg[MLKEM_SYMBYTES])
{
   unsigned int i, j;

   for (i = 0; i < MLKEM_N / 8; i++) {
      for (j = 0; j < 8; j++) {
         r->coeffs[8 * i + j] = 0;
         s_mlkem_cmov_int16(r->coeffs + 8 * i + j, (MLKEM_Q + 1) / 2, (msg[i] >> j) & 1);
      }
   }
}

static void s_mlkem_poly_tomsg(unsigned char msg[MLKEM_SYMBYTES], const mlkem_poly *a)
{
   unsigned int i, j;
   ulong32 t;

   for (i = 0; i < MLKEM_N / 8; i++) {
      msg[i] = 0;
      for (j = 0; j < 8; j++) {
         t  = a->coeffs[8 * i + j];
         t <<= 1;
         t += 1665;
         t *= 80635;
         t >>= 28;
         t &= 1;
         msg[i] |= t << j;
      }
   }
}

static void s_mlkem_poly_reduce(mlkem_poly *r)
{
   unsigned int i;
   for (i = 0; i < MLKEM_N; i++)
      r->coeffs[i] = s_mlkem_barrett_reduce(r->coeffs[i]);
}

static int s_mlkem_poly_getnoise(mlkem_poly *r, const unsigned char seed[MLKEM_SYMBYTES],
                        unsigned char nonce, int eta)
{
   unsigned char buf[3 * MLKEM_N / 4]; /* max for eta=3 */
   unsigned long buflen = (unsigned long)eta * MLKEM_N / 4;
   int err;

   /* a silently ignored failure here would sample the all-zero noise polynomial */
   if ((err = s_mlkem_prf(buf, buflen, seed, nonce)) == CRYPT_OK) {
      s_mlkem_poly_cbd_eta(r, buf, eta);
   }
   zeromem(buf, sizeof(buf));

   return err;
}

static void s_mlkem_poly_ntt(mlkem_poly *r)
{
   s_mlkem_ntt(r->coeffs);
   s_mlkem_poly_reduce(r);
}

static void s_mlkem_poly_invntt_tomont(mlkem_poly *r)
{
   s_mlkem_invntt(r->coeffs);
}

static void s_mlkem_poly_basemul_montgomery(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b)
{
   unsigned int i;
   for (i = 0; i < MLKEM_N / 4; i++) {
      s_mlkem_basemul(&r->coeffs[4 * i], &a->coeffs[4 * i],
                    &b->coeffs[4 * i], s_mlkem_zetas[64 + i]);
      s_mlkem_basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2],
                    &b->coeffs[4 * i + 2], -s_mlkem_zetas[64 + i]);
   }
}

static void s_mlkem_poly_tomont(mlkem_poly *r)
{
   unsigned int i;
   const ishort16 f = (1ULL << 32) % MLKEM_Q;
   for (i = 0; i < MLKEM_N; i++)
      r->coeffs[i] = s_mlkem_montgomery_reduce((int)r->coeffs[i] * f);
}

static void s_mlkem_poly_add(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b)
{
   unsigned int i;
   for (i = 0; i < MLKEM_N; i++)
      r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

static void s_mlkem_poly_sub(mlkem_poly *r, const mlkem_poly *a, const mlkem_poly *b)
{
   unsigned int i;
   for (i = 0; i < MLKEM_N; i++)
      r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/* Polynomial vector operations */

static void s_mlkem_polyvec_compress(unsigned char *r, const mlkem_polyvec *a, const mlkem_params *p)
{
   unsigned int i, j, k;
   ulong64 d0;

   if (p->du == 11) {
      ushort16 t[8];
      for (i = 0; i < (unsigned)p->k; i++) {
         for (j = 0; j < MLKEM_N / 8; j++) {
            for (k = 0; k < 8; k++) {
               t[k]  = a->vec[i].coeffs[8 * j + k];
               t[k] += ((ishort16)t[k] >> 15) & MLKEM_Q;
               d0 = t[k];
               d0 <<= 11;
               d0 += 1664;
               d0 *= 645084;
               d0 >>= 31;
               t[k] = d0 & 0x7ff;
            }
            r[ 0] = (t[0] >>  0);
            r[ 1] = (t[0] >>  8) | (t[1] << 3);
            r[ 2] = (t[1] >>  5) | (t[2] << 6);
            r[ 3] = (t[2] >>  2);
            r[ 4] = (t[2] >> 10) | (t[3] << 1);
            r[ 5] = (t[3] >>  7) | (t[4] << 4);
            r[ 6] = (t[4] >>  4) | (t[5] << 7);
            r[ 7] = (t[5] >>  1);
            r[ 8] = (t[5] >>  9) | (t[6] << 2);
            r[ 9] = (t[6] >>  6) | (t[7] << 5);
            r[10] = (t[7] >>  3);
            r += 11;
         }
      }
   }
   else { /* du == 10 */
      ushort16 t[4];
      for (i = 0; i < (unsigned)p->k; i++) {
         for (j = 0; j < MLKEM_N / 4; j++) {
            for (k = 0; k < 4; k++) {
               t[k]  = a->vec[i].coeffs[4 * j + k];
               t[k] += ((ishort16)t[k] >> 15) & MLKEM_Q;
               d0 = t[k];
               d0 <<= 10;
               d0 += 1665;
               d0 *= 1290167;
               d0 >>= 32;
               t[k] = d0 & 0x3ff;
            }
            r[0] = (t[0] >> 0);
            r[1] = (t[0] >> 8) | (t[1] << 2);
            r[2] = (t[1] >> 6) | (t[2] << 4);
            r[3] = (t[2] >> 4) | (t[3] << 6);
            r[4] = (t[3] >> 2);
            r += 5;
         }
      }
   }
}

static void s_mlkem_polyvec_decompress(mlkem_polyvec *r, const unsigned char *a, const mlkem_params *p)
{
   unsigned int i, j, k;

   if (p->du == 11) {
      ushort16 t[8];
      for (i = 0; i < (unsigned)p->k; i++) {
         for (j = 0; j < MLKEM_N / 8; j++) {
            t[0] = (a[0] >> 0) | ((ushort16)a[ 1] << 8);
            t[1] = (a[1] >> 3) | ((ushort16)a[ 2] << 5);
            t[2] = (a[2] >> 6) | ((ushort16)a[ 3] << 2) | ((ushort16)a[4] << 10);
            t[3] = (a[4] >> 1) | ((ushort16)a[ 5] << 7);
            t[4] = (a[5] >> 4) | ((ushort16)a[ 6] << 4);
            t[5] = (a[6] >> 7) | ((ushort16)a[ 7] << 1) | ((ushort16)a[8] << 9);
            t[6] = (a[8] >> 2) | ((ushort16)a[ 9] << 6);
            t[7] = (a[9] >> 5) | ((ushort16)a[10] << 3);
            a += 11;

            for (k = 0; k < 8; k++)
               r->vec[i].coeffs[8 * j + k] = ((ulong32)(t[k] & 0x7FF) * MLKEM_Q + 1024) >> 11;
         }
      }
   }
   else { /* du == 10 */
      ushort16 t[4];
      for (i = 0; i < (unsigned)p->k; i++) {
         for (j = 0; j < MLKEM_N / 4; j++) {
            t[0] = (a[0] >> 0) | ((ushort16)a[1] << 8);
            t[1] = (a[1] >> 2) | ((ushort16)a[2] << 6);
            t[2] = (a[2] >> 4) | ((ushort16)a[3] << 4);
            t[3] = (a[3] >> 6) | ((ushort16)a[4] << 2);
            a += 5;

            for (k = 0; k < 4; k++)
               r->vec[i].coeffs[4 * j + k] = ((ulong32)(t[k] & 0x3FF) * MLKEM_Q + 512) >> 10;
         }
      }
   }
}

static void s_mlkem_polyvec_tobytes(unsigned char *r, const mlkem_polyvec *a, int k)
{
   int i;
   for (i = 0; i < k; i++)
      s_mlkem_poly_tobytes(r + i * MLKEM_POLYBYTES, &a->vec[i]);
}

static void s_mlkem_polyvec_frombytes(mlkem_polyvec *r, const unsigned char *a, int k)
{
   int i;
   for (i = 0; i < k; i++)
      s_mlkem_poly_frombytes(&r->vec[i], a + i * MLKEM_POLYBYTES);
}

static void s_mlkem_polyvec_ntt(mlkem_polyvec *r, int k)
{
   int i;
   for (i = 0; i < k; i++)
      s_mlkem_poly_ntt(&r->vec[i]);
}

static void s_mlkem_polyvec_invntt_tomont(mlkem_polyvec *r, int k)
{
   int i;
   for (i = 0; i < k; i++)
      s_mlkem_poly_invntt_tomont(&r->vec[i]);
}

static void s_mlkem_polyvec_basemul_acc_montgomery(mlkem_poly *r, const mlkem_polyvec *a,
                                          const mlkem_polyvec *b, int k)
{
   int i;
   mlkem_poly t;

   s_mlkem_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
   for (i = 1; i < k; i++) {
      s_mlkem_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
      s_mlkem_poly_add(r, r, &t);
   }

   s_mlkem_poly_reduce(r);
}

static void s_mlkem_polyvec_reduce(mlkem_polyvec *r, int k)
{
   int i;
   for (i = 0; i < k; i++)
      s_mlkem_poly_reduce(&r->vec[i]);
}

static void s_mlkem_polyvec_add(mlkem_polyvec *r, const mlkem_polyvec *a,
                       const mlkem_polyvec *b, int k)
{
   int i;
   for (i = 0; i < k; i++)
      s_mlkem_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}

/* IND-CPA: rejection sampling and matrix generation */

static unsigned int s_mlkem_rej_uniform(ishort16 *r, unsigned int len,
                                  const unsigned char *buf, unsigned int buflen)
{
   unsigned int ctr, pos;
   ushort16 val0, val1;

   ctr = pos = 0;
   while (ctr < len && pos + 3 <= buflen) {
      val0 = ((buf[pos + 0] >> 0) | ((ushort16)buf[pos + 1] << 8)) & 0xFFF;
      val1 = ((buf[pos + 1] >> 4) | ((ushort16)buf[pos + 2] << 4)) & 0xFFF;
      pos += 3;

      if (val0 < MLKEM_Q)
         r[ctr++] = val0;
      if (ctr < len && val1 < MLKEM_Q)
         r[ctr++] = val1;
   }

   return ctr;
}

#define GEN_MATRIX_NBLOCKS ((12*MLKEM_N/8*(1 << 12)/MLKEM_Q + MLKEM_XOF_BLOCKBYTES)/MLKEM_XOF_BLOCKBYTES)

static int s_mlkem_gen_matrix(mlkem_polyvec *a, const unsigned char seed[MLKEM_SYMBYTES],
                        int transposed, int k)
{
   unsigned int ctr, i, j, buflen;
   unsigned char buf[GEN_MATRIX_NBLOCKS * MLKEM_XOF_BLOCKBYTES + MLKEM_XOF_BLOCKBYTES];
   hash_state state;
   int err;

   for (i = 0; i < (unsigned)k; i++) {
      for (j = 0; j < (unsigned)k; j++) {
         if (transposed)
            err = s_mlkem_xof_absorb(&state, seed, (unsigned char)i, (unsigned char)j);
         else
            err = s_mlkem_xof_absorb(&state, seed, (unsigned char)j, (unsigned char)i);
         if (err != CRYPT_OK) return err;

         buflen = GEN_MATRIX_NBLOCKS * MLKEM_XOF_BLOCKBYTES;
         if ((err = s_mlkem_xof_squeeze(&state, buf, buflen)) != CRYPT_OK) return err;
         ctr = s_mlkem_rej_uniform(a[i].vec[j].coeffs, MLKEM_N, buf, buflen);

         while (ctr < MLKEM_N) {
            if ((err = s_mlkem_xof_squeeze(&state, buf, MLKEM_XOF_BLOCKBYTES)) != CRYPT_OK) return err;
            ctr += s_mlkem_rej_uniform(a[i].vec[j].coeffs + ctr, MLKEM_N - ctr,
                                 buf, MLKEM_XOF_BLOCKBYTES);
         }
      }
   }

   return CRYPT_OK;
}

/* IND-CPA scheme */

static int s_mlkem_indcpa_keypair(unsigned char *pk, unsigned char *sk,
                         const unsigned char coins[MLKEM_SYMBYTES],
                         const mlkem_params *p)
{
   unsigned int i;
   unsigned char buf[2 * MLKEM_SYMBYTES];
   const unsigned char *publicseed = buf;
   const unsigned char *noiseseed = buf + MLKEM_SYMBYTES;
   unsigned char nonce = 0;
   mlkem_polyvec a[MLKEM_K_MAX], e, pkpv, skpv;
   int err;

   XMEMCPY(buf, coins, MLKEM_SYMBYTES);
   buf[MLKEM_SYMBYTES] = (unsigned char)p->k;
   if ((err = s_mlkem_hash_g(buf, buf, MLKEM_SYMBYTES + 1)) != CRYPT_OK) goto LBL_ERR;

   if ((err = s_mlkem_gen_matrix(a, publicseed, 0, p->k)) != CRYPT_OK) goto LBL_ERR;

   for (i = 0; i < (unsigned)p->k; i++)
      if ((err = s_mlkem_poly_getnoise(&skpv.vec[i], noiseseed, nonce++, p->eta1)) != CRYPT_OK) goto LBL_ERR;
   for (i = 0; i < (unsigned)p->k; i++)
      if ((err = s_mlkem_poly_getnoise(&e.vec[i], noiseseed, nonce++, p->eta1)) != CRYPT_OK) goto LBL_ERR;

   s_mlkem_polyvec_ntt(&skpv, p->k);
   s_mlkem_polyvec_ntt(&e, p->k);

   for (i = 0; i < (unsigned)p->k; i++) {
      s_mlkem_polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv, p->k);
      s_mlkem_poly_tomont(&pkpv.vec[i]);
   }

   s_mlkem_polyvec_add(&pkpv, &pkpv, &e, p->k);
   s_mlkem_polyvec_reduce(&pkpv, p->k);

   s_mlkem_polyvec_tobytes(sk, &skpv, p->k);
   s_mlkem_polyvec_tobytes(pk, &pkpv, p->k);
   XMEMCPY(pk + p->polyvec_bytes, publicseed, MLKEM_SYMBYTES);

   err = CRYPT_OK;
LBL_ERR:
   zeromem(buf, sizeof(buf));
   zeromem(&skpv, sizeof(skpv));
   zeromem(&e, sizeof(e));
   return err;
}

static int s_mlkem_indcpa_enc(unsigned char *c,
                     const unsigned char m[MLKEM_SYMBYTES],
                     const unsigned char *pk,
                     const unsigned char coins[MLKEM_SYMBYTES],
                     const mlkem_params *p)
{
   unsigned int i;
   unsigned char seed[MLKEM_SYMBYTES];
   unsigned char nonce = 0;
   mlkem_polyvec sp, pkpv, ep, at[MLKEM_K_MAX], b;
   mlkem_poly v, k, epp;
   int err;

   s_mlkem_polyvec_frombytes(&pkpv, pk, p->k);
   XMEMCPY(seed, pk + p->polyvec_bytes, MLKEM_SYMBYTES);
   s_mlkem_poly_frommsg(&k, m);
   if ((err = s_mlkem_gen_matrix(at, seed, 1, p->k)) != CRYPT_OK) goto LBL_ERR;

   for (i = 0; i < (unsigned)p->k; i++)
      if ((err = s_mlkem_poly_getnoise(&sp.vec[i], coins, nonce++, p->eta1)) != CRYPT_OK) goto LBL_ERR;
   for (i = 0; i < (unsigned)p->k; i++)
      if ((err = s_mlkem_poly_getnoise(&ep.vec[i], coins, nonce++, p->eta2)) != CRYPT_OK) goto LBL_ERR;
   if ((err = s_mlkem_poly_getnoise(&epp, coins, nonce++, p->eta2)) != CRYPT_OK) goto LBL_ERR;

   s_mlkem_polyvec_ntt(&sp, p->k);

   for (i = 0; i < (unsigned)p->k; i++)
      s_mlkem_polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp, p->k);

   s_mlkem_polyvec_basemul_acc_montgomery(&v, &pkpv, &sp, p->k);

   s_mlkem_polyvec_invntt_tomont(&b, p->k);
   s_mlkem_poly_invntt_tomont(&v);

   s_mlkem_polyvec_add(&b, &b, &ep, p->k);
   s_mlkem_poly_add(&v, &v, &epp);
   s_mlkem_poly_add(&v, &v, &k);
   s_mlkem_polyvec_reduce(&b, p->k);
   s_mlkem_poly_reduce(&v);

   s_mlkem_polyvec_compress(c, &b, p);
   s_mlkem_poly_compress(c + p->polyvec_compressed_bytes, &v, p->dv);

   err = CRYPT_OK;
LBL_ERR:
   zeromem(&sp, sizeof(sp));
   zeromem(&ep, sizeof(ep));
   zeromem(&epp, sizeof(epp));
   zeromem(&k, sizeof(k));
   return err;
}

static void s_mlkem_indcpa_dec(unsigned char m[MLKEM_SYMBYTES],
                      const unsigned char *c,
                      const unsigned char *sk,
                      const mlkem_params *p)
{
   mlkem_polyvec b, skpv;
   mlkem_poly v, mp;

   s_mlkem_polyvec_decompress(&b, c, p);
   s_mlkem_poly_decompress(&v, c + p->polyvec_compressed_bytes, p->dv);
   s_mlkem_polyvec_frombytes(&skpv, sk, p->k);

   s_mlkem_polyvec_ntt(&b, p->k);
   s_mlkem_polyvec_basemul_acc_montgomery(&mp, &skpv, &b, p->k);
   s_mlkem_poly_invntt_tomont(&mp);

   s_mlkem_poly_sub(&mp, &v, &mp);
   s_mlkem_poly_reduce(&mp);

   s_mlkem_poly_tomsg(m, &mp);

   zeromem(&skpv, sizeof(skpv));
   zeromem(&mp, sizeof(mp));
}

/* KEM operations */

static int s_mlkem_kem_keypair(unsigned char *pk, unsigned char *sk,
                         const unsigned char coins[2 * MLKEM_SYMBYTES],
                         const mlkem_params *p)
{
   int err;

   if ((err = s_mlkem_indcpa_keypair(pk, sk, coins, p)) != CRYPT_OK) return err;
   XMEMCPY(sk + p->indcpa_sk_bytes, pk, p->pk_bytes);
   if ((err = s_mlkem_hash_h(sk + p->sk_bytes - 2 * MLKEM_SYMBYTES, pk, p->pk_bytes)) != CRYPT_OK)
      return err;
   /* Value z for pseudo-random output on reject */
   XMEMCPY(sk + p->sk_bytes - MLKEM_SYMBYTES, coins + MLKEM_SYMBYTES, MLKEM_SYMBYTES);

   return CRYPT_OK;
}

/**
   Modulus check of an encapsulation key, FIPS 203 7.2

   ByteEncode12(ByteDecode12(ek)) has to reproduce ek, which is the case exactly when every
   12 bit coefficient is already reduced, so compare them against q instead of re-encoding.
*/
static int s_mlkem_validate_public_key(const unsigned char *pk,
                                       const mlkem_params *p)
{
   unsigned long i, n = (unsigned long)p->k * MLKEM_POLYBYTES;

   for (i = 0; i < n; i += 3) {
      if ((((ushort16)pk[i + 0] | ((ushort16)pk[i + 1] << 8)) & 0xFFF) >= MLKEM_Q) return CRYPT_INVALID_PACKET;
      if ((((ushort16)pk[i + 1] >> 4) | ((ushort16)pk[i + 2] << 4)) >= MLKEM_Q) return CRYPT_INVALID_PACKET;
   }

   return CRYPT_OK;
}

static int s_mlkem_validate_private_key(const unsigned char *sk,
                                        const mlkem_params *p)
{
   unsigned char h[MLKEM_SYMBYTES];
   int err;

   if ((err = s_mlkem_hash_h(h, sk + p->indcpa_sk_bytes, p->pk_bytes)) != CRYPT_OK) {
      return err;
   }

   return XMEM_NEQ(h, sk + p->sk_bytes - 2 * MLKEM_SYMBYTES, MLKEM_SYMBYTES) == 0
        ? CRYPT_OK
        : CRYPT_INVALID_PACKET;
}

static int s_mlkem_kem_enc(unsigned char *ct, unsigned char *ss,
                     const unsigned char *pk,
                     const unsigned char coins[MLKEM_SYMBYTES],
                     const mlkem_params *p)
{
   unsigned char buf[2 * MLKEM_SYMBYTES];
   unsigned char kr[2 * MLKEM_SYMBYTES];
   int err;

   XMEMCPY(buf, coins, MLKEM_SYMBYTES);

   /* buf = m || H(ek), FIPS 203 7.2 */
   if ((err = s_mlkem_hash_h(buf + MLKEM_SYMBYTES, pk, p->pk_bytes)) != CRYPT_OK) goto LBL_ERR;
   if ((err = s_mlkem_hash_g(kr, buf, 2 * MLKEM_SYMBYTES)) != CRYPT_OK) goto LBL_ERR;

   /* coins are in kr+MLKEM_SYMBYTES */
   if ((err = s_mlkem_indcpa_enc(ct, buf, pk, kr + MLKEM_SYMBYTES, p)) != CRYPT_OK) goto LBL_ERR;

   XMEMCPY(ss, kr, MLKEM_SYMBYTES);
   err = CRYPT_OK;
LBL_ERR:
   zeromem(buf, sizeof(buf));
   zeromem(kr, sizeof(kr));
   return err;
}

static int s_mlkem_kem_dec(unsigned char *ss,
                     const unsigned char *ct,
                     const unsigned char *sk,
                     const mlkem_params *p)
{
   int fail, err;
   unsigned char buf[2 * MLKEM_SYMBYTES];
   unsigned char kr[2 * MLKEM_SYMBYTES];
   unsigned char cmp[MLKEM_K_MAX * 352 + 160]; /* max ct size */
   const unsigned char *pk = sk + p->indcpa_sk_bytes;

   s_mlkem_indcpa_dec(buf, ct, sk, p);

   /* buf = m' || h with the stored H(ek), FIPS 203 7.3 */
   XMEMCPY(buf + MLKEM_SYMBYTES, sk + p->sk_bytes - 2 * MLKEM_SYMBYTES, MLKEM_SYMBYTES);
   if ((err = s_mlkem_hash_g(kr, buf, 2 * MLKEM_SYMBYTES)) != CRYPT_OK) goto LBL_ERR;

   /* coins are in kr+MLKEM_SYMBYTES */
   if ((err = s_mlkem_indcpa_enc(cmp, buf, pk, kr + MLKEM_SYMBYTES, p)) != CRYPT_OK) goto LBL_ERR;

   fail = s_mlkem_ct_verify(ct, cmp, p->ct_bytes);

   /* Compute rejection key */
   if ((err = s_mlkem_rkprf(ss, sk + p->sk_bytes - MLKEM_SYMBYTES, ct, p->ct_bytes)) != CRYPT_OK)
      goto LBL_ERR;

   /* Copy true key to return buffer if fail is false */
   s_mlkem_cmov(ss, kr, MLKEM_SYMBYTES, (unsigned char)!fail);

   err = CRYPT_OK;
LBL_ERR:
   zeromem(buf, sizeof(buf));
   zeromem(kr, sizeof(kr));
   zeromem(cmp, sizeof(cmp));
   return err;
}

/* Public API */

/**
   Generate an ML-KEM key pair.
   @param prng     An active PRNG state
   @param wprng    The index of the desired PRNG
   @param alg      The parameter set (LTC_MLKEM_512, LTC_MLKEM_768, or LTC_MLKEM_1024)
   @param key      [out] Destination for the newly created key pair
   @return CRYPT_OK if successful
*/
int mlkem_make_key(prng_state *prng, int wprng, int alg, mlkem_key *key)
{
   unsigned char coins[2 * MLKEM_SYMBYTES];
   int err;

   LTC_ARGCHK(key != NULL);

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) return err;
   if (prng_descriptor[wprng].read(coins, sizeof(coins), prng) != sizeof(coins)) {
      zeromem(coins, sizeof(coins));
      return CRYPT_ERROR_READPRNG;
   }

   err = mlkem_make_key_from_seed(alg, coins, sizeof(coins), key);
   zeromem(coins, sizeof(coins));
   return err;
}

/**
   Generate an ML-KEM key pair deterministically from a seed.
   @param alg      The parameter set (LTC_MLKEM_512, LTC_MLKEM_768, or LTC_MLKEM_1024)
   @param seed     The input seed (exactly 64 bytes)
   @param seedlen  Length of the seed in bytes
   @param key      [out] Destination for the newly created key pair
   @return CRYPT_OK if successful
*/
int mlkem_make_key_from_seed(int alg, const unsigned char *seed, unsigned long seedlen, mlkem_key *key)
{
   mlkem_params p;
   int err;

   LTC_ARGCHK(seed != NULL);
   LTC_ARGCHK(key  != NULL);

   if (seedlen != 2uL * MLKEM_SYMBYTES) {
      return CRYPT_INVALID_ARG;
   }
   if ((err = s_mlkem_get_params(alg, &p)) != CRYPT_OK) {
      return err;
   }

   XMEMSET(key, 0, sizeof(*key));
   key->pk = XMALLOC(p.pk_bytes);
   key->sk = XMALLOC(p.sk_bytes);
   if (key->pk == NULL || key->sk == NULL) {
      mlkem_free(key);
      return CRYPT_MEM;
   }

   if ((err = s_mlkem_kem_keypair(key->pk, key->sk, seed, &p)) != CRYPT_OK) {
      zeromem(key->sk, p.sk_bytes);
      mlkem_free(key);
      return err;
   }

   key->alg = alg;
   key->type = PK_PRIVATE;
   key->pklen = p.pk_bytes;
   key->sklen = p.sk_bytes;
   err = s_mlkem_validate_private_key(key->sk, &p);
   if (err != CRYPT_OK) {
      mlkem_free(key);
      return err;
   }

   /* store the seed only after the key validates */
   XMEMCPY(key->seed, seed, LTC_MLKEM_KEYGEN_SEED_BYTES);
   key->has_seed = 1;
   return CRYPT_OK;
}

/**
   Free an ML-KEM key from memory.
   @param key   The key to free
*/
void mlkem_free(mlkem_key *key)
{
   if (key == NULL) return;
   if (key->sk != NULL) {
      zeromem(key->sk, key->sklen);
      XFREE(key->sk);
   }
   if (key->pk != NULL) {
      XFREE(key->pk);
   }
   zeromem(key->seed, sizeof(key->seed));
   key->has_seed = 0;
   XMEMSET(key, 0, sizeof(*key));
}

/* Cheap check of the key fields only, the key material is checked by mlkem_check_key() */
static int s_mlkem_key_valid(const mlkem_key *key, int require_private, mlkem_params *p)
{
   int err;

   if ((err = s_mlkem_get_params(key->alg, p)) != CRYPT_OK) return err;
   if (require_private && key->type != PK_PRIVATE) return CRYPT_PK_NOT_PRIVATE;
   if (key->type != PK_PRIVATE && key->type != PK_PUBLIC) return CRYPT_PK_INVALID_TYPE;
   if (key->pk == NULL || key->pklen != p->pk_bytes) return CRYPT_PK_INVALID_TYPE;
   if (key->type == PK_PRIVATE && (key->sk == NULL || key->sklen != p->sk_bytes)) return CRYPT_PK_INVALID_TYPE;

   return CRYPT_OK;
}

/**
   Export an ML-KEM key to a byte buffer.
   @param out      [out] Destination for the exported key
   @param outlen   [in/out] Max size and resulting size of the exported key
   @param which    PK_PUBLIC for the encapsulation key, PK_PRIVATE for the decapsulation key
   @param key      The key to export
   @return CRYPT_OK if successful
*/
int mlkem_export_raw(unsigned char *out, unsigned long *outlen, int which, const mlkem_key *key)
{
   mlkem_params p;
   unsigned long needed;
   int err;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   if (which == PK_PUBLIC) {
      if ((err = s_mlkem_key_valid(key, 0, &p)) != CRYPT_OK) return err;
      needed = p.pk_bytes;
      if (*outlen < needed) { *outlen = needed; return CRYPT_BUFFER_OVERFLOW; }
      XMEMCPY(out, key->pk, needed);
   }
   else if (which == PK_PRIVATE) {
      if ((err = s_mlkem_key_valid(key, 1, &p)) != CRYPT_OK) return err;
      needed = p.sk_bytes;
      if (*outlen < needed) { *outlen = needed; return CRYPT_BUFFER_OVERFLOW; }
      XMEMCPY(out, key->sk, needed);
   }
   else {
      return CRYPT_INVALID_ARG;
   }

   *outlen = needed;
   return CRYPT_OK;
}

/**
   Import an ML-KEM key from a byte buffer.
   @param in       The buffer to import from
   @param inlen    Length of the buffer
   @param which    PK_PUBLIC for an encapsulation key, PK_PRIVATE for a decapsulation key
   @param alg      The parameter set (LTC_MLKEM_512, LTC_MLKEM_768, or LTC_MLKEM_1024)
   @param key      [out] Destination for the imported key
   @return CRYPT_OK if successful
*/
int mlkem_import_raw(const unsigned char *in, unsigned long inlen, int which, int alg, mlkem_key *key)
{
   mlkem_params p;
   int err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   if ((err = s_mlkem_get_params(alg, &p)) != CRYPT_OK) return err;

   XMEMSET(key, 0, sizeof(*key));
   key->alg = alg;

   if (which == PK_PUBLIC) {
      if (inlen != p.pk_bytes) return CRYPT_INVALID_PACKET;
      if ((err = s_mlkem_validate_public_key(in, &p)) != CRYPT_OK) return err;
      key->pk = XMALLOC(p.pk_bytes);
      if (key->pk == NULL) return CRYPT_MEM;
      XMEMCPY(key->pk, in, p.pk_bytes);
      key->pklen = p.pk_bytes;
      key->type = PK_PUBLIC;
   }
   else if (which == PK_PRIVATE) {
      if (inlen != p.sk_bytes) return CRYPT_INVALID_PACKET;
      /* encapsulation may use the key embedded in the decapsulation key */
      if ((err = s_mlkem_validate_public_key(in + p.indcpa_sk_bytes, &p)) != CRYPT_OK) return err;
      key->sk = XMALLOC(p.sk_bytes);
      /* Extract pk from sk (it's embedded at offset indcpa_sk_bytes) */
      key->pk = XMALLOC(p.pk_bytes);
      if (key->sk == NULL || key->pk == NULL) {
         mlkem_free(key);
         return CRYPT_MEM;
      }
      XMEMCPY(key->sk, in, p.sk_bytes);
      XMEMCPY(key->pk, in + p.indcpa_sk_bytes, p.pk_bytes);
      key->sklen = p.sk_bytes;
      key->pklen = p.pk_bytes;
      key->type = PK_PRIVATE;
      if ((err = s_mlkem_validate_private_key(key->sk, &p)) != CRYPT_OK) {
         mlkem_free(key);
         return err;
      }
   }
   else {
      return CRYPT_INVALID_ARG;
   }

   return CRYPT_OK;
}

/**
   Check the internal consistency of an ML-KEM key.

   Checks the coefficient bound on pk, the copy of pk inside sk and the stored H(ek), and
   expands a stored seed again.
   @param key      The key to check
   @return CRYPT_OK if the key is consistent, CRYPT_PK_INVALID_TYPE if a key field is wrong,
           CRYPT_INVALID_PACKET if the key material does not match
*/
int mlkem_check_key(const mlkem_key *key)
{
   mlkem_params p;
   mlkem_key tmp;
   int err;

   LTC_ARGCHK(key != NULL);

   if ((err = s_mlkem_get_params(key->alg, &p)) != CRYPT_OK) return err;
   if (key->pk == NULL || key->pklen != p.pk_bytes) return CRYPT_PK_INVALID_TYPE;
   if ((err = s_mlkem_validate_public_key(key->pk, &p)) != CRYPT_OK) return err;

   if (key->type == PK_PUBLIC) {
      return (key->sk == NULL && key->sklen == 0 && !key->has_seed) ? CRYPT_OK : CRYPT_PK_INVALID_TYPE;
   }
   if (key->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;
   if (key->sk == NULL || key->sklen != p.sk_bytes) return CRYPT_PK_INVALID_TYPE;

   /* sk contains its own copy of pk, both have to be the same */
   if (XMEM_NEQ(key->sk + p.indcpa_sk_bytes, key->pk, p.pk_bytes) != 0) return CRYPT_INVALID_PACKET;
   if ((err = s_mlkem_validate_private_key(key->sk, &p)) != CRYPT_OK) return err;

   if (!key->has_seed) return CRYPT_OK;

   if ((err = mlkem_make_key_from_seed(key->alg, key->seed, sizeof(key->seed), &tmp)) != CRYPT_OK) {
      return err;
   }
   if (tmp.pklen != key->pklen || tmp.sklen != key->sklen ||
       XMEM_NEQ(tmp.pk, key->pk, key->pklen) != 0 ||
       XMEM_NEQ(tmp.sk, key->sk, key->sklen) != 0) {
      err = CRYPT_INVALID_PACKET;
   }
   mlkem_free(&tmp);
   return err;
}

/**
   Tell whether a key still has the seed it was generated from.
   @param key      The key to query (may be NULL)
   @return 1 if the key is private and still has its generation seed, 0 otherwise
*/
int mlkem_has_seed(const mlkem_key *key)
{
   if (key == NULL) return 0;
   return key->has_seed ? 1 : 0;
}

/**
   Export the 64-byte generation seed (d || z) of an ML-KEM private key.
   A seed cannot be computed back from the expanded key, so only generated keys and keys
   imported from the PKCS#8 seed or both form have one.
   @param out      [out] Destination for the seed
   @param outlen   [in/out] Max size and resulting size of the seed
   @param key      The private key to export the seed of
   @return CRYPT_OK if successful, CRYPT_PK_NOT_PRIVATE for a public key,
           CRYPT_PK_INVALID_TYPE if the key has no seed
*/
int mlkem_export_seed(unsigned char *out, unsigned long *outlen, const mlkem_key *key)
{
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   if (key->type != PK_PRIVATE) return CRYPT_PK_NOT_PRIVATE;
   if (!key->has_seed)          return CRYPT_PK_INVALID_TYPE;

   if (*outlen < LTC_MLKEM_KEYGEN_SEED_BYTES) {
      *outlen = LTC_MLKEM_KEYGEN_SEED_BYTES;
      return CRYPT_BUFFER_OVERFLOW;
   }
   XMEMCPY(out, key->seed, LTC_MLKEM_KEYGEN_SEED_BYTES);
   *outlen = LTC_MLKEM_KEYGEN_SEED_BYTES;

   return CRYPT_OK;
}

/**
   ML-KEM encapsulation: generate a shared secret and ciphertext from a public key.
   @param ct              [out] The ciphertext
   @param ctlen           [in/out] Max size and resulting size of the ciphertext
   @param shared_secret   [out] The shared secret (32 bytes)
   @param sslen           [in/out] Max size and resulting size of the shared secret
   @param prng            An active PRNG state
   @param wprng           The index of the desired PRNG
   @param key             The public (encapsulation) key
   @return CRYPT_OK if successful
*/
int mlkem_encaps(unsigned char *ct,            unsigned long *ctlen,
                 unsigned char *shared_secret, unsigned long *sslen,
                 prng_state    *prng,          int            wprng,
                 const mlkem_key *key)
{
   unsigned char coins[MLKEM_SYMBYTES];
   int err;

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) return err;
   if (prng_descriptor[wprng].read(coins, sizeof(coins), prng) != sizeof(coins)) {
      zeromem(coins, sizeof(coins));
      return CRYPT_ERROR_READPRNG;
   }

   err = mlkem_encaps_ex(ct, ctlen, shared_secret, sslen, coins, sizeof(coins), key);

   zeromem(coins, sizeof(coins));
   return err;
}

/**
   ML-KEM deterministic encapsulation (FIPS 203 6.2 ML-KEM.Encaps_internal).

   Like mlkem_encaps(), but the 32-byte entropy m comes from the caller. It is meant for KAT,
   ACVP and interoperability testing. ML-KEM is only secure if m is secret and unpredictable,
   so applications should call mlkem_encaps() and let the PRNG produce it.
   @param ct              [out] The ciphertext
   @param ctlen           [in/out] Max size and resulting size of the ciphertext
   @param shared_secret   [out] The shared secret (32 bytes)
   @param sslen           [in/out] Max size and resulting size of the shared secret
   @param m               The 32-byte encapsulation entropy
   @param mlen            Length of m in bytes; must equal 32
   @param key             The public (encapsulation) key
   @return CRYPT_OK if successful
*/
int mlkem_encaps_ex(unsigned char       *ct,            unsigned long *ctlen,
                    unsigned char       *shared_secret, unsigned long *sslen,
                    const unsigned char *m,             unsigned long  mlen,
                    const mlkem_key     *key)
{
   mlkem_params p;
   int err;

   LTC_ARGCHK(ct            != NULL);
   LTC_ARGCHK(ctlen         != NULL);
   LTC_ARGCHK(shared_secret != NULL);
   LTC_ARGCHK(sslen         != NULL);
   LTC_ARGCHK(m             != NULL);
   LTC_ARGCHK(key           != NULL);

   if (mlen != MLKEM_SYMBYTES) return CRYPT_INVALID_ARG;
   if ((err = s_mlkem_key_valid(key, 0, &p)) != CRYPT_OK) return err;
   if (*ctlen < p.ct_bytes)    { *ctlen = p.ct_bytes;    return CRYPT_BUFFER_OVERFLOW; }
   if (*sslen < MLKEM_SSBYTES) { *sslen = MLKEM_SSBYTES; return CRYPT_BUFFER_OVERFLOW; }

   if ((err = s_mlkem_kem_enc(ct, shared_secret, key->pk, m, &p)) != CRYPT_OK) {
      return err;
   }

   /* only advertise the lengths once the buffers really hold that much */
   *ctlen = p.ct_bytes;
   *sslen = MLKEM_SSBYTES;

   return CRYPT_OK;
}

/**
   ML-KEM decapsulation: recover a shared secret from a ciphertext using a private key.
   @param shared_secret   [out] The shared secret (32 bytes)
   @param sslen           [in/out] Max size and resulting size of the shared secret
   @param ct              The ciphertext
   @param ctlen           Length of the ciphertext
   @param key             The private (decapsulation) key
   @return CRYPT_OK if successful

   @note On implicit rejection (invalid ciphertext), a pseudorandom value is
         returned instead of an error, as required by the ML-KEM specification.
*/
int mlkem_decaps(unsigned char       *shared_secret, unsigned long *sslen,
                 const unsigned char *ct,            unsigned long  ctlen,
                 const mlkem_key     *key)
{
   mlkem_params p;
   int err;

   LTC_ARGCHK(shared_secret != NULL);
   LTC_ARGCHK(sslen         != NULL);
   LTC_ARGCHK(ct            != NULL);
   LTC_ARGCHK(key           != NULL);

   if ((err = s_mlkem_key_valid(key, 1, &p)) != CRYPT_OK) return err;
   if (ctlen != p.ct_bytes) return CRYPT_INVALID_PACKET;
   if (*sslen < MLKEM_SSBYTES) { *sslen = MLKEM_SSBYTES; return CRYPT_BUFFER_OVERFLOW; }

   if ((err = s_mlkem_kem_dec(shared_secret, ct, key->sk, &p)) != CRYPT_OK) {
      return err;
   }

   /* only advertise the length once the buffer really holds that much */
   *sslen = MLKEM_SSBYTES;

   return CRYPT_OK;
}

/**
   Get the sizes for a given ML-KEM parameter set.
   Any output pointer may be NULL if the caller does not need that value.
   @param alg              The parameter set (LTC_MLKEM_512, LTC_MLKEM_768, or LTC_MLKEM_1024)
   @param public_key_sz    [out] Public key size in bytes
   @param secret_key_sz    [out] Secret key size in bytes
   @param ciphertext_sz    [out] Ciphertext size in bytes
   @param shared_secret_sz [out] Shared secret size in bytes (always 32)
   @param keygen_seed_sz   [out] Seed size in bytes for mlkem_make_key_from_seed (always 64)
   @param encaps_entropy_sz [out] Size in bytes of m for mlkem_encaps_ex (always 32)
   @return CRYPT_OK if successful
*/
int mlkem_get_sizes(int alg,
                    unsigned long *public_key_sz,
                    unsigned long *secret_key_sz,
                    unsigned long *ciphertext_sz,
                    unsigned long *shared_secret_sz,
                    unsigned long *keygen_seed_sz,
                    unsigned long *encaps_entropy_sz)
{
   mlkem_params p;
   int err;

   if ((err = s_mlkem_get_params(alg, &p)) != CRYPT_OK) return err;

   if (public_key_sz != NULL)      *public_key_sz      = p.pk_bytes;
   if (secret_key_sz != NULL)      *secret_key_sz      = p.sk_bytes;
   if (ciphertext_sz != NULL)      *ciphertext_sz      = p.ct_bytes;
   if (shared_secret_sz != NULL)   *shared_secret_sz   = MLKEM_SSBYTES;
   if (keygen_seed_sz != NULL)     *keygen_seed_sz     = LTC_MLKEM_KEYGEN_SEED_BYTES;
   if (encaps_entropy_sz != NULL)  *encaps_entropy_sz  = LTC_MLKEM_M_BYTES;

   return CRYPT_OK;
}

/* Algorithm name / OID lookup */

typedef struct {
   int alg;
   const char *name;
   const char *oid;
} mlkem_alg_entry;

static const mlkem_alg_entry s_mlkem_alg_table[] = {
   { LTC_MLKEM_512,  "ML-KEM-512",  "2.16.840.1.101.3.4.4.1" },
   { LTC_MLKEM_768,  "ML-KEM-768",  "2.16.840.1.101.3.4.4.2" },
   { LTC_MLKEM_1024, "ML-KEM-1024", "2.16.840.1.101.3.4.4.3" },
};

/**
   Resolve an ML-KEM parameter set from its FIPS 203 name or its dotted-decimal OID.
   Name matching is case-insensitive and ignores '-' and '_', so e.g.
   "ML-KEM-768", "ml_kem_768", and "MLKEM768" all resolve identically.
   @param name_or_oid   The canonical name (e.g. "ML-KEM-768") or the OID
                        string (e.g. "2.16.840.1.101.3.4.4.2")
   @param alg           [out] Matching ltc_mlkem_id value
   @return CRYPT_OK if a match was found, CRYPT_INVALID_ARG otherwise
*/
int mlkem_find_alg(const char *name_or_oid, int *alg)
{
   unsigned i;

   LTC_ARGCHK(name_or_oid != NULL);
   LTC_ARGCHK(alg         != NULL);

   for (i = 0; i < LTC_ARRAY_SIZE(s_mlkem_alg_table); ++i) {
      if (ltc_algname_match(s_mlkem_alg_table[i].name, name_or_oid) ||
          ltc_algname_match(s_mlkem_alg_table[i].oid,  name_or_oid)) {
         *alg = s_mlkem_alg_table[i].alg;
         return CRYPT_OK;
      }
   }
   return CRYPT_INVALID_ARG;
}

/**
   Get the canonical FIPS 203 name of an ML-KEM parameter set.
   @param alg    The parameter set (one of ltc_mlkem_id)
   @param name   [out] Pointer to a static, NUL-terminated name string
                 (e.g. "ML-KEM-768"); must not be freed by the caller
   @return CRYPT_OK if alg is valid, CRYPT_INVALID_ARG otherwise
*/
int mlkem_alg_name(int alg, const char **name)
{
   unsigned i;

   LTC_ARGCHK(name != NULL);

   for (i = 0; i < LTC_ARRAY_SIZE(s_mlkem_alg_table); ++i) {
      if (s_mlkem_alg_table[i].alg == alg) {
         *name = s_mlkem_alg_table[i].name;
         return CRYPT_OK;
      }
   }
   return CRYPT_INVALID_ARG;
}

#endif /* LTC_MLKEM */
