/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/**
  @file mldsa.c
  ML-DSA (FIPS 204) implementation: polynomial arithmetic, NTT, packing,
  signing, and verification.
  Based on the CRYSTALS-Dilithium reference implementation (public domain).

  Reviewed against the FIPS 204 errata of 2026-07-31.
*/

#include "tomcrypt_private.h"

#ifdef LTC_MLDSA

/* Constants */

#define MLDSA_N          256
#define MLDSA_Q          8380417
#define MLDSA_D          13
#define MLDSA_QINV       58728449   /* Q^{-1} mod 2^32 */

#define MLDSA_SEEDBYTES  32
#define MLDSA_CRHBYTES   64
#define MLDSA_TRBYTES    64
#define MLDSA_RNDBYTES   32

/* Limit for the signing rejection loop. FIPS 204 requires at least 821, normal signing needs a few. */
#define MLDSA_SIGN_MAX_REJECTIONS 1024u

LTC_STATIC_ASSERT(mldsa_keygen_seed_size, LTC_MLDSA_KEYGEN_SEED_BYTES == MLDSA_SEEDBYTES)
LTC_STATIC_ASSERT(mldsa_rnd_size, LTC_MLDSA_RND_BYTES == MLDSA_RNDBYTES)
LTC_STATIC_ASSERT(mldsa_mu_size, LTC_MLDSA_MU_BYTES == MLDSA_CRHBYTES)

#define MLDSA_K_MAX      8
#define MLDSA_L_MAX      7

#define MLDSA_POLYT1_PACKEDBYTES  320
#define MLDSA_POLYT0_PACKEDBYTES  416

#define MLDSA_SHAKE128_RATE  168
#define MLDSA_SHAKE256_RATE  136

/* Runtime parameter set */

typedef struct {
   int k, l, eta, tau, omega;
   int beta;
   int gamma1, gamma2;
   int ctilde_bytes;
   unsigned long polyz_packed, polyw1_packed, polyeta_packed;
   unsigned long pk_bytes, sk_bytes, sig_bytes;
} mldsa_params;

/* Polynomial types */

typedef struct {
   int coeffs[MLDSA_N];
} mldsa_poly;

typedef struct {
   mldsa_poly vec[MLDSA_L_MAX];
} mldsa_polyvecl;

typedef struct {
   mldsa_poly vec[MLDSA_K_MAX];
} mldsa_polyveck;

/* Montgomery / Barrett reduction */

static int s_mldsa_montgomery_reduce(long64 a)
{
   int t;
   t = (long64)(int)a * MLDSA_QINV;
   t = (a - (long64)t * MLDSA_Q) >> 32;
   return t;
}

static int s_mldsa_reduce32(int a)
{
   int t;
   t = (a + (1 << 22)) >> 23;
   t = a - t * MLDSA_Q;
   return t;
}

static int s_mldsa_caddq(int a)
{
   a += (a >> 31) & MLDSA_Q;
   return a;
}


/* NTT */

static const int s_mldsa_zetas[MLDSA_N] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

static void s_mldsa_ntt(int a[MLDSA_N])
{
   unsigned int len, start, j, k;
   int zeta, t;

   k = 0;
   for (len = 128; len > 0; len >>= 1) {
      for (start = 0; start < (unsigned)MLDSA_N; start = j + len) {
         zeta = s_mldsa_zetas[++k];
         for (j = start; j < start + len; ++j) {
            t = s_mldsa_montgomery_reduce((long64)zeta * a[j + len]);
            a[j + len] = a[j] - t;
            a[j] = a[j] + t;
         }
      }
   }
}

static void s_mldsa_invntt_tomont(int a[MLDSA_N])
{
   unsigned int start, len, j, k;
   int t, zeta;
   const int f = 41978; /* mont^2/256 */

   k = 256;
   for (len = 1; len < (unsigned)MLDSA_N; len <<= 1) {
      for (start = 0; start < (unsigned)MLDSA_N; start = j + len) {
         zeta = -s_mldsa_zetas[--k];
         for (j = start; j < start + len; ++j) {
            t = a[j];
            a[j] = t + a[j + len];
            a[j + len] = t - a[j + len];
            a[j + len] = s_mldsa_montgomery_reduce((long64)zeta * a[j + len]);
         }
      }
   }

   for (j = 0; j < (unsigned)MLDSA_N; ++j) {
      a[j] = s_mldsa_montgomery_reduce((long64)f * a[j]);
   }
}

/* Rounding */

static int s_power2round(int *a0, int a)
{
   int a1;
   a1 = (a + (1 << (MLDSA_D - 1)) - 1) >> MLDSA_D;
   *a0 = a - (a1 << MLDSA_D);
   return a1;
}

static int s_decompose(int *a0, int a, int gamma2)
{
   int a1;

   a1 = (a + 127) >> 7;
   if (gamma2 == (MLDSA_Q - 1) / 32) {
      a1 = (a1 * 1025 + (1 << 21)) >> 22;
      a1 &= 15;
   }
   else {
      /* gamma2 == (MLDSA_Q - 1) / 88 */
      a1 = (a1 * 11275 + (1 << 23)) >> 24;
      a1 ^= ((43 - a1) >> 31) & a1;
   }

   *a0 = a - a1 * 2 * gamma2;
   *a0 -= (((MLDSA_Q - 1) / 2 - *a0) >> 31) & MLDSA_Q;
   return a1;
}

static unsigned int s_make_hint(int a0, int a1, int gamma2)
{
   if (a0 > gamma2 || a0 < -gamma2 || (a0 == -gamma2 && a1 != 0))
      return 1;
   return 0;
}

static int s_use_hint(int a, unsigned int hint, int gamma2)
{
   int a0, a1;

   a1 = s_decompose(&a0, a, gamma2);
   if (hint == 0)
      return a1;

   if (gamma2 == (MLDSA_Q - 1) / 32) {
      if (a0 > 0)
         return (a1 + 1) & 15;
      else
         return (a1 - 1) & 15;
   }
   else {
      /* gamma2 == (MLDSA_Q - 1) / 88 */
      if (a0 > 0)
         return (a1 == 43) ? 0 : a1 + 1;
      else
         return (a1 == 0) ? 43 : a1 - 1;
   }
}

/* Parameter lookup */

static int s_mldsa_get_params(int alg, mldsa_params *p)
{
   LTC_ARGCHK(p != NULL);

   XMEMSET(p, 0, sizeof(*p));

   switch (alg) {
      case LTC_MLDSA_44:
         p->k = 4; p->l = 4; p->eta = 2; p->tau = 39;
         p->beta = 78; p->gamma1 = (1 << 17);
         p->gamma2 = (MLDSA_Q - 1) / 88; p->omega = 80;
         p->ctilde_bytes = 32;
         break;
      case LTC_MLDSA_65:
         p->k = 6; p->l = 5; p->eta = 4; p->tau = 49;
         p->beta = 196; p->gamma1 = (1 << 19);
         p->gamma2 = (MLDSA_Q - 1) / 32; p->omega = 55;
         p->ctilde_bytes = 48;
         break;
      case LTC_MLDSA_87:
         p->k = 8; p->l = 7; p->eta = 2; p->tau = 60;
         p->beta = 120; p->gamma1 = (1 << 19);
         p->gamma2 = (MLDSA_Q - 1) / 32; p->omega = 75;
         p->ctilde_bytes = 64;
         break;
      default:
         return CRYPT_INVALID_ARG;
   }

   p->polyz_packed   = (p->gamma1 == (1 << 17)) ? 576u : 640u;
   p->polyw1_packed  = (p->gamma2 == (MLDSA_Q - 1) / 88) ? 192u : 128u;
   p->polyeta_packed = (p->eta == 2) ? 96u : 128u;
   p->pk_bytes = MLDSA_SEEDBYTES + (unsigned long)p->k * MLDSA_POLYT1_PACKEDBYTES;
   p->sk_bytes = 2u * MLDSA_SEEDBYTES + MLDSA_TRBYTES
               + (unsigned long)p->l * p->polyeta_packed
               + (unsigned long)p->k * p->polyeta_packed
               + (unsigned long)p->k * MLDSA_POLYT0_PACKEDBYTES;
   p->sig_bytes = (unsigned long)p->ctilde_bytes
                + (unsigned long)p->l * p->polyz_packed
                + (unsigned long)p->omega + (unsigned long)p->k;

   return CRYPT_OK;
}

/* Symmetric primitives using libtomcrypt SHA3 */

static int s_shake256(unsigned char *out, unsigned long outlen,
                      const unsigned char *in, unsigned long inlen)
{
   int err;
   hash_state md;

   if ((err = sha3_shake_init(&md, 256)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&md, in, inlen)) != CRYPT_OK) goto LBL_ERR;
   err = sha3_shake_done(&md, out, outlen);

LBL_ERR:
   zeromem(&md.sha3, sizeof(md.sha3));
   return err;
}

static int s_shake128_stream_init(hash_state *state,
                                  const unsigned char seed[MLDSA_SEEDBYTES],
                                  unsigned int nonce)
{
   int err;
   unsigned char t[2];
   t[0] = (unsigned char)(nonce & 0xff);
   t[1] = (unsigned char)(nonce >> 8);

   if ((err = sha3_shake_init(state, 128)) != CRYPT_OK) return err;
   if ((err = sha3_shake_process(state, seed, MLDSA_SEEDBYTES)) != CRYPT_OK) return err;
   return sha3_shake_process(state, t, 2);
}

static int s_shake256_stream_init(hash_state *state,
                                  const unsigned char *seed,
                                  unsigned long seedlen,
                                  unsigned int nonce)
{
   int err;
   unsigned char t[2];
   t[0] = (unsigned char)(nonce & 0xff);
   t[1] = (unsigned char)(nonce >> 8);

   if ((err = sha3_shake_init(state, 256)) != CRYPT_OK) return err;
   if ((err = sha3_shake_process(state, seed, seedlen)) != CRYPT_OK) return err;
   return sha3_shake_process(state, t, 2);
}

/* Poly operations */

static void s_mldsa_poly_reduce(mldsa_poly *a)
{
   unsigned int i;
   for (i = 0; i < MLDSA_N; ++i)
      a->coeffs[i] = s_mldsa_reduce32(a->coeffs[i]);
}

static void s_poly_caddq(mldsa_poly *a)
{
   unsigned int i;
   for (i = 0; i < MLDSA_N; ++i)
      a->coeffs[i] = s_mldsa_caddq(a->coeffs[i]);
}

static void s_mldsa_poly_add(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b)
{
   unsigned int i;
   for (i = 0; i < MLDSA_N; ++i)
      c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

static void s_mldsa_poly_sub(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b)
{
   unsigned int i;
   for (i = 0; i < MLDSA_N; ++i)
      c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

static void s_poly_shiftl(mldsa_poly *a)
{
   unsigned int i;
   for (i = 0; i < MLDSA_N; ++i)
      a->coeffs[i] <<= MLDSA_D;
}

static void s_mldsa_poly_ntt(mldsa_poly *a)
{
   s_mldsa_ntt(a->coeffs);
}

static void s_mldsa_poly_invntt_tomont(mldsa_poly *a)
{
   s_mldsa_invntt_tomont(a->coeffs);
}

static void s_poly_pointwise_montgomery(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b)
{
   unsigned int i;
   for (i = 0; i < MLDSA_N; ++i)
      c->coeffs[i] = s_mldsa_montgomery_reduce((long64)a->coeffs[i] * b->coeffs[i]);
}

static void s_poly_power2round(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a)
{
   unsigned int i;
   for (i = 0; i < MLDSA_N; ++i)
      a1->coeffs[i] = s_power2round(&a0->coeffs[i], a->coeffs[i]);
}

static void s_poly_decompose(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a, int gamma2)
{
   unsigned int i;
   for (i = 0; i < MLDSA_N; ++i)
      a1->coeffs[i] = s_decompose(&a0->coeffs[i], a->coeffs[i], gamma2);
}

static unsigned int s_poly_make_hint(mldsa_poly *h, const mldsa_poly *a0,
                                     const mldsa_poly *a1, int gamma2)
{
   unsigned int i, s = 0;
   for (i = 0; i < MLDSA_N; ++i) {
      h->coeffs[i] = s_make_hint(a0->coeffs[i], a1->coeffs[i], gamma2);
      s += h->coeffs[i];
   }
   return s;
}

static void s_poly_use_hint(mldsa_poly *b, const mldsa_poly *a, const mldsa_poly *h, int gamma2)
{
   unsigned int i;
   for (i = 0; i < MLDSA_N; ++i)
      b->coeffs[i] = s_use_hint(a->coeffs[i], h->coeffs[i], gamma2);
}

static int s_poly_chknorm(const mldsa_poly *a, int B)
{
   unsigned int i;
   int t;

   if (B > (MLDSA_Q - 1) / 8)
      return 1;

   for (i = 0; i < MLDSA_N; ++i) {
      t = a->coeffs[i] >> 31;
      t = a->coeffs[i] - (t & 2 * a->coeffs[i]);
      if (t >= B)
         return 1;
   }
   return 0;
}

/* Sampling */

static unsigned int s_rej_uniform(int *a, unsigned int len,
                                  const unsigned char *buf, unsigned int buflen)
{
   unsigned int ctr, pos;
   ulong32 t;

   ctr = pos = 0;
   while (ctr < len && pos + 3 <= buflen) {
      t  = buf[pos++];
      t |= (ulong32)buf[pos++] << 8;
      t |= (ulong32)buf[pos++] << 16;
      t &= 0x7FFFFF;

      if (t < (ulong32)MLDSA_Q)
         a[ctr++] = (int)t;
   }

   return ctr;
}

static int s_poly_uniform(mldsa_poly *a, const unsigned char seed[MLDSA_SEEDBYTES],
                          unsigned int nonce)
{
   unsigned int ctr, off, i;
   /* SHAKE128 rate = 168. We need ceil(768/168)=5 blocks initially */
   #define S_POLY_UNIFORM_NBLOCKS ((768 + MLDSA_SHAKE128_RATE - 1) / MLDSA_SHAKE128_RATE)
   unsigned int buflen = S_POLY_UNIFORM_NBLOCKS * MLDSA_SHAKE128_RATE;
   unsigned char buf[S_POLY_UNIFORM_NBLOCKS * MLDSA_SHAKE128_RATE + 2];
   hash_state state;
   int err;

   if ((err = s_shake128_stream_init(&state, seed, nonce)) != CRYPT_OK) return err;
   if ((err = sha3_shake_done(&state, buf, buflen)) != CRYPT_OK) return err;

   ctr = s_rej_uniform(a->coeffs, MLDSA_N, buf, buflen);

   while (ctr < MLDSA_N) {
      off = buflen % 3;
      for (i = 0; i < off; ++i)
         buf[i] = buf[buflen - off + i];

      /* sha3_shake_done supports incremental squeezing */
      if ((err = sha3_shake_done(&state, buf + off, MLDSA_SHAKE128_RATE)) != CRYPT_OK) return err;
      buflen = MLDSA_SHAKE128_RATE + off;
      ctr += s_rej_uniform(a->coeffs + ctr, MLDSA_N - ctr, buf, buflen);
   }
   #undef S_POLY_UNIFORM_NBLOCKS

   return CRYPT_OK;
}

static unsigned int s_rej_eta(int *a, unsigned int len,
                              const unsigned char *buf, unsigned int buflen,
                              int eta)
{
   unsigned int ctr, pos;
   ulong32 t0, t1;

   ctr = pos = 0;
   while (ctr < len && pos < buflen) {
      t0 = buf[pos] & 0x0F;
      t1 = buf[pos++] >> 4;

      if (eta == 2) {
         if (t0 < 15) {
            t0 = t0 - (205 * t0 >> 10) * 5;
            a[ctr++] = 2 - (int)t0;
         }
         if (t1 < 15 && ctr < len) {
            t1 = t1 - (205 * t1 >> 10) * 5;
            a[ctr++] = 2 - (int)t1;
         }
      }
      else {
         /* eta == 4 */
         if (t0 < 9)
            a[ctr++] = 4 - (int)t0;
         if (t1 < 9 && ctr < len)
            a[ctr++] = 4 - (int)t1;
      }
   }

   return ctr;
}

static int s_poly_uniform_eta(mldsa_poly *a, const unsigned char seed[MLDSA_CRHBYTES],
                              unsigned int nonce, int eta)
{
   unsigned int ctr;
   /* For eta==2: need 136 bytes. For eta==4: need 227 bytes. ceil(227/136)=2 blocks of SHAKE256 (rate 136) = 272 bytes max */
   unsigned char buf[2 * MLDSA_SHAKE256_RATE];
   unsigned int buflen;
   hash_state state;
   int err;

   if (eta == 2)
      buflen = 136;
   else
      buflen = 227;

   if ((err = s_shake256_stream_init(&state, seed, MLDSA_CRHBYTES, nonce)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_done(&state, buf, buflen)) != CRYPT_OK) goto LBL_ERR;

   ctr = s_rej_eta(a->coeffs, MLDSA_N, buf, buflen, eta);

   while (ctr < MLDSA_N) {
      /* sha3_shake_done supports incremental squeezing */
      if ((err = sha3_shake_done(&state, buf, MLDSA_SHAKE256_RATE)) != CRYPT_OK) goto LBL_ERR;
      ctr += s_rej_eta(a->coeffs + ctr, MLDSA_N - ctr, buf, MLDSA_SHAKE256_RATE, eta);
   }

   err = CRYPT_OK;

LBL_ERR:
   zeromem(buf, sizeof(buf));
   zeromem(&state.sha3, sizeof(state.sha3));
   return err;
}

/* Polynomial packing */

static void s_polyeta_pack(unsigned char *r, const mldsa_poly *a, int eta)
{
   unsigned int i;
   unsigned char t[8];

   if (eta == 2) {
      for (i = 0; i < MLDSA_N / 8; ++i) {
         t[0] = (unsigned char)(eta - a->coeffs[8 * i + 0]);
         t[1] = (unsigned char)(eta - a->coeffs[8 * i + 1]);
         t[2] = (unsigned char)(eta - a->coeffs[8 * i + 2]);
         t[3] = (unsigned char)(eta - a->coeffs[8 * i + 3]);
         t[4] = (unsigned char)(eta - a->coeffs[8 * i + 4]);
         t[5] = (unsigned char)(eta - a->coeffs[8 * i + 5]);
         t[6] = (unsigned char)(eta - a->coeffs[8 * i + 6]);
         t[7] = (unsigned char)(eta - a->coeffs[8 * i + 7]);

         r[3 * i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
         r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
         r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
      }
   }
   else {
      /* eta == 4 */
      for (i = 0; i < MLDSA_N / 2; ++i) {
         t[0] = (unsigned char)(eta - a->coeffs[2 * i + 0]);
         t[1] = (unsigned char)(eta - a->coeffs[2 * i + 1]);
         r[i] = t[0] | (t[1] << 4);
      }
   }
   zeromem(t, sizeof(t));
}

/* FIPS 204 3.6.3: s1, s2 coefficients must lie in [-eta, +eta]. The packed encoding uses bitlen(2*eta) bits per
   coefficient, which is a strict superset of the spec range, so we range-check on unpack and reject malformed keys. */
static int s_polyeta_unpack(mldsa_poly *r, const unsigned char *a, int eta)
{
   unsigned int i, j;

   if (eta == 2) {
      for (i = 0; i < MLDSA_N / 8; ++i) {
         r->coeffs[8 * i + 0] =  (a[3 * i + 0] >> 0) & 7;
         r->coeffs[8 * i + 1] =  (a[3 * i + 0] >> 3) & 7;
         r->coeffs[8 * i + 2] = ((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7;
         r->coeffs[8 * i + 3] =  (a[3 * i + 1] >> 1) & 7;
         r->coeffs[8 * i + 4] =  (a[3 * i + 1] >> 4) & 7;
         r->coeffs[8 * i + 5] = ((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7;
         r->coeffs[8 * i + 6] =  (a[3 * i + 2] >> 2) & 7;
         r->coeffs[8 * i + 7] =  (a[3 * i + 2] >> 5) & 7;

         r->coeffs[8 * i + 0] = eta - r->coeffs[8 * i + 0];
         r->coeffs[8 * i + 1] = eta - r->coeffs[8 * i + 1];
         r->coeffs[8 * i + 2] = eta - r->coeffs[8 * i + 2];
         r->coeffs[8 * i + 3] = eta - r->coeffs[8 * i + 3];
         r->coeffs[8 * i + 4] = eta - r->coeffs[8 * i + 4];
         r->coeffs[8 * i + 5] = eta - r->coeffs[8 * i + 5];
         r->coeffs[8 * i + 6] = eta - r->coeffs[8 * i + 6];
         r->coeffs[8 * i + 7] = eta - r->coeffs[8 * i + 7];
      }
   }
   else {
      /* eta == 4 */
      for (i = 0; i < MLDSA_N / 2; ++i) {
         r->coeffs[2 * i + 0] = a[i] & 0x0F;
         r->coeffs[2 * i + 1] = a[i] >> 4;
         r->coeffs[2 * i + 0] = eta - r->coeffs[2 * i + 0];
         r->coeffs[2 * i + 1] = eta - r->coeffs[2 * i + 1];
      }
   }

   for (j = 0; j < MLDSA_N; ++j) {
      if (r->coeffs[j] < -eta || r->coeffs[j] > eta) return CRYPT_INVALID_PACKET;
   }
   return CRYPT_OK;
}

static void s_polyt1_pack(unsigned char *r, const mldsa_poly *a)
{
   unsigned int i;

   for (i = 0; i < MLDSA_N / 4; ++i) {
      r[5 * i + 0] = (unsigned char)(a->coeffs[4 * i + 0] >> 0);
      r[5 * i + 1] = (unsigned char)((a->coeffs[4 * i + 0] >> 8) | (a->coeffs[4 * i + 1] << 2));
      r[5 * i + 2] = (unsigned char)((a->coeffs[4 * i + 1] >> 6) | (a->coeffs[4 * i + 2] << 4));
      r[5 * i + 3] = (unsigned char)((a->coeffs[4 * i + 2] >> 4) | (a->coeffs[4 * i + 3] << 6));
      r[5 * i + 4] = (unsigned char)(a->coeffs[4 * i + 3] >> 2);
   }
}

static void s_polyt1_unpack(mldsa_poly *r, const unsigned char *a)
{
   unsigned int i;

   for (i = 0; i < MLDSA_N / 4; ++i) {
      r->coeffs[4 * i + 0] = ((a[5 * i + 0] >> 0) | ((ulong32)a[5 * i + 1] << 8)) & 0x3FF;
      r->coeffs[4 * i + 1] = ((a[5 * i + 1] >> 2) | ((ulong32)a[5 * i + 2] << 6)) & 0x3FF;
      r->coeffs[4 * i + 2] = ((a[5 * i + 2] >> 4) | ((ulong32)a[5 * i + 3] << 4)) & 0x3FF;
      r->coeffs[4 * i + 3] = ((a[5 * i + 3] >> 6) | ((ulong32)a[5 * i + 4] << 2)) & 0x3FF;
   }
}

static void s_polyt0_pack(unsigned char *r, const mldsa_poly *a)
{
   unsigned int i;
   ulong32 t[8];

   for (i = 0; i < MLDSA_N / 8; ++i) {
      t[0] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 0];
      t[1] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 1];
      t[2] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 2];
      t[3] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 3];
      t[4] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 4];
      t[5] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 5];
      t[6] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 6];
      t[7] = (1 << (MLDSA_D - 1)) - a->coeffs[8 * i + 7];

      r[13 * i +  0]  =  (unsigned char)(t[0]);
      r[13 * i +  1]  =  (unsigned char)(t[0] >>  8);
      r[13 * i +  1] |=  (unsigned char)(t[1] <<  5);
      r[13 * i +  2]  =  (unsigned char)(t[1] >>  3);
      r[13 * i +  3]  =  (unsigned char)(t[1] >> 11);
      r[13 * i +  3] |=  (unsigned char)(t[2] <<  2);
      r[13 * i +  4]  =  (unsigned char)(t[2] >>  6);
      r[13 * i +  4] |=  (unsigned char)(t[3] <<  7);
      r[13 * i +  5]  =  (unsigned char)(t[3] >>  1);
      r[13 * i +  6]  =  (unsigned char)(t[3] >>  9);
      r[13 * i +  6] |=  (unsigned char)(t[4] <<  4);
      r[13 * i +  7]  =  (unsigned char)(t[4] >>  4);
      r[13 * i +  8]  =  (unsigned char)(t[4] >> 12);
      r[13 * i +  8] |=  (unsigned char)(t[5] <<  1);
      r[13 * i +  9]  =  (unsigned char)(t[5] >>  7);
      r[13 * i +  9] |=  (unsigned char)(t[6] <<  6);
      r[13 * i + 10]  =  (unsigned char)(t[6] >>  2);
      r[13 * i + 11]  =  (unsigned char)(t[6] >> 10);
      r[13 * i + 11] |=  (unsigned char)(t[7] <<  3);
      r[13 * i + 12]  =  (unsigned char)(t[7] >>  5);
   }
   zeromem(t, sizeof(t));
}

static void s_polyt0_unpack(mldsa_poly *r, const unsigned char *a)
{
   unsigned int i;

   for (i = 0; i < MLDSA_N / 8; ++i) {
      r->coeffs[8 * i + 0]  = a[13 * i + 0];
      r->coeffs[8 * i + 0] |= (ulong32)a[13 * i + 1] << 8;
      r->coeffs[8 * i + 0] &= 0x1FFF;

      r->coeffs[8 * i + 1]  = a[13 * i + 1] >> 5;
      r->coeffs[8 * i + 1] |= (ulong32)a[13 * i + 2] << 3;
      r->coeffs[8 * i + 1] |= (ulong32)a[13 * i + 3] << 11;
      r->coeffs[8 * i + 1] &= 0x1FFF;

      r->coeffs[8 * i + 2]  = a[13 * i + 3] >> 2;
      r->coeffs[8 * i + 2] |= (ulong32)a[13 * i + 4] << 6;
      r->coeffs[8 * i + 2] &= 0x1FFF;

      r->coeffs[8 * i + 3]  = a[13 * i + 4] >> 7;
      r->coeffs[8 * i + 3] |= (ulong32)a[13 * i + 5] << 1;
      r->coeffs[8 * i + 3] |= (ulong32)a[13 * i + 6] << 9;
      r->coeffs[8 * i + 3] &= 0x1FFF;

      r->coeffs[8 * i + 4]  = a[13 * i + 6] >> 4;
      r->coeffs[8 * i + 4] |= (ulong32)a[13 * i + 7] << 4;
      r->coeffs[8 * i + 4] |= (ulong32)a[13 * i + 8] << 12;
      r->coeffs[8 * i + 4] &= 0x1FFF;

      r->coeffs[8 * i + 5]  = a[13 * i + 8] >> 1;
      r->coeffs[8 * i + 5] |= (ulong32)a[13 * i + 9] << 7;
      r->coeffs[8 * i + 5] &= 0x1FFF;

      r->coeffs[8 * i + 6]  = a[13 * i + 9] >> 6;
      r->coeffs[8 * i + 6] |= (ulong32)a[13 * i + 10] << 2;
      r->coeffs[8 * i + 6] |= (ulong32)a[13 * i + 11] << 10;
      r->coeffs[8 * i + 6] &= 0x1FFF;

      r->coeffs[8 * i + 7]  = a[13 * i + 11] >> 3;
      r->coeffs[8 * i + 7] |= (ulong32)a[13 * i + 12] << 5;
      r->coeffs[8 * i + 7] &= 0x1FFF;

      r->coeffs[8 * i + 0] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 0];
      r->coeffs[8 * i + 1] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 1];
      r->coeffs[8 * i + 2] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 2];
      r->coeffs[8 * i + 3] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 3];
      r->coeffs[8 * i + 4] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 4];
      r->coeffs[8 * i + 5] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 5];
      r->coeffs[8 * i + 6] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 6];
      r->coeffs[8 * i + 7] = (1 << (MLDSA_D - 1)) - r->coeffs[8 * i + 7];
   }
}

static void s_polyz_pack(unsigned char *r, const mldsa_poly *a, int gamma1)
{
   unsigned int i;
   ulong32 t[4];

   if (gamma1 == (1 << 17)) {
      for (i = 0; i < MLDSA_N / 4; ++i) {
         t[0] = gamma1 - a->coeffs[4 * i + 0];
         t[1] = gamma1 - a->coeffs[4 * i + 1];
         t[2] = gamma1 - a->coeffs[4 * i + 2];
         t[3] = gamma1 - a->coeffs[4 * i + 3];

         r[9 * i + 0]  = (unsigned char)(t[0]);
         r[9 * i + 1]  = (unsigned char)(t[0] >> 8);
         r[9 * i + 2]  = (unsigned char)(t[0] >> 16);
         r[9 * i + 2] |= (unsigned char)(t[1] << 2);
         r[9 * i + 3]  = (unsigned char)(t[1] >> 6);
         r[9 * i + 4]  = (unsigned char)(t[1] >> 14);
         r[9 * i + 4] |= (unsigned char)(t[2] << 4);
         r[9 * i + 5]  = (unsigned char)(t[2] >> 4);
         r[9 * i + 6]  = (unsigned char)(t[2] >> 12);
         r[9 * i + 6] |= (unsigned char)(t[3] << 6);
         r[9 * i + 7]  = (unsigned char)(t[3] >> 2);
         r[9 * i + 8]  = (unsigned char)(t[3] >> 10);
      }
   }
   else {
      /* gamma1 == (1 << 19) */
      for (i = 0; i < MLDSA_N / 2; ++i) {
         t[0] = gamma1 - a->coeffs[2 * i + 0];
         t[1] = gamma1 - a->coeffs[2 * i + 1];

         r[5 * i + 0]  = (unsigned char)(t[0]);
         r[5 * i + 1]  = (unsigned char)(t[0] >> 8);
         r[5 * i + 2]  = (unsigned char)(t[0] >> 16);
         r[5 * i + 2] |= (unsigned char)(t[1] << 4);
         r[5 * i + 3]  = (unsigned char)(t[1] >> 4);
         r[5 * i + 4]  = (unsigned char)(t[1] >> 12);
      }
   }
   zeromem(t, sizeof(t));
}

static void s_polyz_unpack(mldsa_poly *r, const unsigned char *a, int gamma1)
{
   unsigned int i;

   if (gamma1 == (1 << 17)) {
      for (i = 0; i < MLDSA_N / 4; ++i) {
         r->coeffs[4 * i + 0]  = a[9 * i + 0];
         r->coeffs[4 * i + 0] |= (ulong32)a[9 * i + 1] << 8;
         r->coeffs[4 * i + 0] |= (ulong32)a[9 * i + 2] << 16;
         r->coeffs[4 * i + 0] &= 0x3FFFF;

         r->coeffs[4 * i + 1]  = a[9 * i + 2] >> 2;
         r->coeffs[4 * i + 1] |= (ulong32)a[9 * i + 3] << 6;
         r->coeffs[4 * i + 1] |= (ulong32)a[9 * i + 4] << 14;
         r->coeffs[4 * i + 1] &= 0x3FFFF;

         r->coeffs[4 * i + 2]  = a[9 * i + 4] >> 4;
         r->coeffs[4 * i + 2] |= (ulong32)a[9 * i + 5] << 4;
         r->coeffs[4 * i + 2] |= (ulong32)a[9 * i + 6] << 12;
         r->coeffs[4 * i + 2] &= 0x3FFFF;

         r->coeffs[4 * i + 3]  = a[9 * i + 6] >> 6;
         r->coeffs[4 * i + 3] |= (ulong32)a[9 * i + 7] << 2;
         r->coeffs[4 * i + 3] |= (ulong32)a[9 * i + 8] << 10;
         r->coeffs[4 * i + 3] &= 0x3FFFF;

         r->coeffs[4 * i + 0] = gamma1 - r->coeffs[4 * i + 0];
         r->coeffs[4 * i + 1] = gamma1 - r->coeffs[4 * i + 1];
         r->coeffs[4 * i + 2] = gamma1 - r->coeffs[4 * i + 2];
         r->coeffs[4 * i + 3] = gamma1 - r->coeffs[4 * i + 3];
      }
   }
   else {
      /* gamma1 == (1 << 19) */
      for (i = 0; i < MLDSA_N / 2; ++i) {
         r->coeffs[2 * i + 0]  = a[5 * i + 0];
         r->coeffs[2 * i + 0] |= (ulong32)a[5 * i + 1] << 8;
         r->coeffs[2 * i + 0] |= (ulong32)a[5 * i + 2] << 16;
         r->coeffs[2 * i + 0] &= 0xFFFFF;

         r->coeffs[2 * i + 1]  = a[5 * i + 2] >> 4;
         r->coeffs[2 * i + 1] |= (ulong32)a[5 * i + 3] << 4;
         r->coeffs[2 * i + 1] |= (ulong32)a[5 * i + 4] << 12;
         r->coeffs[2 * i + 1] &= 0xFFFFF;

         r->coeffs[2 * i + 0] = gamma1 - r->coeffs[2 * i + 0];
         r->coeffs[2 * i + 1] = gamma1 - r->coeffs[2 * i + 1];
      }
   }
}

static void s_polyw1_pack(unsigned char *r, const mldsa_poly *a, int gamma2)
{
   unsigned int i;

   if (gamma2 == (MLDSA_Q - 1) / 88) {
      for (i = 0; i < MLDSA_N / 4; ++i) {
         r[3 * i + 0]  = (unsigned char)(a->coeffs[4 * i + 0]);
         r[3 * i + 0] |= (unsigned char)(a->coeffs[4 * i + 1] << 6);
         r[3 * i + 1]  = (unsigned char)(a->coeffs[4 * i + 1] >> 2);
         r[3 * i + 1] |= (unsigned char)(a->coeffs[4 * i + 2] << 4);
         r[3 * i + 2]  = (unsigned char)(a->coeffs[4 * i + 2] >> 4);
         r[3 * i + 2] |= (unsigned char)(a->coeffs[4 * i + 3] << 2);
      }
   }
   else {
      /* gamma2 == (MLDSA_Q - 1) / 32 */
      for (i = 0; i < MLDSA_N / 2; ++i)
         r[i] = (unsigned char)(a->coeffs[2 * i + 0] | (a->coeffs[2 * i + 1] << 4));
   }
}

/* Now implement s_poly_uniform_gamma1 */
static int s_poly_uniform_gamma1(mldsa_poly *a, const unsigned char seed[MLDSA_CRHBYTES],
                                 unsigned int nonce, const mldsa_params *p)
{
   /* polyz_packed bytes: 576 or 640. SHAKE256 rate=136. ceil(640/136) = 5 blocks = 680 bytes max */
   unsigned char buf[5 * MLDSA_SHAKE256_RATE];
   unsigned int buflen;
   hash_state state;
   int err;

   buflen = (unsigned int)p->polyz_packed;
   if (buflen > sizeof(buf))
      buflen = sizeof(buf);

   if ((err = s_shake256_stream_init(&state, seed, MLDSA_CRHBYTES, nonce)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_done(&state, buf, buflen)) != CRYPT_OK) goto LBL_ERR;

   s_polyz_unpack(a, buf, p->gamma1);
   err = CRYPT_OK;

LBL_ERR:
   zeromem(buf, sizeof(buf));
   zeromem(&state.sha3, sizeof(state.sha3));
   return err;
}

static int s_poly_challenge(mldsa_poly *c, const unsigned char *seed,
                            int ctilde_bytes, int tau)
{
   unsigned int i, b, pos;
   ulong64 signs;
   unsigned char buf[MLDSA_SHAKE256_RATE];
   hash_state state;
   int err;

   if ((err = sha3_shake_init(&state, 256)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&state, seed, ctilde_bytes)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_done(&state, buf, MLDSA_SHAKE256_RATE)) != CRYPT_OK) goto LBL_ERR;

   signs = 0;
   for (i = 0; i < 8; ++i)
      signs |= (ulong64)buf[i] << (8 * i);
   pos = 8;

   for (i = 0; i < MLDSA_N; ++i)
      c->coeffs[i] = 0;

   for (i = MLDSA_N - (unsigned int)tau; i < MLDSA_N; ++i) {
      do {
         if (pos >= MLDSA_SHAKE256_RATE) {
            /* sha3_shake_done supports incremental squeezing */
            if ((err = sha3_shake_done(&state, buf, MLDSA_SHAKE256_RATE)) != CRYPT_OK) goto LBL_ERR;
            pos = 0;
         }

         b = buf[pos++];
      } while (b > i);

      c->coeffs[i] = c->coeffs[b];
      c->coeffs[b] = 1 - 2 * (int)(signs & 1);
      signs >>= 1;
   }

   err = CRYPT_OK;

LBL_ERR:
   zeromem(buf, sizeof(buf));
   zeromem(&signs, sizeof(signs));
   zeromem(&state.sha3, sizeof(state.sha3));
   return err;
}

/* Polyvec operations (runtime k/l) */

/* mat is k*l polynomials in row-major order, only signing keeps the matrix around */
static int s_polyvec_matrix_expand(mldsa_poly *mat, int k, int l,
                                   const unsigned char rho[MLDSA_SEEDBYTES])
{
   int i, j, err;

   for (i = 0; i < k; ++i)
      for (j = 0; j < l; ++j) {
         if ((err = s_poly_uniform(&mat[i * l + j], rho, (unsigned int)((i << 8) + j))) != CRYPT_OK)
            return err;
      }

   return CRYPT_OK;
}

/**
 * Compute t = A*v with A expanded from rho one polynomial at a time.
 *
 * Equivalent to s_polyvec_matrix_expand() followed by s_polyvec_matrix_pointwise_montgomery(),
 * but keeps a single polynomial live instead of the whole k*l matrix. Use it wherever the
 * matrix is needed only once, it saves ~56 kB of stack.
 */
static int s_polyvec_matrix_expand_mul(mldsa_polyveck *t,
                                       const unsigned char rho[MLDSA_SEEDBYTES],
                                       const mldsa_polyvecl *v,
                                       int k, int l)
{
   int i, j, err;
   mldsa_poly a;

   for (i = 0; i < k; ++i) {
      for (j = 0; j < l; ++j) {
         if ((err = s_poly_uniform(&a, rho, (unsigned int)((i << 8) + j))) != CRYPT_OK) goto LBL_ERR;
         s_poly_pointwise_montgomery(&a, &a, &v->vec[j]);
         if (j == 0) {
            t->vec[i] = a;
         }
         else {
            s_mldsa_poly_add(&t->vec[i], &t->vec[i], &a);
         }
      }
   }

   err = CRYPT_OK;

LBL_ERR:
   zeromem(&a, sizeof(a));
   return err;
}

static void s_polyvec_matrix_pointwise_montgomery(mldsa_polyveck *t,
                                                  const mldsa_poly *mat,
                                                  const mldsa_polyvecl *v,
                                                  int k, int l)
{
   int i, j;
   mldsa_poly tmp;

   for (i = 0; i < k; ++i) {
      s_poly_pointwise_montgomery(&t->vec[i], &mat[i * l], &v->vec[0]);
      for (j = 1; j < l; ++j) {
         s_poly_pointwise_montgomery(&tmp, &mat[i * l + j], &v->vec[j]);
         s_mldsa_poly_add(&t->vec[i], &t->vec[i], &tmp);
      }
   }
   zeromem(&tmp, sizeof(tmp));
}

/* ---- polyvecl operations ---- */

static int s_polyvecl_uniform_eta(mldsa_polyvecl *v,
                                  const unsigned char seed[MLDSA_CRHBYTES],
                                  unsigned int nonce, int l, int eta)
{
   int i, err;
   for (i = 0; i < l; ++i) {
      if ((err = s_poly_uniform_eta(&v->vec[i], seed, nonce++, eta)) != CRYPT_OK)
         return err;
   }
   return CRYPT_OK;
}

static int s_polyvecl_uniform_gamma1(mldsa_polyvecl *v,
                                     const unsigned char seed[MLDSA_CRHBYTES],
                                     unsigned int nonce, int l,
                                     const mldsa_params *p)
{
   int i, err;
   for (i = 0; i < l; ++i) {
      if ((err = s_poly_uniform_gamma1(&v->vec[i], seed, (unsigned int)(l * nonce + i), p)) != CRYPT_OK)
         return err;
   }
   return CRYPT_OK;
}

static void s_polyvecl_reduce(mldsa_polyvecl *v, int l)
{
   int i;
   for (i = 0; i < l; ++i)
      s_mldsa_poly_reduce(&v->vec[i]);
}

static void s_polyvecl_add(mldsa_polyvecl *w, const mldsa_polyvecl *u,
                           const mldsa_polyvecl *v, int l)
{
   int i;
   for (i = 0; i < l; ++i)
      s_mldsa_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

static void s_polyvecl_ntt(mldsa_polyvecl *v, int l)
{
   int i;
   for (i = 0; i < l; ++i)
      s_mldsa_poly_ntt(&v->vec[i]);
}

static void s_polyvecl_invntt_tomont(mldsa_polyvecl *v, int l)
{
   int i;
   for (i = 0; i < l; ++i)
      s_mldsa_poly_invntt_tomont(&v->vec[i]);
}

static void s_polyvecl_pointwise_poly_montgomery(mldsa_polyvecl *r,
                                                  const mldsa_poly *a,
                                                  const mldsa_polyvecl *v, int l)
{
   int i;
   for (i = 0; i < l; ++i)
      s_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

static int s_polyvecl_chknorm(const mldsa_polyvecl *v, int bound, int l)
{
   int i;
   for (i = 0; i < l; ++i)
      if (s_poly_chknorm(&v->vec[i], bound))
         return 1;
   return 0;
}

/* ---- polyveck operations ---- */

static int s_polyveck_uniform_eta(mldsa_polyveck *v,
                                  const unsigned char seed[MLDSA_CRHBYTES],
                                  unsigned int nonce, int k, int eta)
{
   int i, err;
   for (i = 0; i < k; ++i) {
      if ((err = s_poly_uniform_eta(&v->vec[i], seed, nonce++, eta)) != CRYPT_OK)
         return err;
   }
   return CRYPT_OK;
}

static void s_polyveck_reduce(mldsa_polyveck *v, int k)
{
   int i;
   for (i = 0; i < k; ++i)
      s_mldsa_poly_reduce(&v->vec[i]);
}

static void s_polyveck_caddq(mldsa_polyveck *v, int k)
{
   int i;
   for (i = 0; i < k; ++i)
      s_poly_caddq(&v->vec[i]);
}

static void s_polyveck_add(mldsa_polyveck *w, const mldsa_polyveck *u,
                           const mldsa_polyveck *v, int k)
{
   int i;
   for (i = 0; i < k; ++i)
      s_mldsa_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

static void s_polyveck_sub(mldsa_polyveck *w, const mldsa_polyveck *u,
                           const mldsa_polyveck *v, int k)
{
   int i;
   for (i = 0; i < k; ++i)
      s_mldsa_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

static void s_polyveck_shiftl(mldsa_polyveck *v, int k)
{
   int i;
   for (i = 0; i < k; ++i)
      s_poly_shiftl(&v->vec[i]);
}

static void s_polyveck_ntt(mldsa_polyveck *v, int k)
{
   int i;
   for (i = 0; i < k; ++i)
      s_mldsa_poly_ntt(&v->vec[i]);
}

static void s_polyveck_invntt_tomont(mldsa_polyveck *v, int k)
{
   int i;
   for (i = 0; i < k; ++i)
      s_mldsa_poly_invntt_tomont(&v->vec[i]);
}

static void s_polyveck_pointwise_poly_montgomery(mldsa_polyveck *r,
                                                  const mldsa_poly *a,
                                                  const mldsa_polyveck *v, int k)
{
   int i;
   for (i = 0; i < k; ++i)
      s_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

static int s_polyveck_chknorm(const mldsa_polyveck *v, int bound, int k)
{
   int i;
   for (i = 0; i < k; ++i)
      if (s_poly_chknorm(&v->vec[i], bound))
         return 1;
   return 0;
}

static void s_polyveck_power2round(mldsa_polyveck *v1, mldsa_polyveck *v0,
                                   const mldsa_polyveck *v, int k)
{
   int i;
   for (i = 0; i < k; ++i)
      s_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

static void s_polyveck_decompose(mldsa_polyveck *v1, mldsa_polyveck *v0,
                                 const mldsa_polyveck *v, int k, int gamma2)
{
   int i;
   for (i = 0; i < k; ++i)
      s_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i], gamma2);
}

static unsigned int s_polyveck_make_hint(mldsa_polyveck *h,
                                         const mldsa_polyveck *v0,
                                         const mldsa_polyveck *v1,
                                         int k, int gamma2)
{
   unsigned int i, s = 0;
   for (i = 0; i < (unsigned)k; ++i)
      s += s_poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i], gamma2);
   return s;
}

static void s_polyveck_use_hint(mldsa_polyveck *w, const mldsa_polyveck *u,
                                const mldsa_polyveck *h, int k, int gamma2)
{
   int i;
   for (i = 0; i < k; ++i)
      s_poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i], gamma2);
}

static void s_polyveck_pack_w1(unsigned char *r, const mldsa_polyveck *w1,
                               int k, unsigned long polyw1_packed, int gamma2)
{
   int i;
   for (i = 0; i < k; ++i)
      s_polyw1_pack(r + (unsigned long)i * polyw1_packed, &w1->vec[i], gamma2);
}

/* Packing (key and signature) */

static void s_pack_pk(unsigned char *pk, const unsigned char rho[MLDSA_SEEDBYTES],
                      const mldsa_polyveck *t1, int k)
{
   unsigned int i;

   XMEMCPY(pk, rho, MLDSA_SEEDBYTES);
   pk += MLDSA_SEEDBYTES;

   for (i = 0; i < (unsigned)k; ++i)
      s_polyt1_pack(pk + i * MLDSA_POLYT1_PACKEDBYTES, &t1->vec[i]);
}

static void s_unpack_pk(unsigned char rho[MLDSA_SEEDBYTES], mldsa_polyveck *t1,
                        const unsigned char *pk, int k)
{
   unsigned int i;

   XMEMCPY(rho, pk, MLDSA_SEEDBYTES);
   pk += MLDSA_SEEDBYTES;

   for (i = 0; i < (unsigned)k; ++i)
      s_polyt1_unpack(&t1->vec[i], pk + i * MLDSA_POLYT1_PACKEDBYTES);
}

static void s_pack_sk(unsigned char *sk,
                      const unsigned char rho[MLDSA_SEEDBYTES],
                      const unsigned char tr[MLDSA_TRBYTES],
                      const unsigned char key[MLDSA_SEEDBYTES],
                      const mldsa_polyveck *t0,
                      const mldsa_polyvecl *s1,
                      const mldsa_polyveck *s2,
                      const mldsa_params *p)
{
   unsigned int i;

   XMEMCPY(sk, rho, MLDSA_SEEDBYTES);
   sk += MLDSA_SEEDBYTES;

   XMEMCPY(sk, key, MLDSA_SEEDBYTES);
   sk += MLDSA_SEEDBYTES;

   XMEMCPY(sk, tr, MLDSA_TRBYTES);
   sk += MLDSA_TRBYTES;

   for (i = 0; i < (unsigned)p->l; ++i)
      s_polyeta_pack(sk + i * p->polyeta_packed, &s1->vec[i], p->eta);
   sk += (unsigned long)p->l * p->polyeta_packed;

   for (i = 0; i < (unsigned)p->k; ++i)
      s_polyeta_pack(sk + i * p->polyeta_packed, &s2->vec[i], p->eta);
   sk += (unsigned long)p->k * p->polyeta_packed;

   for (i = 0; i < (unsigned)p->k; ++i)
      s_polyt0_pack(sk + i * MLDSA_POLYT0_PACKEDBYTES, &t0->vec[i]);
}

static int s_unpack_sk(unsigned char rho[MLDSA_SEEDBYTES],
                       unsigned char tr[MLDSA_TRBYTES],
                       unsigned char key[MLDSA_SEEDBYTES],
                       mldsa_polyveck *t0,
                       mldsa_polyvecl *s1,
                       mldsa_polyveck *s2,
                       const unsigned char *sk,
                       const mldsa_params *p)
{
   unsigned int i;
   int err;

   XMEMCPY(rho, sk, MLDSA_SEEDBYTES);
   sk += MLDSA_SEEDBYTES;

   XMEMCPY(key, sk, MLDSA_SEEDBYTES);
   sk += MLDSA_SEEDBYTES;

   XMEMCPY(tr, sk, MLDSA_TRBYTES);
   sk += MLDSA_TRBYTES;

   for (i = 0; i < (unsigned)p->l; ++i)
      if ((err = s_polyeta_unpack(&s1->vec[i], sk + i * p->polyeta_packed, p->eta)) != CRYPT_OK) return err;
   sk += (unsigned long)p->l * p->polyeta_packed;

   for (i = 0; i < (unsigned)p->k; ++i)
      if ((err = s_polyeta_unpack(&s2->vec[i], sk + i * p->polyeta_packed, p->eta)) != CRYPT_OK) return err;
   sk += (unsigned long)p->k * p->polyeta_packed;

   for (i = 0; i < (unsigned)p->k; ++i)
      s_polyt0_unpack(&t0->vec[i], sk + i * MLDSA_POLYT0_PACKEDBYTES);

   return CRYPT_OK;
}

static void s_pack_sig(unsigned char *sig,
                       const unsigned char *c, int ctilde_bytes,
                       const mldsa_polyvecl *z,
                       const mldsa_polyveck *h,
                       const mldsa_params *p)
{
   unsigned int i, j, k;

   XMEMCPY(sig, c, ctilde_bytes);
   sig += ctilde_bytes;

   for (i = 0; i < (unsigned)p->l; ++i)
      s_polyz_pack(sig + i * p->polyz_packed, &z->vec[i], p->gamma1);
   sig += (unsigned long)p->l * p->polyz_packed;

   /* Encode h */
   for (i = 0; i < (unsigned long)p->omega + (unsigned long)p->k; ++i)
      sig[i] = 0;

   k = 0;
   for (i = 0; i < (unsigned)p->k; ++i) {
      for (j = 0; j < MLDSA_N; ++j)
         if (h->vec[i].coeffs[j] != 0)
            sig[k++] = (unsigned char)j;
      sig[p->omega + i] = (unsigned char)k;
   }
}

static int s_unpack_sig(unsigned char *c, int ctilde_bytes,
                        mldsa_polyvecl *z,
                        mldsa_polyveck *h,
                        const unsigned char *sig,
                        const mldsa_params *p)
{
   unsigned int i, j, k;

   XMEMCPY(c, sig, ctilde_bytes);
   sig += ctilde_bytes;

   for (i = 0; i < (unsigned)p->l; ++i)
      s_polyz_unpack(&z->vec[i], sig + i * p->polyz_packed, p->gamma1);
   sig += (unsigned long)p->l * p->polyz_packed;

   /* Decode h */
   k = 0;
   for (i = 0; i < (unsigned)p->k; ++i) {
      for (j = 0; j < MLDSA_N; ++j)
         h->vec[i].coeffs[j] = 0;

      if (sig[p->omega + i] < k || sig[p->omega + i] > (unsigned)p->omega)
         return 1;

      for (j = k; j < sig[p->omega + i]; ++j) {
         /* Coefficients are ordered for strong unforgeability */
         if (j > k && sig[j] <= sig[j - 1]) return 1;
         h->vec[i].coeffs[sig[j]] = 1;
      }

      k = sig[p->omega + i];
   }

   /* Extra indices are zero for strong unforgeability */
   for (j = k; j < (unsigned)p->omega; ++j)
      if (sig[j])
         return 1;

   return 0;
}

/* Sign / verify core */

/* the secret vectors from sk, written once by s_unpack_sk() and only read after that,
   so they go on the heap and keep the signing stack frame about 24 KB smaller */
typedef struct {
   mldsa_polyvecl s1;
   mldsa_polyveck s2, t0;
} mldsa_sk_vecs;

/* mu = SHAKE256(tr || 0x00 || ctxlen || ctx || msg, 64), FIPS 204 5.2 M' framing */
static int s_mldsa_compute_mu(unsigned char mu[MLDSA_CRHBYTES],
                              const unsigned char tr[MLDSA_TRBYTES],
                              const unsigned char *msg, unsigned long msglen,
                              const unsigned char *ctx, unsigned long ctxlen)
{
   unsigned char pre[2];
   hash_state state;
   int err;

   pre[0] = 0;
   pre[1] = (unsigned char)ctxlen;

   if ((err = sha3_shake_init(&state, 256)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&state, tr, MLDSA_TRBYTES)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&state, pre, sizeof(pre))) != CRYPT_OK) goto LBL_ERR;
   /* ctx and msg may be NULL when empty, the hashes reject NULL */
   if (ctxlen > 0) {
      if ((err = sha3_shake_process(&state, ctx, ctxlen)) != CRYPT_OK) goto LBL_ERR;
   }
   if (msglen > 0) {
      if ((err = sha3_shake_process(&state, msg, msglen)) != CRYPT_OK) goto LBL_ERR;
   }
   err = sha3_shake_done(&state, mu, MLDSA_CRHBYTES);

LBL_ERR:
   zeromem(&state.sha3, sizeof(state.sha3));
   return err;
}

static int s_sign_internal(unsigned char *sig, unsigned long *siglen,
                           const unsigned char mu_in[MLDSA_CRHBYTES],
                           const unsigned char rnd[MLDSA_RNDBYTES],
                           const unsigned char *sk,
                           const mldsa_params *p)
{
   unsigned int n;
   unsigned char seedbuf[2 * MLDSA_SEEDBYTES + MLDSA_TRBYTES + 2 * MLDSA_CRHBYTES];
   unsigned char *rho, *tr, *key, *mu, *rhoprime;
   unsigned int nonce = 0;
   unsigned int attempts = 0;
   mldsa_sk_vecs *sec;
   mldsa_polyvecl y, z;
   mldsa_polyveck w1, w0, h;
   mldsa_poly cp, *mat;
   hash_state state;
   int err;

   /* the matrix is reused by every rejection iteration, so it is expanded once and kept on the heap, k*l polynomials are far too much for the stack */
   mat = XMALLOC((unsigned long)p->k * p->l * sizeof(*mat));
   sec = XMALLOC(sizeof(*sec));
   if (mat == NULL || sec == NULL) {
      if (sec != NULL) XFREE(sec);
      if (mat != NULL) XFREE(mat);
      return CRYPT_MEM;
   }

   XMEMSET(sec, 0, sizeof(*sec));

   rho = seedbuf;
   tr = rho + MLDSA_SEEDBYTES;
   key = tr + MLDSA_TRBYTES;
   mu = key + MLDSA_SEEDBYTES;
   rhoprime = mu + MLDSA_CRHBYTES;
   if ((err = s_unpack_sk(rho, tr, key, &sec->t0, &sec->s1, &sec->s2, sk, p)) != CRYPT_OK) goto LBL_ERR;
   XMEMCPY(mu, mu_in, MLDSA_CRHBYTES);

   /* Compute rhoprime = CRH(key, rnd, mu) */
   if ((err = sha3_shake_init(&state, 256)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&state, key, MLDSA_SEEDBYTES)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&state, rnd, MLDSA_RNDBYTES)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&state, mu, MLDSA_CRHBYTES)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_done(&state, rhoprime, MLDSA_CRHBYTES)) != CRYPT_OK) goto LBL_ERR;

   /* Expand matrix and transform vectors */
   if ((err = s_polyvec_matrix_expand(mat, p->k, p->l, rho)) != CRYPT_OK) goto LBL_ERR;
   s_polyvecl_ntt(&sec->s1, p->l);
   s_polyveck_ntt(&sec->s2, p->k);
   s_polyveck_ntt(&sec->t0, p->k);

rej:
   if (attempts++ >= MLDSA_SIGN_MAX_REJECTIONS) {
      err = CRYPT_ERROR;
      goto LBL_ERR;
   }

   /* Sample intermediate vector y */
   if ((err = s_polyvecl_uniform_gamma1(&y, rhoprime, nonce++, p->l, p)) != CRYPT_OK) goto LBL_ERR;

   /* Matrix-vector multiplication */
   z = y;
   s_polyvecl_ntt(&z, p->l);
   s_polyvec_matrix_pointwise_montgomery(&w1, mat, &z, p->k, p->l);
   s_polyveck_reduce(&w1, p->k);
   s_polyveck_invntt_tomont(&w1, p->k);

   /* Decompose w and call the random oracle */
   s_polyveck_caddq(&w1, p->k);
   s_polyveck_decompose(&w1, &w0, &w1, p->k, p->gamma2);
   s_polyveck_pack_w1(sig, &w1, p->k, p->polyw1_packed, p->gamma2);

   if ((err = sha3_shake_init(&state, 256)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&state, mu, MLDSA_CRHBYTES)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&state, sig, (unsigned long)p->k * p->polyw1_packed)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_done(&state, sig, p->ctilde_bytes)) != CRYPT_OK) goto LBL_ERR;
   if ((err = s_poly_challenge(&cp, sig, p->ctilde_bytes, p->tau)) != CRYPT_OK) goto LBL_ERR;
   s_mldsa_poly_ntt(&cp);

   /* Compute z, reject if it reveals secret */
   s_polyvecl_pointwise_poly_montgomery(&z, &cp, &sec->s1, p->l);
   s_polyvecl_invntt_tomont(&z, p->l);
   s_polyvecl_add(&z, &z, &y, p->l);
   s_polyvecl_reduce(&z, p->l);
   if (s_polyvecl_chknorm(&z, p->gamma1 - p->beta, p->l))
      goto rej;

   /* Check that subtracting cs2 does not change high bits of w and low bits do not reveal secret information */
   s_polyveck_pointwise_poly_montgomery(&h, &cp, &sec->s2, p->k);
   s_polyveck_invntt_tomont(&h, p->k);
   s_polyveck_sub(&w0, &w0, &h, p->k);
   s_polyveck_reduce(&w0, p->k);
   if (s_polyveck_chknorm(&w0, p->gamma2 - p->beta, p->k))
      goto rej;

   /* Compute hints for w1 */
   s_polyveck_pointwise_poly_montgomery(&h, &cp, &sec->t0, p->k);
   s_polyveck_invntt_tomont(&h, p->k);
   s_polyveck_reduce(&h, p->k);
   if (s_polyveck_chknorm(&h, p->gamma2, p->k))
      goto rej;

   s_polyveck_add(&w0, &w0, &h, p->k);
   n = s_polyveck_make_hint(&h, &w0, &w1, p->k, p->gamma2);
   if (n > (unsigned)p->omega)
      goto rej;

   /* Write signature */
   s_pack_sig(sig, sig, p->ctilde_bytes, &z, &h, p);
   *siglen = p->sig_bytes;
   err = CRYPT_OK;

LBL_ERR:
   /* the matrix is public data derived from rho, no need to wipe it */
   XFREE(mat);
   zeromem(sec, sizeof(*sec));
   XFREE(sec);
   /* seedbuf holds K and rho'', y is the mask that hides c*s1 in z */
   zeromem(seedbuf, sizeof(seedbuf));
   zeromem(&y, sizeof(y));
   zeromem(&z, sizeof(z));
   zeromem(&w1, sizeof(w1));
   zeromem(&w0, sizeof(w0));
   /* h holds c*s2 and c*t0 before it becomes the hint */
   zeromem(&h, sizeof(h));
   zeromem(&cp, sizeof(cp));
   zeromem(&state.sha3, sizeof(state.sha3));
   return err;
}

static int s_verify_internal(const unsigned char *sig, unsigned long siglen,
                             const unsigned char mu[MLDSA_CRHBYTES],
                             const unsigned char *pk,
                             const mldsa_params *p)
{
   unsigned char *buf = NULL;
   unsigned long buflen = (unsigned long)p->k * p->polyw1_packed;
   unsigned char rho[MLDSA_SEEDBYTES];
   unsigned char c[64]; /* max ctilde_bytes = 64 */
   unsigned char c2[64];
   mldsa_poly cp;
   mldsa_polyvecl z;
   mldsa_polyveck t1, w1, h;
   hash_state state;
   int err;

   XMEMSET(&z, 0, sizeof(z));
   XMEMSET(&t1, 0, sizeof(t1));

   if (siglen != p->sig_bytes) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   buf = XMALLOC(buflen);
   if (buf == NULL) {
      err = CRYPT_MEM;
      goto LBL_ERR;
   }

   s_unpack_pk(rho, &t1, pk, p->k);
   if (s_unpack_sig(c, p->ctilde_bytes, &z, &h, sig, p)) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }
   if (s_polyvecl_chknorm(&z, p->gamma1 - p->beta, p->l)) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   /* Matrix-vector multiplication; compute Az - c2^dt1 */
   if ((err = s_poly_challenge(&cp, c, p->ctilde_bytes, p->tau)) != CRYPT_OK) goto LBL_ERR;

   s_polyvecl_ntt(&z, p->l);
   if ((err = s_polyvec_matrix_expand_mul(&w1, rho, &z, p->k, p->l)) != CRYPT_OK) goto LBL_ERR;

   s_mldsa_poly_ntt(&cp);
   s_polyveck_shiftl(&t1, p->k);
   s_polyveck_ntt(&t1, p->k);
   s_polyveck_pointwise_poly_montgomery(&t1, &cp, &t1, p->k);

   s_polyveck_sub(&w1, &w1, &t1, p->k);
   s_polyveck_reduce(&w1, p->k);
   s_polyveck_invntt_tomont(&w1, p->k);

   /* Reconstruct w1 */
   s_polyveck_caddq(&w1, p->k);
   s_polyveck_use_hint(&w1, &w1, &h, p->k, p->gamma2);
   s_polyveck_pack_w1(buf, &w1, p->k, p->polyw1_packed, p->gamma2);

   /* Call random oracle and verify challenge */
   if ((err = sha3_shake_init(&state, 256)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&state, mu, MLDSA_CRHBYTES)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&state, buf, buflen)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_done(&state, c2, p->ctilde_bytes)) != CRYPT_OK) goto LBL_ERR;

   err = XMEM_NEQ(c, c2, (unsigned long)p->ctilde_bytes) == 0 ? CRYPT_OK : CRYPT_INVALID_PACKET;

LBL_ERR:
   /* FIPS 204 3.6.3: verification intermediates can contain sensitive data. */
   if (buf != NULL) {
      zeromem(buf, buflen);
      XFREE(buf);
   }
   zeromem(rho, sizeof(rho));
   zeromem(c, sizeof(c));
   zeromem(c2, sizeof(c2));
   zeromem(&cp, sizeof(cp));
   zeromem(&z, sizeof(z));
   zeromem(&t1, sizeof(t1));
   zeromem(&w1, sizeof(w1));
   zeromem(&h, sizeof(h));
   zeromem(&state.sha3, sizeof(state.sha3));
   return err;
}

/* Public API */

static int s_mldsa_make_key_seed(int alg,
                                 const unsigned char seedbuf[MLDSA_SEEDBYTES],
                                 mldsa_key *key)
{
   mldsa_params p;
   unsigned char expanded[2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES];
   unsigned char hashbuf[MLDSA_SEEDBYTES + 2];
   unsigned char tr[MLDSA_TRBYTES];
   const unsigned char *rho, *rhoprime, *kk;
   mldsa_polyvecl s1, s1hat;
   mldsa_polyveck s2, t1, t0;
   int err = CRYPT_OK;

   LTC_ARGCHK(key != NULL);

   XMEMSET(&s1, 0, sizeof(s1));
   XMEMSET(&s2, 0, sizeof(s2));
   XMEMSET(key, 0, sizeof(*key));

   if ((err = s_mldsa_get_params(alg, &p)) != CRYPT_OK) goto cleanup;

   /* Expand seed: SHAKE256(xi || k || l) -> rho || rhoprime || key */
   XMEMCPY(hashbuf, seedbuf, MLDSA_SEEDBYTES);
   hashbuf[MLDSA_SEEDBYTES] = (unsigned char)p.k;
   hashbuf[MLDSA_SEEDBYTES + 1] = (unsigned char)p.l;
   if ((err = s_shake256(expanded, 2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES,
                         hashbuf, MLDSA_SEEDBYTES + 2)) != CRYPT_OK) {
      goto cleanup;
   }

   rho = expanded;
   rhoprime = rho + MLDSA_SEEDBYTES;
   kk = rhoprime + MLDSA_CRHBYTES;

   /* Sample short vectors s1 and s2 */
   if ((err = s_polyvecl_uniform_eta(&s1, rhoprime, 0, p.l, p.eta)) != CRYPT_OK) goto cleanup;
   if ((err = s_polyveck_uniform_eta(&s2, rhoprime, (unsigned)p.l, p.k, p.eta)) != CRYPT_OK) goto cleanup;

   /* Matrix-vector multiplication, s1 is still needed by s_pack_sk() */
   s1hat = s1;
   s_polyvecl_ntt(&s1hat, p.l);
   if ((err = s_polyvec_matrix_expand_mul(&t1, rho, &s1hat, p.k, p.l)) != CRYPT_OK) goto cleanup;
   s_polyveck_reduce(&t1, p.k);
   s_polyveck_invntt_tomont(&t1, p.k);

   /* Add error vector s2 */
   s_polyveck_add(&t1, &t1, &s2, p.k);

   /* Extract t1 and write public key */
   s_polyveck_caddq(&t1, p.k);
   s_polyveck_power2round(&t1, &t0, &t1, p.k);

   /* Allocate key storage */
   key->pk = XMALLOC(p.pk_bytes);
   key->sk = XMALLOC(p.sk_bytes);
   if (key->pk == NULL || key->sk == NULL) {
      err = CRYPT_MEM;
      goto cleanup;
   }

   s_pack_pk(key->pk, rho, &t1, p.k);

   /* Compute H(rho, t1) = tr */
   if ((err = s_shake256(tr, MLDSA_TRBYTES, key->pk, p.pk_bytes)) != CRYPT_OK) {
      goto cleanup;
   }

   s_pack_sk(key->sk, rho, tr, kk, &t0, &s1, &s2, &p);

   key->alg = alg;
   key->type = PK_PRIVATE;
   key->pklen = p.pk_bytes;
   key->sklen = p.sk_bytes;

   /* store the seed only after the key is complete */
   XMEMCPY(key->seed, seedbuf, LTC_MLDSA_KEYGEN_SEED_BYTES);
   key->has_seed = 1;

cleanup:
   if (err != CRYPT_OK) {
      mldsa_free(key);
   }
   zeromem(hashbuf, sizeof(hashbuf));
   zeromem(expanded, sizeof(expanded));
   zeromem(tr, sizeof(tr));
   zeromem(&s1, sizeof(s1));
   zeromem(&s1hat, sizeof(s1hat));
   zeromem(&s2, sizeof(s2));
   zeromem(&t0, sizeof(t0));
   return err;
}

/**
   Generate an ML-DSA key pair deterministically from a seed.
   @param alg      The parameter set (LTC_MLDSA_44, LTC_MLDSA_65, or LTC_MLDSA_87)
   @param seed     The input seed (exactly 32 bytes)
   @param seedlen  Length of the seed in bytes
   @param key      [out] Destination for the newly created key pair
   @return CRYPT_OK if successful
*/
int mldsa_make_key_from_seed(int alg, const unsigned char *seed, unsigned long seedlen,
                             mldsa_key *key)
{
   LTC_ARGCHK(seed != NULL);
   LTC_ARGCHK(key  != NULL);

   if (seedlen != MLDSA_SEEDBYTES) {
      return CRYPT_INVALID_ARG;
   }

   return s_mldsa_make_key_seed(alg, seed, key);
}

/**
   Generate an ML-DSA key pair.
   @param prng     An active PRNG state
   @param wprng    The index of the desired PRNG
   @param alg      The parameter set (LTC_MLDSA_44, LTC_MLDSA_65, or LTC_MLDSA_87)
   @param key      [out] Destination for the newly created key pair
   @return CRYPT_OK if successful
*/
int mldsa_make_key(prng_state *prng, int wprng, int alg, mldsa_key *key)
{
   unsigned char seedbuf[MLDSA_SEEDBYTES];
   int err;

   LTC_ARGCHK(key != NULL);

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) return err;
   if (prng_descriptor[wprng].read(seedbuf, MLDSA_SEEDBYTES, prng) != MLDSA_SEEDBYTES) {
      zeromem(seedbuf, sizeof(seedbuf));
      return CRYPT_ERROR_READPRNG;
   }

   err = s_mldsa_make_key_seed(alg, seedbuf, key);
   zeromem(seedbuf, sizeof(seedbuf));
   return err;
}

/**
   Free an ML-DSA key from memory.
   @param key   The key to free
*/
void mldsa_free(mldsa_key *key)
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

/* Cheap check of the key fields only, the key material is checked by mldsa_check_key() */
static int s_mldsa_key_valid(const mldsa_key *key, int require_private, mldsa_params *p)
{
   int err;

   if ((err = s_mldsa_get_params(key->alg, p)) != CRYPT_OK) return err;
   if (require_private && key->type != PK_PRIVATE) return CRYPT_PK_NOT_PRIVATE;
   if (key->type != PK_PRIVATE && key->type != PK_PUBLIC) return CRYPT_PK_INVALID_TYPE;
   if (key->pk == NULL || key->pklen != p->pk_bytes) return CRYPT_PK_INVALID_TYPE;
   if (key->type == PK_PRIVATE && (key->sk == NULL || key->sklen != p->sk_bytes)) return CRYPT_PK_INVALID_TYPE;

   return CRYPT_OK;
}

/**
   Export an ML-DSA key to a byte buffer.
   @param out      [out] Destination for the exported key
   @param outlen   [in/out] Max size and resulting size of the exported key
   @param which    PK_PUBLIC for the verification key, PK_PRIVATE for the signing key
   @param key      The key to export
   @return CRYPT_OK if successful
*/
int mldsa_export_raw(unsigned char *out, unsigned long *outlen, int which, const mldsa_key *key)
{
   mldsa_params p;
   unsigned long needed;
   int err;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   if (which == PK_PUBLIC) {
      if ((err = s_mldsa_key_valid(key, 0, &p)) != CRYPT_OK) return err;
      needed = p.pk_bytes;
      if (*outlen < needed) { *outlen = needed; return CRYPT_BUFFER_OVERFLOW; }
      XMEMCPY(out, key->pk, needed);
   }
   else if (which == PK_PRIVATE) {
      if ((err = s_mldsa_key_valid(key, 1, &p)) != CRYPT_OK) return err;
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

/* Rebuild pk from sk and check the encoded t0 and tr against it, FIPS 204 3.6.3. pk needs room for p->pk_bytes. */
static int s_mldsa_rebuild_pk(unsigned char *pk, const unsigned char *sk, const mldsa_params *p)
{
   unsigned char rho[MLDSA_SEEDBYTES], tr[MLDSA_TRBYTES], kk[MLDSA_SEEDBYTES];
   unsigned char computed_t0[MLDSA_POLYT0_PACKEDBYTES];
   unsigned char computed_tr[MLDSA_TRBYTES];
   const unsigned char *encoded_t0;
   mldsa_polyvecl s1;
   mldsa_polyveck s2, t0, t1;
   unsigned int i;
   int t0_mismatch, err;

   XMEMSET(&s1, 0, sizeof(s1));
   XMEMSET(&s2, 0, sizeof(s2));

   err = s_unpack_sk(rho, tr, kk, &t0, &s1, &s2, sk, p);

   if (err == CRYPT_OK) {
      /* s1 is not needed after this, so transform it in place */
      s_polyvecl_ntt(&s1, p->l);
      err = s_polyvec_matrix_expand_mul(&t1, rho, &s1, p->k, p->l);
   }

   if (err == CRYPT_OK) {
      s_polyveck_reduce(&t1, p->k);
      s_polyveck_invntt_tomont(&t1, p->k);
      s_polyveck_add(&t1, &t1, &s2, p->k);
      s_polyveck_caddq(&t1, p->k);

      /* Reconstruct t0 and compare it with the encoded value. */
      s_polyveck_power2round(&t1, &t0, &t1, p->k);
      encoded_t0 = sk + p->sk_bytes - (unsigned long)p->k * MLDSA_POLYT0_PACKEDBYTES;
      t0_mismatch = 0;
      for (i = 0; i < (unsigned)p->k; ++i) {
         s_polyt0_pack(computed_t0, &t0.vec[i]);
         t0_mismatch |= XMEM_NEQ(computed_t0, encoded_t0 + (unsigned long)i * MLDSA_POLYT0_PACKEDBYTES, MLDSA_POLYT0_PACKEDBYTES);
      }
      if (t0_mismatch != 0) {
         err = CRYPT_INVALID_PACKET;
      }
   }

   if (err == CRYPT_OK) {
      s_pack_pk(pk, rho, &t1, p->k);
      if ((err = s_shake256(computed_tr, MLDSA_TRBYTES, pk, p->pk_bytes)) == CRYPT_OK) {
         if (XMEM_NEQ(tr, computed_tr, MLDSA_TRBYTES) != 0) {
            err = CRYPT_INVALID_PACKET;
         }
      }
   }

   /* kk is K, s1/s2/t0 are the secret polynomials unpacked from sk */
   zeromem(kk, sizeof(kk));
   zeromem(computed_t0, sizeof(computed_t0));
   zeromem(computed_tr, sizeof(computed_tr));
   zeromem(&s1, sizeof(s1));
   zeromem(&s2, sizeof(s2));
   zeromem(&t0, sizeof(t0));
   return err;
}

/**
   Import an ML-DSA key from a byte buffer.
   @param in       The buffer to import from
   @param inlen    Length of the buffer
   @param which    PK_PUBLIC for a verification key, PK_PRIVATE for a signing key
   @param alg      The parameter set (LTC_MLDSA_44, LTC_MLDSA_65, or LTC_MLDSA_87)
   @param key      [out] Destination for the imported key
   @return CRYPT_OK if successful
*/
int mldsa_import_raw(const unsigned char *in, unsigned long inlen, int which, int alg, mldsa_key *key)
{
   mldsa_params p;
   int err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   if ((err = s_mldsa_get_params(alg, &p)) != CRYPT_OK) return err;

   XMEMSET(key, 0, sizeof(*key));
   key->alg = alg;

   if (which == PK_PUBLIC) {
      if (inlen != p.pk_bytes) return CRYPT_INVALID_PACKET;
      key->pk = XMALLOC(p.pk_bytes);
      if (key->pk == NULL) return CRYPT_MEM;
      XMEMCPY(key->pk, in, p.pk_bytes);
      key->pklen = p.pk_bytes;
      key->type = PK_PUBLIC;
   }
   else if (which == PK_PRIVATE) {
      if (inlen != p.sk_bytes) return CRYPT_INVALID_PACKET;
      key->sk = XMALLOC(p.sk_bytes);
      if (key->sk == NULL) return CRYPT_MEM;
      XMEMCPY(key->sk, in, p.sk_bytes);
      key->sklen = p.sk_bytes;

      key->pk = XMALLOC(p.pk_bytes);
      if (key->pk == NULL) {
         mldsa_free(key);
         return CRYPT_MEM;
      }
      if ((err = s_mldsa_rebuild_pk(key->pk, key->sk, &p)) != CRYPT_OK) {
         mldsa_free(key);
         return err;
      }
      key->pklen = p.pk_bytes;

      key->type = PK_PRIVATE;
   }
   else {
      return CRYPT_INVALID_ARG;
   }

   return CRYPT_OK;
}

/**
   Check the internal consistency of an ML-DSA key.

   Rebuilds pk from sk, compares the encoded t0 and tr with it, and expands a stored seed again.
   @param key      The key to check
   @return CRYPT_OK if the key is consistent, CRYPT_PK_INVALID_TYPE if a key field is wrong,
           CRYPT_INVALID_PACKET if the key material does not match
*/
int mldsa_check_key(const mldsa_key *key)
{
   mldsa_params p;
   mldsa_key tmp;
   unsigned char *pk;
   int err;

   LTC_ARGCHK(key != NULL);

   if ((err = s_mldsa_get_params(key->alg, &p)) != CRYPT_OK) return err;
   if (key->pk == NULL || key->pklen != p.pk_bytes) return CRYPT_PK_INVALID_TYPE;

   if (key->type == PK_PUBLIC) {
      return (key->sk == NULL && key->sklen == 0 && !key->has_seed) ? CRYPT_OK : CRYPT_PK_INVALID_TYPE;
   }
   if (key->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;
   if (key->sk == NULL || key->sklen != p.sk_bytes) return CRYPT_PK_INVALID_TYPE;

   pk = XMALLOC(p.pk_bytes);
   if (pk == NULL) return CRYPT_MEM;
   err = s_mldsa_rebuild_pk(pk, key->sk, &p);
   if (err == CRYPT_OK && XMEM_NEQ(pk, key->pk, p.pk_bytes) != 0) {
      err = CRYPT_INVALID_PACKET;
   }
   XFREE(pk);
   if (err != CRYPT_OK) return err;

   if (!key->has_seed) return CRYPT_OK;

   if ((err = mldsa_make_key_from_seed(key->alg, key->seed, sizeof(key->seed), &tmp)) != CRYPT_OK) {
      return err;
   }
   if (tmp.pklen != key->pklen || tmp.sklen != key->sklen ||
       XMEM_NEQ(tmp.pk, key->pk, key->pklen) != 0 ||
       XMEM_NEQ(tmp.sk, key->sk, key->sklen) != 0) {
      err = CRYPT_INVALID_PACKET;
   }
   mldsa_free(&tmp);
   return err;
}

/**
   Tell whether a key still has the seed it was generated from.
   @param key      The key to query (may be NULL)
   @return 1 if the key is private and still has its generation seed, 0 otherwise
*/
int mldsa_has_seed(const mldsa_key *key)
{
   if (key == NULL) return 0;
   return key->has_seed ? 1 : 0;
}

/**
   Export the 32-byte generation seed (xi) of an ML-DSA private key.
   A seed cannot be computed back from the expanded key, so only generated keys and keys
   imported from the PKCS#8 seed or both form have one.
   @param out      [out] Destination for the seed
   @param outlen   [in/out] Max size and resulting size of the seed
   @param key      The private key to export the seed of
   @return CRYPT_OK if successful, CRYPT_PK_NOT_PRIVATE for a public key,
           CRYPT_PK_INVALID_TYPE if the key has no seed
*/
int mldsa_export_seed(unsigned char *out, unsigned long *outlen, const mldsa_key *key)
{
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   if (key->type != PK_PRIVATE) return CRYPT_PK_NOT_PRIVATE;
   if (!key->has_seed)          return CRYPT_PK_INVALID_TYPE;

   if (*outlen < LTC_MLDSA_KEYGEN_SEED_BYTES) {
      *outlen = LTC_MLDSA_KEYGEN_SEED_BYTES;
      return CRYPT_BUFFER_OVERFLOW;
   }
   XMEMCPY(out, key->seed, LTC_MLDSA_KEYGEN_SEED_BYTES);
   *outlen = LTC_MLDSA_KEYGEN_SEED_BYTES;

   return CRYPT_OK;
}

/**
   Sign a message with ML-DSA.
   @param msg      The message to sign
   @param msglen   Length of the message
   @param sig      [out] The signature
   @param siglen   [in/out] Max size and resulting size of the signature
   @param ctx      Optional context string (can be NULL if ctxlen is 0)
   @param ctxlen   Length of the context string (max 255 bytes per FIPS 204)
   @param prng     An active PRNG state (for hedged signing)
   @param wprng    The index of the desired PRNG
   @param key      The private (signing) key
   @return CRYPT_OK if successful, CRYPT_INVALID_PACKET if the private key
           encodes s1/s2 coefficients outside [-eta, +eta] (FIPS 204 3.6.3)
*/
int mldsa_sign(const unsigned char *msg,  unsigned long  msglen,
                     unsigned char *sig,  unsigned long *siglen,
               const unsigned char *ctx,  unsigned long  ctxlen,
                     prng_state    *prng, int            wprng,
               const mldsa_key    *key)
{
   unsigned char rnd[MLDSA_RNDBYTES];
   int err;

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) return err;
   if (prng_descriptor[wprng].read(rnd, MLDSA_RNDBYTES, prng) != MLDSA_RNDBYTES) {
      zeromem(rnd, sizeof(rnd));
      return CRYPT_ERROR_READPRNG;
   }

   err = mldsa_sign_ex(msg, msglen, sig, siglen, ctx, ctxlen, rnd, sizeof(rnd), key);

   zeromem(rnd, sizeof(rnd));
   return err;
}

/**
   ML-DSA signing with caller-supplied per-signature randomness (FIPS 204 6.2 ML-DSA.Sign_internal).

   Like mldsa_sign(), but rnd comes from the caller. An all-zero rnd gives the deterministic
   variant, an rnd from a CSPRNG the hedged variant that mldsa_sign() uses. It is meant for KAT
   and ACVP vectors that fix rnd, applications should call mldsa_sign().
   @param msg      The message to sign
   @param msglen   Length of the message
   @param sig      [out] The signature
   @param siglen   [in/out] Max size and resulting size of the signature
   @param ctx      Optional context string (can be NULL if ctxlen is 0)
   @param ctxlen   Length of the context string (max 255 bytes per FIPS 204)
   @param rnd      The 32-byte per-signature randomness
   @param rndlen   Length of rnd in bytes; must equal 32
   @param key      The private (signing) key
   @return CRYPT_OK if successful, CRYPT_INVALID_PACKET if the private key
           encodes s1/s2 coefficients outside [-eta, +eta] (FIPS 204 3.6.3)
*/
int mldsa_sign_ex(const unsigned char *msg,  unsigned long  msglen,
                        unsigned char *sig,  unsigned long *siglen,
                  const unsigned char *ctx,  unsigned long  ctxlen,
                  const unsigned char *rnd,  unsigned long  rndlen,
                  const mldsa_key    *key)
{
   mldsa_params p;
   unsigned char mu[MLDSA_CRHBYTES];
   int err;

   LTC_ARGCHK(msg    != NULL || msglen == 0);
   LTC_ARGCHK(ctx    != NULL || ctxlen == 0);
   LTC_ARGCHK(sig    != NULL);
   LTC_ARGCHK(siglen != NULL);
   LTC_ARGCHK(rnd    != NULL);
   LTC_ARGCHK(key    != NULL);

   if (ctxlen > LTC_PQC_CTX_MAX_BYTES) return CRYPT_INVALID_ARG;
   if (rndlen != MLDSA_RNDBYTES) return CRYPT_INVALID_ARG;

   if ((err = s_mldsa_key_valid(key, 1, &p)) != CRYPT_OK) return err;
   if (*siglen < p.sig_bytes) { *siglen = p.sig_bytes; return CRYPT_BUFFER_OVERFLOW; }

   /* tr sits at sk[2*MLDSA_SEEDBYTES] */
   err = s_mldsa_compute_mu(mu, key->sk + 2 * MLDSA_SEEDBYTES, msg, msglen, ctx, ctxlen);
   if (err == CRYPT_OK) {
      err = s_sign_internal(sig, siglen, mu, rnd, key->sk, &p);
   }

   zeromem(mu, sizeof(mu));
   return err;
}

/**
   ML-DSA signing with externally precomputed mu (FIPS 204 5.4.1).

   Identical to mldsa_sign_ex() but skips the message-binding hash; the caller
   supplies the 64-byte mu = SHAKE256(BytesToBits(tr) || M', 64) directly.
   This is the streaming/precomputed-hash signing path used by ACVP test
   vectors and protocols that hash the message in a separate step.
   @param mu       The 64-byte precomputed mu
   @param mulen    Length of mu in bytes; must equal 64
   @param sig      [out] The signature
   @param siglen   [in/out] Max size and resulting size of the signature
   @param rnd      The 32-byte per-signature randomness
   @param rndlen   Length of rnd in bytes; must equal 32
   @param key      The private (signing) key
   @return CRYPT_OK if successful, CRYPT_INVALID_PACKET if the private key
           encodes s1/s2 coefficients outside [-eta, +eta] (FIPS 204 3.6.3)
*/
int mldsa_sign_ex_mu(const unsigned char *mu,  unsigned long  mulen,
                           unsigned char *sig, unsigned long *siglen,
                     const unsigned char *rnd, unsigned long  rndlen,
                     const mldsa_key    *key)
{
   mldsa_params p;
   int err;

   LTC_ARGCHK(mu     != NULL);
   LTC_ARGCHK(sig    != NULL);
   LTC_ARGCHK(siglen != NULL);
   LTC_ARGCHK(rnd    != NULL);
   LTC_ARGCHK(key    != NULL);

   if (mulen  != MLDSA_CRHBYTES) return CRYPT_INVALID_ARG;
   if (rndlen != MLDSA_RNDBYTES) return CRYPT_INVALID_ARG;

   if ((err = s_mldsa_key_valid(key, 1, &p)) != CRYPT_OK) return err;
   if (*siglen < p.sig_bytes) { *siglen = p.sig_bytes; return CRYPT_BUFFER_OVERFLOW; }

   return s_sign_internal(sig, siglen, mu, rnd, key->sk, &p);
}

/**
   Compute the ML-DSA message representative mu (FIPS 204 5.4.1).

   mu = SHAKE256(tr || 0x00 || ctxlen || ctx || msg, 64), where tr = SHAKE256(pk, 64).
   Pass the result to mldsa_sign_ex_mu() or mldsa_verify_mu().
   @param mu       [out] The message representative
   @param mulen    [in/out] Max size and resulting size of mu; must be at least 64
   @param msg      The message
   @param msglen   Length of the message
   @param ctx      Optional context string (can be NULL if ctxlen is 0)
   @param ctxlen   Length of the context string (max 255 bytes per FIPS 204)
   @param key      The key used to sign or verify, public or private
   @return CRYPT_OK if successful
*/
int mldsa_compute_mu(unsigned char *mu,  unsigned long *mulen,
                     const unsigned char *msg, unsigned long msglen,
                     const unsigned char *ctx, unsigned long ctxlen,
                     const mldsa_key     *key)
{
   mldsa_params p;
   unsigned char tr[MLDSA_TRBYTES];
   int err;

   LTC_ARGCHK(mu    != NULL);
   LTC_ARGCHK(mulen != NULL);
   LTC_ARGCHK(msg   != NULL || msglen == 0);
   LTC_ARGCHK(ctx   != NULL || ctxlen == 0);
   LTC_ARGCHK(key   != NULL);

   if (ctxlen > LTC_PQC_CTX_MAX_BYTES) return CRYPT_INVALID_ARG;

   if ((err = s_mldsa_key_valid(key, 0, &p)) != CRYPT_OK) return err;
   if (*mulen < MLDSA_CRHBYTES) { *mulen = MLDSA_CRHBYTES; return CRYPT_BUFFER_OVERFLOW; }

   /* tr is computed from pk, so a public key works too */
   if ((err = s_shake256(tr, MLDSA_TRBYTES, key->pk, p.pk_bytes)) != CRYPT_OK) goto LBL_ERR;
   if ((err = s_mldsa_compute_mu(mu, tr, msg, msglen, ctx, ctxlen)) != CRYPT_OK) goto LBL_ERR;

   *mulen = MLDSA_CRHBYTES;
   err = CRYPT_OK;

LBL_ERR:
   zeromem(tr, sizeof(tr));
   return err;
}

/**
   Verify a signature against an externally computed mu (FIPS 204 5.4.1).

   Like mldsa_verify(), but takes the 64-byte mu from mldsa_compute_mu() instead of the message.
   @param sig      The signature to verify
   @param siglen   Length of the signature
   @param mu       The 64-byte message representative
   @param mulen    Length of mu in bytes; must equal 64
   @param stat     [out] Result of the verification: 1==valid, 0==invalid
   @param key      The public (verification) key
   @return CRYPT_OK if successful (even if the signature is invalid)
*/
int mldsa_verify_mu(const unsigned char *sig, unsigned long  siglen,
                    const unsigned char *mu,  unsigned long  mulen,
                          int           *stat,
                    const mldsa_key     *key)
{
   mldsa_params p;
   int err;

   /* stat is cleared before anything else can return, it stays 0 unless the signature is good */
   LTC_ARGCHK(stat != NULL);
   *stat = 0;

   LTC_ARGCHK(sig != NULL);
   LTC_ARGCHK(mu  != NULL);
   LTC_ARGCHK(key != NULL);

   if (mulen != MLDSA_CRHBYTES) return CRYPT_INVALID_ARG;

   if ((err = s_mldsa_key_valid(key, 0, &p)) != CRYPT_OK) return err;

   err = s_verify_internal(sig, siglen, mu, key->pk, &p);
   if (err == CRYPT_OK)
      *stat = 1;
   else if (err == CRYPT_INVALID_PACKET)
      err = CRYPT_OK; /* Verification failed but no internal error */

   return err;
}

/**
   Verify a signature with ML-DSA.
   @param sig      The signature to verify
   @param siglen   Length of the signature
   @param msg      The message that was signed
   @param msglen   Length of the message
   @param ctx      Optional context string (can be NULL if ctxlen is 0)
   @param ctxlen   Length of the context string (max 255 bytes per FIPS 204)
   @param stat     [out] Result of the verification: 1==valid, 0==invalid
   @param key      The public (verification) key
   @return CRYPT_OK if successful (even if the signature is invalid)
*/
int mldsa_verify(const unsigned char *sig,  unsigned long  siglen,
                 const unsigned char *msg,  unsigned long  msglen,
                 const unsigned char *ctx,  unsigned long  ctxlen,
                       int           *stat,
                 const mldsa_key    *key)
{
   mldsa_params p;
   unsigned char tr[MLDSA_TRBYTES], mu[MLDSA_CRHBYTES];
   int err;

   /* stat is cleared before anything else can return, it stays 0 unless the signature is good */
   LTC_ARGCHK(stat != NULL);
   *stat = 0;

   LTC_ARGCHK(sig  != NULL);
   LTC_ARGCHK(msg  != NULL || msglen == 0);
   LTC_ARGCHK(ctx  != NULL || ctxlen == 0);
   LTC_ARGCHK(key  != NULL);

   if (ctxlen > LTC_PQC_CTX_MAX_BYTES) return CRYPT_INVALID_ARG;

   if ((err = s_mldsa_key_valid(key, 0, &p)) != CRYPT_OK) return err;

   if ((err = s_shake256(tr, MLDSA_TRBYTES, key->pk, p.pk_bytes)) != CRYPT_OK) goto LBL_ERR;
   if ((err = s_mldsa_compute_mu(mu, tr, msg, msglen, ctx, ctxlen)) != CRYPT_OK) goto LBL_ERR;

   err = s_verify_internal(sig, siglen, mu, key->pk, &p);
   if (err == CRYPT_OK)
      *stat = 1;
   else if (err == CRYPT_INVALID_PACKET)
      err = CRYPT_OK; /* Verification failed but no internal error */

LBL_ERR:
   zeromem(tr, sizeof(tr));
   zeromem(mu, sizeof(mu));
   return err;
}

/**
   Get the sizes for a given ML-DSA parameter set.
   Any output pointer may be NULL if the caller does not need that value.
   @param alg              The parameter set (LTC_MLDSA_44, LTC_MLDSA_65, or LTC_MLDSA_87)
   @param public_key_sz    [out] Public key size in bytes
   @param secret_key_sz    [out] Secret key size in bytes
   @param signature_sz     [out] Signature size in bytes
   @param rnd_sz           [out] Per-signature rnd size in bytes for mldsa_sign_ex (always 32)
   @param mu_sz            [out] External mu size in bytes for mldsa_sign_ex_mu (always 64)
   @param keygen_seed_sz   [out] Seed size in bytes for mldsa_make_key_from_seed (always 32)
   @return CRYPT_OK if successful
*/
int mldsa_get_sizes(int alg,
                    unsigned long *public_key_sz,
                    unsigned long *secret_key_sz,
                    unsigned long *signature_sz,
                    unsigned long *rnd_sz,
                    unsigned long *mu_sz,
                    unsigned long *keygen_seed_sz)
{
   mldsa_params p;
   int err;

   if ((err = s_mldsa_get_params(alg, &p)) != CRYPT_OK) return err;

   if (public_key_sz  != NULL) *public_key_sz  = p.pk_bytes;
   if (secret_key_sz  != NULL) *secret_key_sz  = p.sk_bytes;
   if (signature_sz   != NULL) *signature_sz   = p.sig_bytes;
   if (rnd_sz         != NULL) *rnd_sz         = LTC_MLDSA_RND_BYTES;
   if (mu_sz          != NULL) *mu_sz          = LTC_MLDSA_MU_BYTES;
   if (keygen_seed_sz != NULL) *keygen_seed_sz = LTC_MLDSA_KEYGEN_SEED_BYTES;

   return CRYPT_OK;
}

/* Algorithm name / OID lookup */

typedef struct {
   int alg;
   const char *name;
   const char *oid;
} mldsa_alg_entry;

static const mldsa_alg_entry s_mldsa_alg_table[] = {
   { LTC_MLDSA_44, "ML-DSA-44", "2.16.840.1.101.3.4.3.17" },
   { LTC_MLDSA_65, "ML-DSA-65", "2.16.840.1.101.3.4.3.18" },
   { LTC_MLDSA_87, "ML-DSA-87", "2.16.840.1.101.3.4.3.19" },
};

/**
   Resolve an ML-DSA parameter set from its FIPS 204 name or its dotted-decimal OID.
   Name matching is case-insensitive and ignores '-' and '_', so e.g.
   "ML-DSA-65", "ml_dsa_65", and "MLDSA65" all resolve identically.
   @param name_or_oid   The canonical name (e.g. "ML-DSA-65") or the OID
                        string (e.g. "2.16.840.1.101.3.4.3.18")
   @param alg           [out] Matching ltc_mldsa_id value
   @return CRYPT_OK if a match was found, CRYPT_INVALID_ARG otherwise
*/
int mldsa_find_alg(const char *name_or_oid, int *alg)
{
   unsigned i;

   LTC_ARGCHK(name_or_oid != NULL);
   LTC_ARGCHK(alg         != NULL);

   for (i = 0; i < LTC_ARRAY_SIZE(s_mldsa_alg_table); ++i) {
      if (ltc_algname_match(s_mldsa_alg_table[i].name, name_or_oid) ||
          ltc_algname_match(s_mldsa_alg_table[i].oid,  name_or_oid)) {
         *alg = s_mldsa_alg_table[i].alg;
         return CRYPT_OK;
      }
   }
   return CRYPT_INVALID_ARG;
}

/**
   Get the canonical FIPS 204 name of an ML-DSA parameter set.
   @param alg    The parameter set (one of ltc_mldsa_id)
   @param name   [out] Pointer to a static, NUL-terminated name string
                 (e.g. "ML-DSA-65"); must not be freed by the caller
   @return CRYPT_OK if alg is valid, CRYPT_INVALID_ARG otherwise
*/
int mldsa_alg_name(int alg, const char **name)
{
   unsigned i;

   LTC_ARGCHK(name != NULL);

   for (i = 0; i < LTC_ARRAY_SIZE(s_mldsa_alg_table); ++i) {
      if (s_mldsa_alg_table[i].alg == alg) {
         *name = s_mldsa_alg_table[i].name;
         return CRYPT_OK;
      }
   }
   return CRYPT_INVALID_ARG;
}

#endif /* LTC_MLDSA */
