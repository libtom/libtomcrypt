/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/**
  @file slhdsa.c
  SLH-DSA (FIPS 205) implementation: WOTS+, FORS, Merkle trees, signing,
  and verification (SHAKE-simple and SHA2-simple variants).
  Based on the SPHINCS+ reference implementation (public domain).
*/

#include "tomcrypt_private.h"

#ifdef LTC_SLHDSA

/* Constants */

#define SPX_N_MAX           32
#define SPX_ADDR_BYTES      32   /* max address bytes (SHAKE uses 32, SHA-2 uses 22) */
#define SPX_WOTS_W          16
#define SPX_WOTS_LOGW        4
#define SPX_FULL_HEIGHT_MAX 68
#define SPX_D_MAX           22
#define SPX_TREE_HEIGHT_MAX 10   /* max(full_height/d) across all param sets */
#define SPX_FORS_HEIGHT_MAX 14
#define SPX_FORS_TREES_MAX  35
#define SPX_WOTS_LEN_MAX    67   /* max len1(64) + len2(3) = 67 for n=32 */
#define SPX_WOTS_BYTES_MAX (SPX_WOTS_LEN_MAX * SPX_N_MAX)  /* 67*32 = 2144 */

/* Address types */
#define SPX_ADDR_TYPE_WOTS     0
#define SPX_ADDR_TYPE_WOTSPK   1
#define SPX_ADDR_TYPE_HASHTREE 2
#define SPX_ADDR_TYPE_FORSTREE 3
#define SPX_ADDR_TYPE_FORSPK   4
#define SPX_ADDR_TYPE_WOTSPRF  5
#define SPX_ADDR_TYPE_FORSPRF  6

/* FIPS 205 M' in two parts: the framing goes to a stack buffer, the message is not copied */
#define SPX_MSG_PREFIX_MAX (2 + LTC_PQC_CTX_MAX_BYTES + 11 + 64)  /* 0x01 || ctxlen || ctx || OID || PH(M) */

typedef struct {
   const unsigned char *part1;
   unsigned long        part1_len;
   const unsigned char *part2;
   unsigned long        part2_len;
} slhdsa_message_view;

/* Runtime parameter set */

typedef struct {
   unsigned int n;
   unsigned int full_height;
   unsigned int d;
   unsigned int fors_height;
   unsigned int fors_trees;
   unsigned int wots_w;
   unsigned int wots_logw;
   unsigned int wots_len1;
   unsigned int wots_len2;
   unsigned int wots_len;
   unsigned int wots_bytes;
   unsigned int tree_height;
   unsigned int fors_msg_bytes;
   unsigned int fors_bytes;
   unsigned long pk_bytes;
   unsigned long sk_bytes;
   unsigned long sig_bytes;
   int is_shake;
   /* Address layout */
   unsigned int addr_bytes;
   unsigned int off_layer;
   unsigned int off_tree;
   unsigned int off_type;
   unsigned int off_kp_addr;
   unsigned int off_chain_addr;
   unsigned int off_hash_addr;
   unsigned int off_tree_hgt;
   unsigned int off_tree_index;
   /* Number of bytes for keypair addr field */
   unsigned int kp_addr_len;
} slhdsa_params;

static int s_slhdsa_is_hash_alg(int alg)
{
   return alg >= LTC_SLHDSA_HASH_SHA2_128S_WITH_SHA256
       && alg <= LTC_SLHDSA_HASH_SHAKE_256F_WITH_SHAKE256;
}

/* the pre-hash an alg id pins, one of ltc_pqc_prehash, 0 for the pure parameter sets */
static int s_slhdsa_hash_mode(int alg)
{
   switch (alg) {
      case LTC_SLHDSA_HASH_SHA2_128S_WITH_SHA256:
      case LTC_SLHDSA_HASH_SHA2_128F_WITH_SHA256:
         return LTC_PQC_PH_SHA256;
      case LTC_SLHDSA_HASH_SHA2_192S_WITH_SHA512:
      case LTC_SLHDSA_HASH_SHA2_192F_WITH_SHA512:
      case LTC_SLHDSA_HASH_SHA2_256S_WITH_SHA512:
      case LTC_SLHDSA_HASH_SHA2_256F_WITH_SHA512:
         return LTC_PQC_PH_SHA512;
      case LTC_SLHDSA_HASH_SHAKE_128S_WITH_SHAKE128:
      case LTC_SLHDSA_HASH_SHAKE_128F_WITH_SHAKE128:
         return LTC_PQC_PH_SHAKE128;
      case LTC_SLHDSA_HASH_SHAKE_192S_WITH_SHAKE256:
      case LTC_SLHDSA_HASH_SHAKE_192F_WITH_SHAKE256:
      case LTC_SLHDSA_HASH_SHAKE_256S_WITH_SHAKE256:
      case LTC_SLHDSA_HASH_SHAKE_256F_WITH_SHAKE256:
         return LTC_PQC_PH_SHAKE256;
      default:
         return 0;
   }
}

static int s_slhdsa_base_alg(int alg)
{
   switch (alg) {
      case LTC_SLHDSA_HASH_SHA2_128S_WITH_SHA256:
         return LTC_SLHDSA_SHA2_128S;
      case LTC_SLHDSA_HASH_SHA2_128F_WITH_SHA256:
         return LTC_SLHDSA_SHA2_128F;
      case LTC_SLHDSA_HASH_SHA2_192S_WITH_SHA512:
         return LTC_SLHDSA_SHA2_192S;
      case LTC_SLHDSA_HASH_SHA2_192F_WITH_SHA512:
         return LTC_SLHDSA_SHA2_192F;
      case LTC_SLHDSA_HASH_SHA2_256S_WITH_SHA512:
         return LTC_SLHDSA_SHA2_256S;
      case LTC_SLHDSA_HASH_SHA2_256F_WITH_SHA512:
         return LTC_SLHDSA_SHA2_256F;
      case LTC_SLHDSA_HASH_SHAKE_128S_WITH_SHAKE128:
         return LTC_SLHDSA_SHAKE_128S;
      case LTC_SLHDSA_HASH_SHAKE_128F_WITH_SHAKE128:
         return LTC_SLHDSA_SHAKE_128F;
      case LTC_SLHDSA_HASH_SHAKE_192S_WITH_SHAKE256:
         return LTC_SLHDSA_SHAKE_192S;
      case LTC_SLHDSA_HASH_SHAKE_192F_WITH_SHAKE256:
         return LTC_SLHDSA_SHAKE_192F;
      case LTC_SLHDSA_HASH_SHAKE_256S_WITH_SHAKE256:
         return LTC_SLHDSA_SHAKE_256S;
      case LTC_SLHDSA_HASH_SHAKE_256F_WITH_SHAKE256:
         return LTC_SLHDSA_SHAKE_256F;
      default:
         return alg;
   }
}

static int s_slhdsa_prepare_message(slhdsa_message_view *m,
                                    unsigned char prefix[SPX_MSG_PREFIX_MAX],
                                    const unsigned char *msg, unsigned long msglen,
                                    const unsigned char *ctx, unsigned long ctxlen,
                                    int alg)
{
   unsigned long oidlen = 0, phm_len;
   const unsigned char *oid = NULL;
   int err;

   LTC_ARGCHK(m != NULL);
   LTC_ARGCHK(prefix != NULL);
   LTC_ARGCHK(msg != NULL || msglen == 0);

   if (ctxlen > LTC_PQC_CTX_MAX_BYTES) {
      return CRYPT_INVALID_ARG;
   }

   prefix[1] = (unsigned char)ctxlen;
   if (ctxlen > 0) {
      XMEMCPY(prefix + 2, ctx, ctxlen);
   }

   if (!s_slhdsa_is_hash_alg(alg)) {
      prefix[0] = 0x00;
      m->part1 = prefix;
      m->part1_len = 2 + ctxlen;
      m->part2 = msg;
      m->part2_len = msglen;
      return CRYPT_OK;
   }

   prefix[0] = 0x01;
   if ((err = pqc_prehash_oid_der(s_slhdsa_hash_mode(alg), &oid, &oidlen)) != CRYPT_OK) {
      return err;
   }
   /* the subtraction below must not underflow if a longer hash OID is ever added */
   if (2 + ctxlen + oidlen > SPX_MSG_PREFIX_MAX) return CRYPT_INVALID_ARG;
   XMEMCPY(prefix + 2 + ctxlen, oid, oidlen);

   phm_len = SPX_MSG_PREFIX_MAX - (2 + ctxlen + oidlen);
   if ((err = pqc_prehash(s_slhdsa_hash_mode(alg), msg, msglen,
                          prefix + 2 + ctxlen + oidlen, &phm_len)) != CRYPT_OK) {
      return err;
   }

   m->part1 = prefix;
   m->part1_len = 2 + ctxlen + oidlen + phm_len;
   m->part2 = NULL;
   m->part2_len = 0;

   return CRYPT_OK;
}

/* Parameter lookup */

static int s_slhdsa_get_params(int alg, slhdsa_params *p)
{
   /* the HashSLH-DSA ids share the parameters of the pure id they are based on */
   int base = s_slhdsa_base_alg(alg);

   LTC_ARGCHK(p != NULL);

   XMEMSET(p, 0, sizeof(*p));

   p->wots_w = SPX_WOTS_W;
   p->wots_logw = SPX_WOTS_LOGW;

   switch (base) {
      case LTC_SLHDSA_SHA2_128S:
      case LTC_SLHDSA_SHAKE_128S:
         p->n = 16; p->full_height = 63; p->d = 7;
         p->fors_height = 12; p->fors_trees = 14;
         p->is_shake = (base == LTC_SLHDSA_SHAKE_128S) ? 1 : 0;
         break;
      case LTC_SLHDSA_SHA2_128F:
      case LTC_SLHDSA_SHAKE_128F:
         p->n = 16; p->full_height = 66; p->d = 22;
         p->fors_height = 6; p->fors_trees = 33;
         p->is_shake = (base == LTC_SLHDSA_SHAKE_128F) ? 1 : 0;
         break;
      case LTC_SLHDSA_SHA2_192S:
      case LTC_SLHDSA_SHAKE_192S:
         p->n = 24; p->full_height = 63; p->d = 7;
         p->fors_height = 14; p->fors_trees = 17;
         p->is_shake = (base == LTC_SLHDSA_SHAKE_192S) ? 1 : 0;
         break;
      case LTC_SLHDSA_SHA2_192F:
      case LTC_SLHDSA_SHAKE_192F:
         p->n = 24; p->full_height = 66; p->d = 22;
         p->fors_height = 8; p->fors_trees = 33;
         p->is_shake = (base == LTC_SLHDSA_SHAKE_192F) ? 1 : 0;
         break;
      case LTC_SLHDSA_SHA2_256S:
      case LTC_SLHDSA_SHAKE_256S:
         p->n = 32; p->full_height = 64; p->d = 8;
         p->fors_height = 14; p->fors_trees = 22;
         p->is_shake = (base == LTC_SLHDSA_SHAKE_256S) ? 1 : 0;
         break;
      case LTC_SLHDSA_SHA2_256F:
      case LTC_SLHDSA_SHAKE_256F:
         p->n = 32; p->full_height = 68; p->d = 17;
         p->fors_height = 9; p->fors_trees = 35;
         p->is_shake = (base == LTC_SLHDSA_SHAKE_256F) ? 1 : 0;
         break;
      default:
         return CRYPT_INVALID_ARG;
   }

   /* Derived WOTS+ parameters */
   p->wots_len1 = 8 * p->n / p->wots_logw;
   /* wots_len2 = floor(log(len1 * (w-1)) / log(w)) + 1, precomputed */
   if (p->n <= 8) {
      p->wots_len2 = 2;
   }
   else if (p->n <= 136) {
      p->wots_len2 = 3;
   }
   else {
      p->wots_len2 = 4;
   }
   p->wots_len = p->wots_len1 + p->wots_len2;
   p->wots_bytes = p->wots_len * p->n;

   /* Derived tree parameters */
   p->tree_height = p->full_height / p->d;
   p->fors_msg_bytes = (p->fors_height * p->fors_trees + 7) / 8;
   p->fors_bytes = (p->fors_height + 1) * p->fors_trees * p->n;

   /* Key and signature sizes */
   p->pk_bytes = 2 * (unsigned long)p->n;
   p->sk_bytes = 4 * (unsigned long)p->n;
   p->sig_bytes = (unsigned long)p->n + (unsigned long)p->fors_bytes
                + (unsigned long)p->d * (unsigned long)p->wots_bytes
                + (unsigned long)p->full_height * (unsigned long)p->n;

   /* Address offsets depend on variant */
   if (p->is_shake) {
      p->addr_bytes     = 32;
      p->off_layer      = 3;
      p->off_tree       = 8;
      p->off_type       = 19;
      p->off_kp_addr    = 20;
      p->off_chain_addr = 27;
      p->off_hash_addr  = 31;
      p->off_tree_hgt   = 27;
      p->off_tree_index = 28;
      p->kp_addr_len    = 4;
   }
   else {
      p->addr_bytes     = 22;
      p->off_layer      = 0;
      p->off_tree       = 1;
      p->off_type       = 9;
      p->off_kp_addr    = 10;
      p->off_chain_addr = 17;
      p->off_hash_addr  = 21;
      p->off_tree_hgt   = 17;
      p->off_tree_index = 18;
      p->kp_addr_len    = 4;
   }

   return CRYPT_OK;
}

/* Address manipulation */

static void s_set_layer_addr(unsigned char addr[SPX_ADDR_BYTES],
                             ulong32 layer, const slhdsa_params *p)
{
   addr[p->off_layer] = (unsigned char)layer;
}

static void s_set_tree_addr(unsigned char addr[SPX_ADDR_BYTES],
                            ulong64 tree, const slhdsa_params *p)
{
   int i;
   for (i = 7; i >= 0; i--) {
      addr[p->off_tree + i] = (unsigned char)(tree & 0xff);
      tree >>= 8;
   }
}

static void s_set_type(unsigned char addr[SPX_ADDR_BYTES],
                       ulong32 type, const slhdsa_params *p)
{
   addr[p->off_type] = (unsigned char)type;
}

static void s_copy_subtree_addr(unsigned char out[SPX_ADDR_BYTES],
                                const unsigned char in[SPX_ADDR_BYTES],
                                const slhdsa_params *p)
{
   XMEMCPY(out, in, p->off_tree + 8);
}

static void s_set_keypair_addr(unsigned char addr[SPX_ADDR_BYTES],
                               ulong32 keypair, const slhdsa_params *p)
{
   addr[p->off_kp_addr + 0] = (unsigned char)(keypair >> 24);
   addr[p->off_kp_addr + 1] = (unsigned char)(keypair >> 16);
   addr[p->off_kp_addr + 2] = (unsigned char)(keypair >> 8);
   addr[p->off_kp_addr + 3] = (unsigned char)(keypair);
}

static void s_copy_keypair_addr(unsigned char out[SPX_ADDR_BYTES],
                                const unsigned char in[SPX_ADDR_BYTES],
                                const slhdsa_params *p)
{
   XMEMCPY(out, in, p->off_tree + 8);
   XMEMCPY(out + p->off_kp_addr, in + p->off_kp_addr, p->kp_addr_len);
}

static void s_set_chain_addr(unsigned char addr[SPX_ADDR_BYTES],
                             ulong32 chain, const slhdsa_params *p)
{
   addr[p->off_chain_addr] = (unsigned char)chain;
}

static void s_set_hash_addr(unsigned char addr[SPX_ADDR_BYTES],
                            ulong32 hash, const slhdsa_params *p)
{
   addr[p->off_hash_addr] = (unsigned char)hash;
}

static void s_set_tree_height(unsigned char addr[SPX_ADDR_BYTES],
                              ulong32 tree_height, const slhdsa_params *p)
{
   addr[p->off_tree_hgt] = (unsigned char)tree_height;
}

static void s_set_tree_index(unsigned char addr[SPX_ADDR_BYTES],
                             ulong32 tree_index, const slhdsa_params *p)
{
   addr[p->off_tree_index + 0] = (unsigned char)(tree_index >> 24);
   addr[p->off_tree_index + 1] = (unsigned char)(tree_index >> 16);
   addr[p->off_tree_index + 2] = (unsigned char)(tree_index >> 8);
   addr[p->off_tree_index + 3] = (unsigned char)(tree_index);
}

/* Byte conversion utilities */

static void s_ull_to_bytes(unsigned char *out, unsigned int outlen, ulong64 in)
{
   int i;
   for (i = (int)outlen - 1; i >= 0; i--) {
      out[i] = (unsigned char)(in & 0xff);
      in >>= 8;
   }
}

static ulong64 s_bytes_to_ull(const unsigned char *in, unsigned int inlen)
{
   ulong64 retval = 0;
   unsigned int i;
   for (i = 0; i < inlen; i++) {
      retval |= ((ulong64)in[i]) << (8 * (inlen - 1 - i));
   }
   return retval;
}

/* ========================================================================= */
/* SHAKE-based hash functions                                                */
/* ========================================================================= */

/**
 * Tweakable hash (SHAKE-simple variant).
 * thash(pub_seed, addr, in, inblocks) = SHAKE256(pub_seed || addr || in)[0:n]
 */
static int s_thash_shake(unsigned char *out, const unsigned char *in,
                         unsigned int inblocks, const unsigned char *pub_seed,
                         unsigned char addr[SPX_ADDR_BYTES],
                         const slhdsa_params *p)
{
   hash_state md;
   int err;
   unsigned long outlen = p->n;

   if ((err = sha3_shake_init(&md, 256)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&md, pub_seed, p->n)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&md, addr, p->addr_bytes)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&md, in, (unsigned long)inblocks * p->n)) != CRYPT_OK) goto LBL_ERR;
   err = sha3_shake_done(&md, out, outlen);

LBL_ERR:
   /* the sponge absorbed values derived from SK.seed */
   zeromem(&md.sha3, sizeof(md.sha3));
   return err;
}

/**
 * PRF(pub_seed, sk_seed, addr) = SHAKE256(pub_seed || addr || sk_seed)[0:n]
 */
static int s_prf_addr_shake(unsigned char *out, const unsigned char *pub_seed,
                            const unsigned char *sk_seed,
                            unsigned char addr[SPX_ADDR_BYTES],
                            const slhdsa_params *p)
{
   hash_state md;
   int err;
   unsigned long outlen = p->n;

   if ((err = sha3_shake_init(&md, 256)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&md, pub_seed, p->n)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&md, addr, p->addr_bytes)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&md, sk_seed, p->n)) != CRYPT_OK) goto LBL_ERR;
   err = sha3_shake_done(&md, out, outlen);

LBL_ERR:
   /* the sponge absorbed SK.seed */
   zeromem(&md.sha3, sizeof(md.sha3));
   return err;
}

/**
 * Compute the message-dependent randomness R (SHAKE variant).
 * R = SHAKE256(sk_prf || optrand || m)[0:n]
 */
static int s_gen_message_random_shake(unsigned char *R,
                                      const unsigned char *sk_prf,
                                      const unsigned char *optrand,
                                      const slhdsa_message_view *m,
                                      const slhdsa_params *p)
{
   hash_state md;
   int err;
   unsigned long outlen = p->n;

   if ((err = sha3_shake_init(&md, 256)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&md, sk_prf, p->n)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&md, optrand, p->n)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&md, m->part1, m->part1_len)) != CRYPT_OK) goto LBL_ERR;
   if (m->part2_len > 0) {
      if ((err = sha3_shake_process(&md, m->part2, m->part2_len)) != CRYPT_OK) goto LBL_ERR;
   }
   err = sha3_shake_done(&md, R, outlen);

LBL_ERR:
   /* the sponge absorbed SK.prf */
   zeromem(&md.sha3, sizeof(md.sha3));
   return err;
}

/**
 * Compute the message digest and leaf index from R, PK and M (SHAKE variant).
 * SHAKE256(R || PK || M) -> (digest, tree, leaf_idx)
 */
static int s_hash_message_shake(unsigned char *digest, ulong64 *tree, ulong32 *leaf_idx,
                                const unsigned char *R, const unsigned char *pk,
                                const slhdsa_message_view *m,
                                const slhdsa_params *p)
{
   unsigned int tree_bits, tree_bytes, leaf_bits, leaf_bytes, dgst_bytes;
   unsigned char buf[SPX_FORS_HEIGHT_MAX * SPX_FORS_TREES_MAX / 8 + 1 + 8 + 4];
   unsigned char *bufp;
   hash_state md;
   int err;
   unsigned long outlen;

   tree_bits = p->tree_height * (p->d - 1);
   tree_bytes = (tree_bits + 7) / 8;
   leaf_bits = p->tree_height;
   leaf_bytes = (leaf_bits + 7) / 8;
   dgst_bytes = p->fors_msg_bytes + tree_bytes + leaf_bytes;

   outlen = dgst_bytes;

   if ((err = sha3_shake_init(&md, 256)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&md, R, p->n)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&md, pk, p->pk_bytes)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha3_shake_process(&md, m->part1, m->part1_len)) != CRYPT_OK) goto LBL_ERR;
   if (m->part2_len > 0) {
      if ((err = sha3_shake_process(&md, m->part2, m->part2_len)) != CRYPT_OK) goto LBL_ERR;
   }
   if ((err = sha3_shake_done(&md, buf, outlen)) != CRYPT_OK) goto LBL_ERR;

   bufp = buf;
   XMEMCPY(digest, bufp, p->fors_msg_bytes);
   bufp += p->fors_msg_bytes;

   if (p->d == 1) {
      *tree = 0;
   }
   else {
      *tree = s_bytes_to_ull(bufp, tree_bytes);
      *tree &= (~(ulong64)0) >> (64 - tree_bits);
   }
   bufp += tree_bytes;

   *leaf_idx = (ulong32)s_bytes_to_ull(bufp, leaf_bytes);
   *leaf_idx &= (~(ulong32)0) >> (32 - leaf_bits);

   err = CRYPT_OK;

LBL_ERR:
   zeromem(&md.sha3, sizeof(md.sha3));
   zeromem(buf, sizeof(buf));
   return err;
}

/* ========================================================================= */
/* SHA-2-based hash functions                                                */
/* ========================================================================= */

/* hash_state is a large union, so only the member the hash actually wrote is wiped */
static void s_wipe_sha2_state(hash_state *md, const struct ltc_hash_descriptor *desc)
{
   if (desc == &sha512_desc) zeromem(&md->sha512, sizeof(md->sha512));
   else                      zeromem(&md->sha256, sizeof(md->sha256));
}

/* PK.seed is padded with zeros up to the hash block size, see FIPS 205 11.2.1 and 11.2.2 */
static const unsigned char s_sha2_zeros[128] = { 0 };

/**
 * The SHA-2 parameter sets fix their hash, so the descriptors are used directly and no
 * registration is needed: SHA-256 for n < 24, SHA-512 for n >= 24.
 */
static const struct ltc_hash_descriptor* s_sha2_desc(const slhdsa_params *p)
{
   return (p->n >= 24) ? &sha512_desc : &sha256_desc;
}

/**
 * Tweakable hash (SHA-2-simple variant).
 * thash(pub_seed, addr, in, inblocks) = SHA-X(pub_seed || toByte(0, blocklen-n) || addr_c || in)[0:n]
 *
 * F (inblocks == 1) always uses SHA-256, H and T_l (inblocks > 1) use SHA-512 for n >= 24.
 */
static int s_thash_sha2(unsigned char *out, const unsigned char *in,
                        unsigned int inblocks, const unsigned char *pub_seed,
                        unsigned char addr[SPX_ADDR_BYTES],
                        const slhdsa_params *p)
{
   const struct ltc_hash_descriptor *desc;
   hash_state md;
   int err;
   unsigned char hash_out[64]; /* max SHA-512 output */

   /* the long variant only moves to SHA-512 above security level 1 */
   desc = (inblocks > 1 && p->n >= 24) ? &sha512_desc : &sha256_desc;

   if ((err = desc->init(&md)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->process(&md, pub_seed, p->n)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->process(&md, s_sha2_zeros, desc->blocksize - p->n)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->process(&md, addr, p->addr_bytes)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->process(&md, in, (unsigned long)inblocks * p->n)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->done(&md, hash_out)) != CRYPT_OK) goto LBL_ERR;

   /* Truncate to n bytes */
   XMEMCPY(out, hash_out, p->n);

LBL_ERR:
   /* md absorbed values derived from SK.seed */
   s_wipe_sha2_state(&md, desc);
   zeromem(hash_out, sizeof(hash_out));
   return err;
}

/**
 * PRF(pub_seed, sk_seed, addr) for SHA-2 variant.
 * PRF = SHA-256(pub_seed || toByte(0, 64-n) || addr_c || sk_seed)[0:n]
 * Always uses SHA-256 regardless of security level.
 */
static int s_prf_addr_sha2(unsigned char *out, const unsigned char *pub_seed,
                           const unsigned char *sk_seed,
                           unsigned char addr[SPX_ADDR_BYTES],
                           const slhdsa_params *p)
{
   hash_state md;
   int err;
   unsigned char hash_out[32]; /* SHA-256 output */

   if ((err = sha256_desc.init(&md)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha256_desc.process(&md, pub_seed, p->n)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha256_desc.process(&md, s_sha2_zeros, sha256_desc.blocksize - p->n)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha256_desc.process(&md, addr, p->addr_bytes)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha256_desc.process(&md, sk_seed, p->n)) != CRYPT_OK) goto LBL_ERR;
   if ((err = sha256_desc.done(&md, hash_out)) != CRYPT_OK) goto LBL_ERR;

   XMEMCPY(out, hash_out, p->n);

LBL_ERR:
   /* md absorbed SK.seed */
   zeromem(&md.sha256, sizeof(md.sha256));
   zeromem(hash_out, sizeof(hash_out));
   return err;
}

/**
 * Compute the message-dependent randomness R (SHA-2 variant).
 * R = HMAC-SHA-X(sk_prf, optrand || m)[0:n]
 * For n < 24: SHA-256; for n >= 24: SHA-512.
 */
static int s_gen_message_random_sha2(unsigned char *R,
                                     const unsigned char *sk_prf,
                                     const unsigned char *optrand,
                                     const slhdsa_message_view *m,
                                     const slhdsa_params *p)
{
   const struct ltc_hash_descriptor *desc = s_sha2_desc(p);
   unsigned char pad[128], hash_out[64]; /* max SHA-512 block and output */
   unsigned long i, blocklen = desc->blocksize;
   hash_state md;
   int err;

   /* SK.prf is n octets and n is at most 32, so the key is never hashed down to blocklen */
   XMEMSET(pad, 0x36, blocklen);
   for (i = 0; i < (unsigned long)p->n; i++) pad[i] = (unsigned char)(sk_prf[i] ^ 0x36);

   if ((err = desc->init(&md)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->process(&md, pad, blocklen)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->process(&md, optrand, p->n)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->process(&md, m->part1, m->part1_len)) != CRYPT_OK) goto LBL_ERR;
   if (m->part2_len > 0) {
      if ((err = desc->process(&md, m->part2, m->part2_len)) != CRYPT_OK) goto LBL_ERR;
   }
   if ((err = desc->done(&md, hash_out)) != CRYPT_OK) goto LBL_ERR;

   XMEMSET(pad, 0x5C, blocklen);
   for (i = 0; i < (unsigned long)p->n; i++) pad[i] = (unsigned char)(sk_prf[i] ^ 0x5C);

   if ((err = desc->init(&md)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->process(&md, pad, blocklen)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->process(&md, hash_out, desc->hashsize)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->done(&md, hash_out)) != CRYPT_OK) goto LBL_ERR;

   XMEMCPY(R, hash_out, p->n);

LBL_ERR:
   /* pad and md are keyed with SK.prf */
   zeromem(pad, sizeof(pad));
   zeromem(hash_out, sizeof(hash_out));
   s_wipe_sha2_state(&md, desc);
   return err;
}

/**
 * MGF1 helper for SHA-2 hash_message.
 * Generates dgst_len bytes of output from mgf_seed of mgf_seed_len bytes.
 * MGF1-SHA-X: for i=0,1,...: out += SHA-X(mgf_seed || i_be32), truncate.
 */
static int s_mgf1_sha2(unsigned char *out, unsigned long dgst_len,
                        const unsigned char *mgf_seed, unsigned long mgf_seed_len,
                        const struct ltc_hash_descriptor *desc)
{
   hash_state md;
   unsigned char hash_out[64]; /* max SHA-512 */
   unsigned char counter_buf[4];
   unsigned long hlen, remaining, copy_len;
   ulong32 counter;
   int err = CRYPT_OK;

   hlen = desc->hashsize;
   remaining = dgst_len;
   counter = 0;

   while (remaining > 0) {
      counter_buf[0] = (unsigned char)(counter >> 24);
      counter_buf[1] = (unsigned char)(counter >> 16);
      counter_buf[2] = (unsigned char)(counter >> 8);
      counter_buf[3] = (unsigned char)(counter);

      if ((err = desc->init(&md)) != CRYPT_OK) goto LBL_ERR;
      if ((err = desc->process(&md, mgf_seed, mgf_seed_len)) != CRYPT_OK) goto LBL_ERR;
      if ((err = desc->process(&md, counter_buf, 4)) != CRYPT_OK) goto LBL_ERR;
      if ((err = desc->done(&md, hash_out)) != CRYPT_OK) goto LBL_ERR;

      copy_len = remaining < hlen ? remaining : hlen;
      XMEMCPY(out, hash_out, copy_len);
      out += copy_len;
      remaining -= copy_len;
      counter++;
   }

LBL_ERR:
   s_wipe_sha2_state(&md, desc);
   zeromem(hash_out, sizeof(hash_out));
   zeromem(counter_buf, sizeof(counter_buf));
   return err;
}

/**
 * Compute the message digest and leaf index from R, PK and M (SHA-2 variant).
 *
 * Per FIPS 205 Section 11.2:
 *   seed = SHA-X(R || PK.seed || PK.root || M)
 *   digest = MGF1-SHA-X(R || PK.seed || seed, dgst_bytes)
 * Then extract (md, tree_idx, leaf_idx) from digest.
 */
static int s_hash_message_sha2(unsigned char *digest, ulong64 *tree, ulong32 *leaf_idx,
                               const unsigned char *R, const unsigned char *pk,
                               const slhdsa_message_view *m,
                               const slhdsa_params *p)
{
   unsigned int tree_bits, tree_bytes, leaf_bits, leaf_bytes, dgst_bytes;
   unsigned char buf[SPX_FORS_HEIGHT_MAX * SPX_FORS_TREES_MAX / 8 + 1 + 8 + 4];
   unsigned char *bufp;
   unsigned char seed[64]; /* max SHA-512 output */
   unsigned char mgf_input[2 * SPX_N_MAX + 64]; /* R || PK.seed || seed */
   const struct ltc_hash_descriptor *desc = s_sha2_desc(p);
   unsigned long mgf_input_len, hlen = desc->hashsize;
   hash_state md;
   int err;

   tree_bits = p->tree_height * (p->d - 1);
   tree_bytes = (tree_bits + 7) / 8;
   leaf_bits = p->tree_height;
   leaf_bytes = (leaf_bits + 7) / 8;
   dgst_bytes = p->fors_msg_bytes + tree_bytes + leaf_bytes;

   /* Step 1: seed = SHA-X(R || PK.seed || PK.root || M) */
   if ((err = desc->init(&md)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->process(&md, R, p->n)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->process(&md, pk, p->pk_bytes)) != CRYPT_OK) goto LBL_ERR;
   if ((err = desc->process(&md, m->part1, m->part1_len)) != CRYPT_OK) goto LBL_ERR;
   if (m->part2_len > 0) {
      if ((err = desc->process(&md, m->part2, m->part2_len)) != CRYPT_OK) goto LBL_ERR;
   }
   if ((err = desc->done(&md, seed)) != CRYPT_OK) goto LBL_ERR;

   /* Step 2: MGF1-SHA-X(R || PK.seed || seed, dgst_bytes) */
   mgf_input_len = (unsigned long)p->n + (unsigned long)p->n + hlen;
   XMEMCPY(mgf_input, R, p->n);
   XMEMCPY(mgf_input + p->n, pk, p->n);  /* PK.seed */
   XMEMCPY(mgf_input + 2 * p->n, seed, hlen);

   err = s_mgf1_sha2(buf, dgst_bytes, mgf_input, mgf_input_len, desc);
   if (err != CRYPT_OK) goto LBL_ERR;

   /* Extract digest, tree index, and leaf index */
   bufp = buf;
   XMEMCPY(digest, bufp, p->fors_msg_bytes);
   bufp += p->fors_msg_bytes;

   if (p->d == 1) {
      *tree = 0;
   }
   else {
      *tree = s_bytes_to_ull(bufp, tree_bytes);
      *tree &= (~(ulong64)0) >> (64 - tree_bits);
   }
   bufp += tree_bytes;

   *leaf_idx = (ulong32)s_bytes_to_ull(bufp, leaf_bytes);
   *leaf_idx &= (~(ulong32)0) >> (32 - leaf_bits);

   err = CRYPT_OK;

LBL_ERR:
   s_wipe_sha2_state(&md, desc);
   zeromem(buf, sizeof(buf));
   zeromem(seed, sizeof(seed));
   zeromem(mgf_input, sizeof(mgf_input));
   return err;
}

/* ========================================================================= */
/* Dispatch wrappers                                                         */
/* ========================================================================= */

static int s_thash(unsigned char *out, const unsigned char *in,
                   unsigned int inblocks, const unsigned char *pub_seed,
                   unsigned char addr[SPX_ADDR_BYTES],
                   const slhdsa_params *p)
{
   if (p->is_shake)
      return s_thash_shake(out, in, inblocks, pub_seed, addr, p);
   else
      return s_thash_sha2(out, in, inblocks, pub_seed, addr, p);
}

static int s_prf_addr(unsigned char *out, const unsigned char *pub_seed,
                      const unsigned char *sk_seed,
                      unsigned char addr[SPX_ADDR_BYTES],
                      const slhdsa_params *p)
{
   if (p->is_shake)
      return s_prf_addr_shake(out, pub_seed, sk_seed, addr, p);
   else
      return s_prf_addr_sha2(out, pub_seed, sk_seed, addr, p);
}

static int s_gen_message_random(unsigned char *R,
                                const unsigned char *sk_prf,
                                const unsigned char *optrand,
                                const slhdsa_message_view *m,
                                const slhdsa_params *p)
{
   if (p->is_shake)
      return s_gen_message_random_shake(R, sk_prf, optrand, m, p);
   else
      return s_gen_message_random_sha2(R, sk_prf, optrand, m, p);
}

static int s_hash_message(unsigned char *digest, ulong64 *tree, ulong32 *leaf_idx,
                          const unsigned char *R, const unsigned char *pk,
                          const slhdsa_message_view *m,
                          const slhdsa_params *p)
{
   if (p->is_shake)
      return s_hash_message_shake(digest, tree, leaf_idx, R, pk, m, p);
   else
      return s_hash_message_sha2(digest, tree, leaf_idx, R, pk, m, p);
}

/* These heap buffers hold values derived from SK.seed, wipe them before free */
static void s_slhdsa_wipe_free(unsigned char *buf, unsigned long len)
{
   zeromem(buf, len);
   XFREE(buf);
}

/* WOTS+ */

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 * Interprets in as start-th value of the chain.
 */
static int s_gen_chain(unsigned char *out, const unsigned char *in,
                       unsigned int start, unsigned int steps,
                       const unsigned char *pub_seed,
                       unsigned char addr[SPX_ADDR_BYTES],
                       const slhdsa_params *p)
{
   ulong32 i;
   int err;

   XMEMCPY(out, in, p->n);

   for (i = start; i < (start + steps) && i < p->wots_w; i++) {
      s_set_hash_addr(addr, i, p);
      if ((err = s_thash(out, out, 1, pub_seed, addr, p)) != CRYPT_OK) return err;
   }
   return CRYPT_OK;
}

/**
 * base_w algorithm: interprets an array of bytes as integers in base w.
 */
static void s_base_w(unsigned int *output, int out_len,
                     const unsigned char *input, const slhdsa_params *p)
{
   int in_idx = 0;
   int out_idx = 0;
   unsigned char total;
   int bits = 0;
   int consumed;

   (void)p;

   for (consumed = 0; consumed < out_len; consumed++) {
      if (bits == 0) {
         total = input[in_idx];
         in_idx++;
         bits += 8;
      }
      bits -= SPX_WOTS_LOGW;
      output[out_idx] = (total >> bits) & (SPX_WOTS_W - 1);
      out_idx++;
   }
}

/**
 * Computes the WOTS+ checksum over a message (in base_w).
 */
static void s_wots_checksum(unsigned int *csum_base_w,
                            const unsigned int *msg_base_w,
                            const slhdsa_params *p)
{
   unsigned int csum = 0;
   unsigned char csum_bytes[(SPX_WOTS_LEN_MAX * SPX_WOTS_LOGW + 7) / 8];
   unsigned int i;
   unsigned int csum_bytes_len;

   for (i = 0; i < p->wots_len1; i++) {
      csum += SPX_WOTS_W - 1 - msg_base_w[i];
   }

   /* Convert checksum to base_w. */
   csum = csum << ((8 - ((p->wots_len2 * SPX_WOTS_LOGW) % 8)) % 8);
   csum_bytes_len = (p->wots_len2 * SPX_WOTS_LOGW + 7) / 8;
   s_ull_to_bytes(csum_bytes, csum_bytes_len, csum);
   s_base_w(csum_base_w, (int)p->wots_len2, csum_bytes, p);
   zeromem(csum_bytes, sizeof(csum_bytes));
}

/**
 * Takes a message and derives the matching chain lengths.
 */
static void s_chain_lengths(unsigned int *lengths, const unsigned char *msg,
                            const slhdsa_params *p)
{
   s_base_w(lengths, (int)p->wots_len1, msg, p);
   s_wots_checksum(lengths + p->wots_len1, lengths, p);
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 */
static int s_wots_pk_from_sig(unsigned char *pk,
                              const unsigned char *sig,
                              const unsigned char *msg,
                              const unsigned char *pub_seed,
                              unsigned char addr[SPX_ADDR_BYTES],
                              const slhdsa_params *p)
{
   unsigned int lengths[SPX_WOTS_LEN_MAX];
   ulong32 i;
   int err;

   s_chain_lengths(lengths, msg, p);

   for (i = 0; i < p->wots_len; i++) {
      s_set_chain_addr(addr, i, p);
      if ((err = s_gen_chain(pk + (unsigned long)i * p->n,
                             sig + (unsigned long)i * p->n,
                             lengths[i], SPX_WOTS_W - 1 - lengths[i],
                             pub_seed, addr, p)) != CRYPT_OK) goto LBL_ERR;
   }
   err = CRYPT_OK;

LBL_ERR:
   zeromem(lengths, sizeof(lengths));
   return err;
}

/**
 * Generate a WOTS leaf node (public key hash).
 * This also generates the WOTS signature if wots_sign_leaf matches leaf_idx.
 *
 * This function corresponds to wots_gen_leafx1 from the reference implementation.
 *
 * @param dest          [out] The computed leaf node (n bytes)
 * @param pub_seed      The public seed
 * @param sk_seed       The secret seed
 * @param leaf_idx      Current leaf index
 * @param wots_sig      [out] If not NULL and leaf_idx == wots_sign_leaf, the WOTS sig is written here
 * @param wots_sign_leaf The leaf index to sign with (~0 if not signing)
 * @param wots_steps    Chain lengths for the message being signed
 * @param leaf_addr     Working WOTS address
 * @param pk_addr       Working WOTS-PK address
 * @param p             Parameter set
 */
static int s_wots_gen_leaf(unsigned char *dest,
                           const unsigned char *pub_seed,
                           const unsigned char *sk_seed,
                           ulong32 leaf_idx,
                           unsigned char *wots_sig,
                           ulong32 wots_sign_leaf,
                           const unsigned int *wots_steps,
                           unsigned char leaf_addr[SPX_ADDR_BYTES],
                           unsigned char pk_addr[SPX_ADDR_BYTES],
                           const slhdsa_params *p)
{
   unsigned int i, k;
   unsigned char pk_buffer[SPX_WOTS_BYTES_MAX];
   unsigned char *buffer;
   ulong32 wots_k_mask;
   int err;

   if (leaf_idx == wots_sign_leaf) {
      wots_k_mask = 0;
   }
   else {
      wots_k_mask = (ulong32)~0;
   }

   s_set_keypair_addr(leaf_addr, leaf_idx, p);
   s_set_keypair_addr(pk_addr, leaf_idx, p);

   for (i = 0, buffer = pk_buffer; i < p->wots_len; i++, buffer += p->n) {
      ulong32 wots_k = (wots_steps != NULL) ? (wots_steps[i] | wots_k_mask) : ((ulong32)~0);

      /* Start with the secret seed */
      s_set_chain_addr(leaf_addr, i, p);
      s_set_hash_addr(leaf_addr, 0, p);
      s_set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF, p);

      if ((err = s_prf_addr(buffer, pub_seed, sk_seed, leaf_addr, p)) != CRYPT_OK)
         goto LBL_ERR;

      s_set_type(leaf_addr, SPX_ADDR_TYPE_WOTS, p);

      /* Iterate down the WOTS chain */
      for (k = 0; ; k++) {
         /* Check if this is the value that needs to be saved as a part of the WOTS signature */
         if (k == wots_k && wots_sig != NULL) {
            XMEMCPY(wots_sig + (unsigned long)i * p->n, buffer, p->n);
         }

         /* Check if we hit the top of the chain */
         if (k == SPX_WOTS_W - 1) break;

         /* Iterate one step on the chain */
         s_set_hash_addr(leaf_addr, k, p);
         if ((err = s_thash(buffer, buffer, 1, pub_seed, leaf_addr, p)) != CRYPT_OK)
            goto LBL_ERR;
      }
   }

   /* Do the final thash to generate the public key */
   err = s_thash(dest, pk_buffer, p->wots_len, pub_seed, pk_addr, p);

LBL_ERR:
   /* pk_buffer starts as the WOTS+ secret key */
   zeromem(pk_buffer, sizeof(pk_buffer));
   return err;
}

/* Tree operations */

/**
 * Computes a root node given a leaf and an auth path.
 */
static int s_compute_root(unsigned char *root, const unsigned char *leaf,
                          ulong32 leaf_idx, ulong32 idx_offset,
                          const unsigned char *auth_path, ulong32 tree_height,
                          const unsigned char *pub_seed,
                          unsigned char addr[SPX_ADDR_BYTES],
                          const slhdsa_params *p)
{
   ulong32 i;
   unsigned char buffer[2 * SPX_N_MAX];
   int err;

   if (leaf_idx & 1) {
      XMEMCPY(buffer + p->n, leaf, p->n);
      XMEMCPY(buffer, auth_path, p->n);
   }
   else {
      XMEMCPY(buffer, leaf, p->n);
      XMEMCPY(buffer + p->n, auth_path, p->n);
   }
   auth_path += p->n;

   for (i = 0; i < tree_height - 1; i++) {
      leaf_idx >>= 1;
      idx_offset >>= 1;
      s_set_tree_height(addr, i + 1, p);
      s_set_tree_index(addr, leaf_idx + idx_offset, p);

      if (leaf_idx & 1) {
         if ((err = s_thash(buffer + p->n, buffer, 2, pub_seed, addr, p)) != CRYPT_OK) goto LBL_ERR;
         XMEMCPY(buffer, auth_path, p->n);
      }
      else {
         if ((err = s_thash(buffer, buffer, 2, pub_seed, addr, p)) != CRYPT_OK) goto LBL_ERR;
         XMEMCPY(buffer + p->n, auth_path, p->n);
      }
      auth_path += p->n;
   }

   leaf_idx >>= 1;
   idx_offset >>= 1;
   s_set_tree_height(addr, tree_height, p);
   s_set_tree_index(addr, leaf_idx + idx_offset, p);
   err = s_thash(root, buffer, 2, pub_seed, addr, p);

LBL_ERR:
   zeromem(buffer, sizeof(buffer));
   return err;
}

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's TreeHash algorithm.
 *
 * This is the treehashx1 variant that supports generating WOTS signatures
 * during traversal (needed by merkle_sign).
 *
 * @param root          [out] Root of the tree (n bytes)
 * @param auth_path     [out] Authentication path (tree_height * n bytes)
 * @param pub_seed      Public seed
 * @param sk_seed       Secret seed
 * @param leaf_idx      Target leaf index
 * @param idx_offset    Offset applied to leaf indices
 * @param tree_height   Height of the tree
 * @param tree_addr     Address structure for the tree
 * @param wots_sig      [out] If not NULL, WOTS signature for wots_sign_leaf
 * @param wots_sign_leaf Leaf to sign with (~0 if not signing)
 * @param wots_steps    Chain lengths for signing
 * @param wots_addr     Working WOTS address (for leaf generation)
 * @param p             Parameter set
 */
static int s_treehashx1(unsigned char *root, unsigned char *auth_path,
                        const unsigned char *pub_seed,
                        const unsigned char *sk_seed,
                        ulong32 leaf_idx, ulong32 idx_offset,
                        ulong32 tree_height,
                        unsigned char tree_addr[SPX_ADDR_BYTES],
                        unsigned char *wots_sig,
                        ulong32 wots_sign_leaf,
                        const unsigned int *wots_steps,
                        unsigned char wots_addr[SPX_ADDR_BYTES],
                        const slhdsa_params *p)
{
   unsigned char *stack;
   ulong32 idx;
   ulong32 max_idx = ((ulong32)1 << tree_height) - 1;
   int err;

   /* Allocate stack: tree_height * n bytes for intermediate nodes */
   stack = XMALLOC((unsigned long)tree_height * p->n);
   if (stack == NULL) return CRYPT_MEM;

   for (idx = 0; ; idx++) {
      unsigned char current[2 * SPX_N_MAX];
      unsigned char leaf_addr[SPX_ADDR_BYTES];
      unsigned char pk_addr[SPX_ADDR_BYTES];

      XMEMSET(leaf_addr, 0, SPX_ADDR_BYTES);
      XMEMSET(pk_addr, 0, SPX_ADDR_BYTES);

      s_copy_subtree_addr(leaf_addr, wots_addr, p);
      s_copy_subtree_addr(pk_addr, wots_addr, p);
      s_set_type(pk_addr, SPX_ADDR_TYPE_WOTSPK, p);

      /* Generate the leaf node */
      err = s_wots_gen_leaf(&current[p->n], pub_seed, sk_seed,
                            idx + idx_offset,
                            wots_sig, wots_sign_leaf, wots_steps,
                            leaf_addr, pk_addr, p);
      if (err != CRYPT_OK) {
         zeromem(current, sizeof(current));
         zeromem(leaf_addr, sizeof(leaf_addr));
         zeromem(pk_addr, sizeof(pk_addr));
         s_slhdsa_wipe_free(stack, (unsigned long)tree_height * p->n);
         return err;
      }

      /* Combine with previously generated nodes */
      {
         ulong32 internal_idx_offset = idx_offset;
         ulong32 internal_idx = idx;
         ulong32 internal_leaf = leaf_idx;
         ulong32 h;

         for (h = 0; ; h++, internal_idx >>= 1, internal_leaf >>= 1) {
            if (h == tree_height) {
               XMEMCPY(root, &current[p->n], p->n);
               zeromem(current, sizeof(current));
               zeromem(leaf_addr, sizeof(leaf_addr));
               zeromem(pk_addr, sizeof(pk_addr));
               s_slhdsa_wipe_free(stack, (unsigned long)tree_height * p->n);
               return CRYPT_OK;
            }

            if ((internal_idx ^ internal_leaf) == 0x01) {
               XMEMCPY(&auth_path[h * p->n], &current[p->n], p->n);
            }

            if ((internal_idx & 1) == 0 && idx < max_idx) {
               break;
            }

            /* Combine left and right nodes */
            internal_idx_offset >>= 1;
            s_set_tree_height(tree_addr, h + 1, p);
            s_set_tree_index(tree_addr, internal_idx / 2 + internal_idx_offset, p);

            XMEMCPY(&current[0], &stack[h * p->n], p->n);
            err = s_thash(&current[p->n], &current[0], 2, pub_seed, tree_addr, p);
            if (err != CRYPT_OK) {
               zeromem(current, sizeof(current));
               zeromem(leaf_addr, sizeof(leaf_addr));
               zeromem(pk_addr, sizeof(pk_addr));
               s_slhdsa_wipe_free(stack, (unsigned long)tree_height * p->n);
               return err;
            }
         }

         XMEMCPY(&stack[h * p->n], &current[p->n], p->n);
      }
      zeromem(current, sizeof(current));
      zeromem(leaf_addr, sizeof(leaf_addr));
      zeromem(pk_addr, sizeof(pk_addr));
   }
}

/**
 * Simplified treehash for FORS: uses a callback-style leaf generation.
 * This version generates FORS leaf nodes directly.
 *
 * @param root          [out] Root of the tree (n bytes)
 * @param auth_path     [out] Authentication path
 * @param pub_seed      Public seed
 * @param sk_seed       Secret seed
 * @param leaf_idx      Target leaf index
 * @param idx_offset    Offset applied to leaf indices
 * @param tree_height   Height of the tree
 * @param tree_addr     Address structure for the tree
 * @param fors_leaf_addr FORS leaf address
 * @param p             Parameter set
 */
static int s_treehash_fors(unsigned char *root, unsigned char *auth_path,
                           const unsigned char *pub_seed,
                           const unsigned char *sk_seed,
                           ulong32 leaf_idx, ulong32 idx_offset,
                           ulong32 tree_height,
                           unsigned char tree_addr[SPX_ADDR_BYTES],
                           unsigned char fors_leaf_addr[SPX_ADDR_BYTES],
                           const slhdsa_params *p)
{
   unsigned char *stack;
   ulong32 idx;
   ulong32 max_idx = ((ulong32)1 << tree_height) - 1;
   int err;

   stack = XMALLOC((unsigned long)tree_height * p->n);
   if (stack == NULL) return CRYPT_MEM;

   for (idx = 0; ; idx++) {
      unsigned char current[2 * SPX_N_MAX];

      /* Generate the FORS leaf */
      s_set_tree_index(fors_leaf_addr, idx + idx_offset, p);
      s_set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF, p);
      if ((err = s_prf_addr(&current[p->n], pub_seed, sk_seed, fors_leaf_addr, p)) != CRYPT_OK) {
         zeromem(current, sizeof(current));
         s_slhdsa_wipe_free(stack, (unsigned long)tree_height * p->n);
         return err;
      }

      s_set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE, p);
      if ((err = s_thash(&current[p->n], &current[p->n], 1, pub_seed, fors_leaf_addr, p)) != CRYPT_OK) {
         zeromem(current, sizeof(current));
         s_slhdsa_wipe_free(stack, (unsigned long)tree_height * p->n);
         return err;
      }

      /* Combine with previously generated nodes */
      {
         ulong32 internal_idx_offset = idx_offset;
         ulong32 internal_idx = idx;
         ulong32 internal_leaf = leaf_idx;
         ulong32 h;

         for (h = 0; ; h++, internal_idx >>= 1, internal_leaf >>= 1) {
            if (h == tree_height) {
               XMEMCPY(root, &current[p->n], p->n);
               zeromem(current, sizeof(current));
               s_slhdsa_wipe_free(stack, (unsigned long)tree_height * p->n);
               return CRYPT_OK;
            }

            if ((internal_idx ^ internal_leaf) == 0x01) {
               XMEMCPY(&auth_path[h * p->n], &current[p->n], p->n);
            }

            if ((internal_idx & 1) == 0 && idx < max_idx) {
               break;
            }

            internal_idx_offset >>= 1;
            s_set_tree_height(tree_addr, h + 1, p);
            s_set_tree_index(tree_addr, internal_idx / 2 + internal_idx_offset, p);

            XMEMCPY(&current[0], &stack[h * p->n], p->n);
            err = s_thash(&current[p->n], &current[0], 2, pub_seed, tree_addr, p);
            if (err != CRYPT_OK) {
               zeromem(current, sizeof(current));
               s_slhdsa_wipe_free(stack, (unsigned long)tree_height * p->n);
               return err;
            }
         }

         XMEMCPY(&stack[h * p->n], &current[p->n], p->n);
      }
      zeromem(current, sizeof(current));
   }
}

/* FORS */

/**
 * base_2b(m, fors_height, fors_trees) - interprets m as fors_height-bit unsigned
 * integers, most significant bit first (FIPS 205, Algorithm 4).
 */
static void s_message_to_indices(ulong32 *indices, const unsigned char *m,
                                 const slhdsa_params *p)
{
   unsigned int i, in = 0, bits = 0;
   ulong32 total = 0;

   for (i = 0; i < p->fors_trees; i++) {
      while (bits < p->fors_height) {
         total = (total << 8) | m[in++];
         bits += 8;
      }
      bits -= p->fors_height;
      indices[i] = (total >> bits) & ((1u << p->fors_height) - 1u);
   }
}

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 */
static int s_fors_sign(unsigned char *sig, unsigned char *pk,
                       const unsigned char *m,
                       const unsigned char *pub_seed,
                       const unsigned char *sk_seed,
                       const unsigned char fors_addr[SPX_ADDR_BYTES],
                       const slhdsa_params *p)
{
   ulong32 indices[SPX_FORS_TREES_MAX];
   unsigned char *roots;
   unsigned char fors_tree_addr[SPX_ADDR_BYTES];
   unsigned char fors_leaf_addr[SPX_ADDR_BYTES];
   unsigned char fors_pk_addr[SPX_ADDR_BYTES];
   ulong32 idx_offset;
   unsigned int i;
   int err;

   roots = XMALLOC((unsigned long)p->fors_trees * p->n);
   if (roots == NULL) return CRYPT_MEM;

   XMEMSET(fors_tree_addr, 0, SPX_ADDR_BYTES);
   XMEMSET(fors_leaf_addr, 0, SPX_ADDR_BYTES);
   XMEMSET(fors_pk_addr, 0, SPX_ADDR_BYTES);

   s_copy_keypair_addr(fors_tree_addr, fors_addr, p);
   s_copy_keypair_addr(fors_leaf_addr, fors_addr, p);
   s_copy_keypair_addr(fors_pk_addr, fors_addr, p);
   s_set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK, p);

   s_message_to_indices(indices, m, p);

   for (i = 0; i < p->fors_trees; i++) {
      idx_offset = i * ((ulong32)1 << p->fors_height);

      s_set_tree_height(fors_tree_addr, 0, p);
      s_set_tree_index(fors_tree_addr, indices[i] + idx_offset, p);
      s_set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF, p);

      /* Include the secret key part that produces the selected leaf node. */
      if ((err = s_prf_addr(sig, pub_seed, sk_seed, fors_tree_addr, p)) != CRYPT_OK) goto LBL_ERR;
      s_set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE, p);
      sig += p->n;

      /* Compute the authentication path for this leaf node. */
      err = s_treehash_fors(roots + (unsigned long)i * p->n, sig,
                            pub_seed, sk_seed,
                            indices[i], idx_offset, p->fors_height,
                            fors_tree_addr, fors_leaf_addr, p);
      if (err != CRYPT_OK) goto LBL_ERR;

      sig += (unsigned long)p->n * p->fors_height;
   }

   /* Hash horizontally across all tree roots to derive the public key. */
   err = s_thash(pk, roots, p->fors_trees, pub_seed, fors_pk_addr, p);

LBL_ERR:
   s_slhdsa_wipe_free(roots, (unsigned long)p->fors_trees * p->n);
   zeromem(indices, sizeof(indices));
   zeromem(fors_tree_addr, sizeof(fors_tree_addr));
   zeromem(fors_leaf_addr, sizeof(fors_leaf_addr));
   zeromem(fors_pk_addr, sizeof(fors_pk_addr));
   return err;
}

/**
 * Derives the FORS public key from a signature.
 */
static int s_fors_pk_from_sig(unsigned char *pk,
                              const unsigned char *sig,
                              const unsigned char *m,
                              const unsigned char *pub_seed,
                              const unsigned char fors_addr[SPX_ADDR_BYTES],
                              const slhdsa_params *p)
{
   ulong32 indices[SPX_FORS_TREES_MAX];
   unsigned char *roots;
   unsigned char leaf[SPX_N_MAX];
   unsigned char fors_tree_addr[SPX_ADDR_BYTES];
   unsigned char fors_pk_addr[SPX_ADDR_BYTES];
   ulong32 idx_offset;
   unsigned int i;
   int err;

   roots = XMALLOC((unsigned long)p->fors_trees * p->n);
   if (roots == NULL) return CRYPT_MEM;

   XMEMSET(fors_tree_addr, 0, SPX_ADDR_BYTES);
   XMEMSET(fors_pk_addr, 0, SPX_ADDR_BYTES);

   s_copy_keypair_addr(fors_tree_addr, fors_addr, p);
   s_copy_keypair_addr(fors_pk_addr, fors_addr, p);

   s_set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE, p);
   s_set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK, p);

   s_message_to_indices(indices, m, p);

   for (i = 0; i < p->fors_trees; i++) {
      idx_offset = i * ((ulong32)1 << p->fors_height);

      s_set_tree_height(fors_tree_addr, 0, p);
      s_set_tree_index(fors_tree_addr, indices[i] + idx_offset, p);

      /* Derive the leaf from the included secret key part. */
      err = s_thash(leaf, sig, 1, pub_seed, fors_tree_addr, p);
      if (err != CRYPT_OK) goto LBL_ERR;
      sig += p->n;

      /* Derive the corresponding root node of this tree. */
      err = s_compute_root(roots + (unsigned long)i * p->n, leaf,
                           indices[i], idx_offset,
                           sig, p->fors_height, pub_seed, fors_tree_addr, p);
      if (err != CRYPT_OK) goto LBL_ERR;
      sig += (unsigned long)p->n * p->fors_height;
   }

   /* Hash horizontally across all tree roots to derive the public key. */
   err = s_thash(pk, roots, p->fors_trees, pub_seed, fors_pk_addr, p);

LBL_ERR:
   s_slhdsa_wipe_free(roots, (unsigned long)p->fors_trees * p->n);
   zeromem(indices, sizeof(indices));
   zeromem(leaf, sizeof(leaf));
   zeromem(fors_tree_addr, sizeof(fors_tree_addr));
   zeromem(fors_pk_addr, sizeof(fors_pk_addr));
   return err;
}

/* Merkle */

/**
 * Generate a Merkle signature (WOTS signature followed by authentication path).
 */
static int s_merkle_sign(unsigned char *sig, unsigned char *root,
                         const unsigned char *pub_seed,
                         const unsigned char *sk_seed,
                         unsigned char wots_addr[SPX_ADDR_BYTES],
                         unsigned char tree_addr[SPX_ADDR_BYTES],
                         ulong32 idx_leaf,
                         const slhdsa_params *p)
{
   unsigned char *auth_path = sig + p->wots_bytes;
   unsigned int steps[SPX_WOTS_LEN_MAX];
   int err;

   s_chain_lengths(steps, root, p);

   s_set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE, p);

   err = s_treehashx1(root, auth_path, pub_seed, sk_seed,
                      idx_leaf, 0, p->tree_height,
                      tree_addr, sig, idx_leaf, steps,
                      wots_addr, p);
   zeromem(steps, sizeof(steps));
   return err;
}

/**
 * Compute root node of the top-most subtree.
 */
static int s_merkle_gen_root(unsigned char *root,
                             const unsigned char *pub_seed,
                             const unsigned char *sk_seed,
                             const slhdsa_params *p)
{
   unsigned char auth_path[SPX_TREE_HEIGHT_MAX * SPX_N_MAX + SPX_WOTS_BYTES_MAX];
   unsigned char top_tree_addr[SPX_ADDR_BYTES];
   unsigned char wots_addr[SPX_ADDR_BYTES];
   int err;

   XMEMSET(top_tree_addr, 0, SPX_ADDR_BYTES);
   XMEMSET(wots_addr, 0, SPX_ADDR_BYTES);

   s_set_layer_addr(top_tree_addr, p->d - 1, p);
   s_set_layer_addr(wots_addr, p->d - 1, p);

   err = s_merkle_sign(auth_path, root, pub_seed, sk_seed,
                       wots_addr, top_tree_addr,
                       (ulong32)~0, /* ~0 means "don't generate an auth path" */
                       p);
   zeromem(auth_path, sizeof(auth_path));
   zeromem(top_tree_addr, sizeof(top_tree_addr));
   zeromem(wots_addr, sizeof(wots_addr));
   return err;
}

/* Sign / verify core */

static int s_sign_core(unsigned char *sig, unsigned long *siglen,
                       const slhdsa_message_view *m,
                       const unsigned char *sk,
                       const unsigned char *optrand,
                       const slhdsa_params *p)
{
   const unsigned char *sk_seed = sk;
   const unsigned char *sk_prf = sk + p->n;
   const unsigned char *pk = sk + 2 * p->n;
   const unsigned char *pub_seed = pk;
   unsigned char mhash[SPX_FORS_HEIGHT_MAX * SPX_FORS_TREES_MAX / 8 + 1];
   unsigned char root[SPX_N_MAX];
   ulong64 tree;
   ulong32 idx_leaf;
   unsigned char wots_addr[SPX_ADDR_BYTES];
   unsigned char tree_addr[SPX_ADDR_BYTES];
   ulong32 i;
   int err;

   XMEMSET(wots_addr, 0, SPX_ADDR_BYTES);
   XMEMSET(tree_addr, 0, SPX_ADDR_BYTES);

   s_set_type(wots_addr, SPX_ADDR_TYPE_WOTS, p);
   s_set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE, p);

   /* Compute the digest randomization value R. */
   if ((err = s_gen_message_random(sig, sk_prf, optrand, m, p)) != CRYPT_OK) goto LBL_ERR;

   /* Derive the message digest and leaf index from R, PK and M. */
   if ((err = s_hash_message(mhash, &tree, &idx_leaf, sig, pk, m, p)) != CRYPT_OK) goto LBL_ERR;
   sig += p->n;

   s_set_tree_addr(wots_addr, tree, p);
   s_set_keypair_addr(wots_addr, idx_leaf, p);

   /* Sign the message hash using FORS. */
   if ((err = s_fors_sign(sig, root, mhash, pub_seed, sk_seed, wots_addr, p)) != CRYPT_OK) goto LBL_ERR;
   sig += p->fors_bytes;

   for (i = 0; i < p->d; i++) {
      s_set_layer_addr(tree_addr, i, p);
      s_set_tree_addr(tree_addr, tree, p);

      s_copy_subtree_addr(wots_addr, tree_addr, p);
      s_set_keypair_addr(wots_addr, idx_leaf, p);

      if ((err = s_merkle_sign(sig, root, pub_seed, sk_seed,
                               wots_addr, tree_addr, idx_leaf, p)) != CRYPT_OK) goto LBL_ERR;
      sig += p->wots_bytes + (unsigned long)p->tree_height * p->n;

      /* Update the indices for the next layer. */
      idx_leaf = (ulong32)(tree & (((ulong64)1 << p->tree_height) - 1));
      tree = tree >> p->tree_height;
   }

   *siglen = p->sig_bytes;
   err = CRYPT_OK;

LBL_ERR:
   /* FIPS 205 3.1: intermediate values can contain sensitive data. */
   zeromem(mhash, sizeof(mhash));
   zeromem(root, sizeof(root));
   zeromem(&tree, sizeof(tree));
   zeromem(&idx_leaf, sizeof(idx_leaf));
   zeromem(wots_addr, sizeof(wots_addr));
   zeromem(tree_addr, sizeof(tree_addr));
   return err;
}

static int s_verify_core(const unsigned char *sig, unsigned long siglen,
                         const slhdsa_message_view *m,
                         const unsigned char *pk,
                         const slhdsa_params *p)
{
   const unsigned char *pub_seed = pk;
   const unsigned char *pub_root = pk + p->n;
   unsigned char mhash[SPX_FORS_HEIGHT_MAX * SPX_FORS_TREES_MAX / 8 + 1];
   unsigned char wots_pk[SPX_WOTS_BYTES_MAX];
   unsigned char root[SPX_N_MAX];
   unsigned char leaf[SPX_N_MAX];
   unsigned int i;
   ulong64 tree;
   ulong32 idx_leaf;
   unsigned char wots_addr[SPX_ADDR_BYTES];
   unsigned char tree_addr[SPX_ADDR_BYTES];
   unsigned char wots_pk_addr[SPX_ADDR_BYTES];
   unsigned char diff;
   int err;

   if (siglen != p->sig_bytes) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   XMEMSET(wots_addr, 0, SPX_ADDR_BYTES);
   XMEMSET(tree_addr, 0, SPX_ADDR_BYTES);
   XMEMSET(wots_pk_addr, 0, SPX_ADDR_BYTES);

   s_set_type(wots_addr, SPX_ADDR_TYPE_WOTS, p);
   s_set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE, p);
   s_set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK, p);

   /* Derive the message digest and leaf index from R || PK || M. */
   if ((err = s_hash_message(mhash, &tree, &idx_leaf, sig, pk, m, p)) != CRYPT_OK) goto LBL_ERR;
   sig += p->n;

   /* Layer correctly defaults to 0, so no need to set_layer_addr */
   s_set_tree_addr(wots_addr, tree, p);
   s_set_keypair_addr(wots_addr, idx_leaf, p);

   if ((err = s_fors_pk_from_sig(root, sig, mhash, pub_seed, wots_addr, p)) != CRYPT_OK) goto LBL_ERR;
   sig += p->fors_bytes;

   /* For each subtree.. */
   for (i = 0; i < p->d; i++) {
      s_set_layer_addr(tree_addr, i, p);
      s_set_tree_addr(tree_addr, tree, p);

      s_copy_subtree_addr(wots_addr, tree_addr, p);
      s_set_keypair_addr(wots_addr, idx_leaf, p);

      s_copy_keypair_addr(wots_pk_addr, wots_addr, p);

      /* The WOTS public key is only correct if the signature was correct. */
      if ((err = s_wots_pk_from_sig(wots_pk, sig, root, pub_seed, wots_addr, p)) != CRYPT_OK)
         goto LBL_ERR;
      sig += p->wots_bytes;

      /* Compute the leaf node using the WOTS public key. */
      if ((err = s_thash(leaf, wots_pk, p->wots_len, pub_seed, wots_pk_addr, p)) != CRYPT_OK)
         goto LBL_ERR;

      /* Compute the root node of this subtree. */
      if ((err = s_compute_root(root, leaf, idx_leaf, 0, sig, p->tree_height,
                                pub_seed, tree_addr, p)) != CRYPT_OK) goto LBL_ERR;
      sig += (unsigned long)p->tree_height * p->n;

      /* Update the indices for the next layer. */
      idx_leaf = (ulong32)(tree & (((ulong64)1 << p->tree_height) - 1));
      tree = tree >> p->tree_height;
   }

   /* Check if the root node equals the root node in the public key. */
   diff = 0;
   for (i = 0; i < p->n; i++) {
      diff |= root[i] ^ pub_root[i];
   }
   err = (diff == 0) ? CRYPT_OK : CRYPT_INVALID_PACKET;

LBL_ERR:
   zeromem(mhash, sizeof(mhash));
   zeromem(wots_pk, sizeof(wots_pk));
   zeromem(root, sizeof(root));
   zeromem(leaf, sizeof(leaf));
   zeromem(&tree, sizeof(tree));
   zeromem(&idx_leaf, sizeof(idx_leaf));
   zeromem(wots_addr, sizeof(wots_addr));
   zeromem(tree_addr, sizeof(tree_addr));
   zeromem(wots_pk_addr, sizeof(wots_pk_addr));
   zeromem(&diff, sizeof(diff));
   return err;
}

/* Public API */

/**
   Generate an SLH-DSA key pair.
   @param prng     An active PRNG state
   @param wprng    The index of the desired PRNG
   @param alg      The parameter set (one of ltc_slhdsa_id)
   @param key      [out] Destination for the newly created key pair
   @return CRYPT_OK if successful
*/
int slhdsa_make_key(prng_state *prng, int wprng, int alg, slhdsa_key *key)
{
   slhdsa_params p;
   unsigned char seed[3 * SPX_N_MAX]; /* SK_SEED || SK_PRF || PUB_SEED */
   int err;

   if ((err = s_slhdsa_get_params(alg, &p)) != CRYPT_OK) return err;
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) return err;

   if (prng_descriptor[wprng].read(seed, 3 * p.n, prng) != 3 * p.n) {
      zeromem(seed, sizeof(seed));
      return CRYPT_ERROR_READPRNG;
   }

   err = slhdsa_make_key_from_seed(alg, seed, 3uL * p.n, key);

   zeromem(seed, sizeof(seed));
   return err;
}

/**
   Generate an SLH-DSA key pair deterministically from a seed (FIPS 205 10.1 slh_keygen_internal).
   @param alg      The parameter set (one of ltc_slhdsa_id)
   @param seed     The input seed: SK.seed || SK.prf || PK.seed (3*n bytes,
                   where n is 16, 24, or 32 depending on the parameter set)
   @param seedlen  Length of the seed in bytes; must equal 3*n
   @param key      [out] Destination for the newly created key pair
   @return CRYPT_OK if successful
*/
int slhdsa_make_key_from_seed(int alg, const unsigned char *seed, unsigned long seedlen, slhdsa_key *key)
{
   slhdsa_params p;
   int err;

   LTC_ARGCHK(seed != NULL);
   LTC_ARGCHK(key  != NULL);

   if ((err = s_slhdsa_get_params(alg, &p)) != CRYPT_OK) return err;
   if (seedlen != 3uL * p.n) return CRYPT_INVALID_ARG;

   /* Allocate key storage:
      sk = [SK_SEED || SK_PRF || PUB_SEED || root]  (4*n bytes)
      pk = [PUB_SEED || root]                        (2*n bytes) */
   XMEMSET(key, 0, sizeof(*key));
   key->sk = XMALLOC(p.sk_bytes);
   key->pk = XMALLOC(p.pk_bytes);
   if (key->sk == NULL || key->pk == NULL) {
      slhdsa_free(key);
      return CRYPT_MEM;
   }
   /* set the lengths up front so slhdsa_free() wipes SK_SEED and SK_PRF on the error path */
   key->pklen = p.pk_bytes;
   key->sklen = p.sk_bytes;

   /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
   XMEMCPY(key->sk, seed, 3 * p.n);
   XMEMCPY(key->pk, seed + 2 * p.n, p.n);  /* PUB_SEED */

   /* Compute root node of the top-most subtree. */
   if ((err = s_merkle_gen_root(key->sk + 3 * p.n, key->pk, key->sk, &p)) != CRYPT_OK) {
      slhdsa_free(key);
      return err;
   }

   XMEMCPY(key->pk + p.n, key->sk + 3 * p.n, p.n); /* root */

   key->alg = alg;
   key->type = PK_PRIVATE;

   return CRYPT_OK;
}

/**
   Free an SLH-DSA key from memory.
   @param key   The key to free
*/
void slhdsa_free(slhdsa_key *key)
{
   if (key == NULL) return;
   if (key->sk != NULL) {
      zeromem(key->sk, key->sklen);
      XFREE(key->sk);
   }
   if (key->pk != NULL) {
      XFREE(key->pk);
   }
   XMEMSET(key, 0, sizeof(*key));
}

/* Cheap check of the key fields only, the key material is checked by slhdsa_check_key() */
static int s_slhdsa_key_valid(const slhdsa_key *key, int require_private, slhdsa_params *p)
{
   int err;

   if ((err = s_slhdsa_get_params(key->alg, p)) != CRYPT_OK) return err;
   if (require_private && key->type != PK_PRIVATE) return CRYPT_PK_NOT_PRIVATE;
   if (key->type != PK_PRIVATE && key->type != PK_PUBLIC) return CRYPT_PK_INVALID_TYPE;
   if (key->pk == NULL || key->pklen != p->pk_bytes) return CRYPT_PK_INVALID_TYPE;
   if (key->type == PK_PRIVATE && (key->sk == NULL || key->sklen != p->sk_bytes)) return CRYPT_PK_INVALID_TYPE;

   return CRYPT_OK;
}

/**
   Export an SLH-DSA key to a byte buffer.
   @param out      [out] Destination for the exported key
   @param outlen   [in/out] Max size and resulting size of the exported key
   @param which    PK_PUBLIC for the verification key, PK_PRIVATE for the signing key
   @param key      The key to export
   @return CRYPT_OK if successful
*/
int slhdsa_export_raw(unsigned char *out, unsigned long *outlen, int which, const slhdsa_key *key)
{
   slhdsa_params p;
   unsigned long needed;
   int err;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   if (which == PK_PUBLIC) {
      if ((err = s_slhdsa_key_valid(key, 0, &p)) != CRYPT_OK) return err;
      needed = p.pk_bytes;
      if (*outlen < needed) { *outlen = needed; return CRYPT_BUFFER_OVERFLOW; }
      XMEMCPY(out, key->pk, needed);
   }
   else if (which == PK_PRIVATE) {
      if ((err = s_slhdsa_key_valid(key, 1, &p)) != CRYPT_OK) return err;
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
   Import an SLH-DSA key from a byte buffer.
   @param in       The buffer to import from
   @param inlen    Length of the buffer
   @param which    PK_PUBLIC for a verification key, PK_PRIVATE for a signing key
   @param alg      The parameter set (one of ltc_slhdsa_id)
   @param key      [out] Destination for the imported key
   @return CRYPT_OK if successful
*/
int slhdsa_import_raw(const unsigned char *in, unsigned long inlen, int which, int alg, slhdsa_key *key)
{
   slhdsa_params p;
   unsigned char root[SPX_N_MAX];
   int err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   if ((err = s_slhdsa_get_params(alg, &p)) != CRYPT_OK) return err;

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

      /* Recompute PK.root from SK.seed and PK.seed. */
      err = s_merkle_gen_root(root, in + 2 * p.n, in, &p);
      if (err != CRYPT_OK) {
         zeromem(root, sizeof(root));
         return err;
      }
      if (XMEM_NEQ(root, in + 3 * p.n, p.n) != 0) {
         zeromem(root, sizeof(root));
         return CRYPT_INVALID_PACKET;
      }
      zeromem(root, sizeof(root));

      key->sk = XMALLOC(p.sk_bytes);
      if (key->sk == NULL) return CRYPT_MEM;
      XMEMCPY(key->sk, in, p.sk_bytes);
      key->sklen = p.sk_bytes;

      /* Reconstruct pk from sk:
         sk = [SK_SEED || SK_PRF || PUB_SEED || root]
         pk = [PUB_SEED || root] */
      key->pk = XMALLOC(p.pk_bytes);
      if (key->pk == NULL) {
         slhdsa_free(key);
         return CRYPT_MEM;
      }
      XMEMCPY(key->pk, in + 2 * p.n, 2 * p.n); /* PUB_SEED || root */
      key->pklen = p.pk_bytes;
      key->type = PK_PRIVATE;
   }
   else {
      return CRYPT_INVALID_ARG;
   }

   return CRYPT_OK;
}

/**
   Check the internal consistency of an SLH-DSA key.

   Recomputes PK.root from SK.seed and PK.seed and compares it with both stored copies.
   This rebuilds the whole top Merkle tree, so it is a separate call and not done per signature.
   @param key      The key to check
   @return CRYPT_OK if the key is consistent, CRYPT_PK_INVALID_TYPE if a key field is wrong,
           CRYPT_INVALID_PACKET if the key material does not match
*/
int slhdsa_check_key(const slhdsa_key *key)
{
   slhdsa_params p;
   unsigned char root[SPX_N_MAX];
   int err;

   LTC_ARGCHK(key != NULL);

   if ((err = s_slhdsa_get_params(key->alg, &p)) != CRYPT_OK) return err;
   if (key->pk == NULL || key->pklen != p.pk_bytes) return CRYPT_PK_INVALID_TYPE;

   if (key->type == PK_PUBLIC) {
      return (key->sk == NULL && key->sklen == 0) ? CRYPT_OK : CRYPT_PK_INVALID_TYPE;
   }
   if (key->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;
   if (key->sk == NULL || key->sklen != p.sk_bytes) return CRYPT_PK_INVALID_TYPE;

   /* sk = SK.seed || SK.prf || PK.seed || PK.root, pk = PK.seed || PK.root */
   if (XMEM_NEQ(key->sk + 2 * p.n, key->pk, p.pk_bytes) != 0) return CRYPT_INVALID_PACKET;

   err = s_merkle_gen_root(root, key->sk + 2 * p.n, key->sk, &p);
   if (err == CRYPT_OK && XMEM_NEQ(root, key->sk + 3 * p.n, p.n) != 0) {
      err = CRYPT_INVALID_PACKET;
   }
   zeromem(root, sizeof(root));
   return err;
}

/**
   Sign a message with SLH-DSA.
   @param msg      The message to sign
   @param msglen   Length of the message
   @param sig      [out] The signature
   @param siglen   [in/out] Max size and resulting size of the signature
   @param ctx      Optional context string (can be NULL if ctxlen is 0)
   @param ctxlen   Length of the context string (max 255 bytes per FIPS 205)
   @param prng     An active PRNG state (for hedged signing)
   @param wprng    The index of the desired PRNG
   @param key      The private (signing) key
   @return CRYPT_OK if successful
*/
int slhdsa_sign(const unsigned char *msg,  unsigned long  msglen,
                      unsigned char *sig,  unsigned long *siglen,
                const unsigned char *ctx,  unsigned long  ctxlen,
                      prng_state    *prng, int            wprng,
                const slhdsa_key   *key)
{
   slhdsa_params p;
   unsigned char optrand[SPX_N_MAX];
   int err;

   LTC_ARGCHK(key != NULL);

   if ((err = s_slhdsa_key_valid(key, 1, &p)) != CRYPT_OK) return err;
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) return err;
   if (prng_descriptor[wprng].read(optrand, p.n, prng) != p.n) {
      zeromem(optrand, sizeof(optrand));
      return CRYPT_ERROR_READPRNG;
   }

   err = slhdsa_sign_ex(msg, msglen, sig, siglen, ctx, ctxlen, optrand, p.n, key);

   zeromem(optrand, sizeof(optrand));
   return err;
}

/**
   SLH-DSA signing with caller-supplied opt_rand (FIPS 205 9.2 slh_sign_internal).

   Like slhdsa_sign(), but opt_rand comes from the caller. opt_rand set to PK.seed gives the
   deterministic variant, an opt_rand from a CSPRNG the hedged variant that slhdsa_sign() uses.
   It is meant for KAT and ACVP vectors that fix opt_rand, applications should call slhdsa_sign().
   @param msg         The message to sign
   @param msglen      Length of the message
   @param sig         [out] The signature
   @param siglen      [in/out] Max size and resulting size of the signature
   @param ctx         Optional context string (can be NULL if ctxlen is 0)
   @param ctxlen      Length of the context string (max 255 bytes per FIPS 205)
   @param optrand     The per-signature randomness (n bytes, where n is 16, 24,
                      or 32 depending on the parameter set)
   @param optrandlen  Length of optrand in bytes; must equal n for the key's
                      parameter set
   @param key         The private (signing) key
   @return CRYPT_OK if successful
*/
int slhdsa_sign_ex(const unsigned char *msg,     unsigned long  msglen,
                         unsigned char *sig,     unsigned long *siglen,
                   const unsigned char *ctx,     unsigned long  ctxlen,
                   const unsigned char *optrand, unsigned long  optrandlen,
                   const slhdsa_key   *key)
{
   slhdsa_params p;
   slhdsa_message_view m_prime;
   unsigned char prefix[SPX_MSG_PREFIX_MAX];
   int err;

   LTC_ARGCHK(msg     != NULL || msglen == 0);
   LTC_ARGCHK(ctx     != NULL || ctxlen == 0);
   LTC_ARGCHK(sig     != NULL);
   LTC_ARGCHK(siglen  != NULL);
   LTC_ARGCHK(optrand != NULL);
   LTC_ARGCHK(key     != NULL);

   if ((err = s_slhdsa_key_valid(key, 1, &p)) != CRYPT_OK) return err;
   if (optrandlen != (unsigned long)p.n) return CRYPT_INVALID_ARG;
   if (*siglen < p.sig_bytes) { *siglen = p.sig_bytes; return CRYPT_BUFFER_OVERFLOW; }

   err = s_slhdsa_prepare_message(&m_prime, prefix,
                                  msg, msglen, ctx, ctxlen, key->alg);
   if (err == CRYPT_OK) {
      err = s_sign_core(sig, siglen, &m_prime, key->sk, optrand, &p);
   }

   zeromem(prefix, sizeof(prefix));
   zeromem(&m_prime, sizeof(m_prime));
   return err;
}

/**
   Verify a signature with SLH-DSA.
   @param sig      The signature to verify
   @param siglen   Length of the signature
   @param msg      The message that was signed
   @param msglen   Length of the message
   @param ctx      Optional context string (can be NULL if ctxlen is 0)
   @param ctxlen   Length of the context string (max 255 bytes per FIPS 205)
   @param stat     [out] Result of the verification: 1==valid, 0==invalid
   @param key      The public (verification) key
   @return CRYPT_OK if successful (even if the signature is invalid)
*/
int slhdsa_verify(const unsigned char *sig,  unsigned long  siglen,
                  const unsigned char *msg,  unsigned long  msglen,
                  const unsigned char *ctx,  unsigned long  ctxlen,
                        int           *stat,
                  const slhdsa_key   *key)
{
   slhdsa_params p;
   slhdsa_message_view m_prime;
   unsigned char prefix[SPX_MSG_PREFIX_MAX];
   int err;

   /* stat is cleared before anything else can return, it stays 0 unless the signature is good */
   LTC_ARGCHK(stat != NULL);
   *stat = 0;

   LTC_ARGCHK(sig  != NULL);
   LTC_ARGCHK(msg  != NULL || msglen == 0);
   LTC_ARGCHK(ctx  != NULL || ctxlen == 0);
   LTC_ARGCHK(key  != NULL);

   if ((err = s_slhdsa_key_valid(key, 0, &p)) != CRYPT_OK) return err;

   err = s_slhdsa_prepare_message(&m_prime, prefix,
                                  msg, msglen, ctx, ctxlen, key->alg);
   if (err != CRYPT_OK) {
      zeromem(prefix, sizeof(prefix));
      zeromem(&m_prime, sizeof(m_prime));
      return err;
   }

   err = s_verify_core(sig, siglen, &m_prime, key->pk, &p);
   zeromem(prefix, sizeof(prefix));
   zeromem(&m_prime, sizeof(m_prime));

   if (err == CRYPT_OK)
      *stat = 1;
   else if (err == CRYPT_INVALID_PACKET)
      err = CRYPT_OK; /* Verification failed but no internal error */

   return err;
}

/**
   Get the sizes for a given SLH-DSA parameter set.
   Any output pointer may be NULL if the caller does not need that value.
   @param alg              The parameter set (one of ltc_slhdsa_id)
   @param public_key_sz    [out] Public key size in bytes
   @param secret_key_sz    [out] Secret key size in bytes
   @param signature_sz     [out] Signature size in bytes
   @param optrand_sz       [out] Per-signature opt_rand size in bytes (= n)
   @param keygen_seed_sz   [out] Seed size in bytes for slhdsa_make_key_from_seed (= 3*n)
   @return CRYPT_OK if successful
*/
int slhdsa_get_sizes(int alg,
                     unsigned long *public_key_sz,
                     unsigned long *secret_key_sz,
                     unsigned long *signature_sz,
                     unsigned long *optrand_sz,
                     unsigned long *keygen_seed_sz)
{
   slhdsa_params p;
   int err;

   if ((err = s_slhdsa_get_params(alg, &p)) != CRYPT_OK) return err;

   if (public_key_sz   != NULL) *public_key_sz   = p.pk_bytes;
   if (secret_key_sz   != NULL) *secret_key_sz   = p.sk_bytes;
   if (signature_sz    != NULL) *signature_sz    = p.sig_bytes;
   if (optrand_sz      != NULL) *optrand_sz      = (unsigned long)p.n;
   if (keygen_seed_sz  != NULL) *keygen_seed_sz  = 3uL * p.n;

   return CRYPT_OK;
}

/* Algorithm name / OID lookup */

typedef struct {
   int alg;
   const char *name;
   const char *oid;
} slhdsa_alg_entry;

static const slhdsa_alg_entry s_slhdsa_alg_table[] = {
   /* Pure SLH-DSA (FIPS 205) */
   { LTC_SLHDSA_SHA2_128S,  "SLH-DSA-SHA2-128s",  "2.16.840.1.101.3.4.3.20" },
   { LTC_SLHDSA_SHA2_128F,  "SLH-DSA-SHA2-128f",  "2.16.840.1.101.3.4.3.21" },
   { LTC_SLHDSA_SHA2_192S,  "SLH-DSA-SHA2-192s",  "2.16.840.1.101.3.4.3.22" },
   { LTC_SLHDSA_SHA2_192F,  "SLH-DSA-SHA2-192f",  "2.16.840.1.101.3.4.3.23" },
   { LTC_SLHDSA_SHA2_256S,  "SLH-DSA-SHA2-256s",  "2.16.840.1.101.3.4.3.24" },
   { LTC_SLHDSA_SHA2_256F,  "SLH-DSA-SHA2-256f",  "2.16.840.1.101.3.4.3.25" },
   { LTC_SLHDSA_SHAKE_128S, "SLH-DSA-SHAKE-128s", "2.16.840.1.101.3.4.3.26" },
   { LTC_SLHDSA_SHAKE_128F, "SLH-DSA-SHAKE-128f", "2.16.840.1.101.3.4.3.27" },
   { LTC_SLHDSA_SHAKE_192S, "SLH-DSA-SHAKE-192s", "2.16.840.1.101.3.4.3.28" },
   { LTC_SLHDSA_SHAKE_192F, "SLH-DSA-SHAKE-192f", "2.16.840.1.101.3.4.3.29" },
   { LTC_SLHDSA_SHAKE_256S, "SLH-DSA-SHAKE-256s", "2.16.840.1.101.3.4.3.30" },
   { LTC_SLHDSA_SHAKE_256F, "SLH-DSA-SHAKE-256f", "2.16.840.1.101.3.4.3.31" },
   /* HashSLH-DSA */
   { LTC_SLHDSA_HASH_SHA2_128S_WITH_SHA256,    "HashSLH-DSA-SHA2-128s-with-SHA256",    "2.16.840.1.101.3.4.3.35" },
   { LTC_SLHDSA_HASH_SHA2_128F_WITH_SHA256,    "HashSLH-DSA-SHA2-128f-with-SHA256",    "2.16.840.1.101.3.4.3.36" },
   { LTC_SLHDSA_HASH_SHA2_192S_WITH_SHA512,    "HashSLH-DSA-SHA2-192s-with-SHA512",    "2.16.840.1.101.3.4.3.37" },
   { LTC_SLHDSA_HASH_SHA2_192F_WITH_SHA512,    "HashSLH-DSA-SHA2-192f-with-SHA512",    "2.16.840.1.101.3.4.3.38" },
   { LTC_SLHDSA_HASH_SHA2_256S_WITH_SHA512,    "HashSLH-DSA-SHA2-256s-with-SHA512",    "2.16.840.1.101.3.4.3.39" },
   { LTC_SLHDSA_HASH_SHA2_256F_WITH_SHA512,    "HashSLH-DSA-SHA2-256f-with-SHA512",    "2.16.840.1.101.3.4.3.40" },
   { LTC_SLHDSA_HASH_SHAKE_128S_WITH_SHAKE128, "HashSLH-DSA-SHAKE-128s-with-SHAKE128", "2.16.840.1.101.3.4.3.41" },
   { LTC_SLHDSA_HASH_SHAKE_128F_WITH_SHAKE128, "HashSLH-DSA-SHAKE-128f-with-SHAKE128", "2.16.840.1.101.3.4.3.42" },
   { LTC_SLHDSA_HASH_SHAKE_192S_WITH_SHAKE256, "HashSLH-DSA-SHAKE-192s-with-SHAKE256", "2.16.840.1.101.3.4.3.43" },
   { LTC_SLHDSA_HASH_SHAKE_192F_WITH_SHAKE256, "HashSLH-DSA-SHAKE-192f-with-SHAKE256", "2.16.840.1.101.3.4.3.44" },
   { LTC_SLHDSA_HASH_SHAKE_256S_WITH_SHAKE256, "HashSLH-DSA-SHAKE-256s-with-SHAKE256", "2.16.840.1.101.3.4.3.45" },
   { LTC_SLHDSA_HASH_SHAKE_256F_WITH_SHAKE256, "HashSLH-DSA-SHAKE-256f-with-SHAKE256", "2.16.840.1.101.3.4.3.46" },
};

/**
   Resolve an SLH-DSA parameter set from its FIPS 205 name or its dotted-decimal OID.
   Recognises both Pure SLH-DSA (e.g. "SLH-DSA-SHA2-128s") and HashSLH-DSA names
   (e.g. "HashSLH-DSA-SHA2-128s-with-SHA256"). Name matching is case-insensitive
   and ignores '-' and '_'.
   @param name_or_oid   The canonical name or the OID string
   @param alg           [out] Matching ltc_slhdsa_id value
   @return CRYPT_OK if a match was found, CRYPT_INVALID_ARG otherwise
*/
int slhdsa_find_alg(const char *name_or_oid, int *alg)
{
   unsigned i;

   LTC_ARGCHK(name_or_oid != NULL);
   LTC_ARGCHK(alg         != NULL);

   for (i = 0; i < LTC_ARRAY_SIZE(s_slhdsa_alg_table); ++i) {
      if (ltc_algname_match(s_slhdsa_alg_table[i].name, name_or_oid) ||
          ltc_algname_match(s_slhdsa_alg_table[i].oid,  name_or_oid)) {
         *alg = s_slhdsa_alg_table[i].alg;
         return CRYPT_OK;
      }
   }
   return CRYPT_INVALID_ARG;
}

/**
   Get the canonical FIPS 205 name of an SLH-DSA parameter set.
   @param alg    The parameter set (one of ltc_slhdsa_id)
   @param name   [out] Pointer to a static, NUL-terminated name string
                 (e.g. "SLH-DSA-SHA2-128s"); must not be freed by the caller
   @return CRYPT_OK if alg is valid, CRYPT_INVALID_ARG otherwise
*/
int slhdsa_alg_name(int alg, const char **name)
{
   unsigned i;

   LTC_ARGCHK(name != NULL);

   for (i = 0; i < LTC_ARRAY_SIZE(s_slhdsa_alg_table); ++i) {
      if (s_slhdsa_alg_table[i].alg == alg) {
         *name = s_slhdsa_alg_table[i].name;
         return CRYPT_OK;
      }
   }
   return CRYPT_INVALID_ARG;
}

#endif /* LTC_SLHDSA */
