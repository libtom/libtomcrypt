/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file argon2.c
   Argon2 password hashing function (RFC 9106)
*/
#ifdef LTC_ARGON2

#define ARGON2_BLOCK_SIZE          1024
#define ARGON2_QWORDS_IN_BLOCK     128
#define ARGON2_ADDRESSES_IN_BLOCK  128
#define ARGON2_PREHASH_DIGEST_LEN  64
#define ARGON2_PREHASH_SEED_LEN    72
#define ARGON2_SYNC_POINTS         4
#define ARGON2_MAX_LANES           0xFFFFFF /* RFC 9106: parallelism p is at most 2^24-1 */
#define ARGON2_VERSION             0x13
#define ARGON2_MIN_OUTLEN          4
#define ARGON2_BLAKE2B_OUTBYTES    64

/* 1024-byte memory block */
typedef struct argon2_block {
   ulong64 v[ARGON2_QWORDS_IN_BLOCK];
} argon2_block;

/* instance state */
typedef struct argon2_instance {
   argon2_block *memory;
   ulong32       passes;
   ulong32       memory_blocks;
   ulong32       segment_length;
   ulong32       lane_length;
   ulong32       lanes;
   int           type; /* 0=d  1=i  2=id */
} argon2_instance;

/* position within the memory matrix */
typedef struct argon2_position {
   ulong32       pass;
   ulong32       lane;
   unsigned char slice;
   ulong32       index;
} argon2_position;

static void s_block_init(argon2_block *b, unsigned char v)
{
   XMEMSET(b->v, v, sizeof(b->v));
}

static void s_block_copy(argon2_block *dst, const argon2_block *src)
{
   XMEMCPY(dst->v, src->v, sizeof(dst->v));
}

static void s_block_xor(argon2_block *dst, const argon2_block *src)
{
   unsigned i;
   for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
      dst->v[i] ^= src->v[i];
   }
}

static void s_block_load(argon2_block *dst, const unsigned char *input)
{
   unsigned i;
   for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
      LOAD64L(dst->v[i], input + i * 8);
   }
}

static void s_block_store(unsigned char *output, const argon2_block *src)
{
   unsigned i;
   for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
      STORE64L(src->v[i], output + i * 8);
   }
}

/* Variable-length hash H' (RFC 9106 Section 3.2) */
static int s_blake2b_hash(unsigned char *out, unsigned long outlen, const unsigned char *in, unsigned long inlen)
{
   hash_state md;
   int err;

   if ((err = blake2b_init(&md, outlen, NULL, 0)) != CRYPT_OK) return err;
   if ((err = blake2b_process(&md, in, inlen))    != CRYPT_OK) return err;
   if ((err = blake2b_done(&md, out))             != CRYPT_OK) return err;
   return CRYPT_OK;
}

static int s_blake2b_long(unsigned char *out, unsigned long outlen, const unsigned char *in, unsigned long inlen)
{
   unsigned char outlen_le[4];
   int err;

   STORE32L((ulong32)outlen, outlen_le);

   if (outlen <= ARGON2_BLAKE2B_OUTBYTES) {
      /* single hash with truncated output */
      hash_state md;
      if ((err = blake2b_init(&md, outlen, NULL, 0)) != CRYPT_OK) return err;
      if ((err = blake2b_process(&md, outlen_le, 4)) != CRYPT_OK) return err;
      if ((err = blake2b_process(&md, in, inlen))    != CRYPT_OK) return err;
      if ((err = blake2b_done(&md, out))             != CRYPT_OK) return err;
   }
   else {
      /* chained hashing for longer outputs */
      ulong32 toproduce;
      unsigned char out_buffer[ARGON2_BLAKE2B_OUTBYTES];
      unsigned char in_buffer[ARGON2_BLAKE2B_OUTBYTES];
      hash_state md;

      if ((err = blake2b_init(&md, ARGON2_BLAKE2B_OUTBYTES, NULL, 0)) != CRYPT_OK) return err;
      if ((err = blake2b_process(&md, outlen_le, 4))                  != CRYPT_OK) return err;
      if ((err = blake2b_process(&md, in, inlen))                     != CRYPT_OK) return err;
      if ((err = blake2b_done(&md, out_buffer))                       != CRYPT_OK) return err;

      XMEMCPY(out, out_buffer, ARGON2_BLAKE2B_OUTBYTES / 2);
      out += ARGON2_BLAKE2B_OUTBYTES / 2;
      toproduce = (ulong32)outlen - ARGON2_BLAKE2B_OUTBYTES / 2;

      while (toproduce > ARGON2_BLAKE2B_OUTBYTES) {
         XMEMCPY(in_buffer, out_buffer, ARGON2_BLAKE2B_OUTBYTES);
         if ((err = s_blake2b_hash(out_buffer, ARGON2_BLAKE2B_OUTBYTES, in_buffer, ARGON2_BLAKE2B_OUTBYTES)) != CRYPT_OK) return err;
         XMEMCPY(out, out_buffer, ARGON2_BLAKE2B_OUTBYTES / 2);
         out += ARGON2_BLAKE2B_OUTBYTES / 2;
         toproduce -= ARGON2_BLAKE2B_OUTBYTES / 2;
      }

      XMEMCPY(in_buffer, out_buffer, ARGON2_BLAKE2B_OUTBYTES);
      if ((err = s_blake2b_hash(out_buffer, toproduce, in_buffer, ARGON2_BLAKE2B_OUTBYTES)) != CRYPT_OK) return err;
      XMEMCPY(out, out_buffer, toproduce);
   }
   return CRYPT_OK;
}

/* BlaMka compression G (RFC 9106 Section 3.4 / 3.5) */
static LTC_INLINE ulong64 s_fBlaMka(ulong64 x, ulong64 y)
{
   ulong64 m = CONST64(0xFFFFFFFF);
   ulong64 xy = (x & m) * (y & m);
   return x + y + 2 * xy;
}

#define ARGON2_GB(a, b, c, d)  \
   do {                        \
      a = s_fBlaMka(a, b);     \
      d = ROR64(d ^ a, 32);    \
      c = s_fBlaMka(c, d);     \
      b = ROR64(b ^ c, 24);    \
      a = s_fBlaMka(a, b);     \
      d = ROR64(d ^ a, 16);    \
      c = s_fBlaMka(c, d);     \
      b = ROR64(b ^ c, 63);    \
   } while (0)

#define ARGON2_ROUND(v0,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15) \
   do {                             \
      ARGON2_GB(v0, v4,  v8, v12);  \
      ARGON2_GB(v1, v5,  v9, v13);  \
      ARGON2_GB(v2, v6, v10, v14);  \
      ARGON2_GB(v3, v7, v11, v15);  \
      ARGON2_GB(v0, v5, v10, v15);  \
      ARGON2_GB(v1, v6, v11, v12);  \
      ARGON2_GB(v2, v7,  v8, v13);  \
      ARGON2_GB(v3, v4,  v9, v14);  \
   } while (0)

/* Fill a new block from prev_block and ref_block. If with_xor, XOR result with existing next_block content. */
static void s_fill_block(const argon2_block *prev_block, const argon2_block *ref_block, argon2_block *next_block, int with_xor)
{
   argon2_block blockR, block_tmp;
   unsigned i;

   s_block_copy(&blockR, ref_block);
   s_block_xor(&blockR, prev_block);
   s_block_copy(&block_tmp, &blockR);

   if (with_xor) {
      s_block_xor(&block_tmp, next_block);
   }

   /* Apply P on columns: (0..15), (16..31), ..., (112..127) */
   for (i = 0; i < 8; ++i) {
      ARGON2_ROUND(
         blockR.v[16*i],    blockR.v[16*i+1],  blockR.v[16*i+2],  blockR.v[16*i+3],
         blockR.v[16*i+4],  blockR.v[16*i+5],  blockR.v[16*i+6],  blockR.v[16*i+7],
         blockR.v[16*i+8],  blockR.v[16*i+9],  blockR.v[16*i+10], blockR.v[16*i+11],
         blockR.v[16*i+12], blockR.v[16*i+13], blockR.v[16*i+14], blockR.v[16*i+15]);
   }

   /* Apply P on rows: (0,1,16,17,32,33,...,112,113), etc. */
   for (i = 0; i < 8; ++i) {
      ARGON2_ROUND(
         blockR.v[2*i],    blockR.v[2*i+1],  blockR.v[2*i+16], blockR.v[2*i+17],
         blockR.v[2*i+32], blockR.v[2*i+33], blockR.v[2*i+48], blockR.v[2*i+49],
         blockR.v[2*i+64], blockR.v[2*i+65], blockR.v[2*i+80], blockR.v[2*i+81],
         blockR.v[2*i+96], blockR.v[2*i+97], blockR.v[2*i+112],blockR.v[2*i+113]);
   }

   s_block_copy(next_block, &block_tmp);
   s_block_xor(next_block, &blockR);
}

/* Generate next pseudo-random addresses for data-independent indexing */
static void s_next_addresses(argon2_block *address_block, argon2_block *input_block, const argon2_block *zero_block)
{
   input_block->v[6]++;
   s_fill_block(zero_block, input_block, address_block, 0);
   s_fill_block(zero_block, address_block, address_block, 0);
}

/* Index computation (RFC 9106 Section 3.3) */
static ulong32 s_index_alpha(const argon2_instance *instance, const argon2_position *position, ulong32 pseudo_rand, int same_lane)
{
   ulong32 reference_area_size;
   ulong64 relative_position;
   ulong32 start_position, absolute_position;

   if (position->pass == 0) {
      if (position->slice == 0) {
         reference_area_size = position->index - 1;
      }
      else {
         if (same_lane) {
            reference_area_size = position->slice * instance->segment_length + position->index - 1;
         }
         else {
            reference_area_size = position->slice * instance->segment_length + ((position->index == 0) ? ((ulong32)-1) : 0);
         }
      }
   }
   else {
      if (same_lane) {
         reference_area_size = instance->lane_length - instance->segment_length + position->index - 1;
      }
      else {
         reference_area_size = instance->lane_length - instance->segment_length + ((position->index == 0) ? ((ulong32)-1) : 0);
      }
   }

   /* Map pseudo_rand to 0..reference_area_size-1 */
   relative_position = (ulong64)pseudo_rand;
   relative_position = relative_position * relative_position >> 32;
   relative_position = reference_area_size - 1 - ((ulong64)reference_area_size * relative_position >> 32);

   start_position = 0;
   if (position->pass != 0) {
      start_position = (position->slice == ARGON2_SYNC_POINTS - 1) ? 0 : (position->slice + 1) * instance->segment_length;
   }
   absolute_position = (start_position + (ulong32)relative_position) % instance->lane_length;
   return absolute_position;
}

/* Fill one segment (lane x slice intersection) */
static void s_fill_segment(const argon2_instance *instance, argon2_position position)
{
   argon2_block *ref_block, *curr_block;
   argon2_block address_block, input_block, zero_block;
   ulong64 pseudo_rand;
   ulong32 ref_index, prev_offset, curr_offset;
   ulong32 starting_index, i;
   ulong64 ref_lane;
   int data_independent;

   data_independent = (instance->type == ARGON2_I) || (instance->type == ARGON2_ID && position.pass == 0 && position.slice < ARGON2_SYNC_POINTS / 2);

   if (data_independent) {
      s_block_init(&zero_block, 0);
      s_block_init(&input_block, 0);
      input_block.v[0] = position.pass;
      input_block.v[1] = position.lane;
      input_block.v[2] = position.slice;
      input_block.v[3] = instance->memory_blocks;
      input_block.v[4] = instance->passes;
      input_block.v[5] = instance->type;
   }

   starting_index = 0;
   if (position.pass == 0 && position.slice == 0) {
      starting_index = 2;
      if (data_independent) {
         s_next_addresses(&address_block, &input_block, &zero_block);
      }
   }

   curr_offset = position.lane * instance->lane_length + position.slice * instance->segment_length + starting_index;

   if (curr_offset % instance->lane_length == 0) {
      prev_offset = curr_offset + instance->lane_length - 1;
   }
   else {
      prev_offset = curr_offset - 1;
   }

   for (i = starting_index; i < instance->segment_length; ++i, ++curr_offset, ++prev_offset) {
      if (curr_offset % instance->lane_length == 1) {
         prev_offset = curr_offset - 1;
      }

      /* Get pseudo-random value */
      if (data_independent) {
         if (i % ARGON2_ADDRESSES_IN_BLOCK == 0) {
            s_next_addresses(&address_block, &input_block, &zero_block);
         }
         pseudo_rand = address_block.v[i % ARGON2_ADDRESSES_IN_BLOCK];
      }
      else {
         pseudo_rand = instance->memory[prev_offset].v[0];
      }

      ref_lane = (pseudo_rand >> 32) % instance->lanes;
      if (position.pass == 0 && position.slice == 0) {
         ref_lane = position.lane;
      }

      position.index = i;
      ref_index  = s_index_alpha(instance, &position, (ulong32)(pseudo_rand & CONST64(0xFFFFFFFF)), ref_lane == position.lane);
      ref_block  = instance->memory + instance->lane_length * (ulong32)ref_lane + ref_index;
      curr_block = instance->memory + curr_offset;

      if (position.pass == 0) {
         s_fill_block(instance->memory + prev_offset, ref_block, curr_block, 0);
      }
      else {
         s_fill_block(instance->memory + prev_offset, ref_block, curr_block, 1);
      }
   }
}

/* Initial hash H_0 (RFC 9106 Section 3.1 step 1) */
static int s_initial_hash(unsigned char *blockhash,
                          const unsigned char *pwd,  unsigned long pwdlen,
                          const unsigned char *salt, unsigned long saltlen,
                          const unsigned char *secret, unsigned long secretlen,
                          const unsigned char *ad, unsigned long adlen,
                          ulong32 t_cost, ulong32 m_cost, ulong32 parallelism,
                          ulong32 outlen, int type)
{
   hash_state md;
   unsigned char value[4];
   int err;

   if ((err = blake2b_init(&md, ARGON2_PREHASH_DIGEST_LEN, NULL, 0)) != CRYPT_OK) return err;

   STORE32L(parallelism, value);
   if ((err = blake2b_process(&md, value, 4)) != CRYPT_OK) return err;

   STORE32L(outlen, value);
   if ((err = blake2b_process(&md, value, 4)) != CRYPT_OK) return err;

   STORE32L(m_cost, value);
   if ((err = blake2b_process(&md, value, 4)) != CRYPT_OK) return err;

   STORE32L(t_cost, value);
   if ((err = blake2b_process(&md, value, 4)) != CRYPT_OK) return err;

   STORE32L((ulong32)ARGON2_VERSION, value);
   if ((err = blake2b_process(&md, value, 4)) != CRYPT_OK) return err;

   STORE32L((ulong32)type, value);
   if ((err = blake2b_process(&md, value, 4)) != CRYPT_OK) return err;

   STORE32L((ulong32)pwdlen, value);
   if ((err = blake2b_process(&md, value, 4)) != CRYPT_OK) return err;
   if (pwdlen > 0) {
      if ((err = blake2b_process(&md, pwd, pwdlen)) != CRYPT_OK) return err;
   }

   STORE32L((ulong32)saltlen, value);
   if ((err = blake2b_process(&md, value, 4)) != CRYPT_OK) return err;
   if (saltlen > 0) {
      if ((err = blake2b_process(&md, salt, saltlen)) != CRYPT_OK) return err;
   }

   STORE32L((ulong32)secretlen, value);
   if ((err = blake2b_process(&md, value, 4)) != CRYPT_OK) return err;
   if (secretlen > 0 && secret != NULL) {
      if ((err = blake2b_process(&md, secret, secretlen)) != CRYPT_OK) return err;
   }

   STORE32L((ulong32)adlen, value);
   if ((err = blake2b_process(&md, value, 4)) != CRYPT_OK) return err;
   if (adlen > 0 && ad != NULL) {
      if ((err = blake2b_process(&md, ad, adlen)) != CRYPT_OK) return err;
   }

   if ((err = blake2b_done(&md, blockhash)) != CRYPT_OK) return err;
   return CRYPT_OK;
}

/* Generate first two blocks in each lane */

static int s_fill_first_blocks(unsigned char *blockhash, const argon2_instance *instance)
{
   ulong32 l;
   unsigned char blockhash_bytes[ARGON2_BLOCK_SIZE];
   int err;

   for (l = 0; l < instance->lanes; ++l) {
      /* B[i][0] = H'(H_0 || LE32(0) || LE32(i)) */
      STORE32L(0, blockhash + ARGON2_PREHASH_DIGEST_LEN);
      STORE32L(l, blockhash + ARGON2_PREHASH_DIGEST_LEN + 4);
      if ((err = s_blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LEN)) != CRYPT_OK) return err;
      s_block_load(&instance->memory[l * instance->lane_length + 0], blockhash_bytes);

      /* B[i][1] = H'(H_0 || LE32(1) || LE32(i)) */
      STORE32L(1, blockhash + ARGON2_PREHASH_DIGEST_LEN);
      if ((err = s_blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LEN)) != CRYPT_OK) return err;
      s_block_load(&instance->memory[l * instance->lane_length + 1], blockhash_bytes);
   }

   zeromem(blockhash_bytes, ARGON2_BLOCK_SIZE);
   return CRYPT_OK;
}

/* Finalize: XOR last blocks, produce tag */
static int s_finalize(unsigned char *out, unsigned long outlen,
                      const argon2_instance *instance)
{
   argon2_block blockhash;
   unsigned char blockhash_bytes[ARGON2_BLOCK_SIZE];
   ulong32 l;
   int err;

   s_block_copy(&blockhash, instance->memory + instance->lane_length - 1);

   for (l = 1; l < instance->lanes; ++l) {
      ulong32 last = l * instance->lane_length + (instance->lane_length - 1);
      s_block_xor(&blockhash, instance->memory + last);
   }

   s_block_store(blockhash_bytes, &blockhash);
   err = s_blake2b_long(out, outlen, blockhash_bytes, ARGON2_BLOCK_SIZE);

   zeromem(blockhash.v, ARGON2_BLOCK_SIZE);
   zeromem(blockhash_bytes, ARGON2_BLOCK_SIZE);
   return err;
}

/* Fill the entire memory */
static void s_fill_memory(argon2_instance *instance)
{
   ulong32 r, s, l;

   for (r = 0; r < instance->passes; ++r) {
      for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {
         for (l = 0; l < instance->lanes; ++l) {
            argon2_position position;
            position.pass  = r;
            position.lane  = l;
            position.slice = (unsigned char)s;
            position.index = 0;
            s_fill_segment(instance, position);
         }
      }
   }
}

/**
   Hash a password with Argon2 (RFC 9106)

   @param pwd         Password (or message)
   @param pwdlen      Length of password
   @param salt        Salt
   @param saltlen     Length of salt
   @param secret      Optional secret value (may be NULL)
   @param secretlen   Length of secret
   @param ad          Optional associated data (may be NULL)
   @param adlen       Length of associated data
   @param t_cost      Number of passes (iterations), minimum 1
   @param m_cost      Memory size in KiB, minimum 8*parallelism
   @param parallelism Degree of parallelism (number of lanes), minimum 1
   @param type        ARGON2_D, ARGON2_I, or ARGON2_ID
   @param out         [out] Output tag
   @param outlen      Desired output length (4..2^32-1)
   @return CRYPT_OK on success
*/
int argon2_hash(const unsigned char *pwd,  unsigned long pwdlen,
                const unsigned char *salt, unsigned long saltlen,
                const unsigned char *secret, unsigned long secretlen,
                const unsigned char *ad, unsigned long adlen,
                unsigned int t_cost, unsigned int m_cost,
                unsigned int parallelism,
                argon2_type type,
                unsigned char *out, unsigned long outlen)
{
   argon2_instance instance;
   unsigned char blockhash[ARGON2_PREHASH_SEED_LEN];
   ulong32 memory_blocks, segment_length;
   int err;

   LTC_ARGCHK(out != NULL);
   LTC_ARGCHK(outlen >= ARGON2_MIN_OUTLEN);
   LTC_ARGCHK(pwd != NULL || pwdlen == 0);
   LTC_ARGCHK(salt != NULL || saltlen == 0);
   LTC_ARGCHK(secret != NULL || secretlen == 0);
   LTC_ARGCHK(ad != NULL || adlen == 0);
   LTC_ARGCHK(t_cost >= 1);
   LTC_ARGCHK(type == ARGON2_D || type == ARGON2_I || type == ARGON2_ID);

   if (parallelism < 1 || parallelism > ARGON2_MAX_LANES || m_cost < 8 * parallelism) {
      return CRYPT_INVALID_ARG;
   }

   /* Align memory: ensure memory_blocks is a multiple of 4*parallelism */
   memory_blocks = (ulong32)m_cost;
   if (memory_blocks < 2 * ARGON2_SYNC_POINTS * (ulong32)parallelism) {
      memory_blocks = 2 * ARGON2_SYNC_POINTS * (ulong32)parallelism;
   }
   segment_length = memory_blocks / ((ulong32)parallelism * ARGON2_SYNC_POINTS);
   memory_blocks = segment_length * ((ulong32)parallelism * ARGON2_SYNC_POINTS);

   /* Set up instance */
   instance.passes         = (ulong32)t_cost;
   instance.memory_blocks  = memory_blocks;
   instance.segment_length = segment_length;
   instance.lane_length    = segment_length * ARGON2_SYNC_POINTS;
   instance.lanes          = (ulong32)parallelism;
   instance.type           = (int)type;
   instance.memory         = NULL;

   /* Allocate memory */
   {
      unsigned long alloc_size = (unsigned long)memory_blocks * sizeof(argon2_block);
      /* overflow check */
      if (alloc_size / sizeof(argon2_block) != memory_blocks) {
         return CRYPT_OVERFLOW;
      }
      instance.memory = XMALLOC(alloc_size);
      if (instance.memory == NULL) {
         return CRYPT_MEM;
      }
   }

   /* Initial hash H_0 */
   err = s_initial_hash(blockhash, pwd, pwdlen, salt, saltlen,
                        secret, secretlen, ad, adlen,
                        (ulong32)t_cost, (ulong32)m_cost,
                        (ulong32)parallelism, (ulong32)outlen,
                        (int)type);
   if (err != CRYPT_OK) goto cleanup;

   /* Zero the extra 8 bytes after digest */
   XMEMSET(blockhash + ARGON2_PREHASH_DIGEST_LEN, 0, ARGON2_PREHASH_SEED_LEN - ARGON2_PREHASH_DIGEST_LEN);

   /* Generate first blocks */
   err = s_fill_first_blocks(blockhash, &instance);
   if (err != CRYPT_OK) goto cleanup;

   /* Fill memory */
   s_fill_memory(&instance);

   /* Finalize */
   err = s_finalize(out, outlen, &instance);

cleanup:
   if (instance.memory != NULL) {
      zeromem(instance.memory, (unsigned long)memory_blocks * sizeof(argon2_block));
      XFREE(instance.memory);
   }
   zeromem(blockhash, ARGON2_PREHASH_SEED_LEN);
   return err;
}

#endif /* LTC_ARGON2 */
