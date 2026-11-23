/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

/**
  @file ecc_sm2.c
  SM2 helpers built on top of the existing ECC implementation
*/

#ifdef LTC_MECC

static int s_sm2_hash_idx(int hash_idx)
{
   if (hash_idx == -1) hash_idx = find_hash("sm3");
   return hash_idx >= 0 ? hash_idx : CRYPT_INVALID_HASH;
}

static int s_sm2_only_curve(const ecc_key *key)
{
   const ltc_ecc_curve *curve;
   unsigned long oid[16], oidlen = 16;
   int err;

   LTC_ARGCHK(key != NULL);

   if ((err = ecc_find_curve("SM2", &curve)) != CRYPT_OK) return err;
   if (curve->OID == NULL) return CRYPT_INVALID_ARG;
   if (key->dp.oidlen == 0) return CRYPT_INVALID_ARG;
   if ((err = pk_oid_str_to_num(curve->OID, oid, &oidlen)) != CRYPT_OK) return err;
   if (key->dp.oidlen != oidlen) return CRYPT_INVALID_ARG;
   if (XMEM_NEQ(key->dp.oid, oid, oidlen * sizeof(oid[0])) != 0) return CRYPT_INVALID_ARG;
   return CRYPT_OK;
}

static int s_sm2_export_fixed(void *num, unsigned long size, unsigned char *out)
{
   unsigned long used;

   LTC_ARGCHK(num != NULL);
   LTC_ARGCHK(out != NULL);

   if (size > ECC_BUF_SIZE) return CRYPT_BUFFER_OVERFLOW;
   used = ltc_mp_unsigned_bin_size(num);
   if (used > size) return CRYPT_BUFFER_OVERFLOW;
   zeromem(out, size);
   return ltc_mp_to_unsigned_bin(num, out + (size - used));
}

static int s_sm2_hash_to_e(const unsigned char *in, unsigned long inlen, const ecc_key *key, void *e)
{
   int err;
   unsigned long pbits, pbytes, i, shift_right;
   unsigned char ch, buf[MAXBLOCKSIZE];
   void *p;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(e   != NULL);

   p = key->dp.order;
   pbits = ltc_mp_count_bits(p);
   pbytes = (pbits + 7uL) >> 3;

   if (pbits > inlen * 8uL)    return ltc_mp_read_unsigned_bin(e, in, inlen);
   if ((pbits % 8uL) == 0uL)   return ltc_mp_read_unsigned_bin(e, in, pbytes);
   if (pbytes >= MAXBLOCKSIZE) return CRYPT_BUFFER_OVERFLOW;

   shift_right = 8uL - (pbits % 8uL);
   for (i = 0, ch = 0; i < pbytes; i++) {
      buf[i] = ch;
      ch = (unsigned char)(in[i] << (8uL - shift_right));
      buf[i] ^= (unsigned char)(in[i] >> shift_right);
   }

   err = ltc_mp_read_unsigned_bin(e, buf, pbytes);
#ifdef LTC_CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return err;
}

static int s_sm2_is_all_zero(const unsigned char *buf, unsigned long len)
{
   unsigned char acc = 0;
   while (len-- > 0uL) acc |= *buf++;
   return acc == 0;
}

static int s_sm2_kdf(int hash_idx, const unsigned char *z, unsigned long zlen, unsigned char *out, unsigned long outlen)
{
   hash_state md;
   unsigned char *digest;
   unsigned long copied, hashsize, take;
   ulong32 counter;
   int err;

   LTC_ARGCHK(z   != NULL);
   LTC_ARGCHK(out != NULL || outlen == 0uL);

   if (outlen == 0uL) return CRYPT_OK;

   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) return err;

   hashsize = hash_descriptor[hash_idx].hashsize;
   digest = XMALLOC(hashsize);
   if (digest == NULL) {
      return CRYPT_MEM;
   }

   err = CRYPT_OK;
   copied = 0;
   counter = 1;
   while (copied < outlen) {
      unsigned char ctr[4];

      ctr[0] = (unsigned char)((counter >> 24) & 255);
      ctr[1] = (unsigned char)((counter >> 16) & 255);
      ctr[2] = (unsigned char)((counter >>  8) & 255);
      ctr[3] = (unsigned char)(counter & 255);

      if ((err = hash_descriptor[hash_idx].init(&md)) != CRYPT_OK)                      goto cleanup;
      if ((err = hash_descriptor[hash_idx].process(&md, z, zlen)) != CRYPT_OK)          goto cleanup;
      if ((err = hash_descriptor[hash_idx].process(&md, ctr, sizeof(ctr))) != CRYPT_OK) goto cleanup;
      if ((err = hash_descriptor[hash_idx].done(&md, digest)) != CRYPT_OK)              goto cleanup;

      take = MIN(hashsize, outlen - copied);
      XMEMCPY(out + copied, digest, take);
      copied += take;

      counter++;
      if (copied < outlen && counter == 0uL) {
         err = CRYPT_OVERFLOW;
         goto cleanup;
      }
   }

cleanup:
#ifdef LTC_CLEAN_STACK
   zeromem(&md, sizeof(md));
   zeromem(digest, hashsize);
#endif
   XFREE(digest);
   return err;
}

static int s_sm2_shared_xy(const ecc_key *private_key, const ecc_key *public_key, unsigned char *out)
{
   ecc_point *result;
   int err;

   LTC_ARGCHK(private_key != NULL);
   LTC_ARGCHK(public_key  != NULL);
   LTC_ARGCHK(out         != NULL);

   result = ltc_ecc_new_point();
   if (result == NULL) return CRYPT_MEM;

   err = ltc_mp.ecc_ptmul(private_key->k, &public_key->pubkey, result, private_key->dp.A, private_key->dp.prime, 1);
   if (err == CRYPT_OK) {
      err = s_sm2_export_fixed(result->x, private_key->dp.size, out);
   }
   if (err == CRYPT_OK) {
      err = s_sm2_export_fixed(result->y, private_key->dp.size, out + private_key->dp.size);
   }
   ltc_ecc_del_point(result);
   return err;
}

static int s_ecc_compute_z_sm2(unsigned char *out, unsigned long *outlen,
                               const unsigned char *id, unsigned long idlen,
                               int hash_idx, const ecc_key *key)
{
   hash_state md;
   unsigned char entl[2];
   unsigned char buf[ECC_BUF_SIZE];
   unsigned long bits;
   int err;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(id     != NULL);
   LTC_ARGCHK(key    != NULL);

   if (key->type != PK_PUBLIC && key->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;
   if ((err = s_sm2_only_curve(key)) != CRYPT_OK) return err;
   if ((hash_idx = s_sm2_hash_idx(hash_idx)) < 0) return hash_idx;
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) return err;

   if (key->dp.size < 0 || (unsigned long)key->dp.size > sizeof(buf)) return CRYPT_BUFFER_OVERFLOW;

   LTC_ARGCHK(idlen <= 8191uL);

   if (*outlen < hash_descriptor[hash_idx].hashsize) {
      *outlen = hash_descriptor[hash_idx].hashsize;
      return CRYPT_BUFFER_OVERFLOW;
   }

   bits = idlen * 8uL;
   entl[0] = (unsigned char)((bits >> 8) & 255);
   entl[1] = (unsigned char)(bits & 255);

   /* ZA = H(ENTL || ID || a || b || xG || yG || xA || yA) */
   if ((err = hash_descriptor[hash_idx].init(&md)) != CRYPT_OK)                         goto cleanup;
   if ((err = hash_descriptor[hash_idx].process(&md, entl, sizeof(entl))) != CRYPT_OK)  goto cleanup;
   if (idlen > 0uL) {
      if ((err = hash_descriptor[hash_idx].process(&md, id, idlen)) != CRYPT_OK)        goto cleanup;
   }
   if ((err = s_sm2_export_fixed(key->dp.A, key->dp.size, buf)) != CRYPT_OK)            goto cleanup;
   if ((err = hash_descriptor[hash_idx].process(&md, buf, key->dp.size)) != CRYPT_OK)   goto cleanup;
   if ((err = s_sm2_export_fixed(key->dp.B, key->dp.size, buf)) != CRYPT_OK)            goto cleanup;
   if ((err = hash_descriptor[hash_idx].process(&md, buf, key->dp.size)) != CRYPT_OK)   goto cleanup;
   if ((err = s_sm2_export_fixed(key->dp.base.x, key->dp.size, buf)) != CRYPT_OK)       goto cleanup;
   if ((err = hash_descriptor[hash_idx].process(&md, buf, key->dp.size)) != CRYPT_OK)   goto cleanup;
   if ((err = s_sm2_export_fixed(key->dp.base.y, key->dp.size, buf)) != CRYPT_OK)       goto cleanup;
   if ((err = hash_descriptor[hash_idx].process(&md, buf, key->dp.size)) != CRYPT_OK)   goto cleanup;
   if ((err = s_sm2_export_fixed(key->pubkey.x, key->dp.size, buf)) != CRYPT_OK)        goto cleanup;
   if ((err = hash_descriptor[hash_idx].process(&md, buf, key->dp.size)) != CRYPT_OK)   goto cleanup;
   if ((err = s_sm2_export_fixed(key->pubkey.y, key->dp.size, buf)) != CRYPT_OK)        goto cleanup;
   if ((err = hash_descriptor[hash_idx].process(&md, buf, key->dp.size)) != CRYPT_OK)   goto cleanup;
   if ((err = hash_descriptor[hash_idx].done(&md, out)) != CRYPT_OK)                    goto cleanup;
   *outlen = hash_descriptor[hash_idx].hashsize;

cleanup:
#ifdef LTC_CLEAN_STACK
   zeromem(&md, sizeof(md));
   zeromem(buf, sizeof(buf));
#endif
   return err;
}

#if defined(LTC_DER)
static int s_sm2_digest_message(unsigned char *out, unsigned long *outlen,
                                const unsigned char *id, unsigned long idlen,
                                const unsigned char *msg, unsigned long msglen,
                                int hash_idx, const ecc_key *key)
{
   hash_state md;
   unsigned char za[MAXBLOCKSIZE];
   unsigned long hashsize, zalen;
   int err;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(id     != NULL);
   LTC_ARGCHK(msg    != NULL);
   LTC_ARGCHK(key    != NULL);

   if ((hash_idx = s_sm2_hash_idx(hash_idx)) < 0) return hash_idx;
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) return err;

   hashsize = hash_descriptor[hash_idx].hashsize;
   if (hashsize > sizeof(za)) return CRYPT_BUFFER_OVERFLOW;
   if (*outlen < hashsize) {
      *outlen = hashsize;
      return CRYPT_BUFFER_OVERFLOW;
   }

   zalen = hashsize;
   if ((err = s_ecc_compute_z_sm2(za, &zalen, id, idlen, hash_idx, key)) != CRYPT_OK) return err;
   /* e = H(ZA || msg) */
   if ((err = hash_descriptor[hash_idx].init(&md)) != CRYPT_OK) goto cleanup;
   if ((err = hash_descriptor[hash_idx].process(&md, za, zalen)) != CRYPT_OK) goto cleanup;
   if (msglen > 0uL) {
      if ((err = hash_descriptor[hash_idx].process(&md, msg, msglen)) != CRYPT_OK) goto cleanup;
   }
   if ((err = hash_descriptor[hash_idx].done(&md, out)) != CRYPT_OK) goto cleanup;
   *outlen = hashsize;

cleanup:
#ifdef LTC_CLEAN_STACK
   zeromem(&md, sizeof(md));
   zeromem(za, sizeof(za));
#endif
   return err;
}

static int s_ecc_sign_hash_sm2(const unsigned char *in, unsigned long inlen,
                               unsigned char *out, unsigned long *outlen,
                               prng_state *prng, int wprng, const ecc_key *key)
{
   ecc_key pubkey;
   void *r, *s, *e, *b, *one_plus_d, *tmp;
   int err, have_pubkey = 0, max_iterations;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   if (key->type != PK_PRIVATE) return CRYPT_PK_NOT_PRIVATE;

   if ((err = ltc_mp_init_multi(&r, &s, &e, &b, &one_plus_d, &tmp, LTC_NULL)) != CRYPT_OK) return err;

   if ((err = s_sm2_hash_to_e(in, inlen, key, e)) != CRYPT_OK)  goto cleanup;
   if ((err = ltc_mp_add_d(key->k, 1, one_plus_d)) != CRYPT_OK) goto cleanup;
   if (ltc_mp_cmp(one_plus_d, key->dp.order) != LTC_MP_LT) {
      err = CRYPT_INVALID_ARG;
      goto cleanup;
   }

   /* r = (e + x1) mod n
      s = modinv(1+dA) * (k - r*dA) mod n
      modular inverse is blinded with random b
   */

   have_pubkey = 0;
   for (max_iterations = LTC_PK_MAX_RETRIES; max_iterations > 0; max_iterations--) {
      if ((err = ecc_copy_curve(key, &pubkey)) != CRYPT_OK)                     goto cleanup;
      have_pubkey = 1;
      if ((err = ecc_generate_key(prng, wprng, &pubkey)) != CRYPT_OK)           goto cleanup;
      if ((err = ltc_mp_add(e, pubkey.pubkey.x, r)) != CRYPT_OK)                goto cleanup;
      if ((err = ltc_mp_mod(r, key->dp.order, r)) != CRYPT_OK)                  goto cleanup;
      if (ltc_mp_iszero(r) == LTC_MP_YES) {
         ecc_free(&pubkey);
         have_pubkey = 0;
         continue;
      }
      if ((err = ltc_mp_add(r, pubkey.k, tmp)) != CRYPT_OK)                     goto cleanup;
      if (ltc_mp_cmp(tmp, key->dp.order) == LTC_MP_EQ) {
         ecc_free(&pubkey);
         have_pubkey = 0;
         continue;
      }
      if ((err = rand_bn_upto(b, key->dp.order, prng, wprng)) != CRYPT_OK)      goto cleanup;
      if ((err = ltc_mp_mulmod(key->k, r, key->dp.order, s)) != CRYPT_OK)       goto cleanup;
      if ((err = ltc_mp_submod(pubkey.k, s, key->dp.order, s)) != CRYPT_OK)     goto cleanup;
      if ((err = ltc_mp_mulmod(one_plus_d, b, key->dp.order, tmp)) != CRYPT_OK) goto cleanup;
      if ((err = ltc_mp_invmod(tmp, key->dp.order, tmp)) != CRYPT_OK)           goto cleanup;
      if ((err = ltc_mp_mulmod(s, b, key->dp.order, s)) != CRYPT_OK)            goto cleanup;
      if ((err = ltc_mp_mulmod(s, tmp, key->dp.order, s)) != CRYPT_OK)          goto cleanup;
      ecc_free(&pubkey);
      have_pubkey = 0;
      if (ltc_mp_iszero(s) == LTC_MP_NO) {
         err = der_encode_sequence_multi(out, outlen, LTC_ASN1_INTEGER, 1uL, r, LTC_ASN1_INTEGER, 1uL, s, LTC_ASN1_EOL, 0uL, NULL);
         goto cleanup;
      }
   }
   err = CRYPT_ERROR;

cleanup:
   if (have_pubkey) ecc_free(&pubkey);
   ltc_mp_deinit_multi(r, s, e, b, one_plus_d, tmp, LTC_NULL);
   return err;
}

/**
  Sign a message with SM2
  @param id         The signer identifier used to compute ZA
  @param idlen      The length of the signer identifier in octets
  @param msg        The message to sign
  @param msglen     The length of the message in octets
  @param out        [out] The destination for the DER-encoded signature
  @param outlen     [in/out] The max size and resulting size of the signature
  @param prng       An active PRNG state
  @param wprng      The index of the PRNG to use
  @param hash_idx   The index of the hash to use for ZA and message digesting, or -1 to use the default SM3 hash
  @param key        The private ECC key to sign with; it must use the built-in sm2p256v1 curve
  @return CRYPT_OK if successful
  @note             The default hash is SM3. Other hashes should only rarely be used in practice.
*/
int ecc_sign_sm2(const unsigned char *id, unsigned long idlen,
                 const unsigned char *msg, unsigned long msglen,
                 unsigned char *out, unsigned long *outlen,
                 prng_state *prng, int wprng,
                 int hash_idx, const ecc_key *key)
{
   unsigned char digest[MAXBLOCKSIZE];
   unsigned long digestlen = sizeof(digest);
   int err;

   LTC_ARGCHK(id     != NULL);
   LTC_ARGCHK(msg    != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   if ((err = s_sm2_only_curve(key)) != CRYPT_OK) return err;
   if ((err = s_sm2_digest_message(digest, &digestlen, id, idlen, msg, msglen, hash_idx, key)) != CRYPT_OK) return err;
   return s_ecc_sign_hash_sm2(digest, digestlen, out, outlen, prng, wprng, key);
}

static int s_ecc_verify_hash_sm2(const unsigned char *sig, unsigned long siglen,
                                 const unsigned char *hash, unsigned long hashlen,
                                 int *stat, const ecc_key *key)
{
   ecc_point *mG = NULL, *mQ = NULL;
   void *r, *s, *t, *e, *R, *a_plus3;
   void *mu = NULL, *ma = NULL;
   void *mp = NULL;
   int err;

   LTC_ARGCHK(sig  != NULL);
   LTC_ARGCHK(hash != NULL);
   LTC_ARGCHK(stat != NULL);
   LTC_ARGCHK(key  != NULL);

   if (key->type != PK_PUBLIC && key->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;

   *stat = 0;

   if ((err = ltc_mp_init_multi(&r, &s, &t, &e, &R, &a_plus3, LTC_NULL)) != CRYPT_OK) return err;

   if ((err = der_decode_sequence_multi_ex(sig, siglen,
                                           LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_STRICT,
                                           LTC_ASN1_INTEGER, 1uL, r,
                                           LTC_ASN1_INTEGER, 1uL, s,
                                           LTC_ASN1_EOL, 0uL, LTC_NULL)) != CRYPT_OK) goto cleanup;

   if (ltc_mp_cmp_d(r, 0) != LTC_MP_GT || ltc_mp_cmp_d(s, 0) != LTC_MP_GT ||
       ltc_mp_cmp(r, key->dp.order) != LTC_MP_LT || ltc_mp_cmp(s, key->dp.order) != LTC_MP_LT) {
      err = CRYPT_INVALID_PACKET;
      goto cleanup;
   }

   /* t = r + s mod n
      mG = scalmult(s, G) + scalmult(t, pubkey)
      R = (e + mG.x) mod n
      accept only if R == r
   */

   if ((err = s_sm2_hash_to_e(hash, hashlen, key, e)) != CRYPT_OK) goto cleanup;
   if ((err = ltc_mp_add(r, s, t)) != CRYPT_OK) goto cleanup;
   if ((err = ltc_mp_mod(t, key->dp.order, t)) != CRYPT_OK) goto cleanup;
   if (ltc_mp_iszero(t) == LTC_MP_YES) {
      err = CRYPT_OK;
      goto cleanup;
   }

   if ((err = ltc_mp_add_d(key->dp.A, 3, a_plus3)) != CRYPT_OK) goto cleanup;

   mG = ltc_ecc_new_point();
   mQ = ltc_ecc_new_point();
   if (mG == NULL || mQ == NULL) {
      err = CRYPT_MEM;
      goto cleanup;
   }

   if ((err = ltc_ecc_copy_point(&key->dp.base, mG)) != CRYPT_OK)                       goto cleanup;
   if ((err = ltc_ecc_copy_point(&key->pubkey, mQ)) != CRYPT_OK)                        goto cleanup;
   if ((err = ltc_mp_montgomery_setup(key->dp.prime, &mp)) != CRYPT_OK)                 goto cleanup;
   if (ltc_mp_cmp(a_plus3, key->dp.prime) != LTC_MP_EQ) {
      if ((err = ltc_mp_init_multi(&mu, &ma, LTC_NULL)) != CRYPT_OK)                    goto cleanup;
      if ((err = ltc_mp_montgomery_normalization(mu, key->dp.prime)) != CRYPT_OK)       goto cleanup;
      if ((err = ltc_mp_mulmod(key->dp.A, mu, key->dp.prime, ma)) != CRYPT_OK)          goto cleanup;
   }
   if (ltc_mp.ecc_mul2add == NULL) {
      if ((err = ltc_mp.ecc_ptmul(s, mG, mG, key->dp.A, key->dp.prime, 0)) != CRYPT_OK) goto cleanup;
      if ((err = ltc_mp.ecc_ptmul(t, mQ, mQ, key->dp.A, key->dp.prime, 0)) != CRYPT_OK) goto cleanup;
      if ((err = ltc_mp.ecc_ptadd(mQ, mG, mG, ma, key->dp.prime, mp)) != CRYPT_OK)      goto cleanup;
      if ((err = ltc_mp.ecc_map(mG, key->dp.prime, mp)) != CRYPT_OK)                    goto cleanup;
   }
   else {
      if ((err = ltc_mp.ecc_mul2add(mG, s, mQ, t, mG, ma, key->dp.prime)) != CRYPT_OK)  goto cleanup;
   }
   if ((err = ltc_mp_add(e, mG->x, R)) != CRYPT_OK)                                     goto cleanup;
   if ((err = ltc_mp_mod(R, key->dp.order, R)) != CRYPT_OK)                             goto cleanup;

   if (ltc_mp_cmp(R, r) == LTC_MP_EQ) *stat = 1;
   err = CRYPT_OK;

cleanup:
   if (mG != NULL) ltc_ecc_del_point(mG);
   if (mQ != NULL) ltc_ecc_del_point(mQ);
   if (mu != NULL) ltc_mp_clear(mu);
   if (ma != NULL) ltc_mp_clear(ma);
   if (mp != NULL) ltc_mp_montgomery_free(mp);
   ltc_mp_deinit_multi(r, s, t, e, R, a_plus3, LTC_NULL);
   return err;
}

/**
  Verify an SM2 signature against a message
  @param id         The signer identifier used to compute ZA
  @param idlen      The length of the signer identifier in octets
  @param msg        The message to verify
  @param msglen     The length of the message in octets
  @param sig        The DER-encoded signature to verify
  @param siglen     The length of the signature in octets
  @param hash_idx   The index of the hash to use for ZA and message digesting, or -1 to use the default SM3 hash
  @param stat       [out] 1 if the signature is valid, 0 if it is invalid
  @param key        The ECC key containing the public key to verify with; it must use the built-in sm2p256v1 curve
  @return CRYPT_OK if successful
  @note             The default hash is SM3. Other hashes should only rarely be used in practice.
*/
int ecc_verify_sm2(const unsigned char *id, unsigned long idlen,
                   const unsigned char *msg, unsigned long msglen,
                   const unsigned char *sig, unsigned long siglen,
                   int hash_idx, int *stat, const ecc_key *key)
{
   unsigned char digest[MAXBLOCKSIZE];
   unsigned long digestlen = sizeof(digest);
   int err;

   LTC_ARGCHK(id   != NULL);
   LTC_ARGCHK(msg  != NULL);
   LTC_ARGCHK(sig  != NULL);
   LTC_ARGCHK(stat != NULL);
   LTC_ARGCHK(key  != NULL);

   if ((err = s_sm2_only_curve(key)) != CRYPT_OK) return err;
   if ((err = s_sm2_digest_message(digest, &digestlen, id, idlen, msg, msglen, hash_idx, key)) != CRYPT_OK) return err;
   return s_ecc_verify_hash_sm2(sig, siglen, digest, digestlen, stat, key);
}
#endif /* LTC_DER */

/**
  Encrypt a message with SM2 public-key encryption
  @param in         The plaintext to encrypt
  @param inlen      The length of the plaintext in octets
  @param out        [out] The destination for the ciphertext in C1 || C3 || C2 format
  @param outlen     [in/out] The max size and resulting size of the ciphertext
  @param prng       An active PRNG state
  @param wprng      The index of the PRNG to use
  @param hash_idx   The index of the hash to use for KDF and C3, or -1 to use the default SM3 hash
  @param key        The ECC key containing the recipient public key; it must use the built-in sm2p256v1 curve
  @return CRYPT_OK if successful
  @note             The default hash is SM3. Other hashes should only rarely be used in practice.
*/
int ecc_encrypt_key_sm2(const unsigned char *in, unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        prng_state *prng, int wprng,
                        int hash_idx, const ecc_key *key)
{
   ecc_key pubkey;
   unsigned char *mask = NULL, *xy = NULL, *c3 = NULL;
   unsigned long need, c1len, hashsize, i;
   int err, have_pubkey = 0, max_iterations;
   hash_state md;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   if ((err = s_sm2_only_curve(key)) != CRYPT_OK) return err;
   if ((hash_idx = s_sm2_hash_idx(hash_idx)) < 0) return hash_idx;
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) return err;
   if (key->type != PK_PUBLIC && key->type != PK_PRIVATE) return CRYPT_PK_INVALID_TYPE;

   c1len = 1uL + (2uL * key->dp.size);
   hashsize = hash_descriptor[hash_idx].hashsize;
   need = c1len + hashsize + inlen;
   if (*outlen < need) {
      *outlen = need;
      return CRYPT_BUFFER_OVERFLOW;
   }

   xy = XMALLOC(2uL * key->dp.size);
   c3 = XMALLOC(hashsize);
   if (xy == NULL || c3 == NULL) {
      err = CRYPT_MEM;
      goto cleanup;
   }
   if (inlen > 0uL) {
      mask = XMALLOC(inlen);
      if (mask == NULL) {
         err = CRYPT_MEM;
         goto cleanup;
      }
   }

   /* C1 = scalmult(k, G), (x2, y2) = scalmult(k, PB), mask = KDF(x2 || y2) */
   have_pubkey = 0;
   for (max_iterations = LTC_PK_MAX_RETRIES; max_iterations > 0; max_iterations--) {
      unsigned long tmplen = c1len;
      if ((err = ecc_copy_curve(key, &pubkey)) != CRYPT_OK)                                 goto cleanup;
      have_pubkey = 1;
      if ((err = ecc_generate_key(prng, wprng, &pubkey)) != CRYPT_OK)                       goto cleanup;
      if ((err = ltc_ecc_export_point(out, &tmplen, pubkey.pubkey.x, pubkey.pubkey.y, key->dp.size, 0)) != CRYPT_OK) goto cleanup;
      if ((err = s_sm2_shared_xy(&pubkey, key, xy)) != CRYPT_OK)                            goto cleanup;
      if (inlen > 0uL) {
         if ((err = s_sm2_kdf(hash_idx, xy, 2uL * key->dp.size, mask, inlen)) != CRYPT_OK)  goto cleanup;
      }
      ecc_free(&pubkey);
      have_pubkey = 0;
      if (inlen == 0uL || !s_sm2_is_all_zero(mask, inlen)) break;
   }

   if (max_iterations == 0) {
      err = CRYPT_ERROR;
      goto cleanup;
   }

   /* C3 = H(x2 || M || y2), C2 = M ^ KDF(x2 || y2) */
   if ((err = hash_descriptor[hash_idx].init(&md)) != CRYPT_OK)                                     goto cleanup;
   if ((err = hash_descriptor[hash_idx].process(&md, xy, key->dp.size)) != CRYPT_OK)                goto cleanup;
   if (inlen > 0uL) {
      if ((err = hash_descriptor[hash_idx].process(&md, in, inlen)) != CRYPT_OK)                    goto cleanup;
   }
   if ((err = hash_descriptor[hash_idx].process(&md, xy + key->dp.size, key->dp.size)) != CRYPT_OK) goto cleanup;
   if ((err = hash_descriptor[hash_idx].done(&md, c3)) != CRYPT_OK)                                 goto cleanup;
   XMEMCPY(out + c1len, c3, hashsize);
   for (i = 0; i < inlen; i++) {
      out[c1len + hashsize + i] = in[i] ^ mask[i];
   }
   *outlen = need;
   err = CRYPT_OK;

cleanup:
   if (have_pubkey) {
      ecc_free(&pubkey);
   }
#ifdef LTC_CLEAN_STACK
   zeromem(&md, sizeof(md));
   if (mask != NULL) zeromem(mask, inlen);
   if (xy != NULL) zeromem(xy, 2uL * key->dp.size);
   if (c3 != NULL) zeromem(c3, hashsize);
#endif
   if (mask != NULL) XFREE(mask);
   if (xy != NULL) XFREE(xy);
   if (c3 != NULL) XFREE(c3);
   return err;
}

/**
  Decrypt and authenticate an SM2 ciphertext
  @param in         The ciphertext in C1 || C3 || C2 format
  @param inlen      The length of the ciphertext in octets
  @param out        [out] The destination for the recovered plaintext
  @param outlen     [in/out] The max size and resulting size of the plaintext
  @param hash_idx   The index of the hash to use for KDF and C3 verification, or -1 to use the default SM3 hash
  @param key        The private ECC key to decrypt with; it must use the built-in sm2p256v1 curve
  @return CRYPT_OK if successful
  @note             The default hash is SM3. Other hashes should only rarely be used in practice.
*/
int ecc_decrypt_key_sm2(const unsigned char *in, unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        int hash_idx, const ecc_key *key)
{
   ecc_key pubkey;
   unsigned char *mask = NULL, *xy = NULL, *u = NULL;
   unsigned long c1len, c2len, hashsize, i;
   int err, have_pubkey = 0;
   hash_state md;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   if ((err = s_sm2_only_curve(key)) != CRYPT_OK) return err;
   if ((hash_idx = s_sm2_hash_idx(hash_idx)) < 0) return hash_idx;
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) return err;
   if (key->type != PK_PRIVATE) return CRYPT_PK_NOT_PRIVATE;
   if (inlen == 0uL) return CRYPT_INVALID_PACKET;

   if (in[0] == 0x04) {
      c1len = 1uL + (2uL * key->dp.size);
   }
   else if (in[0] == 0x02 || in[0] == 0x03) {
      c1len = 1uL + key->dp.size;
   }
   else {
      return CRYPT_INVALID_PACKET;
   }

   hashsize = hash_descriptor[hash_idx].hashsize;
   if (inlen < c1len + hashsize) return CRYPT_INVALID_PACKET;

   c2len = inlen - c1len - hashsize;
   if (*outlen < c2len) {
      *outlen = c2len;
      return CRYPT_BUFFER_OVERFLOW;
   }

   xy = XMALLOC(2uL * key->dp.size);
   u = XMALLOC(hashsize);
   if (xy == NULL || u == NULL) {
      err = CRYPT_MEM;
      goto cleanup;
   }
   if (c2len > 0uL) {
      mask = XMALLOC(c2len);
      if (mask == NULL) {
         err = CRYPT_MEM;
         goto cleanup;
      }
   }

   /* (x2, y2) = scalmult(dB, C1) */
   have_pubkey = 0;
   if ((err = ecc_copy_curve(key, &pubkey)) != CRYPT_OK)                                goto cleanup;
   have_pubkey = 1;
   if ((err = ecc_set_key(in, c1len, PK_PUBLIC, &pubkey)) != CRYPT_OK)                  goto cleanup;
   if ((err = s_sm2_shared_xy(key, &pubkey, xy)) != CRYPT_OK)                           goto cleanup;
   ecc_free(&pubkey);
   have_pubkey = 0;
   if (c2len > 0uL) {
      if ((err = s_sm2_kdf(hash_idx, xy, 2uL * key->dp.size, mask, c2len)) != CRYPT_OK) goto cleanup;
      if (s_sm2_is_all_zero(mask, c2len)) {
         err = CRYPT_INVALID_PACKET;
         goto cleanup;
      }
   }

   /* M = C2 ^ KDF(x2 || y2) */
   for (i = 0; i < c2len; i++) {
      out[i] = in[c1len + hashsize + i] ^ mask[i];
   }

   /* u = H(x2 || M || y2); verify u == C3 */
   if ((err = hash_descriptor[hash_idx].init(&md)) != CRYPT_OK)                                     goto cleanup;
   if ((err = hash_descriptor[hash_idx].process(&md, xy, key->dp.size)) != CRYPT_OK)                goto cleanup;
   if (c2len > 0uL) {
      if ((err = hash_descriptor[hash_idx].process(&md, out, c2len)) != CRYPT_OK)                   goto cleanup;
   }
   if ((err = hash_descriptor[hash_idx].process(&md, xy + key->dp.size, key->dp.size)) != CRYPT_OK) goto cleanup;
   if ((err = hash_descriptor[hash_idx].done(&md, u)) != CRYPT_OK)                                  goto cleanup;

   if (XMEM_NEQ(u, in + c1len, hashsize) != 0) {
      err = CRYPT_INVALID_PACKET;
      goto cleanup;
   }

   *outlen = c2len;
   err = CRYPT_OK;

cleanup:
   if (have_pubkey) {
      ecc_free(&pubkey);
   }
#ifdef LTC_CLEAN_STACK
   zeromem(&md, sizeof(md));
   if (mask != NULL) zeromem(mask, c2len);
   if (xy != NULL) zeromem(xy, 2uL * key->dp.size);
   if (u != NULL) zeromem(u, hashsize);
#endif
   if (mask != NULL) XFREE(mask);
   if (xy != NULL) XFREE(xy);
   if (u != NULL) XFREE(u);
   return err;
}

#endif /* LTC_MECC */
