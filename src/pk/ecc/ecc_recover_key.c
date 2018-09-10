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

#ifdef LTC_ECC_SHAMIR

/**
  @file ecc_recover_key.c
  ECC Crypto, Russ Williams
*/

static int _ecc_recover_key(const unsigned char *sig,  unsigned long siglen,
                            const unsigned char *hash, unsigned long hashlen,
                            int recid, ecc_key *key)
{
   ecc_point     *mG = NULL, *mQ = NULL, *mR = NULL;
   void          *p, *m, *a, *b;
   void          *r, *s, *v, *w, *t1, *t2, *u1, *u2, *v1, *v2, *e, *x, *y, *a_plus3;
   void          *mu = NULL, *ma = NULL;
   void          *mp = NULL;
   int           err;
   unsigned long pbits, pbytes, i, shift_right;
   unsigned char ch, buf[MAXBLOCKSIZE];

   LTC_ARGCHK(sig  != NULL);
   LTC_ARGCHK(hash != NULL);
   LTC_ARGCHK(key  != NULL);

   /* BEWARE: requires sqrtmod_prime */
   if (ltc_mp.sqrtmod_prime == NULL) {
      return CRYPT_ERROR;
   }

   /* allocate ints */
   if ((err = mp_init_multi(&r, &s, &v, &w, &t1, &t2, &u1, &u2, &v1, &v2, &e, &x, &y, &a_plus3, NULL)) != CRYPT_OK) {
      return err;
   }

   p = key->dp.order;
   m = key->dp.prime;
   a = key->dp.A;
   b = key->dp.B;
   if ((err = mp_add_d(a, 3, a_plus3)) != CRYPT_OK) {
      goto error;
   }

   /* allocate points */
   mG = ltc_ecc_new_point();
   mQ = ltc_ecc_new_point();
   mR = ltc_ecc_new_point();
   if (mR == NULL || mQ  == NULL || mG == NULL) {
      err = CRYPT_MEM;
      goto error;
   }

   /* Only ASN.1 format signatures supported for now */
   if ((err = der_decode_sequence_multi_ex(sig, siglen, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_STRICT,
                                     LTC_ASN1_INTEGER, 1UL, r,
                                     LTC_ASN1_INTEGER, 1UL, s,
                                     LTC_ASN1_EOL, 0UL, NULL)) != CRYPT_OK)                             { goto error; }

   /* check for zero */
   if (mp_cmp_d(r, 0) != LTC_MP_GT || mp_cmp_d(s, 0) != LTC_MP_GT ||
       mp_cmp(r, p) != LTC_MP_LT || mp_cmp(s, p) != LTC_MP_LT) {
      err = CRYPT_INVALID_PACKET;
      goto error;
   }

   /* read hash - truncate if needed */
   pbits = mp_count_bits(p);
   pbytes = (pbits+7) >> 3;
   if (pbits > hashlen*8) {
      if ((err = mp_read_unsigned_bin(e, (unsigned char *)hash, hashlen)) != CRYPT_OK)                  { goto error; }
   }
   else if (pbits % 8 == 0) {
      if ((err = mp_read_unsigned_bin(e, (unsigned char *)hash, pbytes)) != CRYPT_OK)                   { goto error; }
   }
   else {
      shift_right = 8 - pbits % 8;
      for (i=0, ch=0; i<pbytes; i++) {
        buf[i] = ch;
        ch = (hash[i] << (8-shift_right));
        buf[i] = buf[i] ^ (hash[i] >> shift_right);
      }
      if ((err = mp_read_unsigned_bin(e, (unsigned char *)buf, pbytes)) != CRYPT_OK)                    { goto error; }
   }

   /* decompress point from r=(x mod p) - BEWARE: requires sqrtmod_prime */
   /* x = r + p*(recid/2) */
   if ((err = mp_set(x, recid/2)) != CRYPT_OK)                                                          { goto error; }
   if ((err = mp_mulmod(p, x, m, x)) != CRYPT_OK)                                                       { goto error; }
   if ((err = mp_add(x, r, x)) != CRYPT_OK)                                                             { goto error; }
   /* compute x^3 */
   if ((err = mp_sqr(x, t1)) != CRYPT_OK)                                                               { goto error; }
   if ((err = mp_mulmod(t1, x, m, t1)) != CRYPT_OK)                                                     { goto error; }
   /* compute x^3 + a*x */
   if ((err = mp_mulmod(a, x, m, t2)) != CRYPT_OK)                                                      { goto error; }
   if ((err = mp_add(t1, t2, t1)) != CRYPT_OK)                                                          { goto error; }
   /* compute x^3 + a*x + b */
   if ((err = mp_add(t1, b, t1)) != CRYPT_OK)                                                           { goto error; }
   /* compute sqrt(x^3 + a*x + b) */
   if ((err = mp_sqrtmod_prime(t1, m, t2)) != CRYPT_OK)                                                 { goto error; }

   /* fill in mR */
   if ((err = mp_copy(x, mR->x)) != CRYPT_OK)                                                           { goto error; }
   if ((mp_isodd(t2) && (recid%2)) || (!mp_isodd(t2) && !(recid%2))) {
      if ((err = mp_mod(t2, m, mR->y)) != CRYPT_OK)                                                     { goto error; }
   }
   else {
      if ((err = mp_submod(m, t2, m, mR->y)) != CRYPT_OK)                                               { goto error; }
   }
   if ((err = mp_set(mR->z, 1)) != CRYPT_OK)                                                            { goto error; }

   /*  w  = r^-1 mod n */
   if ((err = mp_invmod(r, p, w)) != CRYPT_OK)                                                          { goto error; }
   /* v1 = sw */
   if ((err = mp_mulmod(s, w, p, v1)) != CRYPT_OK)                                                      { goto error; }
   /* v2 = -ew */
   if ((err = mp_mulmod(e, w, p, v2)) != CRYPT_OK)                                                      { goto error; }
   if ((err = mp_submod(p, v2, p, v2)) != CRYPT_OK)                                                     { goto error; }

   /*  w  = s^-1 mod n */
   if ((err = mp_invmod(s, p, w)) != CRYPT_OK)                                                          { goto error; }
   /* u1 = ew */
   if ((err = mp_mulmod(e, w, p, u1)) != CRYPT_OK)                                                      { goto error; }
   /* u2 = rw */
   if ((err = mp_mulmod(r, w, p, u2)) != CRYPT_OK)                                                      { goto error; }

   /* find mG */
   if ((err = ltc_ecc_copy_point(&key->dp.base, mG)) != CRYPT_OK)                                       { goto error; }

   /* find the montgomery mp */
   if ((err = mp_montgomery_setup(m, &mp)) != CRYPT_OK)                                                 { goto error; }

   /* for curves with a == -3 keep ma == NULL */
   if (mp_cmp(a_plus3, m) != LTC_MP_EQ) {
      if ((err = mp_init_multi(&mu, &ma, NULL)) != CRYPT_OK)                                            { goto error; }
      if ((err = mp_montgomery_normalization(mu, m)) != CRYPT_OK)                                       { goto error; }
      if ((err = mp_mulmod(a, mu, m, ma)) != CRYPT_OK)                                                  { goto error; }
   }

   /* recover mQ from mR */
   /* compute v1*mR + v2*mG = mQ using Shamir's trick */
   if ((err = ltc_mp.ecc_mul2add(mR, v1, mG, v2, mQ, ma, m)) != CRYPT_OK)                               { goto error; }

   /* compute u1*mG + u2*mQ = mG using Shamir's trick */
   if ((err = ltc_mp.ecc_mul2add(mG, u1, mQ, u2, mG, ma, m)) != CRYPT_OK)                               { goto error; }

   /* v = X_x1 mod n */
   if ((err = mp_mod(mG->x, p, v)) != CRYPT_OK)                                                         { goto error; }

   /* does v == r */
   if (mp_cmp(v, r) == LTC_MP_EQ) {
      /* found public key which verifies signature */
      if ((err = ltc_ecc_copy_point(mQ, &key->pubkey)) != CRYPT_OK)                                     { goto error; }
      /* point on the curve + other checks */
      if ((err = ltc_ecc_verify_key(key)) != CRYPT_OK)                                                  { goto error; }

      key->type = PK_PUBLIC;

      err = CRYPT_OK;
   }
   else {
      /* not found - recid is wrong or we're unable to calculate public key for some other reason */
      err = CRYPT_INVALID_ARG;
   }

error:
   if (ma != NULL) mp_clear(ma);
   if (mu != NULL) mp_clear(mu);
   if (mp != NULL) mp_montgomery_free(mp);
   if (mR != NULL) ltc_ecc_del_point(mR);
   if (mQ != NULL) ltc_ecc_del_point(mQ);
   if (mG != NULL) ltc_ecc_del_point(mG);
   mp_clear_multi(r, s, v, w, t1, t2, u1, u2, v1, v2, e, x, y, a_plus3, NULL);
   return err;
}

/**
   Recover ECC public key from signature and hash
   @param sig         The signature to verify
   @param siglen      The length of the signature (octets)
   @param hash        The hash (message digest) that was signed
   @param hashlen     The length of the hash (octets)
   @param recid       0 or 1 to select parity ("v")
   @param key         The recovered public ECC key
   @return CRYPT_OK if successful (even if the signature is not valid)
*/
int ecc_recover_key(const unsigned char *sig,  unsigned long siglen,
                    const unsigned char *hash, unsigned long hashlen,
                    int recid, ecc_key *key)
{
   return _ecc_recover_key(sig, siglen, hash, hashlen, recid, key);
}

#endif
#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
