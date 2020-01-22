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

int ecc_verify_hash_internal(void *r, void *s,
                             const unsigned char *hash, unsigned long hashlen,
                             int *stat, const ecc_key *key)
{
   ecc_point     *mG = NULL, *mQ = NULL;
   void          *v, *w, *u1, *u2, *e, *p, *m, *a, *a_plus3;
   void          *mu = NULL, *ma = NULL;
   void          *mp = NULL;
   int           err;
   unsigned long pbits, pbytes, i, shift_right;
   unsigned char ch, buf[MAXBLOCKSIZE];

   LTC_ARGCHK(r    != NULL);
   LTC_ARGCHK(s    != NULL);
   LTC_ARGCHK(hash != NULL);
   LTC_ARGCHK(stat != NULL);
   LTC_ARGCHK(key  != NULL);

   /* default to invalid signature */
   *stat = 0;

   /* allocate ints */
   if ((err = mp_init_multi(&v, &w, &u1, &u2, &e, &a_plus3, NULL)) != CRYPT_OK) {
      return err;
   }

   p = key->dp.order;
   m = key->dp.prime;
   a = key->dp.A;
   if ((err = mp_add_d(a, 3, a_plus3)) != CRYPT_OK) {
      goto error;
   }

   /* allocate points */
   mG = ltc_ecc_new_point();
   mQ = ltc_ecc_new_point();
   if (mQ  == NULL || mG == NULL) {
      err = CRYPT_MEM;
      goto error;
   }

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
      if (pbytes >= MAXBLOCKSIZE) {
         err = CRYPT_BUFFER_OVERFLOW;
         goto error;
      }
      shift_right = 8 - pbits % 8;
      for (i=0, ch=0; i<pbytes; i++) {
        buf[i] = ch;
        ch = (hash[i] << (8-shift_right));
        buf[i] = buf[i] ^ (hash[i] >> shift_right);
      }
      if ((err = mp_read_unsigned_bin(e, (unsigned char *)buf, pbytes)) != CRYPT_OK)                    { goto error; }
   }

   /*  w  = s^-1 mod n */
   if ((err = mp_invmod(s, p, w)) != CRYPT_OK)                                                          { goto error; }

   /* u1 = ew */
   if ((err = mp_mulmod(e, w, p, u1)) != CRYPT_OK)                                                      { goto error; }

   /* u2 = rw */
   if ((err = mp_mulmod(r, w, p, u2)) != CRYPT_OK)                                                      { goto error; }

   /* find mG and mQ */
   if ((err = ltc_ecc_copy_point(&key->dp.base, mG)) != CRYPT_OK)                                       { goto error; }
   if ((err = ltc_ecc_copy_point(&key->pubkey, mQ)) != CRYPT_OK)                                        { goto error; }

   /* find the montgomery mp */
   if ((err = mp_montgomery_setup(m, &mp)) != CRYPT_OK)                                                 { goto error; }

   /* for curves with a == -3 keep ma == NULL */
   if (mp_cmp(a_plus3, m) != LTC_MP_EQ) {
      if ((err = mp_init_multi(&mu, &ma, NULL)) != CRYPT_OK)                                            { goto error; }
      if ((err = mp_montgomery_normalization(mu, m)) != CRYPT_OK)                                       { goto error; }
      if ((err = mp_mulmod(a, mu, m, ma)) != CRYPT_OK)                                                  { goto error; }
   }

   /* compute u1*mG + u2*mQ = mG */
   if (ltc_mp.ecc_mul2add == NULL) {
      if ((err = ltc_mp.ecc_ptmul(u1, mG, mG, a, m, 0)) != CRYPT_OK)                                    { goto error; }
      if ((err = ltc_mp.ecc_ptmul(u2, mQ, mQ, a, m, 0)) != CRYPT_OK)                                    { goto error; }

      /* add them */
      if ((err = ltc_mp.ecc_ptadd(mQ, mG, mG, ma, m, mp)) != CRYPT_OK)                                  { goto error; }

      /* reduce */
      if ((err = ltc_mp.ecc_map(mG, m, mp)) != CRYPT_OK)                                                { goto error; }
   } else {
      /* use Shamir's trick to compute u1*mG + u2*mQ using half of the doubles */
      if ((err = ltc_mp.ecc_mul2add(mG, u1, mQ, u2, mG, ma, m)) != CRYPT_OK)                            { goto error; }
   }

   /* v = X_x1 mod n */
   if ((err = mp_mod(mG->x, p, v)) != CRYPT_OK)                                                         { goto error; }

   /* does v == r */
   if (mp_cmp(v, r) == LTC_MP_EQ) {
      *stat = 1;
   }

   /* clear up and return */
   err = CRYPT_OK;
error:
   if (mG != NULL) ltc_ecc_del_point(mG);
   if (mQ != NULL) ltc_ecc_del_point(mQ);
   if (mu != NULL) mp_clear(mu);
   if (ma != NULL) mp_clear(ma);
   mp_clear_multi(v, w, u1, u2, e, a_plus3, NULL);
   if (mp != NULL) mp_montgomery_free(mp);
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
