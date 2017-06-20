/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

/**
  @file ecc_make_key.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

/**
  Make a new ECC key
  @param prng         An active PRNG state
  @param wprng        The index of the PRNG you wish to use
  @param keysize      The keysize for the new key (in octets from 20 to 65 bytes)
  @param key          [out] Destination of the newly created key
  @return CRYPT_OK if successful, upon error all allocated memory will be freed
*/
int ecc_make_key(prng_state *prng, int wprng, int keysize, ecc_key *key)
{
   /* BEWARE: Here we are looking up the curve params by keysize (neither curve name nor curve oid),
    *         which might be ambiguous (there can more than one curve for given keysize).
    *         Thus the chosen curve depends on order of items in ltc_ecc_sets[] - see ecc.c file.
    */
   int x, err;

   /* find key size */
   for (x = 0; (keysize > ltc_ecc_sets[x].size) && (ltc_ecc_sets[x].size != 0); x++);
   keysize = ltc_ecc_sets[x].size;

   if (keysize > ECC_MAXSIZE || ltc_ecc_sets[x].size == 0) {
      return CRYPT_INVALID_KEYSIZE;
   }
   err = ecc_make_key_ex(prng, wprng, key, &ltc_ecc_sets[x]);
   key->idx = x;
   return err;
}

int ecc_make_key_ex(prng_state *prng, int wprng, ecc_key *key, const ltc_ecc_set_type *dp)
{
   int            err;
   ecc_point     *base;
   void          *prime, *order, *a;
   unsigned char *buf;
   int            keysize, orderbits;

   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);
   LTC_ARGCHK(dp          != NULL);

   /* good prng? */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   key->idx = -1;
   key->dp  = dp;
   keysize  = dp->size;

   /* allocate ram */
   base = NULL;
   buf  = XMALLOC(ECC_MAXSIZE);
   if (buf == NULL) {
      return CRYPT_MEM;
   }

   /* make up random string */
   if (prng_descriptor[wprng].read(buf, (unsigned long)keysize, prng) != (unsigned long)keysize) {
      err = CRYPT_ERROR_READPRNG;
      goto ERR_BUF;
   }

   /* setup the key variables */
   if ((err = mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, &prime, &order, &a, NULL)) != CRYPT_OK) {
      goto ERR_BUF;
   }
   base = ltc_ecc_new_point();
   if (base == NULL) {
      err = CRYPT_MEM;
      goto errkey;
   }

   /* read in the specs for this key */
   if ((err = mp_read_radix(prime,   (char *)key->dp->prime, 16)) != CRYPT_OK)                  { goto errkey; }
   if ((err = mp_read_radix(order,   (char *)key->dp->order, 16)) != CRYPT_OK)                  { goto errkey; }
   if ((err = mp_read_radix(base->x, (char *)key->dp->Gx, 16)) != CRYPT_OK)                     { goto errkey; }
   if ((err = mp_read_radix(base->y, (char *)key->dp->Gy, 16)) != CRYPT_OK)                     { goto errkey; }
   if ((err = mp_set(base->z, 1)) != CRYPT_OK)                                                  { goto errkey; }
   if ((err = mp_read_unsigned_bin(key->k, (unsigned char *)buf, keysize)) != CRYPT_OK)         { goto errkey; }

   /* ECC key pair generation according to FIPS-186-4 (B.4.2 Key Pair Generation by Testing Candidates):
    * the generated private key k should be the range [1, order-1]
    *  a/ N = bitlen(order)
    *  b/ generate N random bits and convert them into big integer k
    *  c/ if k not in [1, order-1] go to b/
    *  e/ Q = k*G
    */
   orderbits = mp_count_bits(order);
   do {
     if ((err = rand_bn_bits(key->k, orderbits, prng, wprng)) != CRYPT_OK)                      { goto errkey; }
   } while (mp_iszero(key->k) || mp_cmp(key->k, order) != LTC_MP_LT);

   /* make the public key */
   if ((err = mp_read_radix(a, (char *)key->dp->A, 16)) != CRYPT_OK)                            { goto errkey; }
   if ((err = ltc_mp.ecc_ptmul(key->k, base, &key->pubkey, a, prime, 1)) != CRYPT_OK)           { goto errkey; }
   key->type = PK_PRIVATE;

   /* free up ram */
   err = CRYPT_OK;
   goto cleanup;
errkey:
   mp_clear_multi(key->pubkey.x, key->pubkey.y, key->pubkey.z, key->k, NULL);
cleanup:
   ltc_ecc_del_point(base);
   mp_clear_multi(prime, order, a, NULL);
ERR_BUF:
#ifdef LTC_CLEAN_STACK
   zeromem(buf, ECC_MAXSIZE);
#endif
   XFREE(buf);
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
