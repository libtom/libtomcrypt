/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.org
 */
#include "tomcrypt.h"

/**
  @file dh.c
  DH crypto, Tom St Denis
*/

#ifdef LTC_MDH


#include "dh_static.h"

/**
   Test the DH sub-system (can take a while)
   @return CRYPT_OK if successful
*/
int dh_compat_test(void)
{
    void *p, *g, *tmp;
    int x, err, primality;

    if ((err = mp_init_multi(&p, &g, &tmp, NULL)) != CRYPT_OK)                 { goto error; }

    for (x = 0; sets[x].size != 0; x++) {
#if 0
        printf("dh_test():testing size %d-bits\n", sets[x].size * 8);
#endif
        if ((err = mp_read_radix(g,(char *)sets[x].base, 64)) != CRYPT_OK)    { goto error; }
        if ((err = mp_read_radix(p,(char *)sets[x].prime, 64)) != CRYPT_OK)   { goto error; }

        /* ensure p is prime */
        if ((err = mp_prime_is_prime(p, 8, &primality)) != CRYPT_OK)                     { goto done; }
        if (primality != LTC_MP_YES ) {
           err = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }

        if ((err = mp_sub_d(p, 1, tmp)) != CRYPT_OK)                         { goto error; }
        if ((err = mp_div_2(tmp, tmp)) != CRYPT_OK)                          { goto error; }

        /* ensure (p-1)/2 is prime */
        if ((err = mp_prime_is_prime(tmp, 8, &primality)) != CRYPT_OK)                   { goto done; }
        if (primality == 0) {
           err = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }

        /* now see if g^((p-1)/2) mod p is in fact 1 */
        if ((err = mp_exptmod(g, tmp, p, tmp)) != CRYPT_OK)                { goto error; }
        if (mp_cmp_d(tmp, 1)) {
           err = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }
    }
    err = CRYPT_OK;
error:
done:
    mp_clear_multi(tmp, g, p, NULL);
    return err;
}

/**
   Get the min and max DH key sizes (octets)
   @param low    [out] The smallest key size supported
   @param high   [out] The largest key size supported
*/
void dh_sizes(int *low, int *high)
{
   int x;
   LTC_ARGCHKVD(low != NULL);
   LTC_ARGCHKVD(high != NULL);
   *low  = INT_MAX;
   *high = 0;
   for (x = 0; sets[x].size != 0; x++) {
       if (*low > sets[x].size)  *low  = sets[x].size;
       if (*high < sets[x].size) *high = sets[x].size;
   }
}

/**
  Returns the key size of a given DH key (octets)
  @param key   The DH key to get the size of
  @return The size if valid or INT_MAX if not
*/
int dh_get_size(dh_key *key)
{
    LTC_ARGCHK(key != NULL);
    if (dh_is_valid_idx(key->idx) == 1) {
        return sets[key->idx].size;
    } else {
        return INT_MAX; /* large value that would cause dh_make_key() to fail */
    }
}

/**
  Make a DH key [private key pair]
  @param prng     An active PRNG state
  @param wprng    The index for the PRNG you desire to use
  @param keysize  The key size (octets) desired
  @param key      [out] Where the newly created DH key will be stored
  @return CRYPT_OK if successful, note: on error all allocated memory will be freed automatically.
*/
int dh_make_key(prng_state *prng, int wprng, int keysize, dh_key *key)
{
   unsigned char *buf;
   unsigned long x;
   void *p, *g;
   int err;

   LTC_ARGCHK(key  != NULL);

   /* good prng? */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   /* find key size */
   for (x = 0; (keysize > sets[x].size) && (sets[x].size != 0); x++);
#ifdef FAST_PK
   keysize = MIN(sets[x].size, 32);
#else
   keysize = sets[x].size;
#endif
   if (sets[x].size == 0) {
      return CRYPT_INVALID_KEYSIZE;
   }
   key->idx = x;

   /* allocate buffer */
   buf = XMALLOC(keysize);
   if (buf == NULL) {
      return CRYPT_MEM;
   }

   /* make up random string */
   if ( rng_make_prng( keysize, wprng, prng, NULL) != CRYPT_OK) {
      err = CRYPT_ERROR_READPRNG;
      goto error2;
   }

   if (prng_descriptor[wprng].read(buf, keysize, prng) != (unsigned long)keysize) {
      err = CRYPT_ERROR_READPRNG;
      goto error2;
   }

   /* init parameters */
   if ((err = mp_init_multi(&g, &p, &key->x, &key->y, NULL)) != CRYPT_OK) {
      goto error;
   }

   if ((err = mp_read_radix(g, sets[key->idx].base, 64)) != CRYPT_OK)      { goto error; }
   if ((err = mp_read_radix(p, sets[key->idx].prime, 64)) != CRYPT_OK)     { goto error; }

   /* load the x value */
   if ((err = mp_read_unsigned_bin(key->x, buf, keysize)) != CRYPT_OK)     { goto error; }
   if ((err = mp_exptmod(g, key->x, p, key->y)) != CRYPT_OK)            { goto error; }
   key->type = PK_PRIVATE;

   /* free up ram */
   err = CRYPT_OK;
   goto done;
error:
   mp_clear_multi(key->x, key->y, NULL);
done:
   mp_clear_multi(p, g, NULL);
error2:
#ifdef LTC_CLEAN_STACK
   zeromem(buf, keysize);
#endif
   XFREE(buf);
   return err;
}

/**
  Free the allocated ram for a DH key
  @param key   The key which you wish to free
*/
void dh_free(dh_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   if ( key->x ) {
      mp_clear( key->x );
      key->x = NULL;
   }
   if ( key->y ) {
      mp_clear( key->y );
      key->y = NULL;
   }
}

/**
  Export a DH key to a binary packet
  @param out    [out] The destination for the key
  @param outlen [in/out] The max size and resulting size of the DH key
  @param type   Which type of key (PK_PRIVATE or PK_PUBLIC)
  @param key    The key you wish to export
  @return CRYPT_OK if successful
*/
int dh_export(unsigned char *out, unsigned long *outlen, int type, dh_key *key)
{
   unsigned long y, z;
   int err;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* can we store the static header?  */
   if (*outlen < (PACKET_SIZE + 2)) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   if (type == PK_PRIVATE && key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* header */
   y = PACKET_SIZE;

   /* header */
   out[y++] = type;
   out[y++] = (unsigned char)(sets[key->idx].size / 8);

   /* export y */
   OUTPUT_BIGNUM(key->y, out, y, z);

   if (type == PK_PRIVATE) {
      /* export x */
      OUTPUT_BIGNUM(key->x, out, y, z);
   }

   /* store header */
   packet_store_header(out, PACKET_SECT_DH, PACKET_SUB_KEY);

   /* store len */
   *outlen = y;
   return CRYPT_OK;
}

/**
  Import a DH key from a binary packet
  @param in     The packet to read
  @param inlen  The length of the input packet
  @param key    [out] Where to import the key to
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int dh_import(const unsigned char *in, unsigned long inlen, dh_key *key)
{
   unsigned long x, y, s;
   int err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   /* make sure valid length */
   if ((2+PACKET_SIZE) > inlen) {
      return CRYPT_INVALID_PACKET;
   }

   /* check type byte */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_DH, PACKET_SUB_KEY)) != CRYPT_OK) {
      return err;
   }

   /* init */
   if ((err = mp_init_multi(&key->x, &key->y, NULL)) != CRYPT_OK) {
      return err;
   }

   /* advance past packet header */
   y = PACKET_SIZE;

   /* key type, e.g. private, public */
   key->type = (int)in[y++];

   /* key size in bytes */
   s  = (unsigned long)in[y++] * 8;

   for (x = 0; (s > (unsigned long)sets[x].size) && (sets[x].size != 0); x++);
   if (sets[x].size == 0) {
      err = CRYPT_INVALID_KEYSIZE;
      goto error;
   }
   key->idx = (int)x;

   /* type check both values */
   if ((key->type != PK_PUBLIC) && (key->type != PK_PRIVATE))  {
      err = CRYPT_PK_TYPE_MISMATCH;
      goto error;
   }

   /* is the key idx valid? */
   if (dh_is_valid_idx(key->idx) != 1) {
      err = CRYPT_PK_TYPE_MISMATCH;
      goto error;
   }

   /* load public value g^x mod p*/
   INPUT_BIGNUM(key->y, in, x, y, inlen);

   if (key->type == PK_PRIVATE) {
      INPUT_BIGNUM(key->x, in, x, y, inlen);
   }

   /* eliminate private key if public */
   if (key->type == PK_PUBLIC) {
      mp_clear(key->x);
      key->x = NULL;
   }

   return CRYPT_OK;
error:
   mp_clear_multi(key->y, key->x, NULL);
   return err;
}

/**
   Create a DH shared secret.
   @param private_key     The private DH key in the pair
   @param public_key      The public DH key in the pair
   @param out             [out] The destination of the shared data
   @param outlen          [in/out] The max size and resulting size of the shared data.
   @return CRYPT_OK if successful
*/
int dh_shared_secret(dh_key *private_key, dh_key *public_key,
                     unsigned char *out, unsigned long *outlen)
{
   void *tmp, *p;
   unsigned long x;
   int err;

   LTC_ARGCHK(private_key != NULL);
   LTC_ARGCHK(public_key  != NULL);
   LTC_ARGCHK(out         != NULL);
   LTC_ARGCHK(outlen      != NULL);

   /* types valid? */
   if (private_key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* same idx? */
   if (private_key->idx != public_key->idx) {
      return CRYPT_PK_TYPE_MISMATCH;
   }

   /* compute y^x mod p */
   if ((err = mp_init_multi(&tmp, &p, NULL)) != CRYPT_OK) {
      return err;
   }

   if ((err = mp_read_radix(p, (char *)sets[private_key->idx].prime, 64)) != CRYPT_OK)     { goto error; }
   if ((err = mp_exptmod(public_key->y, private_key->x, p, tmp)) != CRYPT_OK)           { goto error; }

   /* enough space for output? */
   x = (unsigned long)mp_unsigned_bin_size(tmp);
   if (*outlen < x) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto done;
   }
   if ((err = mp_to_unsigned_bin(tmp, out)) != CRYPT_OK)                                   { goto error; }
   *outlen = x;
   err = CRYPT_OK;
   goto done;
error:
done:
   mp_clear_multi(p, tmp, NULL);
   return err;
}

#endif /* LTC_MDH */
