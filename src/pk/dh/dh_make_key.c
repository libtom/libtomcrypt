/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_MDH

static int _dh_groupsize_to_keysize(int groupsize)
{
   /* The strength estimates from https://tools.ietf.org/html/rfc3526#section-8
    * We use "Estimate 2" to get an appropriate private key (exponent) size.
    */
   if (groupsize <= 0) {
      return 0;
   }
   else if (groupsize <= 192) {
      return 30;     /* 1536-bit => key size 240-bit */
   }
   else if (groupsize <= 256) {
      return 40;     /* 2048-bit => key size 320-bit */
   }
   else if (groupsize <= 384) {
      return 52;     /* 3072-bit => key size 416-bit */
   }
   else if (groupsize <= 512) {
      return 60;     /* 4096-bit => key size 480-bit */
   }
   else if (groupsize <= 768) {
      return 67;     /* 6144-bit => key size 536-bit */
   }
   else if (groupsize <= 1024) {
      return 77;     /* 8192-bit => key size 616-bit */
   }
   else {
      return 0;
   }
}

static int _dh_make_key(prng_state *prng, int wprng, void *prime, void *base, dh_key *key)
{
   unsigned char *buf;
   unsigned long keysize;
   int err, max_iterations = PK_MAX_RETRIES;

   LTC_ARGCHK(key   != NULL);
   LTC_ARGCHK(prng  != NULL);
   LTC_ARGCHK(prime != NULL);
   LTC_ARGCHK(base  != NULL);

   /* good prng? */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   /* init big numbers */
   if ((err = mp_init_multi(&key->x, &key->y, &key->base, &key->prime, NULL)) != CRYPT_OK) {
      return err;
   }

   /* load the prime and the base */
   if ((err = mp_copy(base, key->base)) != CRYPT_OK)   { goto freemp; }
   if ((err = mp_copy(prime, key->prime)) != CRYPT_OK) { goto freemp; }

   keysize = _dh_groupsize_to_keysize(mp_unsigned_bin_size(key->prime));
   if (keysize == 0) {
      err = CRYPT_INVALID_KEYSIZE;
      goto freemp;
   }

   /* allocate buffer */
   buf = XMALLOC(keysize);
   if (buf == NULL) {
      err = CRYPT_MEM;
      goto freemp;
   }

   key->type = PK_PRIVATE;
   do {
      /* make up random buf */
      if (prng_descriptor[wprng].read(buf, keysize, prng) != keysize) {
         err = CRYPT_ERROR_READPRNG;
         goto freebuf;
      }
      /* load the x value - private key */
      if ((err = mp_read_unsigned_bin(key->x, buf, keysize)) != CRYPT_OK) {
         goto freebuf;
      }
      /* compute the y value - public key */
      if ((err = mp_exptmod(key->base, key->x, key->prime, key->y)) != CRYPT_OK) {
         goto freebuf;
      }
      err = dh_check_pubkey(key);
   } while (err != CRYPT_OK && max_iterations-- > 0);

freebuf:
   zeromem(buf, keysize);
   XFREE(buf);
freemp:
   if (err != CRYPT_OK) mp_clear_multi(key->x, key->y, key->base, key->prime, NULL);
   return err;
}

/**
  Make a DH key (custom DH group) [private key pair]
  @param prng       An active PRNG state
  @param wprng      The index for the PRNG you desire to use
  @param prime_hex  The prime p (hexadecimal string)
  @param base_hex   The base g (hexadecimal string)
  @param key        [out] Where the newly created DH key will be stored
  @return CRYPT_OK if successful, note: on error all allocated memory will be freed automatically.
*/
static int _dh_make_key_ex(prng_state *prng, int wprng, int radix,
                   void *prime, unsigned long primelen,
                   void *base,  unsigned long baselen,
                   dh_key *key)
{
   void *p, *b;
   int err;

   LTC_ARGCHK(prime != NULL);
   LTC_ARGCHK(base  != NULL);
   LTC_ARGCHK((radix >= 2 && radix <= 64) || radix == 256);

   if ((err = mp_init_multi(&p, &b, NULL)) != CRYPT_OK)    { return err; }
   if (radix == 256) {
     if ((err = mp_read_unsigned_bin(b, base, baselen)) != CRYPT_OK)   { goto error; }
     if ((err = mp_read_unsigned_bin(p, prime, primelen)) != CRYPT_OK) { goto error; }
   }
   else {
     if ((err = mp_read_radix(b, base, radix)) != CRYPT_OK)  { goto error; }
     if ((err = mp_read_radix(p, prime, radix)) != CRYPT_OK) { goto error; }
   }
   err = _dh_make_key(prng, wprng, p, b, key);

error:
   mp_clear_multi(p, b, NULL);
   return err;
}

/**
  Make a DH key (use built-in DH groups) [private key pair]
  @param prng       An active PRNG state
  @param wprng      The index for the PRNG you desire to use
  @param groupsize  The size (octets) of used DH group
  @param key        [out] Where the newly created DH key will be stored
  @return CRYPT_OK if successful, note: on error all allocated memory will be freed automatically.
*/
int dh_make_key(prng_state *prng, int wprng, int groupsize, dh_key *key)
{
   int i;

   LTC_ARGCHK(groupsize > 0);

   for (i = 0; (groupsize > ltc_dh_sets[i].size) && (ltc_dh_sets[i].size != 0); i++);
   if (ltc_dh_sets[i].size == 0) return CRYPT_INVALID_KEYSIZE;

   return _dh_make_key_ex(prng, wprng, 16,
                         ltc_dh_sets[i].prime, strlen(ltc_dh_sets[i].prime) + 1,
                         ltc_dh_sets[i].base,  strlen(ltc_dh_sets[i].base)  + 1,
                         key);
}

/**
  Make a DH key (dhparam data: openssl dhparam -outform DER -out dhparam.der 2048)
  @param prng       An active PRNG state
  @param wprng      The index for the PRNG you desire to use
  @param dhparam    The DH param DER encoded data
  @param dhparamlen The length of dhparam data
  @param key        [out] Where the newly created DH key will be stored
  @return CRYPT_OK if successful, note: on error all allocated memory will be freed automatically.
*/
int dh_make_key_dhparam(prng_state *prng, int wprng, unsigned char *dhparam, unsigned long dhparamlen, dh_key *key)
{
   void *prime, *base;
   int err;

   LTC_ARGCHK(dhparam != NULL);
   LTC_ARGCHK(dhparamlen > 0);

   if ((err = mp_init_multi(&prime, &base, NULL)) != CRYPT_OK) {
      return err;
   }
   if ((err = der_decode_sequence_multi(dhparam, dhparamlen,
                                        LTC_ASN1_INTEGER, 1UL, prime,
                                        LTC_ASN1_INTEGER, 1UL, base,
                                        LTC_ASN1_EOL,     0UL, NULL)) != CRYPT_OK) {
      goto error;
   }
   err = _dh_make_key(prng, wprng, prime, base, key);

error:
   mp_clear_multi(prime, base, NULL);
   return err;
}


#endif /* LTC_MDH */

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
