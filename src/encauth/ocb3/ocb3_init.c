/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/**
   @file ocb3_init.c
   OCB implementation, initialize state, by Tom St Denis
*/
#include "tomcrypt.h"

#ifdef LTC_OCB3_MODE

static const struct {
    int           len;
    unsigned char poly_mul[MAXBLOCKSIZE];
} polys[] = {
{
    8,
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B }
}, {
    16,
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 }
}
};

/**
   Initialize an OCB context
   @param ocb       [out] The destination of the OCB state
   @param cipher    The index of the desired cipher
   @param key       The secret key
   @param keylen    The length of the secret key (octets)
   @param nonce     The session nonce
   @param noncelen  The length of the session nonce (octets)
   @return CRYPT_OK if successful
*/
int ocb3_init(ocb3_state *ocb, int cipher,
             const unsigned char *key, unsigned long keylen,
             const unsigned char *nonce, unsigned long noncelen,
             unsigned long taglen)
{
   int poly, x, y, m, err;
   unsigned char *previous, *current;

   LTC_ARGCHK(ocb   != NULL);
   LTC_ARGCHK(key   != NULL);
   LTC_ARGCHK(nonce != NULL);

   /* valid cipher? */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }
   ocb->cipher = cipher;

   /* Valid Nonce?
    * As of RFC7253: "string of no more than 120 bits" */
   if (noncelen > (120/8)) {
      return CRYPT_INVALID_ARG;
   }

   /* Make sure taglen isn't too long */
   if (taglen > (unsigned long)cipher_descriptor[cipher].block_length) {
      taglen = cipher_descriptor[cipher].block_length;
   }

   /* determine which polys to use */
   ocb->block_len = cipher_descriptor[cipher].block_length;
   x = (int)(sizeof(polys)/sizeof(polys[0]));
   for (poly = 0; poly < x; poly++) {
       if (polys[poly].len == ocb->block_len) {
          break;
       }
   }
   if (poly == x) {
      return CRYPT_INVALID_ARG; /* block_len not found in polys */
   }
   if (polys[poly].len != ocb->block_len) {
      return CRYPT_INVALID_ARG;
   }

   /* schedule the key */
   if ((err = cipher_descriptor[cipher].setup(key, keylen, 0, &ocb->key)) != CRYPT_OK) {
      return err;
   }

   /* L_* = ENCIPHER(K, zeros(128)) */
   zeromem(ocb->L_star, ocb->block_len);
   if ((err = cipher_descriptor[cipher].ecb_encrypt(ocb->L_star, ocb->L_star, &ocb->key)) != CRYPT_OK) {
      return err;
   }

   /* compute L_$, L_0, L_1, ... */
   for (x = -1; x < 32; x++) {
      if (x == -1) {                /* gonna compute: L_$ = double(L_*) */
         current  = ocb->L_dollar;
         previous = ocb->L_star;
      }
      else if (x == 0) {            /* gonna compute: L_0 = double(L_$) */
         current  = ocb->L_[0];
         previous = ocb->L_dollar;
      }
      else {                        /* gonna compute: L_i = double(L_{i-1}) for every integer i > 0 */
         current  = ocb->L_[x];
         previous = ocb->L_[x-1];
      }
      m = previous[0] >> 7;
      for (y = 0; y < ocb->block_len-1; y++) {
         current[y] = ((previous[y] << 1) | (previous[y+1] >> 7)) & 255;
      }
      current[ocb->block_len-1] = (previous[ocb->block_len-1] << 1) & 255;
      if (m == 1) {
         /* current[] = current[] XOR polys[poly].poly_mul[]*/
         ocb3_int_xor_blocks(current, current, polys[poly].poly_mul, ocb->block_len);
      }
   }

   /* initialize ocb->Offset_current = Offset_0 */
   ocb3_int_calc_offset_zero(ocb, nonce, noncelen, taglen);

   /* initialize checksum to all zeros */
   zeromem(ocb->checksum, ocb->block_len);

   /* set block index */
   ocb->block_index = 1;

   /* initialize AAD related stuff */
   ocb->ablock_index = 1;
   ocb->adata_buffer_bytes = 0;
   zeromem(ocb->aOffset_current, ocb->block_len);
   zeromem(ocb->aSum_current, ocb->block_len);

   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
