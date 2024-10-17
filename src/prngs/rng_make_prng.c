/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_RNG_MAKE_PRNG
/**
  @file rng_make_prng.c
  portable way to get secure random bits to feed a PRNG  (Tom St Denis)
*/

/**
  Create a PRNG from a RNG

     In case you pass bits as '-1' the PRNG will be setup
     as if the export/import functionality has been used,
     but the imported data comes directly from the RNG.

  @param bits     Number of bits of entropy desired (-1 or 64 ... 1024)
  @param prng     [out] PRNG state to initialize
  @param callback A pointer to a void function for when the RNG is slow, this can be NULL
  @return CRYPT_OK if successful
*/
int rng_make_prng(int bits, prng_state *prng,
                  void (*callback)(void))
{
   int (*import_entropy)(const unsigned char*, unsigned long, prng_state*);
   unsigned char* buf;
   unsigned long bytes;
   int err;

   LTC_ARGCHK(prng != NULL);

   if (bits == -1) {
      bytes = prng->desc.export_size;
      import_entropy = prng->desc.pimport;
   } else if (bits < 64 || bits > 1024) {
      return CRYPT_INVALID_PRNGSIZE;
   } else {
      bytes = (unsigned long)((bits+7)/8) * 2;
      import_entropy = prng->desc.add_entropy;
   }

   buf = XMALLOC(bytes);
   if (buf == NULL) {
      return CRYPT_MEM;
   }

   if (rng_get_bytes(buf, bytes, callback) != bytes) {
      err = CRYPT_ERROR_READPRNG;
      goto LBL_ERR;
   }

   if ((err = import_entropy(buf, bytes, prng)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = prng->desc.ready(prng)) != CRYPT_OK) {
      goto LBL_ERR;
   }

LBL_ERR:
   #ifdef LTC_CLEAN_STACK
   zeromem(buf, bytes);
   #endif
   XFREE(buf);
   return err;
}
#endif /* #ifdef LTC_RNG_MAKE_PRNG */

