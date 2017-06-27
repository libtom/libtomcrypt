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
   @file radix_to_bin.c
   Convert an MPI from a specific radix to binary data.
   Steffen Jaeckel
*/

/**
   Convert an MPI from a specific radix to binary data

   @param in    The input
   @param radix The radix of the input
   @param out   The output buffer
   @param len   [in/out] The length of the output buffer

   @return CRYPT_OK on success.
*/
int radix_to_bin(const void *in, int radix, void *out, size_t* len)
{
   size_t l;
   void* mpi;
   int err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(len != NULL);

   if ((err = mp_init(&mpi)) != CRYPT_OK) return err;
   if ((err = mp_read_radix(mpi, in, radix)) != CRYPT_OK) goto LBL_ERR;

   if ((l = mp_unsigned_bin_size(mpi)) > *len) {
      *len = l;
      err = CRYPT_BUFFER_OVERFLOW;
      goto LBL_ERR;
   }
   *len = l;

   if ((err = mp_to_unsigned_bin(mpi, out)) != CRYPT_OK) goto LBL_ERR;

LBL_ERR:
   mp_clear(mpi);
   return err;
}

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
