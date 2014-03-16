/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/**
   @file ocb3_int_aad_add_block.c
   OCB implementation, INTERNALL ONLY helper, by Karel Miko
*/
#include "tomcrypt.h"

#ifdef LTC_OCB3_MODE

/**
   Add one block of AAD data (internal function)
   @param ocb        The OCB state
   @param aad_block  [in] AAD data (block_len size)
   @return CRYPT_OK if successful
*/
int ocb3_int_aad_add_block(ocb3_state *ocb, const unsigned char *aad_block)
{
   unsigned char tmp[MAXBLOCKSIZE];
   int err;

   /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
   ocb3_int_xor_blocks(ocb->aOffset_current, ocb->aOffset_current, ocb->L_[ocb3_int_ntz(ocb->ablock_index)], ocb->block_len);

   /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i) */
   ocb3_int_xor_blocks(tmp, aad_block, ocb->aOffset_current, ocb->block_len);
   if ((err = cipher_descriptor[ocb->cipher].ecb_encrypt(tmp, tmp, &ocb->key)) != CRYPT_OK) {
     return err;
   }
   ocb3_int_xor_blocks(ocb->aSum_current, ocb->aSum_current, tmp, ocb->block_len);

   ocb->ablock_index++;

   return CRYPT_OK;
}

#endif


/* $Source$ */
/* $Revision$ */
/* $Date$ */
