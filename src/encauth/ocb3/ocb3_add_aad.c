/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/**
   @file ocb3_add_aad.c
   OCB implementation, add AAD data, by Karel Miko
*/
#include "tomcrypt.h"

#ifdef LTC_OCB3_MODE

/**
   Add AAD - additional associated data
   @param ocb       The OCB state
   @param aad       The AAD data
   @param aadlen    The size of AAD data (octets)
   @return CRYPT_OK if successful
*/
int ocb3_add_aad(ocb3_state *ocb, const unsigned char *aad, unsigned long aadlen)
{
   int err, x, full_blocks, full_blocks_len, last_block_len;
   unsigned char *data;
   unsigned long datalen, l;

   LTC_ARGCHK(ocb    != NULL);
   LTC_ARGCHK(aad    != NULL);

   if (aadlen == 0) return CRYPT_OK;

   if (ocb->adata_buffer_bytes > 0) {
     l = ocb->block_len - ocb->adata_buffer_bytes;
     if (l > aadlen) l = aadlen;
     XMEMCPY(ocb->adata_buffer+ocb->adata_buffer_bytes, aad, l);
     ocb->adata_buffer_bytes += l;

     if (ocb->adata_buffer_bytes == ocb->block_len) {
       if ((err = ocb3_int_aad_add_block(ocb, ocb->adata_buffer)) != CRYPT_OK) {
         return err;
       }
       ocb->adata_buffer_bytes = 0;
     }

     data = (unsigned char *)aad + l;
     datalen = aadlen - l;
   }
   else {
     data = (unsigned char *)aad;
     datalen = aadlen;
   }

   if (datalen == 0) return CRYPT_OK;

   full_blocks = datalen/ocb->block_len;
   full_blocks_len = full_blocks * ocb->block_len;
   last_block_len = datalen - full_blocks_len;

   for (x=0; x<full_blocks; x++) {
     if ((err = ocb3_int_aad_add_block(ocb, data+x*ocb->block_len)) != CRYPT_OK) {
       return err;
     }
   }

   if (last_block_len>0) {
     XMEMCPY(ocb->adata_buffer, data+full_blocks_len, last_block_len);
     ocb->adata_buffer_bytes = last_block_len;
   }

   return CRYPT_OK;
}

#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
