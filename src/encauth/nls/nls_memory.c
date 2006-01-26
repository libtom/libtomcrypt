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

/**
  @file nls_memory.c
  NLS support, process a block of memory, Tom St Denis
*/

#ifdef NLS_MODE

int nls_memory(const unsigned char *key,    unsigned long keylen,
               const unsigned char *IV,     unsigned long IVlen,
               const unsigned char *adata,  unsigned long adatalen,
                     unsigned char *pt,     unsigned long ptlen,
                     unsigned char *ct, 
                     unsigned char *tag,    unsigned long taglen,
                               int direction)
{
   nls_state *nls;
   int        err;

   LTC_ARGCHK(key   != NULL);
   LTC_ARGCHK(IV    != NULL);
   if (adatalen > 0) {
      LTC_ARGCHK(adata != NULL);
   }      
   LTC_ARGCHK(pt    != NULL);
   LTC_ARGCHK(ct    != NULL);
   if (taglen > 0) {
      LTC_ARGCHK(tag   != NULL);
   }      
   
   /* alloc NLS state */
   nls = XCALLOC(1, sizeof(*nls));
   if (nls == NULL) {
      return CRYPT_MEM;
   }
   
   /* init key and IV */
   if ((err = nls_key(nls, key, keylen)) != CRYPT_OK) {
      goto done;
   }
   if ((err = nls_nonce(nls, IV, IVlen)) != CRYPT_OK) {
      goto done;
   }
   
   /* process adata */
   if (adatalen > 0) {
      if ((err = nls_maconly(nls, adata, adatalen)) != CRYPT_OK) {
         goto done;
      }
   }      
   
   /* process msg */
   if (direction == NLS_ENCRYPT) {
      if ((err = nls_encrypt(nls, pt, nbytes, ct)) != CRYPT_OK) {
         goto done;
      }
   } else {      
      if ((err = nls_decrypt(nls, ct, nbytes, pt)) != CRYPT_OK) {
         goto done;
      }
   }      
   
   /* grab tag */
   if (taglen > 0) {
      if ((err = nls_finish(nls, tag, taglen)) != CRYPT_OK) {
         goto done;
      }
   }
   
   err = CRYPT_OK;
done:
#ifdef LTC_CLEAN_STACK
   zeromem(nls, sizeof(*nls));
#endif
   XFREE(nls);
   
   return err;
}                     

#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
