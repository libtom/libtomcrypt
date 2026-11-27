/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/**
    @file eax_decrypt_verify_memory.c
    EAX implementation, decrypt block of memory, by Tom St Denis
*/
#include "tomcrypt_private.h"

#ifdef LTC_EAX_MODE

/**
   Decrypt a block of memory and verify the provided MAC tag with EAX
   @param cipher     The index of the cipher desired
   @param key        The secret key
   @param keylen     The length of the key (octets)
   @param nonce      The nonce data (use once) for the session
   @param noncelen   The length of the nonce data.
   @param header     The session header data
   @param headerlen  The length of the header (octets)
   @param ct         The ciphertext
   @param ctlen      The length of the ciphertext (octets)
   @param pt         [out] The plaintext
   @param tag        The authentication tag provided by the encoder
   @param taglen     [in/out] The length of the tag (octets)
   @param stat       [out] The result of the decryption (1==valid tag, 0==invalid)
   @return CRYPT_OK if successful regardless of the resulting tag comparison
*/
int eax_decrypt_verify_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  unsigned long noncelen,
    const unsigned char *header, unsigned long headerlen,
    const unsigned char *ct,     unsigned long ctlen,
          unsigned char *pt,
    const unsigned char *tag,    unsigned long taglen,
          int           *stat)
{
   int            err;
   eax_state     *eax;
   unsigned char  buf[MAXBLOCKSIZE];
   unsigned long  buflen;

   /* stat is cleared before anything else can return, it stays 0 unless the tag is good */
   LTC_ARGCHK(stat != NULL);
   *stat = 0;

   LTC_ARGCHK(key  != NULL);
   LTC_ARGCHK(pt   != NULL);
   LTC_ARGCHK(ct   != NULL);
   LTC_ARGCHK(tag  != NULL);

   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }
   /* NOTE: zero-length tag is legal (it just provides no authenticity) */
   if (taglen > (unsigned long)cipher_descriptor[cipher].block_length) {
      return CRYPT_INVALID_ARG;
   }

   eax = XMALLOC(sizeof(*eax));
   if (eax == NULL) {
      return CRYPT_MEM;
   }

   if ((err = eax_init(eax, cipher, key, keylen, nonce, noncelen, header, headerlen)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   if ((err = eax_decrypt(eax, ct, pt, ctlen)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   buflen = taglen;
   if ((err = eax_done(eax, buf, &buflen)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* compare tags */
   if (buflen >= taglen && XMEM_NEQ(buf, tag, taglen) == 0) {
      *stat = 1;
   }

   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(buf, sizeof(buf));
   zeromem(eax, sizeof(*eax));
#endif

   XFREE(eax);

   return err;
}

#endif
