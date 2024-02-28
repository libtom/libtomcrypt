/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#include "tomcrypt_private.h"

#ifdef LTC_CHACHA

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with ChaCha
   @param key     The key
   @param keylen  The key length
   @param rounds  The number of rounds
   @param iv      The initial vector
   @param ivlen   The initial vector length
   @param counter initial counter value, either ignored, 32- or 64-bit, depending on ivlen
   @param datain  The plaintext (or ciphertext)
   @param datalen The length of the input and output (octets)
   @param dataout [out] The ciphertext (or plaintext)
   @return CRYPT_OK if successful
*/
int chacha_memory(const unsigned char *key,    unsigned long keylen,  unsigned long rounds,
                  const unsigned char *iv,     unsigned long ivlen,   ulong64 counter,
                  const unsigned char *datain, unsigned long datalen, unsigned char *dataout)
{
   chacha_state st;
   int err;
   const unsigned char *iv_ = iv;
   unsigned long ivlen_ = ivlen;
   ulong64 counter_ = counter;

   if (ivlen == 16) {
      LOAD64L(counter_, iv);
      iv_ += 8;
      ivlen_ -=8;
   }

   LTC_ARGCHK(ivlen_ <= 8 || counter_ < CONST64(4294967296));       /* 2**32 */

   if ((err = chacha_setup(&st, key, keylen, rounds))       != CRYPT_OK) goto WIPE_KEY;
   if (ivlen_ > 8) {
        if ((err = chacha_ivctr32(&st, iv_, ivlen_, (ulong32)counter_)) != CRYPT_OK) goto WIPE_KEY;
   } else {
        if ((err = chacha_ivctr64(&st, iv_, ivlen_, counter_)) != CRYPT_OK) goto WIPE_KEY;
   }
   err = chacha_crypt(&st, datain, datalen, dataout);
WIPE_KEY:
   chacha_done(&st);
   return err;
}

#endif /* LTC_CHACHA */
