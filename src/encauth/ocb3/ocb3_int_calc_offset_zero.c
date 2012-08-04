/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/**
   @file ocb3_int_calc_offset_zero.c
   OCB implementation, INTERNAL ONLY helper, by Karel Miko
*/
#include "tomcrypt.h"

#ifdef LTC_OCB3_MODE

/**
   Sets 'ocb->Offset_current' to 'Offset_0' value (internal function)
   @param ocb       The OCB state
   @param nonce     The session nonce
   @param noncelen  The length of the session nonce (octets)
*/
void ocb3_int_calc_offset_zero(ocb3_state *ocb, const unsigned char *nonce, unsigned long noncelen)
{
   int x, y, bottom;
   int idx, shift;
   unsigned char iNonce[MAXBLOCKSIZE];
   unsigned char iKtop[MAXBLOCKSIZE];
   unsigned char iStretch[MAXBLOCKSIZE+8];

   /* Nonce = zeros(127-bitlen(N)) || 1 || N          */
   zeromem(iNonce, sizeof(iNonce));
   for (x = ocb->block_len-1, y=0; y<(int)noncelen; x--, y++) {
     iNonce[x] = nonce[noncelen-y-1];
   }
   iNonce[x] = 0x01;

   /* bottom = str2num(Nonce[123..128])               */
   bottom = iNonce[ocb->block_len-1] & 0x3F;

   /* Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6))   */
   iNonce[ocb->block_len-1] = iNonce[ocb->block_len-1] & 0xC0;
   if ((cipher_descriptor[ocb->cipher].ecb_encrypt(iNonce, iKtop, &ocb->key)) != CRYPT_OK) {
      zeromem(ocb->Offset_current, ocb->block_len);
      return;
   }

   /* Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]) */
   for (x = 0; x < ocb->block_len; x++) {
     iStretch[x] = iKtop[x];
   }
   for (y = 0; y < 8; y++) {
     iStretch[x+y] = iKtop[y] ^ iKtop[y+1];
   }

   /* Offset_0 = Stretch[1+bottom..128+bottom]        */
   idx = bottom / 8;
   shift = (bottom % 8);
   for (x = 0; x < ocb->block_len; x++) {
      ocb->Offset_current[x] = iStretch[idx+x] << shift;
      if (shift > 0) {
        ocb->Offset_current[x] |= iStretch[idx+x+1] >> (8-shift);
      }
   }
}

#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
