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
   @file base16_decode.c
   Base16/Hex decode a string.
   Based on https://stackoverflow.com/a/23898449
   Adapted for libtomcrypt by Steffen Jaeckel
*/

#ifdef LTC_BASE16

/**
   Base16 decode a string
   @param in       The Base16 string to decode
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @return CRYPT_OK if successful
*/
int base16_decode(const          char *in,
                        unsigned char *out, unsigned long *outlen)
{
   unsigned long pos, in_len, out_len;
   unsigned char idx0;
   unsigned char idx1;

   const unsigned char hashmap[] = {
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* 01234567 */
         0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 89:;<=>? */
         0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, /* @ABCDEFG */
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* HIJKLMNO */
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* PQRSTUVW */
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* XYZ[\]^_ */
         0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, /* `abcdefg */
   };

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   in_len = strlen(in);
   if ((in_len % 2) == 1) return CRYPT_INVALID_PACKET;
   out_len = *outlen * 2;
   for (pos = 0; ((pos + 1 < out_len) && (pos + 1 < in_len)); pos += 2) {
      idx0 = (unsigned char) (in[pos + 0] & 0x1F) ^ 0x10;
      idx1 = (unsigned char) (in[pos + 1] & 0x1F) ^ 0x10;
      out[pos / 2] = (unsigned char) (hashmap[idx0] << 4) | hashmap[idx1];
   }
   *outlen = pos / 2;
   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
