/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_BLAKE2SMAC

int blake2smac_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   unsigned char k[]   = { 0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b };
   unsigned char tag[] = { 0x96, 0x32, 0xf9, 0x85, 0xf3, 0x30, 0xd6, 0x8c, 0x21, 0x78, 0x6e, 0xae, 0xb4, 0x99, 0xba, 0xbb };
   char m[] = "Cryptographic Forum Research Group";
   unsigned long len = 16, mlen = strlen(m);
   unsigned char out[1000];
   blake2smac_state st;
   /* process piece by piece */
   blake2smac_init(&st,16,  k, 32);
   blake2smac_process(&st, (unsigned char*)m,      5);
   blake2smac_process(&st, (unsigned char*)m + 5,  4);
   blake2smac_process(&st, (unsigned char*)m + 9,  3);
   blake2smac_process(&st, (unsigned char*)m + 12, 2);
   blake2smac_process(&st, (unsigned char*)m + 14, 1);
   blake2smac_process(&st, (unsigned char*)m + 15, mlen - 15);
   blake2smac_done(&st, out, &len);
   if (compare_testvector(out, len, tag, sizeof(tag), "BLAKE2S MAC-TV1", 1) != 0) return CRYPT_FAIL_TESTVECTOR;
   /* process in one go */
   blake2smac_init(&st, 16, k, 32);
   blake2smac_process(&st, (unsigned char*)m, mlen);
   blake2smac_done(&st, out, &len);
   if (compare_testvector(out, len, tag, sizeof(tag), "BLAKE2S MAC-TV2", 1) != 0) return CRYPT_FAIL_TESTVECTOR;
   return CRYPT_OK;
#endif
}

#endif
