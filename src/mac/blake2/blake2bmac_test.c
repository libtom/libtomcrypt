/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_BLAKE2BMAC

int blake2bmac_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   unsigned char k[]   = { 0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b };
   unsigned char tag[] = { 0x3d, 0xd6, 0x35, 0x81, 0x32, 0xb5, 0x3c, 0xc8, 0x0a, 0x8c, 0x33, 0x91, 0x93, 0x5d, 0x30, 0x1b };
   char m[] = "Cryptographic Forum Research Group";
   unsigned long len = 16, mlen = strlen(m);
   unsigned char out[1000];
   blake2bmac_state st;
   /* process piece by piece */
   blake2bmac_init(&st, 16, k, 32);
   blake2bmac_process(&st, (unsigned char*)m,      5);
   blake2bmac_process(&st, (unsigned char*)m + 5,  4);
   blake2bmac_process(&st, (unsigned char*)m + 9,  3);
   blake2bmac_process(&st, (unsigned char*)m + 12, 2);
   blake2bmac_process(&st, (unsigned char*)m + 14, 1);
   blake2bmac_process(&st, (unsigned char*)m + 15, mlen - 15);
   blake2bmac_done(&st, out, &len);
   if (compare_testvector(out, len, tag, sizeof(tag), "BLAKE2B MAC-TV1", 1) != 0) return CRYPT_FAIL_TESTVECTOR;
   /* process in one go */
   blake2bmac_init(&st, 16, k, 32);
   blake2bmac_process(&st, (unsigned char*)m, mlen);
   blake2bmac_done(&st, out, &len);
   if (compare_testvector(out, len, tag, sizeof(tag), "BLAKE2B MAC-TV2", 1) != 0) return CRYPT_FAIL_TESTVECTOR;
   return CRYPT_OK;
#endif
}

#endif
