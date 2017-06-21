/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_MECC

static int _hexstrcmp(const char *hexa, const char *hexb)
{
  #define MY_TOLOWER(a) ((((a)>='A')&&((a)<='Z')) ? ((a)|0x60) : (a))
  /* ignore leading zeroes */
  while(*hexa == '0') hexa++;
  while(*hexb == '0') hexb++;
  /* compare: case insensitive, hexadecimal chars only */
  while (*hexa && *hexb) {
    if ( (*hexa < '0' || *hexa > '9') &&
         (*hexa < 'a' || *hexa > 'f') &&
         (*hexa < 'A' || *hexa > 'F') ) return 1;
    if ( (*hexb < '0' || *hexb > '9') &&
         (*hexb < 'a' || *hexb > 'f') &&
         (*hexb < 'A' || *hexb > 'F') ) return 1;
    if (MY_TOLOWER(*hexa) != MY_TOLOWER(*hexb)) return 1;
    hexa++;
    hexb++;
  }
  if (*hexa == '\0' && *hexb == '\0') return 0; /* success - match */
  return 1;
}

ltc_ecc_set_type* ecc_dp_find_by_params(char *hex_prime, char *hex_A, char *hex_B, char *hex_order, char *hex_Gx, char *hex_Gy, unsigned long cofactor)
{
   int i;

   if (!hex_prime || !hex_A || !hex_B || !hex_order || !hex_Gx || !hex_Gy) return NULL;

   for (i = 0; ltc_ecc_sets[i].size != 0; i++) {
      if (_hexstrcmp(ltc_ecc_sets[i].prime, hex_prime) == 0 &&
          _hexstrcmp(ltc_ecc_sets[i].A,     hex_A)     == 0 &&
          _hexstrcmp(ltc_ecc_sets[i].B,     hex_B)     == 0 &&
          _hexstrcmp(ltc_ecc_sets[i].order, hex_order) == 0 &&
          _hexstrcmp(ltc_ecc_sets[i].Gx,    hex_Gx)    == 0 &&
          _hexstrcmp(ltc_ecc_sets[i].Gy,    hex_Gy)    == 0 &&
          ltc_ecc_sets[i].cofactor == cofactor) {
         return (ltc_ecc_set_type*)&ltc_ecc_sets[i];
      }
   }
   return NULL;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
