/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
  @file der_encode_utctime.c
  ASN.1 DER, encode a GeneralizedTime, Steffen Jaeckel
  Based on der_encode_utctime.c
*/

#ifdef LTC_DER

static const char * const baseten = "0123456789";

#define STORE_V(y) do {\
    out[x++] = der_ia5_char_encode(baseten[(y/10) % 10]); \
    out[x++] = der_ia5_char_encode(baseten[y % 10]); \
} while(0)

#define STORE_V4(y) do {\
    out[x++] = der_ia5_char_encode(baseten[(y/1000) % 10]); \
    out[x++] = der_ia5_char_encode(baseten[(y/100) % 10]); \
    out[x++] = der_ia5_char_encode(baseten[(y/10) % 10]); \
    out[x++] = der_ia5_char_encode(baseten[y % 10]); \
} while(0)

/**
  Encodes a Generalized time structure in DER format
  @param utctime      The UTC time structure to encode
  @param out          The destination of the DER encoding of the UTC time structure
  @param outlen       [in/out] The length of the DER encoding
  @return CRYPT_OK if successful
*/
int der_encode_generalizedtime(ltc_generalizedtime *gtime,
                               unsigned char       *out,   unsigned long *outlen)
{
    unsigned long x, tmplen;
    int           err;

    LTC_ARGCHK(gtime != NULL);
    LTC_ARGCHK(out     != NULL);
    LTC_ARGCHK(outlen  != NULL);

    if ((err = der_length_generalizedtime(gtime, &tmplen)) != CRYPT_OK) {
       return err;
    }
    if (tmplen > *outlen) {
        *outlen = tmplen;
        return CRYPT_BUFFER_OVERFLOW;
    }

    /* store header */
    out[0] = 0x18;

    /* store values */
    x = 2;
    STORE_V4(gtime->YYYY);
    STORE_V(gtime->MM);
    STORE_V(gtime->DD);
    STORE_V(gtime->hh);
    STORE_V(gtime->mm);
    STORE_V(gtime->ss);

    if (gtime->fs) {
       unsigned long div;
       unsigned fs = gtime->fs;
       unsigned len = 0;
       out[x++] = der_ia5_char_encode('.');
       div = 1;
       do {
          fs /= 10;
          div *= 10;
          len++;
       } while(fs != 0);
       while (len-- > 1) {
          out[x++] = der_ia5_char_encode(baseten[(gtime->fs/div) % 10]);
          div /= 10;
       }
       out[x++] = der_ia5_char_encode(baseten[gtime->fs % 10]);
    }

    if (gtime->off_mm || gtime->off_hh) {
       out[x++] = der_ia5_char_encode(gtime->off_dir ? '-' : '+');
       STORE_V(gtime->off_hh);
       STORE_V(gtime->off_mm);
    } else {
       out[x++] = der_ia5_char_encode('Z');
    }

    /* store length */
    out[1] = (unsigned char)(x - 2);

    /* all good let's return */
    *outlen = x;
    return CRYPT_OK;
}

#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
