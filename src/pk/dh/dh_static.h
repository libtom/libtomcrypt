#ifndef __DH_STATIC_H__
#define __DH_STATIC_H__
#ifndef __DECL_DH_STATIC_H__
#define __DECL_DH_STATIC_H__ extern
#endif

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
#include "tomcrypt.h"

/**
  @file dh_static.h
  DH crypto, Tom St Denis
*/

#ifdef LTC_MDH

/* size of a packet header in bytes */
#define PACKET_SIZE            4

/* Section tags */
#define PACKET_SECT_DH         1

/* Subsection Tags for the first three sections */
#define PACKET_SUB_KEY         0
#define PACKET_SUB_ENCRYPTED   1
#define PACKET_SUB_SIGNED      2
#define PACKET_SUB_ENC_KEY     3

#define OUTPUT_BIGNUM(num, out, y, z)                                                             \
{                                                                                                 \
      if ((y + 4) > *outlen) { return CRYPT_BUFFER_OVERFLOW; }                                    \
      z = (unsigned long)mp_unsigned_bin_size(num);                                               \
      STORE32L(z, out+y);                                                                         \
      y += 4;                                                                                     \
      if ((y + z) > *outlen) { return CRYPT_BUFFER_OVERFLOW; }                                    \
      if ((err = mp_to_unsigned_bin(num, out+y)) != CRYPT_OK) { return err; }    \
      y += z;                                                                                     \
}

#define INPUT_BIGNUM(num, in, x, y, inlen)                       \
{                                                                \
     /* load value */                                            \
     if ((y + 4) > inlen) {                                      \
        err = CRYPT_INVALID_PACKET;                              \
        goto error;                                              \
     }                                                           \
     LOAD32L(x, in+y);                                           \
     y += 4;                                                     \
                                                                 \
     /* sanity check... */                                       \
     if ((x+y) > inlen) {                                        \
        err = CRYPT_INVALID_PACKET;                              \
        goto error;                                              \
     }                                                           \
                                                                 \
     /* load it */                                               \
     if ((err = mp_read_unsigned_bin(num, (unsigned char *)in+y, (int)x)) != CRYPT_OK) {\
        goto error;                                              \
     }                                                           \
     y += x;                                                     \
}

static LTC_INLINE void packet_store_header (unsigned char *dst, int section, int subsection)
{
   LTC_ARGCHKVD(dst != NULL);

   /* store version number */
   dst[0] = (unsigned char)(CRYPT&255);
   dst[1] = (unsigned char)((CRYPT>>8)&255);

   /* store section and subsection */
   dst[2] = (unsigned char)(section & 255);
   dst[3] = (unsigned char)(subsection & 255);

}

static LTC_INLINE int packet_valid_header (unsigned char *src, int section, int subsection)
{
   unsigned long ver;

   LTC_ARGCHK(src != NULL);

   /* check version */
   ver = ((unsigned long)src[0]) | ((unsigned long)src[1] << 8U);
   if (CRYPT < ver) {
      return CRYPT_INVALID_PACKET;
   }

   /* check section and subsection */
   if (section != (int)src[2] || subsection != (int)src[3]) {
      return CRYPT_INVALID_PACKET;
   }

   return CRYPT_OK;
}

#ifndef DH_BUF_SIZE
/* max export size we'll encounter (smaller than this but lets round up a bit) */
#define DH_BUF_SIZE 1200
#endif /* DH_BUF_SIZE */

typedef struct {
  int size;
  char *name, *base, *prime;
} dh_set;

/* This holds the key settings.  ***MUST*** be organized by size from smallest to largest. */
__DECL_DH_STATIC_H__ const dh_set sets[];


int dh_is_valid_idx(int n);


#endif /* __DH_STATIC_H__ */

#endif /* LTC_MDH */
