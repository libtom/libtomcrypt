/* LTC_HKDF Header Info */

/* ===> LTC_HKDF -- RFC5869 HMAC-based Key Derivation Function <=== */
#ifdef LTC_HKDF

int hkdf_test(void);

int hkdf_extract(int hash_idx,
                 const unsigned char *salt, unsigned long saltlen,
                 const unsigned char *in,   unsigned long inlen,
                       unsigned char *out,  unsigned long *outlen);

int hkdf_expand(int hash_idx,
                const unsigned char *info, unsigned long infolen,
                const unsigned char *in,   unsigned long inlen,
                      unsigned char *out,  unsigned long outlen);

int hkdf(int hash_idx,
         const unsigned char *salt, unsigned long saltlen,
         const unsigned char *info, unsigned long infolen,
         const unsigned char *in,   unsigned long inlen,
               unsigned char *out,  unsigned long outlen);

#endif  /* LTC_HKDF */

/* $Source$ */
/* $Revision$ */
/* $Date$ */
