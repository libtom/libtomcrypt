/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt.h"

#ifdef LTC_DER
static const oid_st rsa_oid = {
   { 1, 2, 840, 113549, 1, 1, 1  },
   7,
};

static const oid_st dsa_oid = {
   { 1, 2, 840, 10040, 4, 1  },
   6,
};

static const oid_st ec_oid = {
   { 1, 2, 840, 10045, 2, 1 },
   6,
};

static const oid_st ec_primef = {
   { 1, 2, 840, 10045, 1, 1 },
   6,
};

/*
   Returns the OID of the public key algorithm.
   @return CRYPT_OK if valid
*/
int pk_get_oid(int pk, oid_st *st)
{
   switch (pk) {
      case PKA_RSA:
         XMEMCPY(st, &rsa_oid, sizeof(*st));
         break;
      case PKA_DSA:
         XMEMCPY(st, &dsa_oid, sizeof(*st));
         break;
      case PKA_EC:
         XMEMCPY(st, &ec_oid, sizeof(*st));
         break;
      case EC_PRIME_FIELD:
         XMEMCPY(st, &ec_primef, sizeof(*st));
         break;
      default:
         return CRYPT_INVALID_ARG;
   }
   return CRYPT_OK;
}
#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
