/* LibTomCrypt, modular cryptographic library
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 */
#include "tomcrypt.h"

static const oid_st rsa_oid = {
   { 1, 2, 840, 113549, 1, 1, 1  },
   7,
};

static const oid_st dsa_oid = {
   { 1, 2, 840, 10040, 4, 1  },
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
         memcpy(st, &rsa_oid, sizeof(*st));
         break;
      case PKA_DSA:
         memcpy(st, &dsa_oid, sizeof(*st));
         break;
      default:
         return CRYPT_INVALID_ARG;
   }
   return CRYPT_OK;
}
