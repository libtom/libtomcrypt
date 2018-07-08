/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

#ifdef LTC_DER

typedef struct {
   int pka;
   const char* oid;
} pka_oid;

static const pka_oid oids[] = {
                               { PKA_RSA, "1.2.840.113549.1.1.1" },
                               { PKA_DSA, "1.2.840.10040.4.1" },
                               { PKA_EC, "1.2.840.10045.2.1" },
                               { PKA_EC_PRIMEF, "1.2.840.10045.1.1" },
};

/*
   Returns the OID of the public key algorithm.
   @return CRYPT_OK if valid
*/
int pk_get_oid(int pk, const char **st)
{
   unsigned int i;
   LTC_ARGCHK(st != NULL);
   for (i = 0; i < sizeof(oids)/sizeof(oids[0]); ++i) {
      if (oids[i].pka == pk) {
         *st = oids[i].oid;
         return CRYPT_OK;
      }
   }
   return CRYPT_INVALID_ARG;
}
#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
