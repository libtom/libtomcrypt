#ifndef CRYPT_H_
#define CRYPT_H_
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

/* version */
#define CRYPT   0x0076
#define SCRYPT  "0.76"

/* max size of either a cipher/hash block or symmetric key [largest of the two] */
#define MAXBLOCKSIZE           128

/* error codes [will be expanded in future releases] */
enum {
   CRYPT_OK=0,
   CRYPT_ERROR,

   CRYPT_INVALID_KEYSIZE,
   CRYPT_INVALID_ROUNDS,
   CRYPT_FAIL_TESTVECTOR,

   CRYPT_BUFFER_OVERFLOW,
   CRYPT_INVALID_PACKET,

   CRYPT_INVALID_PRNGSIZE,
   CRYPT_ERROR_READPRNG,

   CRYPT_INVALID_CIPHER,
   CRYPT_INVALID_HASH,
   CRYPT_INVALID_PRNG,

   CRYPT_MEM,

   CRYPT_PK_TYPE_MISMATCH,
   CRYPT_PK_NOT_PRIVATE,

   CRYPT_INVALID_ARG,

   CRYPT_PK_INVALID_TYPE,
   CRYPT_PK_INVALID_SYSTEM,
   CRYPT_PK_DUP,
   CRYPT_PK_NOT_FOUND,
   CRYPT_PK_INVALID_SIZE,

   CRYPT_INVALID_PRIME_SIZE
};

#include <mycrypt_cfg.h>
#include <mycrypt_macros.h>
#include <mycrypt_cipher.h>
#include <mycrypt_hash.h>
#include <mycrypt_prng.h>
#include <mycrypt_pk.h>
#include <mycrypt_gf.h>
#include <mycrypt_misc.h>
#include <mycrypt_kr.h>

#include <mycrypt_argchk.h>


#ifdef __cplusplus
   }
#endif

#endif /* CRYPT_H_ */

