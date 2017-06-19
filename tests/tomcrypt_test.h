
#ifndef __TEST_H_
#define __TEST_H_

#include <tomcrypt.h>

#include "common.h"

#ifdef USE_LTM
/* Use libtommath as MPI provider */
#elif defined(USE_TFM)
/* Use tomsfastmath as MPI provider */
#elif defined(USE_GMP)
/* Use GNU Multiple Precision Arithmetic Library as MPI provider */
#else
/* The user must define his own MPI provider! */
#ifndef EXT_MATH_LIB
/*
 * Yes, you're right, you could also name your instance of the MPI provider
 * "EXT_MATH_LIB" and you wouldn't need to define it, but most users won't do
 * this and so it's treated as an error and you have to comment out the
 * following statement :)
 */
#error EXT_MATH_LIB is required to be defined
#endif
#endif

typedef struct {
    char *name, *prov, *req;
    int  (*entry)(void);
} test_entry;

/* TESTS */
int cipher_hash_test(void);
int modes_test(void);
int mac_test(void);
int pkcs_1_test(void);
int pkcs_1_pss_test(void);
int pkcs_1_oaep_test(void);
int pkcs_1_emsa_test(void);
int pkcs_1_eme_test(void);
int store_test(void);
int rotate_test(void);
int rsa_test(void);
int dh_test(void);
int katja_test(void);
int ecc_tests(void);
int dsa_test(void);
int der_test(void);
int misc_test(void);
int base64_test(void);
int file_test(void);
int multi_test(void);
int prng_test(void);

#ifdef LTC_PKCS_1
struct ltc_prng_descriptor* no_prng_desc_get(void);
void no_prng_desc_free(struct ltc_prng_descriptor*);
#endif

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
