/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#ifndef TOMCRYPT_TEST_H_
#define TOMCRYPT_TEST_H_

#define _POSIX_C_SOURCE 200809L /* otherwise PATH_MAX + strdup are not defined for build with -std=c99 */
#include "tomcrypt_private.h"

#include "common.h"

typedef struct {
    char *name, *prov, *req;
    int  (*entry)(void);
} test_entry;

/* TESTS */
int cipher_hash_test(void);
int modes_test(void);
int mac_test(void);
int siv_wycheproof_test(void);
int pkcs_1_test(void);
int pkcs_1_pss_test(void);
int pkcs_1_oaep_test(void);
int pkcs_1_emsa_test(void);
int pkcs_1_eme_test(void);
int store_test(void);
int rotate_test(void);
int rsa_test(void);
int dh_test(void);
int ecc_test(void);
int ecc_sm2_test(void);
int dsa_test(void);
int der_test(void);
int misc_test(void);
int base64_test(void);
int base32_test(void);
int base16_test(void);
int file_test(void);
int multi_test(void);
int pem_test(void);
int prng_test(void);
int mpi_test(void);
int padding_test(void);
int x25519_test(void);
int x25519_mpi_test(void);
int x448_test(void);
int x448_mpi_test(void);
int ed25519_test(void);
int ed25519_mpi_test(void);
int ed448_test(void);
int ed448_mpi_test(void);
int ssh_test(void);
int argon2_test(void);
int bcrypt_test(void);
int scrypt_test(void);
int no_null_termination_check_test(void);
int pk_oid_test(void);
int deprecated_test(void);
int nop_test(void);

extern const char ltc_der_tests_cacert_root_cert[];
extern const unsigned long ltc_der_tests_cacert_root_cert_size;
extern const unsigned char ltc_openssl_public_rsa[];
extern const unsigned long ltc_openssl_public_rsa_sz;

#ifdef LTC_PKCS_1
struct ltc_prng_descriptor* no_prng_desc_get(void);
void no_prng_desc_free(struct ltc_prng_descriptor*);
#endif

#endif
