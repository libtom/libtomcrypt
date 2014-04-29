/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt.h"

/**
  @file hkdf_test.c
  PKCS #5 support, self-test, Steffen Jaeckel
*/

#ifdef LTC_PKCS_5

/*
    TEST CASES SOURCE:

Internet Engineering Task Force (IETF)                      S. Josefsson
Request for Comments: 6070                                        SJD AB
Category: Informational                                     January 2011
ISSN: 2070-1721
*/

/**
  PKCS #5 self-test
  @return CRYPT_OK if successful, CRYPT_NOP if tests have been disabled.
*/
int pkcs_5_test (void)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else

    static const struct {
        char* P;
        unsigned long P_len;
        char* S;
        unsigned long S_len;
        int c;
        unsigned long dkLen;
        unsigned char DK[25];
    } cases_5_2[] = {
        {
            "password",
            8,
            "salt",
            4,
            1,
            20,
            { 0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
              0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
              0x2f, 0xe0, 0x37, 0xa6 }
        },
        {
            "password",
            8,
            "salt",
            4,
            2,
            20,
            { 0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
              0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
              0xd8, 0xde, 0x89, 0x57 }
        },
#ifdef LTC_TEST_EXT
        {
            "password",
            8,
            "salt",
            4,
            4096,
            20,
            { 0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
              0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
              0x65, 0xa4, 0x29, 0xc1 }
        },
        {
            "password",
            8,
            "salt",
            4,
            16777216,
            20,
            { 0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4,
              0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c,
              0x26, 0x34, 0xe9, 0x84 }
        },
        {
            "passwordPASSWORDpassword",
            25,
            "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            36,
            4096,
            25,
            { 0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
              0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
              0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
              0x38 }
        },
        {
            "pass\0word",
            9,
            "sa\0lt",
            5,
            4096,
            16,
            { 0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
              0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3 }
        },
#endif /* LTC_TEST_EXT */
    };

    unsigned char DK[25];
    unsigned long dkLen;
    int i, err;
    int tested=0, failed=0;
    int hash = find_hash("sha1");
    if (hash == -1)
    {
#ifdef LTC_PKCS_5_TEST_DBG
      printf("PKCS#5 test: 'sha1' hash not found\n");
#endif
      return CRYPT_ERROR;
    }
    for(i=0; i < (int)(sizeof(cases_5_2) / sizeof(cases_5_2[0])); i++) {
        ++tested;
        dkLen = cases_5_2[i].dkLen;
        if((err = pkcs_5_alg2((unsigned char*)cases_5_2[i].P, cases_5_2[i].P_len,
                              (unsigned char*)cases_5_2[i].S, cases_5_2[i].S_len,
                              cases_5_2[i].c, hash,
                              DK, &dkLen)) != CRYPT_OK) {
#ifdef LTC_PKCS_5_TEST_DBG
            printf("PKCS#5 test #%d: %s\n", i, error_to_string(err));
#endif
            return err;
        }

        if (dkLen != cases_5_2[i].dkLen)
        {
#ifdef LTC_PKCS_5_TEST_DBG
          printf("PKCS#5 test #%d: %lu != %lu\n", i, dkLen, cases_5_2[i].dkLen);
#endif
          return CRYPT_FAIL_TESTVECTOR;
        }

        if(XMEMCMP(DK, cases_5_2[i].DK, (size_t)cases_5_2[i].dkLen) != 0)  {
            ++failed;
#ifdef LTC_PKCS_5_TEST_DBG
          {
            unsigned int j;
            printf("\nPKCS#5 test #%d:\n", i);
            printf(  "Result:  0x");
            for(j=0; j < cases_5_2[i].dkLen; j++) {
                printf("%02x ", DK[j]);
            }
            printf("\nCorrect: 0x");
            for(j=0; j < cases_5_2[i].dkLen; j++) {
               printf("%02x ", cases_5_2[i].DK[j]);
            }
            printf("\n");
            return CRYPT_FAIL_TESTVECTOR;
          }
#endif
#ifdef LTC_PKCS_5_TEST_DBG
        } else {
            printf("PKCS#5 test #%d: Passed\n", i);
#endif
        }
    }

    if (failed != 0) {
        return CRYPT_FAIL_TESTVECTOR;
    } else {
        return CRYPT_OK;
    }
 #endif
}

#endif


/* $Source$ */
/* $Revision$ */
/* $Date$ */
