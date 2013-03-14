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
  LTC_HKDF support, self-test, Steffen Jaeckel
*/

#ifdef LTC_HKDF

/*
    TEST CASES SOURCE:

Internet Engineering Task Force (IETF)                       H. Krawczyk
Request for Comments: 5869                                  IBM Research
Category: Informational                                        P. Eronen
ISSN: 2070-1721                                                    Nokia
                                                                May 2010
Appendix A. Test Vectors
*/

/**
  LTC_HKDF self-test
  @return CRYPT_OK if successful, CRYPT_NOP if tests have been disabled.
*/
int hkdf_test(void)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else
    unsigned char OKM[82];
    int i;

    static const struct hkdf_test_case {
        char* Hash;
        unsigned char IKM[80];
        unsigned long IKM_l;
        unsigned char salt[80];
        unsigned long salt_l;
        unsigned char info[80];
        unsigned long info_l;
        unsigned long L;
        unsigned char PRK[32];
        unsigned char OKM[82];
    } cases[] = {
#ifdef LTC_SHA256
        /*
           Basic test case with SHA-256

           Hash = SHA-256
           IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
           salt = 0x000102030405060708090a0b0c (13 octets)
           info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
           L    = 42

           PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
                  90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
           OKM  = 0x3cb25f25faacd57a90434f64d0362f2a
                  2d2d0a90cf1a5a4c5db02d56ecc4c5bf
                  34007208d5b887185865 (42 octets)
        */

           { "sha256",
            {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
             0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
             0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b}, 22,
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c}, 13,
            {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
             0xf8, 0xf9}, 10,
             42,
            {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
             0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
             0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
             0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5},
            {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
             0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
             0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
             0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
             0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
             0x58, 0x65} }
#endif /* LTC_SHA256 */
    };

    int err;
    int tested=0,failed=0;
    for(i=0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++) {
        int hash = find_hash(cases[i].Hash);
        if (hash == -1) continue;
        ++tested;
        if((err = hkdf(hash, cases[i].salt, cases[i].salt_l,
                        cases[i].info, cases[i].info_l,
                        cases[i].IKM,   cases[i].IKM_l,
                        OKM,  cases[i].L)) != CRYPT_OK) {
#if 0
            printf("LTC_HKDF-%s test #%d, %s\n", cases[i].Hash, i, error_to_string(err));
#endif
            return err;
        }

        if(XMEMCMP(OKM, cases[i].OKM, (size_t)cases[i].L) != 0)  {
            failed++;
#if 0
          {
            unsigned int j;
            printf("\nLTC_HKDF-%s test #%d:\n", cases[i].Hash, i);
            printf(  "Result:  0x");
            for(j=0; j < cases[i].L; j++) {
                printf("%02x ", OKM[j]);
            }
            printf("\nCorrect: 0x");
            for(j=0; j < cases[i].L; j++) {
               printf("%02x ", cases[i].OKM[j]);
            }
            printf("\n");
            return CRYPT_ERROR;
          }
#endif
#if 0
        } else {
            printf("LTC_HKDF-%s test #%d: Passed\n", cases[i].Hash, i);
#endif
        }
    }

    if (failed != 0) {
        return CRYPT_FAIL_TESTVECTOR;
    } else if (tested == 0) {
        return CRYPT_NOP;
    } else {
        return CRYPT_OK;
    }
 #endif
}

#endif


/* $Source$ */
/* $Revision$ */
/* $Date$ */
