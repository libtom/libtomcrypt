/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
  @file crypt_constants.c

  Make various constants available to dynamic languages
  like Python - Larry Bugbee, February 2013

  LB - Dec 2013 - revised to include compiler define options
  LB - Mar 2014 - added endianness and word size
*/

typedef struct {
    const char *name;
    const long value;
} crypt_constant;

crypt_constant _crypt_constants[] = {
    {"PK_PUBLIC",                 PK_PUBLIC},
    {"PK_PRIVATE",                PK_PRIVATE},

#ifdef LTC_CTR_MODE
    {"CTR_COUNTER_LITTLE_ENDIAN", CTR_COUNTER_LITTLE_ENDIAN},
    {"CTR_COUNTER_BIG_ENDIAN",    CTR_COUNTER_BIG_ENDIAN},
    {"LTC_CTR_RFC3686",           LTC_CTR_RFC3686},
#endif

#ifdef LTC_MRSA
    {"MIN_RSA_SIZE",              MIN_RSA_SIZE},
    {"MAX_RSA_SIZE",              MAX_RSA_SIZE},
#endif

#ifdef LTC_PKCS_1
    {"LTC_PKCS_1_OAEP",           LTC_PKCS_1_OAEP},
    {"LTC_PKCS_1_PSS",            LTC_PKCS_1_PSS},
    {"LTC_PKCS_1_V1_5",           LTC_PKCS_1_V1_5},
#endif

#ifdef ENDIAN_LITTLE
    {"ENDIAN_LITTLE",             1},
#else
    {"ENDIAN_LITTLE",             0},
#endif

#ifdef ENDIAN_BIG
    {"ENDIAN_BIG",                1},
#else
    {"ENDIAN_BIG",                0},
#endif

#ifdef ENDIAN_32BITWORD
    {"ENDIAN_32BITWORD",          1},
#else
    {"ENDIAN_32BITWORD",          0},
#endif

#ifdef ENDIAN_64BITWORD
    {"ENDIAN_64BITWORD",          1},
#else
    {"ENDIAN_64BITWORD",          0},
#endif
};


/* crypt_get_constant()
 * valueout will be the value of the named constant
 * return -1 if named item not found
 */
int crypt_get_constant(const char* namein, int *valueout) {
    int i;
    int _crypt_constants_len = sizeof(_crypt_constants) / sizeof(_crypt_constants[0]);
    for (i=0; i<_crypt_constants_len; i++) {
        if (strcmp(_crypt_constants[i].name, namein) == 0) {
            *valueout = _crypt_constants[i].value;
            return 0;
        }
    }
    return 1;
}

/* crypt_list_all_constants()
 * if names_list is NULL, names_list_size will be the minimum
 *     number of bytes needed to receive the complete names_list
 * if names_list is NOT NULL, names_list must be the addr of
 *     sufficient memory allocated into which the names_list
 *     is to be written.  Also, the value in names_list_size
 *     sets the upper bound of the number of characters to be
 *     written.
 * a -1 return value signifies insufficient space made available
 */
int crypt_list_all_constants(char *names_list, unsigned long *names_list_size) {
    int i;
    unsigned long total_len = 0;
    char number[32];
    int number_len;
    int count = sizeof(_crypt_constants) / sizeof(_crypt_constants[0]);

    /* calculate amount of memory required for the list */
    for (i=0; i<count; i++) {
        total_len += strlen(_crypt_constants[i].name) + 1;
        /* the above +1 is for the commas */
        number_len = snprintf(number, sizeof(number), "%ld", _crypt_constants[i].value);
        if ((number_len < 0) ||
            ((unsigned int)number_len >= sizeof(number)))
          return -1;
        total_len += number_len + 1;
        /* this last +1 is for newlines (and ending NULL) */
    }

    if (names_list == NULL) {
        *names_list_size = total_len;
    } else {
        if (total_len > *names_list_size) {
            return -1;
        }
        /* build the names list */
        char *ptr = names_list;
        for (i=0; i<count; i++) {
            strcpy(ptr, _crypt_constants[i].name);
            ptr += strlen(_crypt_constants[i].name);
            strcpy(ptr, ",");
            ptr += 1;

            number_len = snprintf(number, sizeof(number), "%ld", _crypt_constants[i].value);
            strcpy(ptr, number);
            ptr += number_len;
            strcpy(ptr, "\n");
            ptr += 1;
        }
        /* to remove the trailing new-line */
        ptr -= 1;
        *ptr = 0;
    }
    return 0;
}


/* $Source$ */
/* $Revision$ */
/* $Date$ */
