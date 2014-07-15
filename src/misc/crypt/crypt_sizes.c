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
  @file crypt_sizes.c

  Make various struct sizes available to dynamic languages
  like Python - Larry Bugbee, February 2013

  LB - Dec 2013 - revised to include compiler define options
*/


typedef struct {
    const char *name;
    const long size;
} crypt_size;

crypt_size _crypt_sizes[] = {
    // hash state sizes
    {"hash_descriptor_struct_size",   sizeof(struct ltc_hash_descriptor)},
    {"hash_state_union_size",         sizeof(hash_state)},
#ifdef LTC_SHA256
    {"sha256_state_struct_size",      sizeof(struct sha256_state)},
#endif
#ifdef LTC_SHA512
    {"sha512_state_struct_size",      sizeof(struct sha512_state)},
#endif
#ifdef LTC_WHIRLPOOL
    {"whirlpool_state_struct_size",   sizeof(struct whirlpool_state)},
#endif
#ifdef LTC_MD2
    {"md2_state_struct_size",         sizeof(struct md2_state)},
#endif
#ifdef LTC_MD4
    {"md4_state_struct_size",         sizeof(struct md4_state)},
#endif
#ifdef LTC_MD5
    {"md5_state_struct_size",         sizeof(struct md5_state)},
#endif
#ifdef LTC_RIPEMD128
    {"rmd128_state_struct_size",      sizeof(struct rmd128_state)},
#endif
#ifdef LTC_RIPEMD160
    {"rmd160_state_struct_size",      sizeof(struct rmd160_state)},
#endif
#ifdef LTC_RIPEMD256
    {"rmd256_state_struct_size",      sizeof(struct rmd256_state)},
#endif
#ifdef LTC_RIPEMD320
    {"rmd320_state_struct_size",      sizeof(struct rmd320_state)},
#endif
#ifdef LTC_SHA1
    {"sha1_state_struct_size",        sizeof(struct sha1_state)},
#endif
#ifdef LTC_TIGER
    {"tiger_state_struct_size",       sizeof(struct tiger_state)},
#endif
#ifdef LTC_CHC_HASH
    {"chc_state_struct_size",         sizeof(struct chc_state)},
#endif

    // block cipher key sizes
    {"cipher_descriptor_struct_size", sizeof(struct ltc_cipher_descriptor)},
    {"symmetric_key_union_size",      sizeof(symmetric_key)},
#ifdef LTC_ANUBIS
    {"anubis_key_struct_size",        sizeof(struct anubis_key)},
#endif
#ifdef LTC_CAMELLIA
    {"camellia_key_struct_size",      sizeof(struct camellia_key)},
#endif
#ifdef LTC_BLOWFISH
    {"blowfish_key_struct_size",      sizeof(struct blowfish_key)},
#endif
#ifdef LTC_CAST5
    {"cast5_key_struct_size",         sizeof(struct cast5_key)},
#endif
#ifdef LTC_DES
    {"des_key_struct_size",           sizeof(struct des_key)},
    {"des3_key_struct_size",          sizeof(struct des3_key)},
#endif
#ifdef LTC_KASUMI
    {"kasumi_key_struct_size",        sizeof(struct kasumi_key)},
#endif
#ifdef LTC_KHAZAD
    {"khazad_key_struct_size",        sizeof(struct khazad_key)},
#endif
#ifdef LTC_KSEED
    {"kseed_key_struct_size",         sizeof(struct kseed_key)},
#endif
#ifdef LTC_MULTI2
//    {"multi2_key_struct_size",        sizeof(struct multi2_key)},
#endif
#ifdef LTC_NOEKEON
    {"noekeon_key_struct_size",       sizeof(struct noekeon_key)},
#endif
#ifdef LTC_RC2
    {"rc2_key_struct_size",           sizeof(struct rc2_key)},
#endif
#ifdef LTC_RC5
    {"rc5_key_struct_size",           sizeof(struct rc5_key)},
#endif
#ifdef LTC_RC6
    {"rc6_key_struct_size",           sizeof(struct rc6_key)},
#endif
#ifdef LTC_SKIPJACK
    {"skipjack_key_struct_size",      sizeof(struct skipjack_key)},
#endif
#ifdef LTC_XTEA
    {"xtea_key_struct_size",          sizeof(struct xtea_key)},
#endif
#ifdef LTC_RIJNDAEL
    {"rijndael_key_struct_size",      sizeof(struct rijndael_key)},
#endif
#ifdef LTC_SAFER
    {"safer_key_struct_size",         sizeof(struct safer_key)},
#endif
#ifdef LTC_SAFERP
    {"saferp_key_struct_size",        sizeof(struct saferp_key)},
#endif
#ifdef LTC_TWOFISH
    {"twofish_key_struct_size",       sizeof(struct twofish_key)},
#endif

    // mode sizes
#ifdef LTC_CBC_MODE
    {"symmetric_CBC_struct_size",     sizeof(symmetric_CBC)},
#endif
#ifdef LTC_CFB_MODE
    {"symmetric_CFB_struct_size",     sizeof(symmetric_CFB)},
#endif
#ifdef LTC_CTR_MODE
    {"symmetric_CTR_struct_size",     sizeof(symmetric_CTR)},
#endif
#ifdef LTC_ECB_MODE
    {"symmetric_ECB_struct_size",     sizeof(symmetric_ECB)},
#endif
#ifdef LTC_F8_MODE
    {"symmetric_F8_struct_size",      sizeof(symmetric_F8)},
#endif
#ifdef LTC_LRW_MODE
    {"symmetric_LRW_struct_size",     sizeof(symmetric_LRW)},
#endif
#ifdef LTC_OFB_MODE
    {"symmetric_OFB_struct_size",     sizeof(symmetric_OFB)},
#endif

    // MAC sizes            -- no states for ccm, lrw
#ifdef LTC_F9_MODE
    {"f9_state_struct_size",          sizeof(f9_state)},
#endif
#ifdef LTC_HMAC
    {"hmac_state_struct_size",        sizeof(hmac_state)},
#endif
#ifdef LTC_OMAC
    {"omac_state_struct_size",        sizeof(omac_state)},
#endif
#ifdef LTC_PELICAN
    {"pelican_state_struct_size",     sizeof(pelican_state)},
#endif
#ifdef LTC_PMAC
    {"pmac_state_struct_size",        sizeof(pmac_state)},
#endif
#ifdef LTC_XCBC
    {"xcbc_state_struct_size",        sizeof(xcbc_state)},
#endif
#ifdef LTC_OCB_MODE
    {"ocb_state_struct_size",         sizeof(ocb_state)},
#endif
#ifdef LTC_OCB3_MODE
    {"ocb3_state_struct_size",        sizeof(ocb3_state)},
#endif
#ifdef LTC_GCM_MODE
    {"gcm_state_struct_size",         sizeof(gcm_state)},
#endif
#ifdef LTC_EAX_MODE
    {"eax_state_struct_size",         sizeof(eax_state)},
#endif
#ifdef LTC_CCM_MODE
// not defined
#endif
#ifdef LRW_MODE
// not defined
#endif

    // asymmetric keys
#ifdef LTC_MRSA
    {"rsa_key_struct_size",           sizeof(rsa_key)},
#endif
#ifdef LTC_MDSA
    {"dsa_key_struct_size",           sizeof(dsa_key)},
#endif
#ifdef MDH
    {"dh_key_struct_size",            sizeof(dh_key)},
#endif
#ifdef LTC_MECC
    {"ecc_set_struct_size",           sizeof(ltc_ecc_set_type)},
    {"ecc_key_struct_size",           sizeof(ecc_key)},
    {"ecc_point_struct_size",         sizeof(ecc_point)},
#endif
#ifdef MKAT
//    {"katja_key_struct_size",         sizeof(katja_key)},
#endif

    // prng state sizes
    {"prng_descriptor_struct_size",   sizeof(struct ltc_prng_descriptor)},
    {"prng_state_union_size",         sizeof(prng_state)},
#ifdef LTC_FORTUNA
    {"fortuna_prng_struct_size",      sizeof(struct fortuna_prng)},
#endif
#ifdef LTC_RC4
    {"rc4_prng_struct_size",          sizeof(struct rc4_prng)},
#endif
#ifdef LTC_SOBER128
    {"sober128_prng_struct_size",     sizeof(struct sober128_prng)},
#endif
#ifdef LTC_YARROW
    {"yarrow_prng_struct_size",       sizeof(struct yarrow_prng)},
#endif
    // sprng has no state as it uses other potentially available sources
    // like /dev/random.  See Developers Guide for more info.
};

/* crypt_get_size()
 * sizeout will be the size (bytes) of the named struct or union
 * return -1 if named item not found
 */
int crypt_get_size(const char* namein, int *sizeout) {
    int i;
    int count = sizeof(_crypt_sizes) / sizeof(_crypt_sizes[0]);
    for (i=0; i<count; i++) {
        if (strcmp(_crypt_sizes[i].name, namein) == 0) {
            *sizeout = _crypt_sizes[i].size;
            return 0;
        }
    }
    return -1;
}

/* crypt_list_all_sizes()
 * if names_list is NULL, names_list_size will be the minimum
 *     size needed to receive the complete names_list
 * if names_list is NOT NULL, names_list must be the addr with
 *     sufficient memory allocated into which the names_list
 *     is to be written.  Also, the value in names_list_size
 *     sets the upper bound of the number of characters to be
 *     written.
 * a -1 return value signifies insufficient space made available
 */
int crypt_list_all_sizes(char *names_list, unsigned long *names_list_size) {
    int i;
    unsigned long total_len = 0;
    char number[32];
    int number_len;
    int count = sizeof(_crypt_sizes) / sizeof(_crypt_sizes[0]);

    /* calculate amount of memory required for the list */
    for (i=0; i<count; i++) {
        total_len += strlen(_crypt_sizes[i].name) + 1;
        /* the above +1 is for the commas */
        number_len = snprintf(number, sizeof(number), "%ld", _crypt_sizes[i].size);
        if ((number_len < 0) ||
            ((unsigned int)number_len >= sizeof(number)))
          return -1;
        total_len += strlen(number) + 1;
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
            strcpy(ptr, _crypt_sizes[i].name);
            ptr += strlen(_crypt_sizes[i].name);
            strcpy(ptr, ",");
            ptr += 1;

            number_len = snprintf(number, sizeof(number), "%ld", _crypt_sizes[i].size);
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
