#ifndef TOMCRYPT_CUSTOM_H_
#define TOMCRYPT_CUSTOM_H_

/* macros for various libc functions you can change for embedded targets */
#ifndef XMALLOC
#define XMALLOC  malloc
#endif
#ifndef XREALLOC
#define XREALLOC realloc
#endif
#ifndef XCALLOC
#define XCALLOC  calloc
#endif
#ifndef XFREE
#define XFREE    free
#endif

#ifndef XMEMSET
#define XMEMSET  memset
#endif
#ifndef XMEMCPY
#define XMEMCPY  memcpy
#endif
#ifndef XMEMCMP
#define XMEMCMP  memcmp
#endif

#ifndef XCLOCK
#define XCLOCK   clock
#endif
#ifndef XCLOCKS_PER_SEC
#define XCLOCKS_PER_SEC CLOCKS_PER_SEC
#endif

#ifndef XQSORT
#define XQSORT qsort
#endif

/* Easy button? */
#ifdef LTC_EASY
   #define LTC_NO_CIPHERS
   #define RIJNDAEL
   #define BLOWFISH
   #define DES
   #define CAST5
   
   #define LTC_NO_MODES
   #define ECB
   #define CBC
   #define CTR
   
   #define LTC_NO_HASHES
   #define SHA1
   #define SHA512
   #define SHA384
   #define SHA256
   #define SHA224
   #define WHIRLPOOL
   
   #define LTC_NO_MACS
   #define HMAC
   #define OMAC
   #define CCM_MODE

   #define LTC_NO_PRNGS
   #define SPRNG
   #define YARROW
   #define DEVRANDOM
   #define TRY_URANDOM_FIRST
      
   #define LTC_NO_PK
   #define MRSA
   #define MECC
#endif   
   


/* Use small code where possible */
/* #define LTC_SMALL_CODE */

/* Enable self-test test vector checking */
#ifndef LTC_NO_TEST
   #define LTC_TEST
#endif

/* clean the stack of functions which put private information on stack */
/* #define LTC_CLEAN_STACK */

/* disable all file related functions */
/* #define LTC_NO_FILE */

/* disable all forms of ASM */
/* #define LTC_NO_ASM */

/* disable FAST mode */
/* #define LTC_NO_FAST */

/* disable BSWAP on x86 */
/* #define LTC_NO_BSWAP */

/* ---> Symmetric Block Ciphers <--- */
#ifndef LTC_NO_CIPHERS

#define BLOWFISH
#define RC2
#define RC5
#define RC6
#define SAFERP
#define RIJNDAEL
#define XTEA
/* _TABLES tells it to use tables during setup, _SMALL means to use the smaller scheduled key format
 * (saves 4KB of ram), _ALL_TABLES enables all tables during setup */
#define TWOFISH
#ifndef LTC_NO_TABLES
   #define TWOFISH_TABLES
   /* #define TWOFISH_ALL_TABLES */
#else
   #define TWOFISH_SMALL
#endif
/* #define TWOFISH_SMALL */
/* DES includes EDE triple-DES */
#define DES
#define CAST5
#define NOEKEON
#define SKIPJACK
#define SAFER
#define KHAZAD
#define ANUBIS
#define ANUBIS_TWEAK

#endif /* LTC_NO_CIPHERS */


/* ---> Block Cipher Modes of Operation <--- */
#ifndef LTC_NO_MODES

#define CFB
#define OFB
#define ECB
#define CBC
#define CTR

/* LRW mode */
#define LRW_MODE
#ifndef LTC_NO_TABLES
   /* like GCM mode this will enable 16 8x128 tables [64KB] that make
    * seeking very fast.  
    */
   #define LRW_TABLES
#endif

#endif /* LTC_NO_MODES */

/* ---> One-Way Hash Functions <--- */
#ifndef LTC_NO_HASHES 

#define CHC_HASH
#define WHIRLPOOL
#define SHA512
#define SHA384
#define SHA256
#define SHA224
#define TIGER
#define SHA1
#define MD5
#define MD4
#define MD2
#define RIPEMD128
#define RIPEMD160

#endif /* LTC_NO_HASHES */

/* ---> MAC functions <--- */
#ifndef LTC_NO_MACS

#define HMAC
#define OMAC
#define PMAC
#define PELICAN

#if defined(PELICAN) && !defined(RIJNDAEL)
   #error Pelican-MAC requires RIJNDAEL
#endif

/* ---> Encrypt + Authenticate Modes <--- */

#define EAX_MODE
#if defined(EAX_MODE) && !(defined(CTR) && defined(OMAC))
   #error EAX_MODE requires CTR and OMAC mode
#endif

#define OCB_MODE
#define CCM_MODE
#define GCM_MODE

/* Use 64KiB tables */
#ifndef LTC_NO_TABLES
   #define GCM_TABLES 
#endif

#endif /* LTC_NO_MACS */

/* Various tidbits of modern neatoness */
#define BASE64

/* --> Pseudo Random Number Generators <--- */
#ifndef LTC_NO_PRNGS

/* Yarrow */
#define YARROW
/* which descriptor of AES to use?  */
/* 0 = rijndael_enc 1 = aes_enc, 2 = rijndael [full], 3 = aes [full] */
#define YARROW_AES 0

#if defined(YARROW) && !defined(CTR)
   #error YARROW requires CTR chaining mode to be defined!
#endif

/* a PRNG that simply reads from an available system source */
#define SPRNG

/* The RC4 stream cipher */
#define RC4

/* Fortuna PRNG */
#define FORTUNA
/* reseed every N calls to the read function */
#define FORTUNA_WD    10
/* number of pools (4..32) can save a bit of ram by lowering the count */
#define FORTUNA_POOLS 32

/* Greg's SOBER128 PRNG ;-0 */
#define SOBER128

/* the *nix style /dev/random device */
#define DEVRANDOM
/* try /dev/urandom before trying /dev/random */
#define TRY_URANDOM_FIRST

#endif /* LTC_NO_PRNGS */

/* ---> math provider? <--- */
#ifndef LTC_NO_MATH

/* LibTomMath */
/* #define LTM_DESC */

/* TomsFastMath */
/* #define TFM_DESC */

#endif /* LTC_NO_MATH */

/* ---> Public Key Crypto <--- */
#ifndef LTC_NO_PK

/* Include RSA support */
#define MRSA

/* Include Katja (a Rabin variant like RSA) */
// #define MKAT 

/* Digital Signature Algorithm */
#define MDSA

/* ECC */
#define MECC

/* Timing Resistant? */
/* #define LTC_ECC_TIMING_RESISTANT */

#endif /* LTC_NO_PK */

/* PKCS #1 (RSA) and #5 (Password Handling) stuff */
#ifndef LTC_NO_PKCS

#define PKCS_1
#define PKCS_5

/* Include ASN.1 DER (required by DSA/RSA) */
#define LTC_DER

#endif /* LTC_NO_PKCS */

/* cleanup */

#ifdef MECC
/* Supported ECC Key Sizes */
#ifndef LTC_NO_CURVES
   #define ECC192
   #define ECC224
   #define ECC256
   #define ECC384
   #define ECC521
#endif
#endif

#if defined(MECC) || defined(MRSA) || defined(MDSA) || defined(MKATJA)
   /* Include the MPI functionality?  (required by the PK algorithms) */
   #define MPI
#endif

#ifdef MRSA
   #define PKCS_1
#endif   

#if defined(LTC_DER) && !defined(MPI) 
   #error ASN.1 DER requires MPI functionality
#endif

#if (defined(MDSA) || defined(MRSA) || defined(MECC) || defined(MKATJA)) && !defined(LTC_DER)
   #error PK requires ASN.1 DER functionality, make sure LTC_DER is enabled
#endif

/* THREAD management */

#ifdef LTC_PTHREAD

#include <pthread.h>

#define LTC_MUTEX_GLOBAL(x)   pthread_mutex_t x = PTHREAD_MUTEX_INITIALIZER;
#define LTC_MUTEX_PROTO(x)    extern pthread_mutex_t x;
#define LTC_MUTEX_TYPE(x)     pthread_mutex_t x;
#define LTC_MUTEX_INIT(x)     pthread_mutex_init(x, NULL);
#define LTC_MUTEX_LOCK(x)     pthread_mutex_lock(x);
#define LTC_MUTEX_UNLOCK(x)   pthread_mutex_unlock(x);

#else

/* default no functions */
#define LTC_MUTEX_GLOBAL(x)
#define LTC_MUTEX_PROTO(x)
#define LTC_MUTEX_TYPE(x)
#define LTC_MUTEX_INIT(x)
#define LTC_MUTEX_LOCK(x)
#define LTC_MUTEX_UNLOCK(x)

#endif

#endif



/* $Source$ */
/* $Revision$ */
/* $Date$ */
