/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * gurantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://libtomcrypt.org
 */
#include "mycrypt.h"

#ifdef EAX_MODE

int eax_init(eax_state *eax, int cipher, const unsigned char *key, unsigned long keylen,
             const unsigned char *nonce, unsigned long noncelen,
             const unsigned char *header, unsigned long headerlen)
{
   unsigned char buf[MAXBLOCKSIZE];
   int           err, blklen;
   omac_state    omac;
   unsigned long len;


   _ARGCHK(eax != NULL);
   _ARGCHK(key != NULL);
   _ARGCHK(nonce != NULL);
   if (headerlen > 0) {
      _ARGCHK(header != NULL);
   }

   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }
   blklen = cipher_descriptor[cipher].block_length;

   /* N = OMAC_0K(nonce) */
   zeromem(buf, sizeof(buf));
   if ((err = omac_init(&omac, cipher, key, keylen)) != CRYPT_OK) {
      return err;
   }

   /* omac the [0]_n */
   if ((err = omac_process(&omac, buf, blklen)) != CRYPT_OK) {
      return err;
   }
   /* omac the nonce */
   if ((err = omac_process(&omac, nonce, noncelen)) != CRYPT_OK) {
      return err;
   }
   /* store result */
   len = sizeof(eax->N);
   if ((err = omac_done(&omac, eax->N, &len)) != CRYPT_OK) {
      return err;
   }

   /* H = OMAC_1K(header) */
   zeromem(buf, sizeof(buf));
   buf[blklen - 1] = 1;

   if ((err = omac_init(&eax->headeromac, cipher, key, keylen)) != CRYPT_OK) {
      return err;
   }

   /* omac the [1]_n */
   if ((err = omac_process(&eax->headeromac, buf, blklen)) != CRYPT_OK) {
      return err;
   }
   /* omac the header */
   if (headerlen != 0) {
      if ((err = omac_process(&eax->headeromac, header, headerlen)) != CRYPT_OK) {
         return err;
      }
   }

   /* note we don't finish the headeromac, this allows us to add more header later */

   /* setup the CTR mode */
   if ((err = ctr_start(cipher, eax->N, key, keylen, 0, &eax->ctr)) != CRYPT_OK) {
      return err;
   }
   /* use big-endian counter */
   eax->ctr.mode = 1;

   /* setup the OMAC for the ciphertext */
   if ((err = omac_init(&eax->ctomac, cipher, key, keylen)) != CRYPT_OK) { 
      return err;
   }

   /* omac [2]_n */
   zeromem(buf, sizeof(buf));
   buf[blklen-1] = 2;
   if ((err = omac_process(&eax->ctomac, buf, blklen)) != CRYPT_OK) {
      return err;
   }

#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
   zeromem(&omac, sizeof(omac));
#endif
   return CRYPT_OK;
}

int eax_encrypt(eax_state *eax, const unsigned char *pt, unsigned char *ct, unsigned long length)
{
   int err;
   
   _ARGCHK(eax != NULL);
   _ARGCHK(pt  != NULL);
   _ARGCHK(ct  != NULL);

   /* encrypt */
   if ((err = ctr_encrypt(pt, ct, length, &eax->ctr)) != CRYPT_OK) {
      return err;
   }

   /* omac ciphertext */
   return omac_process(&eax->ctomac, ct, length);
}

int eax_decrypt(eax_state *eax, const unsigned char *ct, unsigned char *pt, unsigned long length)
{
   int err;
   
   _ARGCHK(eax != NULL);
   _ARGCHK(pt  != NULL);
   _ARGCHK(ct  != NULL);

   /* omac ciphertext */
   if ((err = omac_process(&eax->ctomac, ct, length)) != CRYPT_OK) {
      return err;
   }

   /* decrypt  */
   return ctr_decrypt(ct, pt, length, &eax->ctr);
}

/* add header (metadata) to the stream */
int eax_addheader(eax_state *eax, const unsigned char *header, unsigned long length)
{
   _ARGCHK(eax != NULL);
   _ARGCHK(header != NULL);
   return omac_process(&eax->headeromac, header, length);
}

int eax_done(eax_state *eax, unsigned char *tag, unsigned long *taglen)
{
   int           err;
   unsigned char headermac[MAXBLOCKSIZE], ctmac[MAXBLOCKSIZE];
   unsigned long x, len;

   _ARGCHK(eax != NULL);
   _ARGCHK(tag != NULL);
   _ARGCHK(taglen != NULL);

   /* finish ctomac */
   len = sizeof(ctmac);
   if ((err = omac_done(&eax->ctomac, ctmac, &len)) != CRYPT_OK) {
      return err;
   }

   /* finish headeromac */

   /* note we specifically don't reset len so the two lens are minimal */

   if ((err = omac_done(&eax->headeromac, headermac, &len)) != CRYPT_OK) {
      return err;
   }

   /* compute N xor H xor C */
   for (x = 0; x < len && x < *taglen; x++) {
       tag[x] = eax->N[x] ^ headermac[x] ^ ctmac[x];
   }
   *taglen = x;

#ifdef CLEAN_STACK
   zeromem(ctmac, sizeof(ctmac));
   zeromem(headermac, sizeof(headermac));
#endif

   return CRYPT_OK;
}

int eax_encrypt_authenticate_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  unsigned long noncelen,
    const unsigned char *header, unsigned long headerlen,
    const unsigned char *pt,     unsigned long ptlen,
          unsigned char *ct,
          unsigned char *tag,    unsigned long *taglen)
{
   int err;
   eax_state eax;

   if ((err = eax_init(&eax, cipher, key, keylen, nonce, noncelen, header, headerlen)) != CRYPT_OK) {
      return err;
   }

   if ((err = eax_encrypt(&eax, pt, ct, ptlen)) != CRYPT_OK) {
      return err;
   }
 
   if ((err = eax_done(&eax, tag, taglen)) != CRYPT_OK) {
      return err;
   }

#ifdef CLEAN_STACK
   zeromem(&eax, sizeof(eax));
#endif
   return CRYPT_OK;
}

int eax_decrypt_verify_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  unsigned long noncelen,
    const unsigned char *header, unsigned long headerlen,
    const unsigned char *ct,     unsigned long ctlen,
          unsigned char *pt,
          unsigned char *tag,    unsigned long taglen,
          int           *res)
{
   int err;
   eax_state eax;
   unsigned char buf[MAXBLOCKSIZE];
   unsigned long buflen;

   _ARGCHK(res != NULL);

   /* default to zero */
   *res = 0;

   if ((err = eax_init(&eax, cipher, key, keylen, nonce, noncelen, header, headerlen)) != CRYPT_OK) {
      return err;
   }

   if ((err = eax_decrypt(&eax, ct, pt, ctlen)) != CRYPT_OK) {
      return err;
   }
 
   buflen = MIN(sizeof(buf), taglen);
   if ((err = eax_done(&eax, buf, &buflen)) != CRYPT_OK) {
      return err;
   }

   /* compare tags */
   if (buflen >= taglen && memcmp(buf, tag, taglen) == 0) {
      *res = 1;
   }

#ifdef CLEAN_STACK
   zeromem(&eax, sizeof(eax));
   zeromem(buf, sizeof(buf));
#endif
   return CRYPT_OK;
}

int eax_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   static const struct {
       int               keylen, 
                       noncelen, 
                      headerlen, 
                         msglen;

       unsigned char        key[MAXBLOCKSIZE], 
                          nonce[MAXBLOCKSIZE], 
                         header[MAXBLOCKSIZE], 
                      plaintext[MAXBLOCKSIZE],
                     ciphertext[MAXBLOCKSIZE], 
                            tag[MAXBLOCKSIZE];
   } tests[] = {

/* NULL message */
{
   16, 0, 0, 0,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0 },
   /* header */
   { 0 },
   /* plaintext */
   { 0 },
   /* ciphertext */
   { 0 },
   /* tag */
   { 0x9a, 0xd0, 0x7e, 0x7d, 0xbf, 0xf3, 0x01, 0xf5,
     0x05, 0xde, 0x59, 0x6b, 0x96, 0x15, 0xdf, 0xff }
},

/* test with nonce */
{
   16, 16, 0, 0,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* header */
   { 0 },
   /* plaintext */
   { 0 },
   /* ciphertext */
   { 0 },
   /* tag */
   { 0x1c, 0xe1, 0x0d, 0x3e, 0xff, 0xd4, 0xca, 0xdb,
     0xe2, 0xe4, 0x4b, 0x58, 0xd6, 0x0a, 0xb9, 0xec }
},

/* test with header [no nonce]  */
{
   16, 0, 16, 0,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0 },
   /* header */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* plaintext */
   { 0 },
   /* ciphertext */
   { 0 },
   /* tag */
   { 0x3a, 0x69, 0x8f, 0x7a, 0x27, 0x0e, 0x51, 0xb0,
     0xf6, 0x5b, 0x3d, 0x3e, 0x47, 0x19, 0x3c, 0xff }
},

/* test with header + nonce + plaintext */
{
   16, 16, 16, 32,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },  
   /* header */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* plaintext */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
   /* ciphertext */
   { 0x29, 0xd8, 0x78, 0xd1, 0xa3, 0xbe, 0x85, 0x7b,
     0x6f, 0xb8, 0xc8, 0xea, 0x59, 0x50, 0xa7, 0x78,
     0x33, 0x1f, 0xbf, 0x2c, 0xcf, 0x33, 0x98, 0x6f,
     0x35, 0xe8, 0xcf, 0x12, 0x1d, 0xcb, 0x30, 0xbc },
   /* tag */
   { 0x4f, 0xbe, 0x03, 0x38, 0xbe, 0x1c, 0x8c, 0x7e,
     0x1d, 0x7a, 0xe7, 0xe4, 0x5b, 0x92, 0xc5, 0x87 }
},

/* test with header + nonce + plaintext [not even sizes!] */
{
   16, 15, 14, 29,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e },  
   /* header */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d },
   /* plaintext */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c },
   /* ciphertext */
   { 0xdd, 0x25, 0xc7, 0x54, 0xc5, 0xb1, 0x7c, 0x59,
     0x28, 0xb6, 0x9b, 0x73, 0x15, 0x5f, 0x7b, 0xb8,
     0x88, 0x8f, 0xaf, 0x37, 0x09, 0x1a, 0xd9, 0x2c,
     0x8a, 0x24, 0xdb, 0x86, 0x8b },
   /* tag */
   { 0x0d, 0x1a, 0x14, 0xe5, 0x22, 0x24, 0xff, 0xd2,
     0x3a, 0x05, 0xfa, 0x02, 0xcd, 0xef, 0x52, 0xda }
},
};
   int err, x, idx, res;
   unsigned long len;
   unsigned char outct[MAXBLOCKSIZE], outtag[MAXBLOCKSIZE];

    /* AES can be under rijndael or aes... try to find it */ 
    if ((idx = find_cipher("aes")) == -1) {
       if ((idx = find_cipher("rijndael")) == -1) {
          return CRYPT_NOP;
       }
    }

    for (x = 0; x < (int)(sizeof(tests)/sizeof(tests[0])); x++) {
        len = sizeof(outtag);
        if ((err = eax_encrypt_authenticate_memory(idx, tests[x].key, tests[x].keylen,
            tests[x].nonce, tests[x].noncelen, tests[x].header, tests[x].headerlen,
            tests[x].plaintext, tests[x].msglen, outct, outtag, &len)) != CRYPT_OK) {
           return err;
        }
        if (memcmp(outct, tests[x].ciphertext, tests[x].msglen) || memcmp(outtag, tests[x].tag, len)) {
#if 0
           unsigned long y;
           printf("\n\nFailure: \nCT:\n");
           for (y = 0; y < (unsigned long)tests[x].msglen; ) {
               printf("0x%02x", outct[y]);
               if (y < (unsigned long)(tests[x].msglen-1)) printf(", ");
               if (!(++y % 8)) printf("\n");
           }
           printf("\nTAG:\n");
           for (y = 0; y < len; ) {
               printf("0x%02x", outtag[y]);
               if (y < len-1) printf(", ");
               if (!(++y % 8)) printf("\n");
           }
#endif
           return CRYPT_FAIL_TESTVECTOR;
        }

        /* test decrypt */
        if ((err = eax_decrypt_verify_memory(idx, tests[x].key, tests[x].keylen,
             tests[x].nonce, tests[x].noncelen, tests[x].header, tests[x].headerlen,
             outct, tests[x].msglen, outct, outtag, len, &res)) != CRYPT_OK) {
            return err;
        }
        if (res != 1 || memcmp(outct, tests[x].plaintext, tests[x].msglen)) {
#if 0
           unsigned long y;
           printf("\n\nFailure (res == %d): \nPT:\n", res);
           for (y = 0; y < (unsigned long)tests[x].msglen; ) {
               printf("0x%02x", outct[y]);
               if (y < (unsigned long)(tests[x].msglen-1)) printf(", ");
               if (!(++y % 8)) printf("\n");
           }
           printf("\n\n");
#endif
           return CRYPT_FAIL_TESTVECTOR;
        }

     }
     return CRYPT_OK;
#endif /* LTC_TEST */
}

#endif /* EAX_MODE */
