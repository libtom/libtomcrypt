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

#define OCB_MODE
#ifdef OCB_MODE

static const struct {
    int           len;
    unsigned char poly_div[MAXBLOCKSIZE], 
                  poly_mul[MAXBLOCKSIZE];
} polys[] = {
{
    8,
    { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B }
}, {
    16, 
    { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 }
}
};

int ocb_init(ocb_state *ocb, int cipher, 
             const unsigned char *key, unsigned long keylen, const unsigned char *nonce)
{
   int x, y, z, m, p, err;
   unsigned char tmp[MAXBLOCKSIZE];

   _ARGCHK(ocb != NULL);
   _ARGCHK(key != NULL);
   _ARGCHK(nonce != NULL);

   /* valid cipher? */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }

   /* determine which polys to use */
   ocb->block_len = cipher_descriptor[cipher].block_length;
   for (ocb->poly = 0; ocb->poly < (int)(sizeof(polys)/sizeof(polys[0])); ocb->poly++) {
       if (polys[ocb->poly].len == ocb->block_len) { 
          break;
       }
   }
   if (polys[ocb->poly].len != ocb->block_len) {
      return CRYPT_INVALID_ARG;
   }   

   /* schedule the key */
   if ((err = cipher_descriptor[cipher].setup(key, keylen, 0, &ocb->key)) != CRYPT_OK) {
      return err;
   }
 
   /* find L = E[0] */
   zeromem(ocb->L, ocb->block_len);
   cipher_descriptor[cipher].ecb_encrypt(ocb->L, ocb->L, &ocb->key);

   /* find R = E[N xor L] */
   for (x = 0; x < ocb->block_len; x++) {
       ocb->R[x] = ocb->L[x] ^ nonce[x];
   }
   cipher_descriptor[cipher].ecb_encrypt(ocb->R, ocb->R, &ocb->key);

   /* find Ls[i] = L << i for i == 0..31 */
   memcpy(ocb->Ls[0], ocb->L, ocb->block_len);
   for (x = 1; x < 32; x++) {
       m = ocb->Ls[x-1][0] >> 7;
       for (y = 0; y < ocb->block_len-1; y++) {
           ocb->Ls[x][y] = ((ocb->Ls[x-1][y] << 1) | (ocb->Ls[x-1][y+1] >> 7)) & 255;
       }
       ocb->Ls[x][ocb->block_len-1] = (ocb->Ls[x-1][ocb->block_len-1] << 1) & 255;

       if (m == 1) {
          for (y = 0; y < ocb->block_len; y++) {
              ocb->Ls[x][y] ^= polys[ocb->poly].poly_mul[y];
          }
       }
    }

    /* find Lr = L / x */
    m = ocb->L[ocb->block_len-1] & 1;

    /* shift right */
    for (x = ocb->block_len - 1; x > 0; x--) {
        ocb->Lr[x] = ((ocb->L[x] >> 1) | (ocb->L[x-1] << 7)) & 255;
    }
    ocb->Lr[0] = ocb->L[0] >> 1;

    if (m == 1) {
       for (x = 0; x < ocb->block_len; x++) {
           ocb->Lr[x] ^= polys[ocb->poly].poly_div[x];
       }
    }

    /* set Li, checksum */
    zeromem(ocb->Li, ocb->block_len);
    zeromem(ocb->checksum, ocb->block_len);

    /* set other params */
    ocb->block_index = 1;
    ocb->cipher      = cipher;

    return CRYPT_OK;
}

static int ntz(unsigned long x)
{
   int c;
   x &= 0xFFFFFFFFUL;
   c = 0;
   while ((x & 1) == 0) {
      ++c;
      x >>= 1;
   }
   return c;
}

static void shift_xor(ocb_state *ocb, unsigned char *Z)
{
   int x, y;
   y = ntz(ocb->block_index++);
   for (x = 0; x < ocb->block_len; x++) {
       ocb->Li[x] ^= ocb->Ls[y][x];
       Z[x]        = ocb->Li[x] ^ ocb->R[x];
   }
}

int ocb_encrypt(ocb_state *ocb, const unsigned char *pt, unsigned char *ct)
{
   unsigned char Z[MAXBLOCKSIZE], tmp[MAXBLOCKSIZE];
   int err, x, y;

   _ARGCHK(ocb != NULL);
   _ARGCHK(pt  != NULL);
   _ARGCHK(ct  != NULL);
   if ((err = cipher_is_valid(ocb->cipher)) != CRYPT_OK) {
      return err;
   }
   if (ocb->block_len != cipher_descriptor[ocb->cipher].block_length) {
      return CRYPT_INVALID_ARG;
   }

   /* compute checksum */
   for (x = 0; x < ocb->block_len; x++) {
       ocb->checksum[x] ^= pt[x];
   }

   /* Get Z[i] value */
   shift_xor(ocb, Z);

   /* xor pt in, encrypt, xor Z out */
   for (x = 0; x < ocb->block_len; x++) {
       tmp[x] = pt[x] ^ Z[x];
   }
   cipher_descriptor[ocb->cipher].ecb_encrypt(tmp, ct, &ocb->key);
   for (x = 0; x < ocb->block_len; x++) {
       ct[x] ^= Z[x];
   }

#ifdef CLEAN_STACK
   zeromem(Z, sizeof(Z));
   zeromem(tmp, sizeof(tmp));
#endif
   return CRYPT_OK;
}

int ocb_decrypt(ocb_state *ocb, const unsigned char *ct, unsigned char *pt)
{
   unsigned char Z[MAXBLOCKSIZE], tmp[MAXBLOCKSIZE];
   int err, x, y;

   _ARGCHK(ocb != NULL);
   _ARGCHK(pt  != NULL);
   _ARGCHK(ct  != NULL);
   if ((err = cipher_is_valid(ocb->cipher)) != CRYPT_OK) {
      return err;
   }
   if (ocb->block_len != cipher_descriptor[ocb->cipher].block_length) {
      return CRYPT_INVALID_ARG;
   }

   /* Get Z[i] value */
   shift_xor(ocb, Z);

   /* xor ct in, encrypt, xor Z out */
   for (x = 0; x < ocb->block_len; x++) {
       tmp[x] = ct[x] ^ Z[x];
   }
   cipher_descriptor[ocb->cipher].ecb_decrypt(tmp, pt, &ocb->key);
   for (x = 0; x < ocb->block_len; x++) {
       pt[x] ^= Z[x];
   }

   /* compute checksum */
   for (x = 0; x < ocb->block_len; x++) {
       ocb->checksum[x] ^= pt[x];
   }


#ifdef CLEAN_STACK
   zeromem(Z, sizeof(Z));
   zeromem(tmp, sizeof(tmp));
#endif
   return CRYPT_OK;
}


/* Since the last block is encrypted in CTR mode the same code can
 * be used to finish a decrypt or encrypt stream.  The only difference
 * is we XOR the final ciphertext into the checksum so we have to xor it
 * before we CTR [decrypt] or after [encrypt]
 *
 * the names pt/ptlen/ct really just mean in/inlen/out but this is the way I wrote it... 
 */
static int _ocb_done(ocb_state *ocb, const unsigned char *pt, unsigned long ptlen,
                     unsigned char *ct, unsigned char *tag, unsigned long *taglen, int mode)

{
   unsigned char Z[MAXBLOCKSIZE], Y[MAXBLOCKSIZE], X[MAXBLOCKSIZE];
   int err, x, y;

   _ARGCHK(ocb != NULL);
   _ARGCHK(pt  != NULL);
   _ARGCHK(ct  != NULL);
   _ARGCHK(tag != NULL);
   _ARGCHK(taglen != NULL);
   if ((err = cipher_is_valid(ocb->cipher)) != CRYPT_OK) {
      return err;
   }
   if (ocb->block_len != cipher_descriptor[ocb->cipher].block_length ||
       (int)ptlen > ocb->block_len || (int)ptlen < 0) {
      return CRYPT_INVALID_ARG;
   }

   /* compute X[m] = len(pt[m]) XOR Lr XOR Z[m] */
   shift_xor(ocb, X); 
   memcpy(Z, X, ocb->block_len);

   X[ocb->block_len-1] ^= ptlen&255;
   for (x = 0; x < ocb->block_len; x++) {
       X[x] ^= ocb->Lr[x]; 
   }

   /* Y[m] = E(X[m])) */
   cipher_descriptor[ocb->cipher].ecb_encrypt(X, Y, &ocb->key);

   if (mode == 1) {
      /* decrypt mode, so let's xor it first */
      /* xor C[m] into checksum */
      for (x = 0; x < (int)ptlen; x++) {
         ocb->checksum[x] ^= ct[x];
      }  
   }

   /* C[m] = P[m] xor Y[m] */
   for (x = 0; x < (int)ptlen; x++) {
       ct[x] = pt[x] ^ Y[x];
   }

   if (mode == 0) {
      /* encrypt mode */    
      /* xor C[m] into checksum */
      for (x = 0; x < (int)ptlen; x++) {
          ocb->checksum[x] ^= ct[x];
      }
   }

   /* xor Y[m] and Z[m] into checksum */
   for (x = 0; x < ocb->block_len; x++) {
       ocb->checksum[x] ^= Y[x] ^ Z[x];
   }
   
   /* encrypt checksum, er... tag!! */
   cipher_descriptor[ocb->cipher].ecb_encrypt(ocb->checksum, X, &ocb->key);

   /* now store it */
   for (x = 0; x < ocb->block_len && x < (int)*taglen; x++) {
       tag[x] = X[x];
   }
   *taglen = x;

#ifdef CLEAN_STACK
   zeromem(X, sizeof(X));
   zeromem(Y, sizeof(Y));
   zeromem(Z, sizeof(Z));
#endif
   return CRYPT_OK;
}

int ocb_done_encrypt(ocb_state *ocb, const unsigned char *pt, unsigned long ptlen,
                     unsigned char *ct, unsigned char *tag, unsigned long *taglen)
{
   return _ocb_done(ocb, pt, ptlen, ct, tag, taglen, 0);
}


int ocb_done_decrypt(ocb_state *ocb, 
                     const unsigned char *ct,  unsigned long ctlen,
                           unsigned char *pt, 
                     const unsigned char *tag, unsigned long taglen, int *res)
{
   int err;
   unsigned char tagbuf[MAXBLOCKSIZE];
   unsigned long tagbuflen;


   _ARGCHK(ocb != NULL);
   _ARGCHK(pt  != NULL);
   _ARGCHK(ct  != NULL);
   _ARGCHK(tag != NULL);
   _ARGCHK(res != NULL);

   *res = 0;

   tagbuflen = sizeof(tagbuf);
   if ((err = _ocb_done(ocb, ct, ctlen, pt, tagbuf, &tagbuflen, 1)) != CRYPT_OK) {
      return err;
   }

   if (taglen <= tagbuflen && memcmp(tagbuf, tag, taglen) == 0) {
      *res = 1;
   }

#ifdef CLEAN_STACK
   zeromem(tagbuf, sizeof(tagbuf));
#endif

   return CRYPT_OK;
}

int ocb_encrypt_authenticate_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  
    const unsigned char *pt,     unsigned long ptlen,
          unsigned char *ct,
          unsigned char *tag,    unsigned long *taglen)
{
   int err, n;
   ocb_state ocb;

   if ((err = ocb_init(&ocb, cipher, key, keylen, nonce)) != CRYPT_OK) {
      return err;
   }

   while (ptlen > (unsigned long)ocb.block_len) {
        if ((err = ocb_encrypt(&ocb, pt, ct)) != CRYPT_OK) {
           return err;
        }
        ptlen   -= ocb.block_len;
        pt      += ocb.block_len;
        ct      += ocb.block_len;
   }

   err = ocb_done_encrypt(&ocb, pt, ptlen, ct, tag, taglen);

#ifdef CLEAN_STACK
   zeromem(&ocb, sizeof(ocb));
#endif
   return err;
}

int ocb_decrypt_verify_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  
    const unsigned char *ct,     unsigned long ctlen,
          unsigned char *pt,
    const unsigned char *tag,    unsigned long taglen,
          int           *res)
{
   int err, n;
   ocb_state ocb;

   if ((err = ocb_init(&ocb, cipher, key, keylen, nonce)) != CRYPT_OK) {
      return err;
   }

   while (ctlen > (unsigned long)ocb.block_len) {
        if ((err = ocb_decrypt(&ocb, ct, pt)) != CRYPT_OK) {
           return err;
        }
        ctlen   -= ocb.block_len;
        pt      += ocb.block_len;
        ct      += ocb.block_len;
   }

   err = ocb_done_decrypt(&ocb, ct, ctlen, pt, tag, taglen, res);

#ifdef CLEAN_STACK
   zeromem(&ocb, sizeof(ocb));
#endif
   return err;
}

int ocb_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   static const struct {
         int ptlen;
         unsigned char key[16], nonce[16], pt[32], ct[32], tag[16];
   } tests[] = {

   /* NULL message */
{
   0,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* pt */
   { 0x00 },
   /* ct */
   { 0x00 },
   /* tag */
   { 0x04, 0xad, 0xa4, 0x5e, 0x94, 0x7b, 0xc5, 0xb6,
     0xe0, 0x0f, 0x4c, 0x8b, 0x80, 0x53, 0x90, 0x2d }
},
   
   /* one byte message */
{
   1,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* pt */
   { 0x11 },
   /* ct */
   { 0x6f },
   /* tag */
   { 0xe2, 0x61, 0x42, 0x3e, 0xbb, 0x0e, 0x7f, 0x3b,
     0xa6, 0xdd, 0xf1, 0x3e, 0xe8, 0x0b, 0x7b, 0x00}
},

   /* 16 byte message */
{
   16,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* pt */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* ct */
   { 0x6a, 0xaf, 0xac, 0x40, 0x6d, 0xfa, 0x87, 0x40,
     0x57, 0xc7, 0xdb, 0xe9, 0x6f, 0x1b, 0x39, 0x53 },
   /* tag */
   { 0xff, 0xbf, 0x96, 0x87, 0x72, 0xfe, 0xee, 0x59,
     0x08, 0x1f, 0xc7, 0x8c, 0x8f, 0xd9, 0x16, 0xc2 }
},

   /* 17 byte message */
{
   17,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* pt */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10 },
   /* ct */
   { 0x8c, 0x94, 0xbd, 0xd4, 0x2d, 0xdd, 0x1c, 0x40,
     0xbe, 0xe0, 0x06, 0xb5, 0xab, 0x54, 0x3b, 0x00,
     0x20 },
   /* tag */
   { 0x0e, 0x72, 0x7c, 0x88, 0x73, 0xbb, 0x66, 0xd7,
     0x4a, 0x4f, 0xd4, 0x84, 0x83, 0xc7, 0x9a, 0x29 }
}

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
        if ((err = ocb_encrypt_authenticate_memory(idx, tests[x].key, 16,
             tests[x].nonce, tests[x].pt, tests[x].ptlen, outct, outtag, &len)) != CRYPT_OK) {
           return err;
        }
        
        if (memcmp(outtag, tests[x].tag, len) || memcmp(outct, tests[x].ct, tests[x].ptlen)) {
#if 0
           unsigned long y;
           printf("\n\nFailure: \nCT:\n");
           for (y = 0; y < (unsigned long)tests[x].ptlen; ) {
               printf("0x%02x", outct[y]);
               if (y < (unsigned long)(tests[x].ptlen-1)) printf(", ");
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
        
        if ((err = ocb_decrypt_verify_memory(idx, tests[x].key, 16, tests[x].nonce, outct, tests[x].ptlen,
             outct, tests[x].tag, len, &res)) != CRYPT_OK) {
           return err;
        }
        if (res != 1 || memcmp(tests[x].pt, outct, tests[x].ptlen)) {
#if 0
           unsigned long y;
           printf("\n\nFailure-decrypt: \nPT:\n");
           for (y = 0; y < (unsigned long)tests[x].ptlen; ) {
               printf("0x%02x", outct[y]);
               if (y < (unsigned long)(tests[x].ptlen-1)) printf(", ");
               if (!(++y % 8)) printf("\n");
           }
           printf("\nres = %d\n\n", res);
#endif
        }
    }
    return CRYPT_OK;
#endif /* LTC_TEST */
}

#endif /* OCB_MODE */


/* some comments

   -- it's hard to seek
   -- hard to stream [you can't emit ciphertext until full block]
   -- The setup is somewhat complicated...
*/
