/* Implementation of the Digital Signature Algorithm (DSA) by Tom St Denis */
#ifdef MDSA

#include <mycrypt.h>

static const struct {
    int   size, osize;
    char *order,
         *prime,
         *base;
} sets[] = {
#ifdef DSA1024
{
    1024, 160, 

    "PE6GbKzFwpeAAMtC3PUsqsRQMWl",

    "PyhJv87GTec3fBvC8BQT4yQ8gSYB8rk6DfLRfeirnZsQaQBVwh8PZ7V1hKfD"
	"SGGUgr1cAb3YrnZw97HvyaKmypY2dM19OxeNWNI4f6IyYwj/mcAiJpkjxMmZ"
    "mYVrTbGxBG8OaKBD9vFd9/Jif8djJ18GnaRsdRoCBDec+W++x6D",
    
    "3uYLnHhrVRR6hATv30lj/XX5AecEE2tJVgtWcHkbwKuR3WEqqvP8xBUG70Ve"
	"p6kUchz/E/kZaGIJ0mrqme6bNDIxoNqtshyDfska/Zfm/QHuDZWljVGbPx68"
    "eSBw1vzkRKFCmR8QgpT+R887JufEgQRRIQOuLK8c1ND61efJH2t"
},
#endif
#ifdef DSA2048
{
    2048, 256,
    
    "TZLgPgD7D46uoATLyNSgKsgh6LglcVDwlPFvT6dcOdN",
    
    "EUlAFvO8lXjhXn/6BobNq4bo0st12+zwgpshNJgoUap/LFCQcGeVGt/s/ocD"
	"M+4v+bU3dNKjFJEYzb+sxmy5dbzQsa15+Ud4v1UJ/7D4p0IyA+h9aeU9i/C9"
	"tJQC824mQhmL5cxx7SbQPMD/2+P04hLyeDOir1L1vmvE1tWZg43Jbza2LTQJ"
	"52wi/Sguai3vFZVMObEPBfbXzg9b8pH1i75Q1os9w0LtfJ4pYQJD3Xn66jYF"
	"mpLVqK4yuMXOOq07bkM5Nx+jQvFpGuRiD5e4a2FB1NjXbCGMtRxu6eurPAIY"
    "F5dw3QWXkZm74SFmLTi0GW+3pipDWiBSUu9pUpp6rr",
    
    "79PG50FKgZgffOnFiUuuZLhWicqFZ6EwvWXQi7uBmvMQUoXNEBschAhRtLQE"
	"ev5iHrR2g41rEEundwwFTbRdyq2txBS2bClkFjGlojPwayWvXLAaDltfkhws"
	"TjS/gNKch4qD1nPu+Kd1RmjWp1B1JzBXnlcj/z5qMaF8oL4bk9qGGEmaeOLs"
	"90vW0Z/7QWBC8h+65SohFBmydUWwXhs4rAa7NwHbPltnXdF6kZHpQOtT5h+4"
	"hYA83eYzdeOl5rYrFDiyJ+nfOptgLiLIHB9L0wkOhFrb52+S7qKpgYe1+oof"
    "K1/Rd4D8fL5qvGyXWz1dB8W2iqAXeXKlkWZrvHQdMM"
},
#endif
#ifdef DSA4096
{
    4096, 512,
    
    "4GO4hUY+2MqiwNBYFx/JqRejRKXXJfcaY7mIBYksn2Dwn6JQZp9Qpg3bbnOJ"
    "kt5ZqH2dtEjbV9B/AXF51jOkW/",
    
    "Jddrq1iN+f03IKVqcDSOz7IquBVxzb34Cwzmc7rHpIOW3DqW7IjMz47ETtWu"
	"KvG3JxFdYaiv69lAE+X38DEqQSTE8Ba9jfNYs9PYeH4RfsT5op/u3r41anRW"
	"jJTHMhnvwwQ0eQrZ+9d7LQePnQSUs3eXb8ZdNsh8/h30b3gIMk+08bZoJejF"
	"6Y2vMtMQUHmmoM/+IlrMz7TZ4tu0jkYWBp1y74WLGemXkYvU6pqH8dTQX1MM"
	"oG93eBKQ87jHbtBJ+L6EbcqO/jVa6lwUivEbBs9UtKf4lC0pe3SZqfFhrJde"
	"2b5LfbPBLk2pNdC5MJCsIVz7TUL28SWYwx7Nx7ybxtKd76L8kgbLfoOYiJRx"
	"WIFGRE40Q9/0zuqzz6D1WHKQE4wg5oy6WQeO3Q5BN1UC6O4EUSkD7mC3KmWA"
	"MgxNDZYMA+BSCTirVL2eS90WCA4LkTsHhoLgafwZT5xanUKGY/cZix29sy21"
	"J1Ut4cbPFjxg76OVu9obONitMLg+63dz3Ho8LMhXaKN43yl5Kc4PxeUCQWVU"
	"gHXg8RSldQMOvhwohHFibiMUrRkkCs2//Ts6hVdS3cEFgfYhpnzeEiGBCuat"
	"ZZYpaWKZlmrlcUYH7Rg9SyHH1h4DLrki5ySIjGxozT6JhIrMme8uQcN9YOiq"
    "GwRhjR3AM1QiOUfolENTYCn",
    
    "3VIJLic34uyamh2TbNHEjECeH289m938S2wvHYe/3xPNiCjVhBxl6RAgom+Q"
	"3X7+r8EII4QQKXXdqR3Ad/nXzJkgMUJVvt5d5lIwwKM7+ffbLmhJWldO0Jkc"
	"7oZQr7t81khBUG4wgPVZO8OwjB66v9npPCcBLNLO6DAWE82CM8YfPJzQt0tr"
	"JSHwcgixvkFft25SdI0V9zg2H6sj2Q/yAYUEAPzyDfQVvLzqEN2tmIhturnR"
	"wUW4WLy8PSls/tt5eWjdI++ofdGHNJmKaZjHgym52GhNQmWZYWzK/hcllWtC"
	"U8vCw7GY3nE4uF74YuTYC6LGx7wXS5ivj531KTPe4EarZ4j+aVw9ZJhfy/h+"
	"K0esj9ALQP9jSz3OMDKeYaJKjj/scC5NrPdSjeJf7EvlVf41ufZHNGrFVmVW"
	"kqaEuNZr+SmC6/2buPEmL4UO94H1z4QItK+rHqNWEQP6ptST0lcFwHO4uESR"
	"qp8scA2/Fh+G0TfJ/rg8wImqbWsgrUwGnmDmKtFLRiX4aMPIsyFIsJvPQECT"
	"EIR6yd6QIRVGZbCRiVsCqMrHsn0KZWSeKdtW9TRt/yNu+VKcgRZFfU991Nab"
	"OBxkAS1kw9kyj/HZYxPG4NrqL0j5bnb1VjqQZKEEQMSBAyMMfDuMyWhrmsxV"
    "ffmF/sYGxFHCbacGeu06C3U"
},
#endif
{
    0, 0,
    NULL,
    NULL,
    NULL
}
};

int dsa_test(void)
{
   mp_int q, p, g, t;
   int errno, i, res, primality;
   
   /* init memory */
   if (mp_init_multi(&q, &p, &g, &t, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }
   
   res = CRYPT_MEM;
   for (i = 0; i < sets[i].size; i++) {
   #if 0
       printf("Testing size: %d\n", sets[i].size);
   #endif
       /* read in order, prime, generator */
       if (mp_read_radix(&q, sets[i].order, 64) != MP_OKAY)       { goto error; }
       if (mp_read_radix(&p, sets[i].prime, 64) != MP_OKAY)       { goto error; }
       if (mp_read_radix(&g, sets[i].base, 64) != MP_OKAY)        { goto error; }
       
       /* now see if the order and modulus are prime */
       if ((errno = is_prime(&q, &primality)) != CRYPT_OK) {
          res = errno;
          goto error;
       }
       if (primality == 0) {
          res = CRYPT_FAIL_TESTVECTOR;
          goto error;
       }
       
       if ((errno = is_prime(&p, &primality)) != CRYPT_OK) {
          res = errno;
          goto error;
       }
       if (primality == 0) {
          res = CRYPT_FAIL_TESTVECTOR;
          goto error;
       }
       
       /* now see what g^q mod p is (should be 1) */
       if (mp_exptmod(&g, &q, &p, &t) != MP_OKAY)                { goto error; }
       if (mp_cmp_d(&t, 1)) {
          res = CRYPT_FAIL_TESTVECTOR;
          goto error;
       }
   }
   res = CRYPT_OK;
error:
   mp_clear_multi(&t, &g, &p, &q, NULL);
   return res;
}

int dsa_make_key(prng_state *prng, int wprng, int keysize, dsa_key *key)
{
   mp_int g, p, q;
   unsigned char buf[64];
   int errno, idx, x;
   
   _ARGCHK(prng != NULL);
   _ARGCHK(key != NULL);
   
   /* good prng? */
   if ((errno = prng_is_valid(wprng)) != CRYPT_OK) {
      return errno;
   }

   /* find key size */
   for (x = 0; (keysize > sets[x].size) && (sets[x].size); x++);
   if (sets[x].size == 0) {
      return CRYPT_INVALID_KEYSIZE;
   }
   key->idx = x;
   keysize = sets[x].osize;

   /* read prng */
   if (prng_descriptor[wprng].read(buf, keysize, prng) != (unsigned long)keysize) {
      return CRYPT_ERROR_READPRNG;
   }
   
   /* init parameters */
   if (mp_init_multi(&g, &p, &q, &key->x, &key->y, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }
   if (mp_read_radix(&q, sets[x].order, 64) != MP_OKAY)            { goto error; }
   if (mp_read_radix(&g, sets[x].base, 64) != MP_OKAY)             { goto error; }
   if (mp_read_radix(&p, sets[x].prime, 64) != MP_OKAY)            { goto error; }
   
   /* load exponent */
   if (mp_read_unsigned_bin(&key->x, buf, keysize) != MP_OKAY)     { goto error; }
   if (mp_mod(&key->x, &q, &key->x) != MP_OKAY)                    { goto error; }
   
   /* calc public key */
   if (mp_exptmod(&g, &key->x, &p, &key->y) != MP_OKAY)            { goto error; }
   key->type = PK_PRIVATE;
   
   /* shrink values */
   if (mp_shrink(&key->x) != MP_OKAY)                              { goto error; }
   if (mp_shrink(&key->y) != MP_OKAY)                              { goto error; }
   
   /* free temps */
   mp_clear_multi(&g, &q, &p, NULL);
#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif

   return CRYPT_OK;
error:
   mp_clear_multi(&g, &q, &p, &key->x, &key->y, NULL);
   return CRYPT_MEM;
}

void dsa_free(dsa_key *key)
{
   _ARGCHK(key != NULL);
   mp_clear_multi(&key->x, &key->y, NULL);
}

static int is_valid_idx(int n)
{
   int x;

   for (x = 0; sets[x].size; x++);
   if ((n < 0) || (n >= x)) {
      return 0;
   }
   return 1;
}

int dsa_export(unsigned char *out, unsigned long *outlen, int type, dsa_key *key)
{
   unsigned char buf[4096];
   unsigned long x, y;
   
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key != NULL);
   
   if (is_valid_idx(key->idx) == 0) {
      return CRYPT_PK_INVALID_TYPE;
   }
   
   if (type == PK_PRIVATE && key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }
   
   y = PACKET_SIZE;
   
   buf[y++] = type;
   buf[y++] = sets[key->idx].osize/8;
   
   x = mp_unsigned_bin_size(&key->y);
   STORE32L(x, &buf[y]);
   y += 4;
   mp_to_unsigned_bin(&key->y, &buf[y]);
   y += x;
   
   if (type == PK_PRIVATE) {
      x = mp_unsigned_bin_size(&key->x);
      STORE32L(x, &buf[y]);
      y += 4;
      mp_to_unsigned_bin(&key->x, &buf[y]);
      y += x;
   }
      
   /* check for overflow */
   if (*outlen < y) {
      #ifdef CLEAN_STACK
         zeromem(buf, sizeof(buf));
      #endif
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* store header */
   packet_store_header(buf, PACKET_SECT_DSA, PACKET_SUB_KEY);

   /* output it */
   *outlen = y;
   memcpy(out, buf, y);

   /* clear mem */
#ifdef CLEAN_STACK   
   zeromem(buf, sizeof(buf));
#endif   
   return CRYPT_OK;
}

#define INPUT_BIGNUM(num, in, x, y)                              \
{                                                                \
     /* load value */                                            \
     if (y + 4 > inlen) {                                        \
        errno = CRYPT_INVALID_PACKET;                            \
        goto error;                                              \
     }                                                           \
     LOAD32L(x, in+y);                                           \
     y += 4;                                                     \
                                                                 \
     /* sanity check... */                                       \
     if (x+y > inlen) {                                          \
        errno = CRYPT_INVALID_PACKET;                            \
        goto error;                                              \
     }                                                           \
                                                                 \
     /* load it */                                               \
     if (mp_read_unsigned_bin(num, (unsigned char *)in+y, x) != MP_OKAY) {\
        errno =  CRYPT_MEM;                                      \
        goto error;                                              \
     }                                                           \
     y += x;                                                     \
     if (mp_shrink(num) != MP_OKAY) {                            \
        errno = CRYPT_MEM;                                       \
        goto error;                                              \
     }                                                           \
}

int dsa_import(const unsigned char *in, unsigned long inlen, dsa_key *key)
{
   unsigned long x, y, s;
   int errno;

   _ARGCHK(in != NULL);
   _ARGCHK(key != NULL);

   /* check type byte */
   if ((errno = packet_valid_header((unsigned char *)in, PACKET_SECT_DSA, PACKET_SUB_KEY)) != CRYPT_OK) {
      return errno;
   }
   
   if (2+PACKET_SIZE > inlen) {
      return CRYPT_INVALID_PACKET;
   }


   /* init */
   if (mp_init_multi(&key->x, &key->y, NULL) != MP_OKAY) { 
      return CRYPT_MEM;
   }

   y = PACKET_SIZE;
   key->type = in[y++];
   s  = (long)in[y++] * 8;
   
   for (x = 0; (s > (unsigned long)sets[x].osize) && (sets[x].osize); x++);
   if (sets[x].osize == 0) {
      errno = CRYPT_INVALID_KEYSIZE;
      goto error;
   }
   key->idx = x;

   /* type check both values */
   if ((key->type != PK_PUBLIC) && (key->type != PK_PRIVATE))  {
      errno = CRYPT_PK_TYPE_MISMATCH;
      goto error;
   }

   /* is the key idx valid? */
   if (!is_valid_idx(key->idx)) {
      errno = CRYPT_PK_TYPE_MISMATCH;
      goto error;
   }

   /* load public value g^x mod p*/
   INPUT_BIGNUM(&key->y, in, x, y);

   if (key->type == PK_PRIVATE) {
      INPUT_BIGNUM(&key->x, in, x, y);
   }

   /* eliminate private key if public */
   if (key->type == PK_PUBLIC) {
      mp_clear(&key->x);
   }      

   return CRYPT_OK;
error:
   mp_clear_multi(&key->y, &key->x, NULL);
   return errno;
}
   
   

int dsa_sign_hash(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        prng_state *prng, int wprng, dsa_key *key)
{
    mp_int g, q, p, k, tmp;
    unsigned char buf[4096];
    int x, y, errno;
    
    _ARGCHK(in != NULL);
    _ARGCHK(out != NULL);
    _ARGCHK(outlen != NULL);
    _ARGCHK(prng != NULL);
    _ARGCHK(key != NULL);
    
    if ((errno = prng_is_valid(wprng)) != CRYPT_OK) {
       return errno;
    }
    
    if (is_valid_idx(key->idx) == 0) {
       return CRYPT_PK_INVALID_TYPE;
    }

return 0;
}



#endif /* MDSA */

