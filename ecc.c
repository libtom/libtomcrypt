/* Implements ECC over Z/pZ for curve y^2 = x^3 - 3x + b
 *
 * All curves taken from NIST recommendation paper of July 1999
 * Available at http://csrc.nist.gov/cryptval/dss.htm
 */

#include "mycrypt.h"

#ifdef MECC

static const struct {
   int size;
   char *name, *prime, *B, *order, *Gx, *Gy;
} sets[] = {
#ifdef ECC160
{
   20,
   "ECC-160",
   /* prime */
   "1461501637330902918203684832716283019655932542983",
   /* B */
   "1C9E7C2E5891CBE097BD46",
   /* order */
   "1461501637330902918203686297565868358251373258181",
   /* Gx */
   "2DCF462904B478D868A7FF3F2BF1FCD9",
   /* Gy */
   "DFFAF2EE3848FA75FB967CEC7B9A399E085ACED8",
},
#endif
#ifdef ECC192
{  
    24,
   "ECC-192",
   /* prime */
   "6277101735386680763835789423207666416083908700390324961279",

   /* B */
   "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",

   /* order */
   "6277101735386680763835789423176059013767194773182842284081",

   /* Gx */
   "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",

   /* Gy */
   "07192b95ffc8da78631011ed6b24cdd573f977a11e794811"
},
#endif
#ifdef ECC224
{
   28,
   "ECC-224",

   /* prime */
   "26959946667150639794667015087019630673637144422540572481103610249951",

   /* B */
   "2051BA041508CED34B3",

   /* order */
   "26959946667150639794667015087019637467111563745054605861463538557247",

   /* Gx */
   "2DCF462904B478D868A7FF3F2BF1FCD9",
 
   /* Gy */
   "CF337F320BC44A15C3EDB8C4258BB958E57A0CAFA73EB46E9C4BA9AE",
},
#endif
#ifdef ECC256
{
   32,
   "ECC-256",
   /* Prime */
   "115792089210356248762697446949407573530086143415290314195533631308867097853951",

   /* B */
   "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",

   /* Order */
   "115792089210356248762697446949407573529996955224135760342422259061068512044369",

   /* Gx */
   "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",

   /* Gy */
   "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
}, 
#endif
#ifdef ECC384
{
   48,
   "ECC-384",
   /* prime */
   "394020061963944792122790401001436138050797392704654466679482934042457217714968"
   "70329047266088258938001861606973112319",

   /* B */
   "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed1"
   "9d2a85c8edd3ec2aef",

   /* Order */
   "394020061963944792122790401001436138050797392704654466679469052796276593991132"
   "63569398956308152294913554433653942643",

   /* Gx and Gy */
   "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf5529"
   "6c3a545e3872760ab7",
   "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e81"
   "9d7a431d7c90ea0e5f"
},
#endif
#ifdef ECC521
{
   65,
   "ECC-521",
   /* prime */ 
   "686479766013060971498190079908139321726943530014330540939446345918554318339765"
   "6052122559640661454554977296311391480858037121987999716643812574028291115057151",
 
   /* B */
   "051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7"
   "e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
 
   /* Order */ 
   "686479766013060971498190079908139321726943530014330540939446345918554318339765"
   "5394245057746333217197532963996371363321113864768612440380340372808892707005449",

   /* Gx and Gy */
   "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe7"
   "5928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
   "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef"
   "42640c550b9013fad0761353c7086a272c24088be94769fd16650",
},
#endif
{
   0,
   NULL, NULL, NULL, NULL, NULL, NULL
}
};

#if 0

/* you plug in a prime and B value and it finds a pseudo-random base point */
void ecc_find_base(void)
{
   static char *prime = "26959946667150639794667015087019630673637144422540572481103610249951";
   static char *order = "26959946667150639794667015087019637467111563745054605861463538557247";
   static char *b     = "9538957348957353489587";
   mp_int pp, p, r, B, tmp1, tmp2, tx, ty, x, y;
   char buf[4096];
   int i;

   mp_init_multi(&tx, &ty, &x, &y, &p, &pp, &r, &B, &tmp1, &tmp2, NULL);
   mp_read_radix(&p, prime, 10);
   mp_read_radix(&r, order, 10);
   mp_read_radix(&B, b, 10);

   /* get (p+1)/4 */
   mp_add_d(&p, 1, &pp);
   mp_div_2(&pp, &pp);
   mp_div_2(&pp, &pp);

   buf[0] = 0;
   do {
      printf("."); fflush(stdout);
      /* make a random value of x */
      for (i = 0; i < 16; i++) buf[i+1] = rand() & 255;
      mp_read_raw(&x, buf, 17);
      mp_copy(&x, &tx);

      /* now compute x^3 - 3x + b */
      mp_expt_d(&x, 3, &tmp1);
      mp_mul_d(&x, 3, &tmp2);
      mp_sub(&tmp1, &tmp2, &tmp1);
      mp_add(&tmp1, &B, &tmp1);
      mp_mod(&tmp1, &p, &tmp1);

      /* now compute sqrt via x^((p+1)/4) */
      mp_exptmod(&tmp1, &pp, &p, &tmp2);
      mp_copy(&tmp2, &ty);

      /* now square it */
      mp_sqrmod(&tmp2, &p, &tmp2);

      /* tmp2 should equal tmp1 */
   } while (mp_cmp(&tmp1, &tmp2)); 

   /* now output values in way that libtomcrypt wants */
   mp_todecimal(&p, buf);
   printf("\n\np==%s\n", buf);
   mp_tohex(&B, buf);
   printf("b==%s\n", buf);
   mp_todecimal(&r, buf);
   printf("r==%s\n", buf);
   mp_tohex(&tx, buf);
   printf("Gx==%s\n", buf);
   mp_tohex(&ty, buf);
   printf("Gy==%s\n", buf);

   mp_clear_multi(&tx, &ty, &x, &y, &p, &pp, &r, &B, &tmp1, &tmp2, NULL);
}

#endif

static int is_valid_idx(int n)
{
   int x;

   for (x = 0; sets[x].size; x++);
   if ((n < 0) || (n >= x)) {
      return 0;
   }
   return 1;
}

static ecc_point *new_point(void)
{
   ecc_point *p;
   p = XMALLOC(sizeof(ecc_point));
   if (p == NULL) {
      return NULL;
   }
   if (mp_init_multi(&p->x, &p->y, NULL) != MP_OKAY) {
      XFREE(p);
      return NULL;
   }
   return p;
}

static void del_point(ecc_point *p)
{
   mp_clear_multi(&p->x, &p->y, NULL);
   XFREE(p);
}


/* double a point R = 2P, R can be P*/
static int dbl_point(ecc_point *P, ecc_point *R, mp_int *modulus)
{
   mp_int s, tmp, tmpx;
   int res;

   if (mp_init_multi(&s, &tmp, &tmpx, NULL) != MP_OKAY) { 
      return CRYPT_MEM;
   }

   /* s = (3Xp^2 + a) / (2Yp) */
   if (mp_mul_2(&P->y, &tmp) != MP_OKAY)                   { goto error; } /* tmp = 2*y */
   if (mp_invmod(&tmp, modulus, &tmp) != MP_OKAY)          { goto error; } /* tmp = 1/tmp mod modulus */
   if (mp_sqr(&P->x,  &s) != MP_OKAY)                      { goto error; } /* s = x^2  */
   if (mp_mul_d(&s,(mp_digit)3, &s) != MP_OKAY)            { goto error; } /* s = 3*(x^2) */
   if (mp_sub_d(&s,(mp_digit)3, &s) != MP_OKAY)            { goto error; } /* s = 3*(x^2) - 3 */
   if (mp_mulmod(&s, &tmp, modulus, &s) != MP_OKAY)        { goto error; } /* s = tmp * s mod modulus */

   /* Xr = s^2 - 2Xp */
   if (mp_sqr(&s,  &tmpx) != MP_OKAY)                      { goto error; } /* tmpx = s^2  */
   if (mp_sub(&tmpx, &P->x, &tmpx) != MP_OKAY)             { goto error; } /* tmpx = tmpx - x */
   if (mp_submod(&tmpx, &P->x, modulus, &tmpx) != MP_OKAY) { goto error; } /* tmpx = tmpx - x mod modulus */

   /* Yr = -Yp + s(Xp - Xr)  */
   if (mp_sub(&P->x, &tmpx, &tmp) != MP_OKAY)              { goto error; } /* tmp = x - tmpx */
   if (mp_mul(&tmp, &s, &tmp) != MP_OKAY)                  { goto error; } /* tmp = tmp * s */
   if (mp_submod(&tmp, &P->y, modulus, &R->y) != MP_OKAY)  { goto error; } /* y = tmp - y mod modulus */
   if (mp_copy(&tmpx, &R->x) != MP_OKAY)                   { goto error; } /* x = tmpx */

   res = CRYPT_OK;
   goto done;
error:
   res = CRYPT_MEM;
done:
   mp_clear_multi(&tmpx, &tmp, &s, NULL);
   return res;
}

/* add two different points over Z/pZ, R = P + Q, note R can equal either P or Q */
static int add_point(ecc_point *P, ecc_point *Q, ecc_point *R, mp_int *modulus)
{
   mp_int s, tmp, tmpx;
   int res;

   if (mp_init(&tmp) != MP_OKAY) { 
      return CRYPT_MEM;
   }

   /* is P==Q or P==-Q? */
   mp_neg(&Q->y, &tmp);
   mp_mod(&tmp, modulus, &tmp);
   if (!mp_cmp(&P->x, &Q->x))
      if (!mp_cmp(&P->y, &Q->y) || !mp_cmp(&P->y, &tmp)) {
         mp_clear(&tmp);
         return dbl_point(P, R, modulus);
      }

   if (mp_init_multi(&tmpx, &s, NULL) != MP_OKAY) { 
      mp_clear(&tmp);
      return CRYPT_MEM;
   }

   /* get s = (Yp - Yq)/(Xp-Xq) mod p */
   if (mp_submod(&P->x, &Q->x, modulus, &tmp) != MP_OKAY)     { goto error; } /* tmp = Px - Qx mod modulus */
   if (mp_invmod(&tmp, modulus, &tmp) != MP_OKAY)             { goto error; } /* tmp = 1/tmp mod modulus */
   if (mp_sub(&P->y, &Q->y, &s) != MP_OKAY)                   { goto error; } /* s = Py - Qy mod modulus */
   if (mp_mulmod(&s, &tmp, modulus, &s) != MP_OKAY)           { goto error; } /* s = s * tmp mod modulus */

   /* Xr = s^2 - Xp - Xq */
   if (mp_sqrmod(&s, modulus, &tmp) != MP_OKAY)               { goto error; } /* tmp = s^2 mod modulus */
   if (mp_sub(&tmp, &P->x, &tmp) != MP_OKAY)                  { goto error; } /* tmp = tmp - Px */
   if (mp_sub(&tmp, &Q->x, &tmpx) != MP_OKAY)                 { goto error; } /* tmpx = tmp - Qx */

   /* Yr = -Yp + s(Xp - Xr) */
   if (mp_sub(&P->x, &tmpx, &tmp) != MP_OKAY)                 { goto error; } /* tmp = Px - tmpx */
   if (mp_mul(&tmp, &s, &tmp) != MP_OKAY)                     { goto error; } /* tmp = tmp * s */
   if (mp_submod(&tmp, &P->y, modulus, &R->y) != MP_OKAY)     { goto error; } /* Ry = tmp - Py mod modulus */
   if (mp_mod(&tmpx, modulus, &R->x) != MP_OKAY)              { goto error; } /* Rx = tmpx mod modulus */

   res = CRYPT_OK;
   goto done;
error:
   res = CRYPT_MEM;
done:
   mp_clear_multi(&s, &tmpx, &tmp, NULL);
   return res;
}

/* perform R = kG where k == integer and G == ecc_point */
static int ecc_mulmod(mp_int *k, ecc_point *G, ecc_point *R, mp_int *modulus, int idx)
{
   ecc_point *tG;
   int i, j, z, first, res;
   mp_digit d;
   unsigned char bits[768];
   
   /* get bits of k */
   for (z = i = 0; z < (int)USED(k); z++) {
       d = DIGIT(k, z);
       
#define DO1 bits[i++] = d&1; d >>= 1;
#define DO2 DO1 DO1
#define DO4 DO2 DO2

       DO4; DO4; DO4; DO4

#undef DO4
#undef DO2
#undef DO1
   }

   /* make a copy of G incase R==G */
   tG = new_point();
   if (tG == NULL) { 
      return CRYPT_MEM;
   }

   /* tG = G */
   if (mp_copy(&G->x, &tG->x) != MP_OKAY)     { goto error; }
   if (mp_copy(&G->y, &tG->y) != MP_OKAY)     { goto error; }

   /* set result to G, R = G */
   if (mp_copy(&G->x, &R->x) != MP_OKAY)      { goto error; }
   if (mp_copy(&G->y, &R->y) != MP_OKAY)      { goto error; }
   first = 0;

   /* now do dbl+add through all the bits */
   for (j = i-1; j >= 0; j--) {
       if (first) {
           if (dbl_point(R, R, modulus) != CRYPT_OK)       { goto error; }
       }
       if (bits[j] == 1) {
          if (first) {
             if (add_point(R, tG, R, modulus) != CRYPT_OK) { goto error; }
          }
          first = 1;
       }
   }
   res = CRYPT_OK; 
   goto done;
error:
   res = CRYPT_MEM;
done:
   del_point(tG);
#ifdef CLEAN_STACK
   zeromem(bits, sizeof(bits)); 
#endif
   return res;
}

int ecc_test(void)
{
   mp_int     modulus, order;
   ecc_point  *G, *GG;
   int i, res, primality;

   if (mp_init_multi(&modulus, &order, NULL) != MP_OKAY) { 
      return CRYPT_MEM;
   }

   G   = new_point();
   if (G == NULL) { 
      mp_clear_multi(&modulus, &order, NULL);
      return CRYPT_MEM;
   }

   GG  = new_point();
   if (GG == NULL) { 
      mp_clear_multi(&modulus, &order, NULL);
      del_point(G);
      return CRYPT_MEM;
   }

   for (i = 0; sets[i].size; i++) {
       if (mp_read_radix(&modulus, (unsigned char *)sets[i].prime, 10) != MP_OKAY)   { goto error; }
       if (mp_read_radix(&order, (unsigned char *)sets[i].order, 10) != MP_OKAY)     { goto error; }

       /* is prime actually prime? */
       if (is_prime(&modulus, &primality) != CRYPT_OK)           { goto error; }
       if (primality == 0) {
          res = CRYPT_FAIL_TESTVECTOR;
          goto done1;
       }
  
       /* is order prime ? */
       if (is_prime(&order, &primality) != CRYPT_OK)             { goto error; }
       if (primality == 0) {
          res = CRYPT_FAIL_TESTVECTOR;
          goto done1;
       }

       if (mp_read_radix(&G->x, (unsigned char *)sets[i].Gx, 16) != MP_OKAY) { goto error; }
       if (mp_read_radix(&G->y, (unsigned char *)sets[i].Gy, 16) != MP_OKAY) { goto error; }

       /* then we should have G == (order + 1)G */
       if (mp_add_d(&order, 1, &order) != MP_OKAY)                  { goto error; }
       if (ecc_mulmod(&order, G, GG, &modulus, i) != CRYPT_OK)      { goto error; }
       if (mp_cmp(&G->x, &GG->x) || mp_cmp(&G->y, &GG->y)) {
          res = CRYPT_FAIL_TESTVECTOR;
          goto done1;
       }
   }
   res = CRYPT_OK;
   goto done1;
error:
   res = CRYPT_MEM;
done1:
   del_point(GG);
   del_point(G);
   mp_clear_multi(&order, &modulus, NULL);
   return res;
}

void ecc_sizes(int *low, int *high)
{
 int i;
 _ARGCHK(low != NULL);
 _ARGCHK(high != NULL);

 *low = INT_MAX;
 *high = 0;
 for (i = 0; sets[i].size; i++) {
     if (sets[i].size < *low)  { 
        *low  = sets[i].size; 
     }
     if (sets[i].size > *high) { 
        *high = sets[i].size; 
     }
 }
}

int ecc_make_key(prng_state *prng, int wprng, int keysize, ecc_key *key)
{
   int x, res, errno;
   ecc_point *base;
   mp_int prime;
   unsigned char buf[4096];

   _ARGCHK(key != NULL);

   /* good prng? */
   if ((errno = prng_is_valid(wprng)) != CRYPT_OK) {
      return errno;
   }

   /* find key size */
   for (x = 0; (keysize > sets[x].size) && (sets[x].size); x++);
   keysize = sets[x].size;

   if (sets[x].size == 0) { 
      return CRYPT_INVALID_KEYSIZE;
   }
   key->idx = x;

   /* make up random string */
   buf[0] = 0;
   if (prng_descriptor[wprng].read(buf+1, keysize, prng) != (unsigned long)keysize) {
      return CRYPT_ERROR_READPRNG;
   }

   /* setup the key variables */
   if (mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->k, &prime, NULL) != MP_OKAY) { 
      return CRYPT_MEM;
   }
   base = new_point();
   if (base == NULL) {
      mp_clear_multi(&key->pubkey.x, &key->pubkey.y, &key->k, &prime, NULL);
      return CRYPT_MEM;
   }

   /* read in the specs for this key */
   if (mp_read_radix(&prime, (unsigned char *)sets[x].prime, 10) != MP_OKAY)  { goto error; }
   if (mp_read_radix(&base->x, (unsigned char *)sets[x].Gx, 16) != MP_OKAY)   { goto error; }
   if (mp_read_radix(&base->y, (unsigned char *)sets[x].Gy, 16) != MP_OKAY)   { goto error; }
   if (mp_read_raw(&key->k, (unsigned char *)buf, keysize+1) != MP_OKAY)      { goto error; }

   /* make the public key */
   if (ecc_mulmod(&key->k, base, &key->pubkey, &prime, x) != CRYPT_OK) { goto error; }
   key->type = PK_PRIVATE;

   /* free up ram */
   res = CRYPT_OK;
   goto done;
error:
   res = CRYPT_MEM;
done:
   del_point(base);
   mp_clear(&prime);
#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return res;
}

void ecc_free(ecc_key *key)
{
   _ARGCHK(key != NULL);
   mp_clear_multi(&key->pubkey.x, &key->pubkey.y, &key->k, NULL);
}

static int compress_y_point(ecc_point *pt, int idx, int *result)
{
   mp_int tmp, tmp2, p;
   int res;

   _ARGCHK(pt != NULL);
   _ARGCHK(result != NULL);

   if (mp_init_multi(&tmp, &tmp2, &p, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }

   /* get x^3 - 3x + b */
   if (mp_read_radix(&p, (unsigned char *)sets[idx].B, 16) != MP_OKAY) { goto error; } /* p = B */
   if (mp_expt_d(&pt->x, 3, &tmp) != MP_OKAY)              { goto error; } /* tmp = pX^3  */
   if (mp_mul_d(&pt->x, 3, &tmp2) != MP_OKAY)              { goto error; } /* tmp2 = 3*pX^3 */
   if (mp_sub(&tmp, &tmp2, &tmp) != MP_OKAY)               { goto error; } /* tmp = tmp - tmp2 */
   if (mp_add(&tmp, &p, &tmp) != MP_OKAY)                  { goto error; } /* tmp = tmp + p */
   if (mp_read_radix(&p, (unsigned char *)sets[idx].prime, 10) != MP_OKAY)  { goto error; } /* p = prime */
   if (mp_mod(&tmp, &p, &tmp) != MP_OKAY)                  { goto error; } /* tmp = tmp mod p */

   /* now find square root */
   if (mp_add_d(&p, 1, &tmp2) != MP_OKAY)                  { goto error; } /* tmp2 = p + 1 */
   if (mp_div_2(&tmp2, &tmp2) != MP_OKAY)                  { goto error; } /* tmp2 = tmp2/2 */
   if (mp_div_2(&tmp2, &tmp2) != MP_OKAY)                  { goto error; } /* tmp2 = (p+1)/4 */
   if (mp_exptmod(&tmp, &tmp2, &p, &tmp) != MP_OKAY)       { goto error; } /* tmp  = (x^3 - 3x + b)^((p+1)/4) mod p */

   /* if tmp equals the y point give a 0, otherwise 1 */
   if (mp_cmp(&tmp, &pt->y) == 0) { 
      *result = 0;
   } else {
      *result = 1;
   }
   
   res = CRYPT_OK;
   goto done;
error:
   res = CRYPT_MEM;
done:
   mp_clear_multi(&p, &tmp, &tmp2, NULL);
   return res;
}

static int expand_y_point(ecc_point *pt, int idx, int result)
{
   mp_int tmp, tmp2, p;
   int res;

   _ARGCHK(pt != NULL);
 
   if (mp_init_multi(&tmp, &tmp2, &p, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }

   /* get x^3 - 3x + b */
   if (mp_read_radix(&p, (unsigned char *)sets[idx].B, 16) != MP_OKAY) { goto error; } /* p = B */
   if (mp_expt_d(&pt->x, 3, &tmp) != MP_OKAY)              { goto error; } /* tmp = pX^3 */
   if (mp_mul_d(&pt->x, 3, &tmp2) != MP_OKAY)              { goto error; } /* tmp2 = 3*pX^3 */
   if (mp_sub(&tmp, &tmp2, &tmp) != MP_OKAY)               { goto error; } /* tmp = tmp - tmp2 */
   if (mp_add(&tmp, &p, &tmp) != MP_OKAY)                  { goto error; } /* tmp = tmp + p */
   if (mp_read_radix(&p, (unsigned char *)sets[idx].prime, 10) != MP_OKAY)  { goto error; } /* p = prime */
   if (mp_mod(&tmp, &p, &tmp) != MP_OKAY)                  { goto error; } /* tmp = tmp mod p */

   /* now find square root */
   if (mp_add_d(&p, 1, &tmp2) != MP_OKAY)                  { goto error; } /* tmp2 = p + 1 */
   if (mp_div_2(&tmp2, &tmp2) != MP_OKAY)                  { goto error; } /* tmp2 = tmp2/2 */
   if (mp_div_2(&tmp2, &tmp2) != MP_OKAY)                  { goto error; } /* tmp2 = (p+1)/4 */
   if (mp_exptmod(&tmp, &tmp2, &p, &tmp) != MP_OKAY)       { goto error; } /* tmp  = (x^3 - 3x + b)^((p+1)/4) mod p */

   /* if result==0, then y==tmp, otherwise y==p-tmp */
   if (result == 0) {
      if (mp_copy(&tmp, &pt->y) != MP_OKAY) { goto error; }
   } else {
      if (mp_sub(&p, &tmp, &pt->y) != MP_OKAY) { goto error; }
   }
   
   res = CRYPT_OK;
   goto done;
error:
   res = CRYPT_MEM;
done:
   mp_clear_multi(&p, &tmp, &tmp2, NULL);
   return res;
}

#define OUTPUT_BIGNUM(num, buf2, y, z)         \
{                                              \
      z = mp_raw_size(num);                    \
      STORE32L(z, buf2+y);                     \
      y += 4;                                  \
      mp_toraw(num, buf2+y);                   \
      y += z;                                  \
}


#define INPUT_BIGNUM(num, in, x, y)                              \
{                                                                \
     /* load value */                                            \
     LOAD32L(x, in+y);                                           \
     y += 4;                                                     \
                                                                 \
     /* sanity check... */                                       \
     if (x > 1024) {                                             \
        goto error;                                              \
     }                                                           \
                                                                 \
     /* load it */                                               \
     if (mp_read_raw(num, (unsigned char *)in+y, x) != MP_OKAY) {\
        goto error;                                              \
     }                                                           \
     y += x;                                                     \
}

int ecc_export(unsigned char *out, unsigned long *outlen, int type, ecc_key *key)
{
   unsigned long y, z;
   int res, errno;
   unsigned char buf2[512];

   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key != NULL);

   /* type valid? */
   if (key->type != PK_PRIVATE && type == PK_PRIVATE) { 
      return CRYPT_PK_TYPE_MISMATCH; 
   }

   /* output type and magic byte */
   y = PACKET_SIZE;
   buf2[y++] = type;
   buf2[y++] = key->idx;

   /* output x coordinate */
   OUTPUT_BIGNUM(&(key->pubkey.x), buf2, y, z);

   /* compress y and output it  */
   if ((errno = compress_y_point(&key->pubkey, key->idx, &res)) != CRYPT_OK) {
      return errno;
   }
   buf2[y++] = res;

   if (type == PK_PRIVATE) {
      OUTPUT_BIGNUM(&key->k, buf2, y, z);
   }

   /* check size */
   if (*outlen < y) { 
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* store header */
   packet_store_header(buf2, PACKET_SECT_ECC, PACKET_SUB_KEY, y);

   memcpy(out, buf2, y);
   *outlen = y;

   #ifdef CLEAN_STACK
       zeromem(buf2, sizeof(buf2));
   #endif
   return CRYPT_OK;
}

int ecc_import(const unsigned char *in, ecc_key *key)
{
   unsigned long x, y;
   int res, errno;

   _ARGCHK(in != NULL);
   _ARGCHK(key != NULL);

   /* check type */
   if ((errno = packet_valid_header((unsigned char *)in, PACKET_SECT_ECC, PACKET_SUB_KEY)) != CRYPT_OK) { 
      return errno;
   }

   /* init key */
   if (mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->k, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }

   y = PACKET_SIZE;
   key->type = in[y++];
   key->idx  = in[y++];

   /* type check both values */
   if ((key->type != PK_PUBLIC) && (key->type != PK_PRIVATE))  {
      res = CRYPT_INVALID_PACKET;
      goto error2;
   }

   /* is the key idx valid? */
   if (!is_valid_idx(key->idx)) {
      res = CRYPT_INVALID_PACKET;
      goto error2;
   }

   /* load x coordinate */
   INPUT_BIGNUM(&key->pubkey.x, in, x, y);
  
   /* load y */
   x = in[y++];
   if ((errno = expand_y_point(&key->pubkey, key->idx, x)) != CRYPT_OK) { res = errno; goto error2; }

   if (key->type == PK_PRIVATE) {
      /* load private key */
      INPUT_BIGNUM(&key->k, in, x, y);
   }
   res = CRYPT_OK;
   goto done;
error:
   res = CRYPT_MEM;
error2:
   mp_clear_multi(&key->pubkey.x, &key->pubkey.y, &key->k, NULL);
done:
   return res;
}

int ecc_shared_secret(ecc_key *private_key, ecc_key *public_key, 
                      unsigned char *out, unsigned long *outlen)
{
   unsigned long x, y;
   ecc_point *result;
   mp_int prime;
   int res, errno;

   _ARGCHK(private_key != NULL);
   _ARGCHK(public_key != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   /* type valid? */
   if (private_key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   if (private_key->idx != public_key->idx) {
      return CRYPT_PK_TYPE_MISMATCH;
   }

   /* make new point */
   result = new_point();
   if (result == NULL) { 
      return CRYPT_MEM;
   }

   if (mp_init(&prime) != MP_OKAY) { 
      del_point(result);
      return CRYPT_MEM;
   }

   if (mp_read_radix(&prime, (unsigned char *)sets[private_key->idx].prime, 10) != MP_OKAY) { goto error; }
   if ((errno = ecc_mulmod(&private_key->k, &public_key->pubkey, result, &prime, private_key->idx)) != CRYPT_OK) { res = errno; goto done1; }

   x = mp_raw_size(&result->x);
   y = mp_raw_size(&result->y);

   if (*outlen < (x+y)) {
      res = CRYPT_BUFFER_OVERFLOW;
      goto done1;
   }
   *outlen = x+y;
   mp_toraw(&result->x, out);
   mp_toraw(&result->y, out+x);

   res = CRYPT_OK;
   goto done1;
error:
   res = CRYPT_MEM;
done1:
   mp_clear(&prime);
   del_point(result);
   return res;
}

int ecc_get_size(ecc_key *key)
{
   _ARGCHK(key != NULL);
   if (is_valid_idx(key->idx))
      return sets[key->idx].size;
   else
      return INT_MAX; /* large value known to cause it to fail when passed to ecc_make_key() */
}

#include "ecc_sys.c"

#endif


