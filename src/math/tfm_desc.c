/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.org
 */

#define DESC_DEF_ONLY
#include "tomcrypt.h"

#ifdef TFM_DESC

#include <tfm.h>

static const struct {
    int tfm_code, ltc_code;
} tfm_to_ltc_codes[] = {
   { FP_OKAY ,  CRYPT_OK},
   { FP_MEM  ,  CRYPT_MEM},
   { FP_VAL  ,  CRYPT_INVALID_ARG},
};

/**
   Convert a tfm error to a LTC error (Possibly the most powerful function ever!  Oh wait... no) 
   @param err    The error to convert
   @return The equivalent LTC error code or CRYPT_ERROR if none found
*/
static int tfm_to_ltc_error(int err)
{
   int x;

   for (x = 0; x < (int)(sizeof(tfm_to_ltc_codes)/sizeof(tfm_to_ltc_codes[0])); x++) {
       if (err == tfm_to_ltc_codes[x].tfm_code) { 
          return tfm_to_ltc_codes[x].ltc_code;
       }
   }
   return CRYPT_ERROR;
}

static int init(void **a)
{
   LTC_ARGCHK(a != NULL);

   *a = XCALLOC(1, sizeof(fp_int));
   if (*a == NULL) {
      return CRYPT_MEM;
   }
   fp_init(*a);
   return CRYPT_OK;
}

static void deinit(void *a)
{
   LTC_ARGCHK(a != NULL);
   XFREE(a);
}

static int neg(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_neg(((fp_int*)a), ((fp_int*)b));
   return CRYPT_OK;
}

static int copy(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_copy(a, b);
   return CRYPT_OK;
}

static int init_copy(void **a, void *b)
{
   if (init(a) != CRYPT_OK) {
      return CRYPT_MEM;
   }
   return copy(b, *a);
}

/* ---- trivial ---- */
static int set_int(void *a, unsigned long b)
{
   LTC_ARGCHK(a != NULL);
   fp_set(a, b);
   return CRYPT_OK;
}

static unsigned long get_int(void *a)
{
   fp_int *A;
   LTC_ARGCHK(a != NULL);
   A = a;
   return A->used > 0 ? A->dp[0] : 0;
}

static unsigned long get_digit(void *a, int n)
{
   fp_int *A;
   LTC_ARGCHK(a != NULL);
   A = a;
   return (n >= A->used || n < 0) ? 0 : A->dp[n];
}

static int get_digit_count(void *a)
{
   fp_int *A;
   LTC_ARGCHK(a != NULL);
   A = a;
   return A->used;
}
   
static int compare(void *a, void *b)
{
   int ret;
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   ret = fp_cmp(a, b);
   switch (ret) {
      case FP_LT: return LTC_MP_LT;
      case FP_EQ: return LTC_MP_EQ;
      case FP_GT: return LTC_MP_GT;
   }
   return 0;
}

static int compare_d(void *a, unsigned long b)
{
   int ret;
   LTC_ARGCHK(a != NULL);
   ret = fp_cmp_d(a, b);
   switch (ret) {
      case FP_LT: return LTC_MP_LT;
      case FP_EQ: return LTC_MP_EQ;
      case FP_GT: return LTC_MP_GT;
   }
   return 0;
}

static int count_bits(void *a)
{
   LTC_ARGCHK(a != NULL);
   return fp_count_bits(a);
}

static int twoexpt(void *a, int n)
{
   LTC_ARGCHK(a != NULL);
   fp_2expt(a, n);
   return CRYPT_OK;
}

/* ---- conversions ---- */

/* read ascii string */
static int read_radix(void *a, const char *b, int radix)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return tfm_to_ltc_error(fp_read_radix(a, (char *)b, radix));
}

/* write one */
static int write_radix(void *a, char *b, int radix)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return tfm_to_ltc_error(fp_toradix(a, b, radix));
}

/* get size as unsigned char string */
static unsigned long unsigned_size(void *a)
{
   LTC_ARGCHK(a != NULL);
   return fp_unsigned_bin_size(a);
}

/* store */
static int unsigned_write(void *a, unsigned char *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_to_unsigned_bin(a, b);
   return CRYPT_OK;
}

/* read */
static int unsigned_read(void *a, unsigned char *b, unsigned long len)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_read_unsigned_bin(a, b, len);
   return CRYPT_OK;
}

/* add */
static int add(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   fp_add(a, b, c);
   return CRYPT_OK;
}
  
static int addi(void *a, unsigned long b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   fp_add_d(a, b, c);
   return CRYPT_OK;
}

/* sub */
static int sub(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   fp_sub(a, b, c);
   return CRYPT_OK;
}

static int subi(void *a, unsigned long b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   fp_sub_d(a, b, c);
   return CRYPT_OK;
}

/* mul */
static int mul(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   fp_mul(a, b, c); 
   return CRYPT_OK;
}

static int muli(void *a, unsigned long b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   fp_mul_d(a, b, c);
   return CRYPT_OK;
}

/* sqr */
static int sqr(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_sqr(a, b);
   return CRYPT_OK;
}

/* div */
static int divide(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return tfm_to_ltc_error(fp_div(a, b, c, d));
}

static int div_2(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_div_2(a, b);
   return CRYPT_OK;
}

/* modi */
static int modi(void *a, unsigned long b, unsigned long *c)
{
   fp_digit tmp;
   int      err;

   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);

   if ((err = tfm_to_ltc_error(fp_mod_d(a, b, &tmp))) != CRYPT_OK) {
      return err;
   }
   *c = tmp;
   return CRYPT_OK;
}  

/* gcd */
static int gcd(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   fp_gcd(a, b, c);
   return CRYPT_OK;
}

/* lcm */
static int lcm(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   fp_lcm(a, b, c);
   return CRYPT_OK;
}

static int mulmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   return tfm_to_ltc_error(fp_mulmod(a,b,c,d));
}

/* invmod */
static int invmod(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return tfm_to_ltc_error(fp_invmod(a, b, c));
}

/* setup */
static int montgomery_setup(void *a, void **b)
{
   int err;
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   *b = XCALLOC(1, sizeof(fp_digit));
   if (*b == NULL) {
      return CRYPT_MEM;
   }
   if ((err = tfm_to_ltc_error(fp_montgomery_setup(a, (fp_digit *)*b))) != CRYPT_OK) {
      XFREE(*b);
   }
   return err;
}

/* get normalization value */
static int montgomery_normalization(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   fp_montgomery_calc_normalization(a, b);
   return CRYPT_OK;
}

/* reduce */
static int montgomery_reduce(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   fp_montgomery_reduce(a, b, *((fp_digit *)c));
   return CRYPT_OK;
}

/* clean up */
static void montgomery_deinit(void *a)
{
   XFREE(a);
}

static int exptmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   return tfm_to_ltc_error(fp_exptmod(a,b,c,d));
}   

static int isprime(void *a, int *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   *b = (fp_isprime(a) == FP_YES) ? LTC_MP_YES : LTC_MP_NO;
   return CRYPT_OK;
}   

const ltc_math_descriptor tfm_desc = {

   "TomsFastMath",
   (int)DIGIT_BIT,

   &init,
   &init_copy,
   &deinit,

   &neg,
   &copy,

   &set_int,
   &get_int,
   &get_digit,
   &get_digit_count,
   &compare,
   &compare_d,
   &count_bits,
   &twoexpt,

   &read_radix,
   &write_radix,
   &unsigned_size,
   &unsigned_write,
   &unsigned_read,

   &add,
   &addi,
   &sub,
   &subi,
   &mul,
   &muli,
   &sqr,
   &divide,
   &div_2,
   &modi,
   &gcd,
   &lcm,

   &mulmod,
   &invmod,

   &montgomery_setup,
   &montgomery_normalization,
   &montgomery_reduce,
   &montgomery_deinit,

   &exptmod,
   &isprime,

   &ltc_ecc_mulmod,
   &ltc_ecc_projective_add_point,
   &ltc_ecc_map,

   NULL,
   NULL
};


#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
