#define STATIC
#define LTM_DESC
#include "ltm_desc.c"

/* wire up math functions directly to LTM using definitions from ltm_desc.c */

const char *ltc_mp_name(void)
{
	return "LibTomMath";
}

int ltc_mp_bits_per_digit(void)
{
	return MP_DIGIT_BIT;
}

int ltc_mp_init(void *a)
{
	return init(a);
}

void ltc_mp_deinit(void *a)
{
	return deinit(a);
}

int ltc_mp_init_copy(void **dst, void *src)
{
	return init_copy(dst, src);
}

int ltc_mp_neg(void *src, void *dst)
{
	return neg(src, dst);
}

int ltc_mp_copy(void *src, void *dst)
{
	return copy(src, dst);
}

int ltc_mp_set_int(void *a, ltc_mp_digit n)
{
	return set_int(a, n);
}

unsigned long ltc_mp_get_int(void *a)
{
	return get_int(a);
}

ltc_mp_digit ltc_mp_get_digit(void *a, int n)
{
	return get_digit(a, n);
}

int ltc_mp_get_digit_count(void *a)
{
	return get_digit_count(a);
}

int ltc_mp_compare(void *a, void *b)
{
	return compare(a, b);
}

int ltc_mp_compare_d(void *a, ltc_mp_digit n)
{
	return compare_d(a, n);
}

int ltc_mp_count_bits(void *a)
{
	return count_bits(a);
}

int ltc_mp_count_lsb_bits(void *a)
{
	return count_lsb_bits(a);
}

int ltc_mp_twoexpt(void *a , int n)
{
	return twoexpt(a, n);
}

int ltc_mp_read_radix(void *a, const char *str, int radix)
{
	return read_radix(a, str, radix);
}

int ltc_mp_write_radix(void *a, char *str, int radix)
{
	return write_radix(a, str, radix);
}

unsigned long ltc_mp_unsigned_size(void *a)
{
	return unsigned_size(a);
}

int ltc_mp_unsigned_write(void *src, unsigned char *dst)
{
	return unsigned_write(src, dst);
}

int ltc_mp_unsigned_read(void *dst, unsigned char *src, unsigned long len)
{
	return unsigned_read(dst, src, len);
}

int ltc_mp_add(void *a, void *b, void *c)
{
	return add(a, b, c);
}

int ltc_mp_addi(void *a, ltc_mp_digit b, void *c)
{
	return addi(a, b, c);
}

int ltc_mp_sub(void *a, void *b, void *c)
{
	return sub(a, b, c);
}

int ltc_mp_subi(void *a, ltc_mp_digit b, void *c)
{
	return subi(a, b, c);
}

int ltc_mp_mul(void *a, void *b, void *c)
{
	return mul(a, b, c);
}

int ltc_mp_muli(void *a, ltc_mp_digit b, void *c)
{
	return muli(a, b, c);
}

int ltc_mp_sqr(void *a, void *b)
{
	return sqr(a, b);
}

int ltc_mp_sqrtmod_prime_support(void)
{
	return 1;
}

int ltc_mp_sqrtmod_prime(void *a, void *b, void *c)
{
	return sqrtmod_prime(a, b, c);
}

int ltc_mp_mpdiv(void *a, void *b, void *c, void *d)
{
	return divide(a, b, c, d);
}

int ltc_mp_div_2(void *a, void *b)
{
	return div_2(a, b);
}

int ltc_mp_modi(void *a, ltc_mp_digit b, ltc_mp_digit *c)
{
	return modi(a, b, c);
}

int ltc_mp_gcd(void *a, void *b, void *c)
{
	return gcd(a, b, c);
}

int ltc_mp_lcm(void *a, void *b, void *c)
{
	return lcm(a, b, c);
}

int ltc_mp_rsa_me(const unsigned char *in, unsigned long inlen,
	       unsigned char *out, unsigned long *outlen, int which,
	       const rsa_key *key)
{
#ifdef LTC_MRSA
	return rsa_exptmod(in, inlen, out, outlen, which, key);
#endif
	(void)in;
	(void)inlen;
	(void)out;
	(void)outlen;
	(void)which;
	(void)key;
	return CRYPT_ERROR;
}

int ltc_mp_addmod(void *a, void *b, void *c, void *d)
{
	return addmod(a, b, c, d);
}

int ltc_mp_submod(void *a, void *b, void *c, void *d)
{
	return submod(a, b, c, d);

}

int ltc_mp_mulmod(void *a, void *b, void *c, void *d)
{
	return mulmod(a, b, c, d);
}

int ltc_mp_sqrmod(void *a, void *b, void *c)
{
	return sqrmod(a, b, c);
}

int ltc_mp_invmod(void *a, void *b, void *c)
{
	return invmod(a, b, c);

}

int ltc_mp_montgomery_setup(void *a, void **b)
{
	return montgomery_setup(a, b);

}

int ltc_mp_montgomery_normalization(void *a, void *b)
{
	return montgomery_normalization(a, b);
}

int ltc_mp_montgomery_reduce(void *a, void *b, void *c)
{
	return montgomery_reduce(a, b, c);
}

void ltc_mp_montgomery_deinit(void *a)
{
	return montgomery_deinit(a);
}

int ltc_mp_exptmod(void *a, void *b, void *c, void *d)
{
	return exptmod(a, b, c, d);
}

int ltc_mp_isprime(void *a, int b, int *c)
{
	return isprime(a, b, c);
}

int ltc_mp_ecc_ptmul(void *k, const ecc_point *G, ecc_point *R, void *a,
                     void *modulus, int map)
{
#ifdef LTC_MECC
#ifdef LTC_MECC_FP
	return ltc_ecc_fp_mulmod(k, G, R, a, modulus, map);
#else
	return ltc_ecc_mulmod(k, G, R, a, modulus, map);
#endif
#endif
	(void)k;
	(void)G;
	(void)R;
	(void)a;
	(void)modulus;
	(void)map;
	return CRYPT_ERROR;
}

int ltc_mp_ecc_ptadd(const ecc_point *P, const ecc_point *Q, ecc_point *R,
                     void *ma, void *modulus, void *mp)
{
#ifdef LTC_MECC
	return ltc_ecc_projective_add_point(P, Q, R, ma, modulus, mp);
#endif
	(void)P;
	(void)Q;
	(void)R;
	(void)ma;
	(void)modulus;
	(void)mp;
	return CRYPT_ERROR;
}

int ltc_mp_ecc_ptdbl(const ecc_point *P, ecc_point *R, void *ma, void *modulus,
                     void *mp)
{
#ifdef LTC_MECC
	return ltc_ecc_projective_dbl_point(P, R, ma, modulus, mp);
#endif
	(void)P;
	(void)R;
	(void)ma;
	(void)modulus;
	(void)mp;
	return CRYPT_ERROR;
}

int ltc_mp_ecc_map(ecc_point *P, void *modulus, void *mp)
{
#ifdef LTC_MECC
	return ltc_ecc_map(P, modulus, mp);
#endif
	(void)P;
	(void)modulus;
	(void)mp;
	return CRYPT_ERROR;
}

int ltc_mp_ecc_mul2add_support(void)
{
#ifdef LTC_MECC
#ifdef LTC_ECC_SHAMIR
	return 1;
#endif
#endif
	return 0;
}

int ltc_mp_ecc_mul2add(const ecc_point *A, void *kA, const ecc_point *B,
                       void *kB, ecc_point *C, void *ma, void *modulus)
{
#ifdef LTC_MECC
#ifdef LTC_ECC_SHAMIR
#ifdef LTC_MECC_FP
	return ltc_ecc_fp_mul2add(A, kA, B, kB, C, ma, modulus);
#else
	return ltc_ecc_mul2add(A, kA, B, kB, C, ma, modulus);
#endif
#endif
#endif
	(void)A;
	(void)kA;
	(void)B;
	(void)kB;
	(void)C;
	(void)ma;
	(void)modulus;
	return CRYPT_ERROR;
}

int ltc_mp_rand(void *a, int size)
{
	return set_rand(a, size);
}
