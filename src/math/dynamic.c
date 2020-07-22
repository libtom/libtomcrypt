#include "tomcrypt.h"

const char *ltc_mp_name(void)
{
	return ltc_mp.name;
}

int ltc_mp_bits_per_digit(void)
{
	return ltc_mp.bits_per_digit;
}

int ltc_mp_init(void *a)
{
	return ltc_mp.init(a);
}

void ltc_mp_deinit(void *a)
{
	ltc_mp.deinit(a);
}

int ltc_mp_init_copy(void **dst, void *src)
{
	return ltc_mp.init_copy(dst, src);
}

int ltc_mp_neg(void *src, void *dst)
{
	return ltc_mp.neg(src, dst);
}

int ltc_mp_copy(void *src, void *dst)
{
	return ltc_mp.copy(src, dst);
}

int ltc_mp_set_int(void *a, ltc_mp_digit n)
{
	return ltc_mp.set_int(a, n);
}

unsigned long ltc_mp_get_int(void *a)
{
	return ltc_mp.get_int(a);
}

ltc_mp_digit ltc_mp_get_digit(void *a, int n)
{
	return ltc_mp.get_digit(a, n);
}

int ltc_mp_get_digit_count(void *a)
{
	return ltc_mp.get_digit_count(a);
}

int ltc_mp_compare(void *a, void *b)
{
	return ltc_mp.compare(a, b);
}

int ltc_mp_compare_d(void *a, ltc_mp_digit n)
{
	return ltc_mp.compare_d(a, n);
}

int ltc_mp_count_bits(void *a)
{
	return ltc_mp.count_bits(a);
}

int ltc_mp_count_lsb_bits(void *a)
{
	return ltc_mp.count_lsb_bits(a);
}

int ltc_mp_twoexpt(void *a , int n)
{
	return ltc_mp.twoexpt(a, n);
}

int ltc_mp_read_radix(void *a, const char *str, int radix)
{
	return ltc_mp.read_radix(a, str, radix);
}

int ltc_mp_write_radix(void *a, char *str, int radix)
{
	return ltc_mp.write_radix(a, str, radix);
}

unsigned long ltc_mp_unsigned_size(void *a)
{
	return ltc_mp.unsigned_size(a);
}

int ltc_mp_unsigned_write(void *src, unsigned char *dst)
{
	return ltc_mp.unsigned_write(src, dst);
}

int ltc_mp_unsigned_read(void *dst, unsigned char *src, unsigned long len)
{
	return ltc_mp.unsigned_read(dst, src, len);
}

int ltc_mp_add(void *a, void *b, void *c)
{
	return ltc_mp.add(a, b, c);
}

int ltc_mp_addi(void *a, ltc_mp_digit b, void *c)
{
	return ltc_mp.addi(a, b, c);
}

int ltc_mp_sub(void *a, void *b, void *c)
{
	return ltc_mp.sub(a, b, c);
}

int ltc_mp_subi(void *a, ltc_mp_digit b, void *c)
{
	return ltc_mp.subi(a, b, c);
}

int ltc_mp_mul(void *a, void *b, void *c)
{
	return ltc_mp.mul(a, b, c);
}

int ltc_mp_muli(void *a, ltc_mp_digit b, void *c)
{
	return ltc_mp.muli(a, b, c);
}

int ltc_mp_sqr(void *a, void *b)
{
	return ltc_mp.sqr(a, b);
}

int ltc_mp_sqrtmod_prime_support(void)
{
	return ltc_mp.sqrtmod_prime != NULL;
}

int ltc_mp_sqrtmod_prime(void *a, void *b, void *c)
{
	return ltc_mp.sqrtmod_prime(a, b, c);
}

int ltc_mp_mpdiv(void *a, void *b, void *c, void *d)
{
	return ltc_mp.mpdiv(a, b, c, d);
}

int ltc_mp_div_2(void *a, void *b)
{
	return ltc_mp.div_2(a, b);
}

int ltc_mp_modi(void *a, ltc_mp_digit b, ltc_mp_digit *c)
{
	return ltc_mp.modi(a, b, c);
}

int ltc_mp_gcd(void *a, void *b, void *c)
{
	return ltc_mp.gcd(a, b, c);
}

int ltc_mp_lcm(void *a, void *b, void *c)
{
	return ltc_mp.lcm(a, b, c);
}

int ltc_mp_rsa_me(const unsigned char *in, unsigned long inlen,
	       unsigned char *out, unsigned long *outlen, int which,
	       const rsa_key *key)
{
	return ltc_mp.rsa_me(in, inlen, out, outlen, which, key);
}

int ltc_mp_addmod(void *a, void *b, void *c, void *d)
{
	return ltc_mp.addmod(a, b, c, d);
}

int ltc_mp_submod(void *a, void *b, void *c, void *d)
{
	return ltc_mp.submod(a, b, c, d);
}

int ltc_mp_mulmod(void *a, void *b, void *c, void *d)
{
	return ltc_mp.mulmod(a, b, c, d);
}

int ltc_mp_sqrmod(void *a, void *b, void *c)
{
	return ltc_mp.sqrmod(a, b, c);
}

int ltc_mp_invmod(void *a, void *b, void *c)
{
	return ltc_mp.invmod(a, b, c);
}

int ltc_mp_montgomery_setup(void *a, void **b)
{
	return ltc_mp.montgomery_setup(a, b);
}

int ltc_mp_montgomery_normalization(void *a, void *b)
{
	return ltc_mp.montgomery_normalization(a, b);
}

int ltc_mp_montgomery_reduce(void *a, void *b, void *c)
{
	return ltc_mp.montgomery_reduce(a, b, c);
}

void ltc_mp_montgomery_deinit(void *a)
{
	ltc_mp.montgomery_deinit(a);
}

int ltc_mp_exptmod(void *a, void *b, void *c, void *d)
{
	return ltc_mp.exptmod(a,b,c,d);
}

int ltc_mp_isprime(void *a, int b, int *c)
{
	return ltc_mp.isprime(a, b, c);
}

int ltc_mp_ecc_ptmul(void *k, const ecc_point *G, ecc_point *R, void *a,
                     void *modulus, int map)
{
        return ltc_mp.ecc_ptmul(k, G, R, a, modulus, map);
}

int ltc_mp_ecc_ptadd(const ecc_point *P, const ecc_point *Q, ecc_point *R,
                     void *ma, void *modulus, void *mp)
{
        return ltc_mp.ecc_ptadd(P, Q, R, ma, modulus, mp);
}

int ltc_mp_ecc_ptdbl(const ecc_point *P, ecc_point *R, void *ma, void *modulus,
                     void *mp)
{
        return ltc_mp.ecc_ptdbl(P, R, ma, modulus, mp);
}

int ltc_mp_ecc_map(ecc_point *P, void *modulus, void *mp)
{
        return ltc_mp.ecc_map(P, modulus, mp);
}

int ltc_mp_ecc_mul2add_support(void)
{
        return ltc_mp.ecc_mul2add != NULL;
}

int ltc_mp_ecc_mul2add(const ecc_point *A, void *kA, const ecc_point *B,
                       void *kB, ecc_point *C, void *ma, void *modulus)
{
        return ltc_mp.ecc_mul2add(A, kA, B, kB, C, ma, modulus);
}

int ltc_mp_rand(void *a, int size)
{
	return ltc_mp.rand(a, size);
}
