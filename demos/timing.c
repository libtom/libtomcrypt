#include <tomcrypt_test.h>

int main(void)
{

init_timer();
register_algs();

#ifdef USE_LTM
   ltc_mp = ltm_desc;
#elif defined(USE_TFM)
   ltc_mp = tfm_desc;
#elif defined(USE_GMP)
   ltc_mp = gmp_desc;
#else
   extern ltc_math_descriptor EXT_MATH_LIB;
   ltc_mp = EXT_MATH_LIB;
#endif

time_keysched();
time_cipher_ecb();
time_cipher_cbc();
time_cipher_ctr();
time_cipher_lrw();
time_hash();
time_macs();
time_encmacs();
time_prng();
time_mult();
time_sqr();
time_rsa();
time_ecc();
#ifdef USE_LTM
time_katja();
#endif
return EXIT_SUCCESS;

}

/* $Source$ */
/* $Revision$ */
/* $Date$ */
