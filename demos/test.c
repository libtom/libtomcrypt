#include <tomcrypt_test.h>

#define LTC_TEST_FN(f)  { f, #f }

static const struct {
   int (*fn)(void);
   const char* name;
} test_functions[] =
{
      LTC_TEST_FN(store_test),
      LTC_TEST_FN(rotate_test),
      LTC_TEST_FN(misc_test),
      LTC_TEST_FN(cipher_hash_test),
      LTC_TEST_FN(mac_test),
      LTC_TEST_FN(modes_test),
      LTC_TEST_FN(der_tests),
      LTC_TEST_FN(pkcs_1_test),
      LTC_TEST_FN(pkcs_1_pss_test),
      LTC_TEST_FN(pkcs_1_oaep_test),
      LTC_TEST_FN(pkcs_1_emsa_test),
      LTC_TEST_FN(pkcs_1_eme_test),
      LTC_TEST_FN(rsa_test),
      LTC_TEST_FN(dh_test),
      LTC_TEST_FN(ecc_tests),
      LTC_TEST_FN(dsa_test),
      LTC_TEST_FN(katja_test),
      LTC_TEST_FN(file_test),
};

int main(int argc, char **argv)
{
   int x, pass = 0, fail = 0, nop = 0;
   size_t fn_len, i, dots;
   char *single_test = NULL;
   ulong64 ts, dur = 0;
   reg_algs();

   printf("build == \n%s\n", crypt_build_settings);

#ifdef USE_LTM
   ltc_mp = ltm_desc;
   printf("math provider = libtommath\n");
#elif defined(USE_TFM)
   ltc_mp = tfm_desc;
   printf("math provider = tomsfastmath\n");
#elif defined(USE_GMP)
   ltc_mp = gmp_desc;
   printf("math provider = gnump\n");
#else
   extern ltc_math_descriptor EXT_MATH_LIB;
   ltc_mp = EXT_MATH_LIB;
   printf("math provider = EXT_MATH_LIB\n");
#endif
   printf("MP_DIGIT_BIT = %d\n", MP_DIGIT_BIT);

   fn_len = 0;
   for (i = 0; i < sizeof(test_functions)/sizeof(test_functions[0]); ++i) {
      size_t len = strlen(test_functions[i].name);
      if (fn_len < len) fn_len = len;
   }

   fn_len = fn_len + (4 - (fn_len % 4));

   /* single test name from commandline */
   if (argc > 1) single_test = argv[1];

   for (i = 0; i < sizeof(test_functions)/sizeof(test_functions[0]); ++i) {
      if (single_test && strcmp(test_functions[i].name, single_test)) {
        continue;
      }
      dots = fn_len - strlen(test_functions[i].name);

      printf("\n%s", test_functions[i].name);
      while(dots--) printf(".");
      fflush(stdout);

      ts = epoch_usec();
      x = test_functions[i].fn();
      ts = epoch_usec() - ts;
      dur += ts;

      if (x == CRYPT_OK) {
         printf("passed %10.3fms", (double)(ts)/1000);
         pass++;
      }
      else if (x == CRYPT_NOP) {
         printf("nop");
         nop++;
      }
      else {
         printf("failed %10.3fms", (double)(ts)/1000);
         fail++;
      }
   }

   if (fail > 0 || fail+pass+nop == 0) {
      printf("\n\nFAILURE: passed=%d failed=%d nop=%d duration=%.1fsec\n", pass, fail, nop, (double)(dur)/(1000*1000));
      return EXIT_FAILURE;
   }
   else {
      printf("\n\nSUCCESS: passed=%d failed=%d nop=%d duration=%.1fsec\n", pass, fail, nop, (double)(dur)/(1000*1000));
      return EXIT_SUCCESS;
   }
}

/* $Source$ */
/* $Revision$ */
/* $Date$ */
