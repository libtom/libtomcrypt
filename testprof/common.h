#ifndef DEMOS_COMMON_H_
#define DEMOS_COMMON_H_

#include <tomcrypt.h>

extern prng_state yarrow_prng;

void print_hex(const char* what, const void* v, const unsigned long l);
#ifndef compare_testvector
int compare_testvector(const void* is, const unsigned long is_len, const void* should, const unsigned long should_len, const char* what, int which);
#endif

void register_algs(void);
void setup_math(void);

#endif /* DEMOS_COMMON_H_ */
