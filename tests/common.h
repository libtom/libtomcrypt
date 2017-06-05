#ifndef DEMOS_COMMON_H_
#define DEMOS_COMMON_H_

#include <tomcrypt.h>

#if defined(_WIN32)
   #define PRI64  "I64d"
#else
   #define PRI64  "ll"
#endif

extern prng_state yarrow_prng;

#ifdef LTC_VERBOSE
#define DO(x) do { fprintf(stderr, "%s:\n", #x); run_cmd((x), __LINE__, __FILE__, #x, NULL); } while (0)
#define DOX(x, str) do { fprintf(stderr, "%s - %s:\n", #x, (str)); run_cmd((x), __LINE__, __FILE__, #x, (str)); } while (0)
#else
#define DO(x) do { run_cmd((x), __LINE__, __FILE__, #x, NULL); } while (0)
#define DOX(x, str) do { run_cmd((x), __LINE__, __FILE__, #x, (str)); } while (0)
#endif

void run_cmd(int res, int line, char *file, char *cmd, const char *algorithm);

void print_hex(const char* what, const void* v, const unsigned long l);
#ifndef compare_testvector
int compare_testvector(const void* is, const unsigned long is_len, const void* should, const unsigned long should_len, const char* what, int which);
#endif

void register_algs(void);
void setup_math(void);

#endif /* DEMOS_COMMON_H_ */
