/* Defines the _ARGCHK macro used within the library */

/* ARGTYPE is defined in mycrypt_cfg.h */
#if ARGTYPE == 0

#include <signal.h>

/* this is the default LibTomCrypt macro 
 *
 * On embedded platforms you can change the fprintf() to be a routine that would display a message
 * somehow 
 */
#ifndef SONY_PS2

#define _ARGCHK(x) \
    if (!(x)) { \
        fprintf(stderr, "_ARGCHK '%s' failure on line %d of file %s\n", #x, __LINE__, __FILE__); \
        raise(SIGABRT); \
    }

#else

#define _ARGCHK(x) \
    if (!(x)) { \
        printf("_ARGCHK '%s' failure on line %d of file %s\n", #x, __LINE__, __FILE__); \
        raise(SIGABRT); \
    }

#endif  /* SONY_PS2 */

#elif ARGTYPE == 1

/* fatal type of error */
#define _ARGCHK(x) assert((x))

#elif ARGTYPE == 2

#define _ARGCHK(x) 

#endif

