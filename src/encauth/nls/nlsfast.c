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

/**
  @file nlsfast.c
  NLS support, entire suite, Tom St Denis
*/


/* Id: nlsfast.c 346 2005-04-22 18:36:12Z mwp */
/* nlsfast: NLS stream cipher and Mundja MAC -- fast implementation */

/*
THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE AND AGAINST
INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


/* This source has been modified from the original source for the LibTomCrypt project
 * by Tom St Denis.  (Warnings fixed and code GNU indented)
 */

#include "tomcrypt.h"

#ifdef NLS_MODE

#define NLS_LONG_OUTPUT 1
#define N               17
#define NMAC            8
#define WORDSIZE        32
#define F16             0x10001ul
#define MACKONST        8

/* interface, multiplication table and SBox */
#include "nlssbox.inc"
#include "nlsmultab.inc"
/*
 * FOLD is how many register cycles need to be performed after combining the
 * last byte of key and non-linear feedback, before every byte depends on every
 * byte of the key. This depends on the feedback and nonlinear functions, and
 * on where they are combined into the register.
 */
#define FOLD N                  /* how many iterations of folding to do */
#define INITKONST 0x6996c53a    /* value of KONST to use during key loading */
#define KEYP 15                 /* where to insert key words */
#define FOLDP 4                 /* where to insert non-linear feedback */
#if NLS_LONG_OUTPUT
#define CTRP 2                  /* where to insert counter to avoid small cycles */
#endif /*NLS_LONG_OUTPUT */

#define Byte(x,i) ((unsigned char)(((x) >> (8*i)) & 0xFF))

/* define IS_LITTLE_ENDIAN for faster operation when appropriate */
#if defined(ENDIAN_LITTLE) && defined(ENDIAN_32BITWORD)
/* Useful macros -- little endian words on a little endian machine */
#define BYTE2WORD(b) (*(ulong32 *)(b))
#define WORD2BYTE(w, b) ((*(ulong32 *)(b)) = w)
#define XORWORD(w, b) ((*(ulong32 *)(b)) ^= w)
#else
/* Useful macros -- machine independent little-endian version */
#define BYTE2WORD(b) ( \
   (((ulong32)(b)[3] & 0xFF)<<24) | \
   (((ulong32)(b)[2] & 0xFF)<<16) | \
   (((ulong32)(b)[1] & 0xFF)<<8) | \
   (((ulong32)(b)[0] & 0xFF)) \
)
#define WORD2BYTE(w, b) { \
   (b)[3] = Byte(w,3); \
   (b)[2] = Byte(w,2); \
   (b)[1] = Byte(w,1); \
   (b)[0] = Byte(w,0); \
}
#define XORWORD(w, b) { \
   (b)[3] ^= Byte(w,3); \
   (b)[2] ^= Byte(w,2); \
   (b)[1] ^= Byte(w,1); \
   (b)[0] ^= Byte(w,0); \
}
#endif

#if NLS_LONG_OUTPUT
#define ZEROCOUNTER(c)    c->CtrModF16 = c->CtrMod232 = 0
#else
#define ZEROCOUNTER(c)          /* nothing */
#endif /*NLS_LONG_OUTPUT */

/* give correct offset for the current position of the register,
 * where logically R[0] is at position "zero".
 */
#define OFF(zero, i) (((zero)+(i)) % N)

#if NLS_LONG_OUTPUT
/* Increment counter and mix into register every so often */
#define FIXCTR(c,z) \
{ \
    if (++c->CtrModF16 == F16) { \
   c->CtrMod232 += c->CtrModF16; \
   c->R[OFF(z,CTRP)] += c->CtrMod232; \
   c->CtrMod232 = 0; \
    } \
}
#endif /*NLS_LONG_OUTPUT */

/* step the shift register */
/* After stepping, "zero" moves right one place */
#define STEP(c,z) \
    { register ulong32 tt; \
   tt = ROL(c->R[OFF(z,0)],19) + ROL(c->R[OFF(z,15)],9) + c->konst; \
   tt ^= Sbox[(tt >> 24) & 0xFF]; \
   c->R[OFF(z,0)] = tt ^ c->R[OFF(z,4)]; \
    }
static void cycle(nls_state * c)
{
   ulong32 t;
   int i;

   /* nonlinear feedback function */
   STEP(c, 0);
   /* shift register */
   t = c->R[0];
   for (i = 1; i < N; ++i)
      c->R[i - 1] = c->R[i];
   c->R[N - 1] = t;
#if NLS_LONG_OUTPUT
   FIXCTR(c, 0);
#endif /*NLS_LONG_OUTPUT */
}

/* Return a non-linear function of some parts of the register.
 */
#define NLFUNC(c,z) \
    (c->R[OFF(z,0)] + c->R[OFF(z,16)]) \
    ^ (c->R[OFF(z,1)] + c->konst) \
    ^ (c->R[OFF(z,6)] + c->R[OFF(z,13)])

static ulong32 nltap(nls_state * c)
{
   return NLFUNC(c, 0);
}

/* The Mundja MAC function is modelled after the round function of SHA-256.
 * The following lines establish aliases for the MAC accumulator, just
 * so that the definition of that function looks more like FIPS-180-2.
 */
#define A c->M[0]
#define B c->M[1]
#define C c->M[2]
#define D c->M[3]
#define E c->M[4]
#define F c->M[5]
#define G c->M[6]
#define H c->M[7]
#define SIGMA0(x) (ROR((x), 2) ^ ROR((x), 13) ^ ROR((x), 22))
#define SIGMA1(x) (ROR((x), 6) ^ ROR((x), 11) ^ ROR((x), 25))
#define CHOOSE(x,y,z) (z ^ (x & (y ^ z)))
#define MAJORITY(x,y,z) ((x & y) | (z & (x | y)))

/* Accumulate a nonlinear function of a register word and an input word for MAC.
 * Except for the added S-Box and SOBER LFSR input instead of constants,
 * this is exactly a round of SHA-256.
 */
#define SHAFUNC(c,i,k,A,B,C,D,E,F,G,H) \
    { \
   ulong32   t1; \
   t1 = H + k + i; \
   t1 ^= Sbox[(t1 >> 24) & 0xFF]; \
   t1 += SIGMA1(E) + CHOOSE(E, F, G); \
   D += t1; \
   t1 += SIGMA0(A) + MAJORITY(A, B, C); \
   H = t1; \
    }

static void shafunc(nls_state * c, ulong32 i)
{
   ulong32 t;

   SHAFUNC(c, i, c->R[MACKONST], A, B, C, D, E, F, G, H);
   /* now correct alignment of MAC accumulator */
   t = c->M[NMAC - 1];
   for (i = NMAC - 1; i > 0; --i)
      c->M[i] = c->M[i - 1];
   c->M[0] = t;
}

/* Accumulate a CRC of input words, later to be fed into MAC.
 */
#define CRCFUNC(c,i,zero,five) \
    { \
   ulong32   t1; \
   t1 = (c->CRC[zero] << 8) ^ Multab[(c->CRC[zero] >> 24) & 0xFF] \
      ^ c->CRC[five] ^ i; \
   c->CRC[zero] = t1; \
    }

static void crcfunc(nls_state * c, ulong32 i)
{
   ulong32 t;

   CRCFUNC(c, i, 0, 5);
   /* now correct alignment of CRC accumulator */
   t = c->CRC[0];
   for (i = 1; i < NMAC; ++i)
      c->CRC[i - 1] = c->CRC[i];
   c->CRC[NMAC - 1] = t;
}

/* Normal MAC word processing: do both SHA and CRC.
 */
static void macfunc(nls_state * c, ulong32 i)
{
   crcfunc(c, i);
   shafunc(c, i);
}

/* initialise to known state
 */
static void nls_initstate(nls_state * c)
{
   int i;

   /* Register initialised to Fibonacci numbers */
   c->R[0] = 1;
   c->R[1] = 1;
   for (i = 2; i < N; ++i)
      c->R[i] = c->R[i - 1] + c->R[i - 2];
   c->konst = INITKONST;
   ZEROCOUNTER(c);
}

/* Save the current register state
 */
static void nls_savestate(nls_state * c)
{
   int i;

   for (i = 0; i < N; ++i)
      c->initR[i] = c->R[i];
}

/* initialise to previously saved register state
 */
static void nls_reloadstate(nls_state * c)
{
   int i;

   for (i = 0; i < N; ++i)
      c->R[i] = c->initR[i];
   ZEROCOUNTER(c);
}

/* Initialise "konst"
 */
static void nls_genkonst(nls_state * c)
{
   ulong32 newkonst;

   do {
      cycle(c);
      newkonst = nltap(c);
   }
   while ((newkonst & 0xFF000000) == 0);
   c->konst = newkonst;
}

/* Load key material into the register
 */
#define ADDKEY(k) \
   c->R[KEYP] += (k);

#define XORNL(nl) \
   c->R[FOLDP] ^= (nl);

/* nonlinear diffusion of register for key and MAC */
#define DROUND(z) STEP(c,z); c->R[OFF((z+1),FOLDP)] ^= NLFUNC(c,(z+1));
static void nls_diffuse(nls_state * c)
{
   /* relies on FOLD == N! */
   DROUND(0);
   DROUND(1);
   DROUND(2);
   DROUND(3);
   DROUND(4);
   DROUND(5);
   DROUND(6);
   DROUND(7);
   DROUND(8);
   DROUND(9);
   DROUND(10);
   DROUND(11);
   DROUND(12);
   DROUND(13);
   DROUND(14);
   DROUND(15);
   DROUND(16);
}

/* common actions for loading key material */
static void
nls_loadkey(nls_state * c, const unsigned char *key, unsigned long keylen)
{
   ulong32 i, k;

   /* start folding in key, reject odd sized keys */
   if ((keylen & 3) != 0)
      abort();
   for (i = 0; i < keylen; i += 4) {
      k = BYTE2WORD(&key[i]);
      ADDKEY(k);
      cycle(c);
      XORNL(nltap(c));
   }

   /* also fold in the length of the key */
   ADDKEY(keylen);

   /* now diffuse */
   nls_diffuse(c);
}

/* initialise MAC related registers
 */
static void nls_macinit(nls_state * c)
{
   int i;

   for (i = 0; i < NMAC; ++i) {
      c->M[i] = c->R[i];
      c->CRC[i] = c->R[i + NMAC];
   }
}

/* Published "key" interface
 */
int nls_key(nls_state * c, const unsigned char *key, unsigned long keylen)
{
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(key != NULL);

   if (keylen == 0) {
      return CRYPT_INVALID_ARG;
   }
   nls_initstate(c);
   nls_loadkey(c, key, keylen);
   nls_genkonst(c);
   nls_savestate(c);
   nls_macinit(c);
   c->nbuf = 0;
   ZEROCOUNTER(c);
   return CRYPT_OK;
}

/* Published "nonce" interface
 */
int
nls_nonce(nls_state * c, const unsigned char *nonce, unsigned long noncelen)
{
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(nonce != NULL);
   if (noncelen == 0) {
      return CRYPT_INVALID_ARG;
   }
   nls_reloadstate(c);
   nls_loadkey(c, nonce, noncelen);
   nls_macinit(c);
   c->nbuf = 0;
   ZEROCOUNTER(c);
   return CRYPT_OK;
}

#if 0
/* XOR pseudo-random bytes into buffer
 * Note: doesn't play well with MAC functions.
 */
#define SROUND(z) STEP(c,z); t = NLFUNC(c,(z+1)); XORWORD(t, buf+(z*4));
static void
nls_stream(nls_state * c, unsigned char *buf, unsigned long nbytes)
{
   ulong32 t = 0;

   /* handle any previously buffered bytes */
   while (c->nbuf != 0 && nbytes != 0) {
      *buf++ ^= c->sbuf & 0xFF;
      c->sbuf >>= 8;
      c->nbuf -= 8;
      --nbytes;
   }

   /* do lots at a time, if there's enough to do */
   while (nbytes >= N * 4) {
#if NLS_LONG_OUTPUT
      if (c->CtrModF16 < (F16 - 17)) {
#endif /*NLS_LONG_OUTPUT */
         SROUND(0);
         SROUND(1);
         SROUND(2);
         SROUND(3);
         SROUND(4);
         SROUND(5);
         SROUND(6);
         SROUND(7);
         SROUND(8);
         SROUND(9);
         SROUND(10);
         SROUND(11);
         SROUND(12);
         SROUND(13);
         SROUND(14);
         SROUND(15);
         SROUND(16);
#if NLS_LONG_OUTPUT
         c->CtrModF16 += 17;
      } else {
         SROUND(0);
         FIXCTR(c, 1);
         SROUND(1);
         FIXCTR(c, 2);
         SROUND(2);
         FIXCTR(c, 3);
         SROUND(3);
         FIXCTR(c, 4);
         SROUND(4);
         FIXCTR(c, 5);
         SROUND(5);
         FIXCTR(c, 6);
         SROUND(6);
         FIXCTR(c, 7);
         SROUND(7);
         FIXCTR(c, 8);
         SROUND(8);
         FIXCTR(c, 9);
         SROUND(9);
         FIXCTR(c, 10);
         SROUND(10);
         FIXCTR(c, 11);
         SROUND(11);
         FIXCTR(c, 12);
         SROUND(12);
         FIXCTR(c, 13);
         SROUND(13);
         FIXCTR(c, 14);
         SROUND(14);
         FIXCTR(c, 15);
         SROUND(15);
         FIXCTR(c, 16);
         SROUND(16);
         FIXCTR(c, 0);
      }
#endif /*NLS_LONG_OUTPUT */
      buf += 4 * N;
      nbytes -= N * 4;
   }

   /* do small or odd size buffers the slow way */
   while (4 <= nbytes) {
      cycle(c);
      t = nltap(c);
      XORWORD(t, buf);
      buf += 4;
      nbytes -= 4;
   }

   /* handle any trailing bytes */
   if (nbytes != 0) {
      cycle(c);
      c->sbuf = nltap(c);
      c->nbuf = 32;
      while (c->nbuf != 0 && nbytes != 0) {
         *buf++ ^= c->sbuf & 0xFF;
         c->sbuf >>= 8;
         c->nbuf -= 8;
         --nbytes;
      }
   }
}

#endif

/* accumulate words into MAC without encryption
 * Note that plaintext is accumulated for MAC.
 */
#define MROUND(z,A,B,C,D,E,F,G,H) \
    t = BYTE2WORD(buf+(z*4)); \
    STEP(c,z); \
    CRCFUNC(c,t,((z)&0x7),(((z)+5)&0x7)); \
    SHAFUNC(c,t,c->R[OFF(z+1,MACKONST)],A,B,C,D,E,F,G,H);
int nls_maconly(nls_state * c, const unsigned char *buf, unsigned long nbytes)
{
   int i;
   ulong32 t = 0;

   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(buf != NULL);


   /* handle any previously buffered bytes */
   if (c->nbuf != 0) {
      while (c->nbuf != 0 && nbytes != 0) {
         c->mbuf ^= (*buf++) << (32 - c->nbuf);
         c->nbuf -= 8;
         --nbytes;
      }
      if (c->nbuf != 0) {       /* not a whole word yet */
         return CRYPT_OK;
      }
      /* LFSR already cycled */
      macfunc(c, c->mbuf);
   }

   /* do lots at a time, if there's enough to do */
   while (4 * N <= nbytes) {
#if NLS_LONG_OUTPUT
      if (c->CtrModF16 < (F16 - 17)) {
#endif /*NLS_LONG_OUTPUT */
         MROUND(0, A, B, C, D, E, F, G, H);
         MROUND(1, H, A, B, C, D, E, F, G);
         MROUND(2, G, H, A, B, C, D, E, F);
         MROUND(3, F, G, H, A, B, C, D, E);
         MROUND(4, E, F, G, H, A, B, C, D);
         MROUND(5, D, E, F, G, H, A, B, C);
         MROUND(6, C, D, E, F, G, H, A, B);
         MROUND(7, B, C, D, E, F, G, H, A);
         MROUND(8, A, B, C, D, E, F, G, H);
         MROUND(9, H, A, B, C, D, E, F, G);
         MROUND(10, G, H, A, B, C, D, E, F);
         MROUND(11, F, G, H, A, B, C, D, E);
         MROUND(12, E, F, G, H, A, B, C, D);
         MROUND(13, D, E, F, G, H, A, B, C);
         MROUND(14, C, D, E, F, G, H, A, B);
         MROUND(15, B, C, D, E, F, G, H, A);
         MROUND(16, A, B, C, D, E, F, G, H);
#if NLS_LONG_OUTPUT
         c->CtrModF16 += 17;
      } else {
         MROUND(0, A, B, C, D, E, F, G, H);
         FIXCTR(c, 1);
         MROUND(1, H, A, B, C, D, E, F, G);
         FIXCTR(c, 2);
         MROUND(2, G, H, A, B, C, D, E, F);
         FIXCTR(c, 3);
         MROUND(3, F, G, H, A, B, C, D, E);
         FIXCTR(c, 4);
         MROUND(4, E, F, G, H, A, B, C, D);
         FIXCTR(c, 5);
         MROUND(5, D, E, F, G, H, A, B, C);
         FIXCTR(c, 6);
         MROUND(6, C, D, E, F, G, H, A, B);
         FIXCTR(c, 7);
         MROUND(7, B, C, D, E, F, G, H, A);
         FIXCTR(c, 8);
         MROUND(8, A, B, C, D, E, F, G, H);
         FIXCTR(c, 9);
         MROUND(9, H, A, B, C, D, E, F, G);
         FIXCTR(c, 10);
         MROUND(10, G, H, A, B, C, D, E, F);
         FIXCTR(c, 11);
         MROUND(11, F, G, H, A, B, C, D, E);
         FIXCTR(c, 12);
         MROUND(12, E, F, G, H, A, B, C, D);
         FIXCTR(c, 13);
         MROUND(13, D, E, F, G, H, A, B, C);
         FIXCTR(c, 14);
         MROUND(14, C, D, E, F, G, H, A, B);
         FIXCTR(c, 15);
         MROUND(15, B, C, D, E, F, G, H, A);
         FIXCTR(c, 16);
         MROUND(16, A, B, C, D, E, F, G, H);
         FIXCTR(c, 0);
      }
#endif /*NLS_LONG_OUTPUT */
      buf += 4 * N;
      nbytes -= 4 * N;
      /* fix alignment of MAC buffer */
      t = c->M[NMAC - 1];
      for (i = NMAC - 1; i > 0; --i)
         c->M[i] = c->M[i - 1];
      c->M[0] = t;
      /* fix alignment of CRC buffer */
      t = c->CRC[0];
      for (i = 1; i < NMAC; ++i)
         c->CRC[i - 1] = c->CRC[i];
      c->CRC[NMAC - 1] = t;
   }

   /* do small or odd size buffers the slow way */
   while (4 <= nbytes) {
      cycle(c);
      macfunc(c, BYTE2WORD(buf));
      buf += 4;
      nbytes -= 4;
   }

   /* handle any trailing bytes */
   if (nbytes != 0) {
      cycle(c);
      c->sbuf = nltap(c);
      c->mbuf = 0;
      c->nbuf = 32;
      while (nbytes != 0) {
         c->mbuf ^= (*buf++) << (32 - c->nbuf);
         c->nbuf -= 8;
         --nbytes;
      }
   }

   return CRYPT_OK;
}

/* Combined MAC and encryption.
 * Note that plaintext is accumulated for MAC.
 */
#define EROUND(z,A,B,C,D,E,F,G,H) \
    STEP(c,z); \
    t3 = BYTE2WORD(buf+(z*4)); \
    CRCFUNC(c,t3,((z)&0x7),(((z)+5)&0x7)); \
    SHAFUNC(c,t3,c->R[OFF(z+1,MACKONST)],A,B,C,D,E,F,G,H); \
    t = NLFUNC(c,(z+1)); \
    t ^= t3; \
    WORD2BYTE(t,buf+(z*4));
int nls_encrypt(nls_state * c, 
                const unsigned char *pt, unsigned long nbytes,
                      unsigned char *ct)
{
   ulong32 t = 0, t3 = 0;
   int i;

   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   
   #define buf ct
   
   /* do copy as required */
   if (pt != ct) {
       XMEMCPY(ct, pt, nbytes);
   }       

   /* handle any previously buffered bytes */
   if (c->nbuf != 0) {
      while (c->nbuf != 0 && nbytes != 0) {
         c->mbuf ^= *buf << (32 - c->nbuf);
         *buf ^= (c->sbuf >> (32 - c->nbuf)) & 0xFF;
         ++buf;
         c->nbuf -= 8;
         --nbytes;
      }
      if (c->nbuf != 0)         /* not a whole word yet */
         return CRYPT_OK;
      /* LFSR already cycled */
      macfunc(c, c->mbuf);
   }

   /* do lots at a time, if there's enough to do */
   while (4 * N <= nbytes) {
#if NLS_LONG_OUTPUT
      if (c->CtrModF16 < (F16 - 17)) {
#endif /*NLS_LONG_OUTPUT */
         EROUND(0, A, B, C, D, E, F, G, H);
         EROUND(1, H, A, B, C, D, E, F, G);
         EROUND(2, G, H, A, B, C, D, E, F);
         EROUND(3, F, G, H, A, B, C, D, E);
         EROUND(4, E, F, G, H, A, B, C, D);
         EROUND(5, D, E, F, G, H, A, B, C);
         EROUND(6, C, D, E, F, G, H, A, B);
         EROUND(7, B, C, D, E, F, G, H, A);
         EROUND(8, A, B, C, D, E, F, G, H);
         EROUND(9, H, A, B, C, D, E, F, G);
         EROUND(10, G, H, A, B, C, D, E, F);
         EROUND(11, F, G, H, A, B, C, D, E);
         EROUND(12, E, F, G, H, A, B, C, D);
         EROUND(13, D, E, F, G, H, A, B, C);
         EROUND(14, C, D, E, F, G, H, A, B);
         EROUND(15, B, C, D, E, F, G, H, A);
         EROUND(16, A, B, C, D, E, F, G, H);
#if NLS_LONG_OUTPUT
         c->CtrModF16 += 17;
      } else {
         EROUND(0, A, B, C, D, E, F, G, H);
         FIXCTR(c, 1);
         EROUND(1, H, A, B, C, D, E, F, G);
         FIXCTR(c, 2);
         EROUND(2, G, H, A, B, C, D, E, F);
         FIXCTR(c, 3);
         EROUND(3, F, G, H, A, B, C, D, E);
         FIXCTR(c, 4);
         EROUND(4, E, F, G, H, A, B, C, D);
         FIXCTR(c, 5);
         EROUND(5, D, E, F, G, H, A, B, C);
         FIXCTR(c, 6);
         EROUND(6, C, D, E, F, G, H, A, B);
         FIXCTR(c, 7);
         EROUND(7, B, C, D, E, F, G, H, A);
         FIXCTR(c, 8);
         EROUND(8, A, B, C, D, E, F, G, H);
         FIXCTR(c, 9);
         EROUND(9, H, A, B, C, D, E, F, G);
         FIXCTR(c, 10);
         EROUND(10, G, H, A, B, C, D, E, F);
         FIXCTR(c, 11);
         EROUND(11, F, G, H, A, B, C, D, E);
         FIXCTR(c, 12);
         EROUND(12, E, F, G, H, A, B, C, D);
         FIXCTR(c, 13);
         EROUND(13, D, E, F, G, H, A, B, C);
         FIXCTR(c, 14);
         EROUND(14, C, D, E, F, G, H, A, B);
         FIXCTR(c, 15);
         EROUND(15, B, C, D, E, F, G, H, A);
         FIXCTR(c, 16);
         EROUND(16, A, B, C, D, E, F, G, H);
         FIXCTR(c, 0);
      }
#endif /*NLS_LONG_OUTPUT */
      buf += 4 * N;
      nbytes -= 4 * N;
      /* fix alignment of MAC buffer */
      t = c->M[7];
      for (i = NMAC - 1; i > 0; --i)
         c->M[i] = c->M[i - 1];
      c->M[0] = t;
      /* fix alignment of CRC buffer */
      t = c->CRC[0];
      for (i = 1; i < NMAC; ++i)
         c->CRC[i - 1] = c->CRC[i];
      c->CRC[NMAC - 1] = t;
   }

   /* do small or odd size buffers the slow way */
   while (4 <= nbytes) {
      cycle(c);
      t = BYTE2WORD(buf);
      macfunc(c, t);
      t ^= nltap(c);
      WORD2BYTE(t, buf);
      nbytes -= 4;
      buf += 4;
   }

   /* handle any trailing bytes */
   if (nbytes != 0) {
      cycle(c);
      c->sbuf = nltap(c);
      c->mbuf = 0;
      c->nbuf = 32;
      while (c->nbuf != 0 && nbytes != 0) {
         c->mbuf ^= *buf << (32 - c->nbuf);
         *buf ^= (c->sbuf >> (32 - c->nbuf)) & 0xFF;
         ++buf;
         c->nbuf -= 8;
         --nbytes;
      }
   }
   
   #undef buf

   return CRYPT_OK;
}

/* Combined MAC and decryption.
 * Note that plaintext is accumulated for MAC.
 */
#undef DROUND
#define DROUND(z,A,B,C,D,E,F,G,H) \
    STEP(c,z); \
    t = NLFUNC(c,(z+1)); \
    t3 = BYTE2WORD(buf+(z*4)); \
    t ^= t3; \
    CRCFUNC(c,t,((z)&0x7),(((z)+5)&0x7)); \
    SHAFUNC(c,t,c->R[OFF(z+1,MACKONST)],A,B,C,D,E,F,G,H); \
    WORD2BYTE(t, buf+(z*4));
int nls_decrypt(nls_state * c, 
                const unsigned char *ct, unsigned long nbytes,
                      unsigned char *pt)
{
   ulong32 t = 0, t3 = 0;
   int i;

   LTC_ARGCHK(c  != NULL);
   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   
   #define buf pt
   
   if (pt != ct) {
      XMEMCPY(pt, ct, nbytes);
   }      

   /* handle any previously buffered bytes */
   if (c->nbuf != 0) {
      while (c->nbuf != 0 && nbytes != 0) {
         *buf ^= (c->sbuf >> (32 - c->nbuf)) & 0xFF;
         c->mbuf ^= *buf << (32 - c->nbuf);
         ++buf;
         c->nbuf -= 8;
         --nbytes;
      }
      if (c->nbuf != 0)         /* not a whole word yet */
         return CRYPT_OK;
      /* LFSR already cycled */
      macfunc(c, c->mbuf);
   }

   /* now do lots at a time, if there's enough */
   while (4 * N <= nbytes) {
#if NLS_LONG_OUTPUT
      if (c->CtrModF16 < (F16 - 17)) {
#endif /*NLS_LONG_OUTPUT */
         DROUND(0, A, B, C, D, E, F, G, H);
         DROUND(1, H, A, B, C, D, E, F, G);
         DROUND(2, G, H, A, B, C, D, E, F);
         DROUND(3, F, G, H, A, B, C, D, E);
         DROUND(4, E, F, G, H, A, B, C, D);
         DROUND(5, D, E, F, G, H, A, B, C);
         DROUND(6, C, D, E, F, G, H, A, B);
         DROUND(7, B, C, D, E, F, G, H, A);
         DROUND(8, A, B, C, D, E, F, G, H);
         DROUND(9, H, A, B, C, D, E, F, G);
         DROUND(10, G, H, A, B, C, D, E, F);
         DROUND(11, F, G, H, A, B, C, D, E);
         DROUND(12, E, F, G, H, A, B, C, D);
         DROUND(13, D, E, F, G, H, A, B, C);
         DROUND(14, C, D, E, F, G, H, A, B);
         DROUND(15, B, C, D, E, F, G, H, A);
         DROUND(16, A, B, C, D, E, F, G, H);
#if NLS_LONG_OUTPUT
         c->CtrModF16 += 17;
      } else {
         DROUND(0, A, B, C, D, E, F, G, H);
         FIXCTR(c, 1);
         DROUND(1, H, A, B, C, D, E, F, G);
         FIXCTR(c, 2);
         DROUND(2, G, H, A, B, C, D, E, F);
         FIXCTR(c, 3);
         DROUND(3, F, G, H, A, B, C, D, E);
         FIXCTR(c, 4);
         DROUND(4, E, F, G, H, A, B, C, D);
         FIXCTR(c, 5);
         DROUND(5, D, E, F, G, H, A, B, C);
         FIXCTR(c, 6);
         DROUND(6, C, D, E, F, G, H, A, B);
         FIXCTR(c, 7);
         DROUND(7, B, C, D, E, F, G, H, A);
         FIXCTR(c, 8);
         DROUND(8, A, B, C, D, E, F, G, H);
         FIXCTR(c, 9);
         DROUND(9, H, A, B, C, D, E, F, G);
         FIXCTR(c, 10);
         DROUND(10, G, H, A, B, C, D, E, F);
         FIXCTR(c, 11);
         DROUND(11, F, G, H, A, B, C, D, E);
         FIXCTR(c, 12);
         DROUND(12, E, F, G, H, A, B, C, D);
         FIXCTR(c, 13);
         DROUND(13, D, E, F, G, H, A, B, C);
         FIXCTR(c, 14);
         DROUND(14, C, D, E, F, G, H, A, B);
         FIXCTR(c, 15);
         DROUND(15, B, C, D, E, F, G, H, A);
         FIXCTR(c, 16);
         DROUND(16, A, B, C, D, E, F, G, H);
         FIXCTR(c, 0);
      }
#endif /*NLS_LONG_OUTPUT */
      buf += 4 * N;
      nbytes -= 4 * N;
      /* fix alignment of MAC buffer */
      t = c->M[7];
      for (i = NMAC - 1; i > 0; --i)
         c->M[i] = c->M[i - 1];
      c->M[0] = t;
      /* fix alignment of CRC buffer */
      t = c->CRC[0];
      for (i = 1; i < NMAC; ++i)
         c->CRC[i - 1] = c->CRC[i];
      c->CRC[NMAC - 1] = t;
   }

   /* do small or odd size buffers the slow way */
   while (4 <= nbytes) {
      cycle(c);
      t = nltap(c);
      t3 = BYTE2WORD(buf);
      t ^= t3;
      macfunc(c, t);
      WORD2BYTE(t, buf);
      nbytes -= 4;
      buf += 4;
   }

   /* handle any trailing bytes */
   if (nbytes != 0) {
      cycle(c);
      c->sbuf = nltap(c);
      c->mbuf = 0;
      c->nbuf = 32;
      while (c->nbuf != 0 && nbytes != 0) {
         *buf ^= (c->sbuf >> (32 - c->nbuf)) & 0xFF;
         c->mbuf ^= *buf << (32 - c->nbuf);
         ++buf;
         c->nbuf -= 8;
         --nbytes;
      }
   }
   return CRYPT_OK;
   
   #undef buf
}

/* Having accumulated a MAC, finish processing and return it.
 * Note that any unprocessed bytes are treated as if
 * they were encrypted zero bytes, so plaintext (zero) is accumulated.
 */
int nls_finish(nls_state * c, unsigned char *buf, unsigned long nbytes)
{
   ulong32 i;

   LTC_ARGCHK(c   != NULL);
   LTC_ARGCHK(buf != NULL);

   /* handle any previously buffered bytes */
   if (c->nbuf != 0) {
      /* LFSR already cycled */
      macfunc(c, c->mbuf);
   }

   /* perturb the MAC to mark end of input.
    * Note that only the SHA part is updated, not the CRC. This is an
    * action that can't be duplicated by passing in plaintext, hence
    * defeating any kind of extension attack.
    */
   cycle(c);
   shafunc(c, INITKONST + (c->nbuf << 24));
   c->nbuf = 0;

   /* now add the CRC to the MAC like input material */
   for (i = 0; i < NMAC; ++i) {
      cycle(c);
      crcfunc(c, 0);
      shafunc(c, c->CRC[7]);
   }

   /* continue that process, producing output from the MAC buffer */
   while (nbytes > 0) {
      cycle(c);
      crcfunc(c, 0);
      shafunc(c, c->CRC[7]);
      if (nbytes >= 4) {
         WORD2BYTE(A, buf);
         nbytes -= 4;
         buf += 4;
      } else {
         for (i = 0; i < nbytes; ++i)
            buf[i] = Byte(A, i);
         break;
      }
   }

   return CRYPT_OK;
}

#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
