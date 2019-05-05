/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */


/**
 @file sober128_stream.c
 Implementation of SOBER-128 by Tom St Denis.
 Based on s128fast.c reference code supplied by Greg Rose of QUALCOMM.
*/

#ifdef LTC_SOBER128


#if defined(LTC_SOBER128_STREAM_SETUP) || defined(LTC_SOBER128_STREAM_SETIV)

/* local prototypes */
static void _s128_diffuse(sober128_state *st);

#endif  /* LTC_SOBER128_STREAM_SETUP || LTC_SOBER128_STREAM_SETIV */


/* don't change these... */
#define N                        17
#define INITKONST        0x6996c53a /* value of KONST to use during key loading */
#define KEYP                     15 /* where to insert key words */
#define FOLDP                     4 /* where to insert non-linear feedback */


/* give correct offset for the current position of the register,
 * where logically R[0] is at position "zero".
 */
#define OFF(zero, i) (((zero)+(i)) % N)

/* step the LFSR */
/* After stepping, "zero" moves right one place */
#define STEP(R,z) \
    R[OFF(z,0)] = R[OFF(z,15)] ^ R[OFF(z,4)] ^ (R[OFF(z,0)] << 8) ^ Multab[(R[OFF(z,0)] >> 24) & 0xFF];

static void _cycle(ulong32 *R)
{
    ulong32 t;
    int     i;

    STEP(R,0);
    t = R[0];
    for (i = 1; i < N; ++i) {
        R[i-1] = R[i];
    }
    R[N-1] = t;
}

/* Return a non-linear function of some parts of the register.
 */
#define NLFUNC(st,z) \
{ \
    t = st->R[OFF(z,0)] + st->R[OFF(z,16)]; \
    t ^= Sbox[(t >> 24) & 0xFF]; \
    t = RORc(t, 8); \
    t = ((t + st->R[OFF(z,1)]) ^ st->konst) + st->R[OFF(z,6)]; \
    t ^= Sbox[(t >> 24) & 0xFF]; \
    t = t + st->R[OFF(z,13)]; \
}

static ulong32 _nltap(const sober128_state *st)
{
    ulong32 t;
    NLFUNC(st, 0);
    return t;
}


/* Load key material into the register
 */
#define ADDKEY(k) \
   st->R[KEYP] += (k);

#define XORNL(nl) \
   st->R[FOLDP] ^= (nl);


#if defined(LTC_SOBER128_STREAM_SETUP) || defined(LTC_SOBER128_STREAM_SETIV)

/* nonlinear diffusion of register for key */
#define DROUND(z) STEP(st->R,z); NLFUNC(st,(z+1)); st->R[OFF((z+1),FOLDP)] ^= t;

/* _s128_diffuse() used in sober128_stream_setup() and sober128_stream_setiv() */
static void _s128_diffuse(sober128_state *st)
{
    ulong32 t;
    /* relies on FOLD == N == 17! */
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

#endif  /* LTC_SOBER128_STREAM_SETUP || LTC_SOBER128_STREAM_SETIV */


#endif  /* LTC_SOBER128 */

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
