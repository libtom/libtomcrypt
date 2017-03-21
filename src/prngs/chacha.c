/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_CHACHA

const struct ltc_prng_descriptor chacha_prng_desc =
{
   "chacha",
   sizeof(chacha_state),
   &chacha_prng_start,
   &chacha_prng_add_entropy,
   &chacha_prng_ready,
   &chacha_prng_read,
   &chacha_prng_done,
   &chacha_prng_export,
   &chacha_prng_import,
   &chacha_prng_test
};

/**
  Start the PRNG
  @param prng[out] The PRNG state to initialize
  @return CRYPT_OK if successful
*/
int chacha_prng_start(prng_state *prng)
{
   LTC_ARGCHK(prng != NULL);
   prng->chacha.ready = 0;
   XMEMSET(&prng->chacha.ent, 0, 40);
   prng->chacha.idx = 0;
   return CRYPT_OK;
}

/**
  Add entropy to the PRNG state
  @param in       The data to add
  @param inlen    Length of the data to add
  @param prng     PRNG state to update
  @return CRYPT_OK if successful
*/
int chacha_prng_add_entropy(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
   unsigned char buf[40];
   unsigned long i;
   int err;

   LTC_ARGCHK(prng != NULL);
   LTC_ARGCHK(in != NULL);
   LTC_ARGCHK(inlen > 0);

   if (prng->chacha.ready) {
      /* chacha_prng_ready() was already called, do "rekey" operation */
      if ((err = chacha_keystream(&prng->chacha.s, buf, 40)) != CRYPT_OK)      return err;
      for(i = 0; i < inlen; i++) buf[i % 40] ^= in[i];
      /* key 32 bytes, 20 rounds */
      if ((err = chacha_setup(&prng->chacha.s, buf, 32, 20)) != CRYPT_OK)      return err;
      /* iv 8 bytes */
      if ((err = chacha_ivctr64(&prng->chacha.s, buf + 32, 8, 0)) != CRYPT_OK) return err;
   }
   else {
      /* chacha_prng_ready() was not called yet, add entropy to ent buffer */
      while (inlen--) prng->chacha.ent[prng->chacha.idx++ % 40] ^= *in++;
   }

   return CRYPT_OK;
}

/**
  Make the PRNG ready to read from
  @param prng   The PRNG to make active
  @return CRYPT_OK if successful
*/
int chacha_prng_ready(prng_state *prng)
{
   int err;

   LTC_ARGCHK(prng != NULL);

   /* key 32 bytes, 20 rounds */
   if ((err = chacha_setup(&prng->chacha.s, prng->chacha.ent, 32, 20)) != CRYPT_OK)      return err;
   /* iv 8 bytes */
   if ((err = chacha_ivctr64(&prng->chacha.s, prng->chacha.ent + 32, 8, 0)) != CRYPT_OK) return err;
   XMEMSET(&prng->chacha.ent, 0, 40);
   prng->chacha.ready = 1;
   prng->chacha.idx = 0;
   return CRYPT_OK;
}

/**
  Read from the PRNG
  @param out      Destination
  @param outlen   Length of output
  @param prng     The active PRNG to read from
  @return Number of octets read
*/
unsigned long chacha_prng_read(unsigned char *out, unsigned long outlen, prng_state *prng)
{
   if (chacha_keystream(&prng->chacha.s, out, outlen) != CRYPT_OK) return 0;
   return outlen;
}

/**
  Terminate the PRNG
  @param prng   The PRNG to terminate
  @return CRYPT_OK if successful
*/
int chacha_prng_done(prng_state *prng)
{
   LTC_UNUSED_PARAM(prng);
   prng->chacha.ready = 0;
   XMEMSET(&prng->chacha.s, 0, sizeof(chacha_state));
   return CRYPT_OK;
}

/**
  Export the PRNG state
  @param out       [out] Destination
  @param outlen    [in/out] Max size and resulting size of the state
  @param prng      The PRNG to export
  @return CRYPT_OK if successful
*/
int chacha_prng_export(unsigned char *out, unsigned long *outlen, prng_state *prng)
{
   unsigned long len = sizeof(chacha_state);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(prng   != NULL);

   if (!prng->chacha.ready) {
      return CRYPT_ERROR;
   }
   if (*outlen < len) {
      *outlen = len;
      return CRYPT_BUFFER_OVERFLOW;
   }
   XMEMCPY(out, &prng->chacha.s, len);
   *outlen = len;
   return CRYPT_OK;
}

/**
  Import a PRNG state
  @param in       The PRNG state
  @param inlen    Size of the state
  @param prng     The PRNG to import
  @return CRYPT_OK if successful
*/
int chacha_prng_import(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
   unsigned long len = sizeof(chacha_state);
   LTC_ARGCHK(in   != NULL);
   LTC_ARGCHK(prng != NULL);

   if (inlen != len) return CRYPT_INVALID_ARG;
   XMEMCPY(&prng->chacha.s, in, inlen);
   prng->chacha.ready = 1;
   return CRYPT_OK;
}

/**
  PRNG self-test
  @return CRYPT_OK if successful, CRYPT_NOP if self-testing has been disabled
*/
int chacha_prng_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   prng_state st;
   unsigned char en[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                          0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                          0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
                          0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                          0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32 };
   unsigned char dmp[300];
   unsigned long dmplen = sizeof(dmp);
   unsigned char out[500];
   unsigned char t1[] = { 0x59, 0xb2, 0x26, 0x95, 0x2b, 0x01, 0x8f, 0x05, 0xbe, 0xd8 };
   unsigned char t2[] = { 0x30, 0x34, 0x5c, 0x6e, 0x56, 0x18, 0x8c, 0x46, 0xbe, 0x8a };

   chacha_prng_start(&st);
   chacha_prng_add_entropy(en, sizeof(en), &st); /* add entropy to uninitialized prng */
   chacha_prng_ready(&st);
   chacha_prng_read(out, 10, &st);  /* 10 bytes for testing */
   if (compare_testvector(out, 10, t1, sizeof(t1), "CHACHA-PRNG", 1) != 0) return CRYPT_FAIL_TESTVECTOR;
   chacha_prng_read(out, 500, &st);
   chacha_prng_add_entropy(en, sizeof(en), &st); /* add entropy to already initialized prng */
   chacha_prng_read(out, 500, &st);
   chacha_prng_export(dmp, &dmplen, &st);
   chacha_prng_read(out, 500, &st); /* skip 500 bytes */
   chacha_prng_read(out, 10, &st);  /* 10 bytes for testing */
   if (compare_testvector(out, 10, t2, sizeof(t2), "CHACHA-PRNG", 2) != 0) return CRYPT_FAIL_TESTVECTOR;
   chacha_prng_done(&st);

   XMEMSET(&st, 0xFF, sizeof(st)); /* just to be sure */
   chacha_prng_import(dmp, dmplen, &st);
   chacha_prng_read(out, 500, &st); /* skip 500 bytes */
   chacha_prng_read(out, 10, &st);  /* 10 bytes for testing */
   if (compare_testvector(out, 10, t2, sizeof(t2), "CHACHA-PRNG", 3) != 0) return CRYPT_FAIL_TESTVECTOR;
   chacha_prng_done(&st);

   return CRYPT_OK;
#endif
}

#endif
