/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Interoperability test between libtomcrypt and libsodium for:
      1. secretbox  (XSalsa20-Poly1305)
      2. cryptobox  (X25519 + HSalsa20 + XSalsa20-Poly1305)
      3. sealbox    (ephemeral X25519 + BLAKE2b nonce + cryptobox)

   Build (run from the repo root, after `make`):
      cc -Isrc/headers -o demos/libsodium-interop demos/libsodium-interop.c libtomcrypt.a -lsodium

   Run:
      ./demos/libsodium-interop
*/

#include <stdio.h>
#include <string.h>
#include <tomcrypt.h>
#include <sodium.h>

#define CHECK(e) do { if ((e) != 0) { fprintf(stderr, "FAIL line %d\n", __LINE__); return 1; } } while(0)

static int test_secretbox(void)
{
   const unsigned char key[32] = {
      0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7,
      0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
   };
   const unsigned char nonce[24] = {
      0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6,
      0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37
   };
   const char *msg = "Hello from the interop test!";
   unsigned long msglen = strlen(msg);
   unsigned char sbox[256], lbox[256], dec[256];
   unsigned long boxlen, declen;

   printf("  sodium create -> ltc open ... ");
   CHECK(crypto_secretbox_easy(sbox, (const unsigned char *)msg, msglen, nonce, key));
   declen = sizeof(dec);
   CHECK(ltc_secretbox_open(sbox, msglen + 16, nonce, 24, key, 32, dec, &declen));
   CHECK(declen != msglen);
   CHECK(memcmp(dec, msg, msglen));
   printf("OK\n");
   printf("  ltc create -> sodium open ... ");
   boxlen = sizeof(lbox);
   CHECK(ltc_secretbox_create((const unsigned char *)msg, msglen, nonce, 24, key, 32, lbox, &boxlen));
   CHECK(boxlen != msglen + 16);
   CHECK(crypto_secretbox_open_easy(dec, lbox, boxlen, nonce, key));
   CHECK(memcmp(dec, msg, msglen));
   printf("OK\n");
   printf("  identical ciphertext ... ");
   CHECK(memcmp(sbox, lbox, msglen + 16));
   printf("OK\n");
   return 0;
}

static int test_cryptobox(void)
{
   unsigned char alice_pk[32], alice_sk[32];
   unsigned char bob_pk[32], bob_sk[32];
   const unsigned char nonce[24] = {
      0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,
      0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18
   };
   const char *msg = "Testing crypto_box interop between libtomcrypt and libsodium.";
   unsigned long msglen = strlen(msg);
   unsigned char sbox[256], lbox[256], dec[256];
   unsigned long boxlen, declen;

   crypto_box_keypair(alice_pk, alice_sk);
   crypto_box_keypair(bob_pk, bob_sk);
   printf("  sodium create -> ltc open ... ");
   CHECK(crypto_box_easy(sbox, (const unsigned char *)msg, msglen, nonce, bob_pk, alice_sk));
   declen = sizeof(dec);
   CHECK(ltc_cryptobox_open(sbox, msglen + 16, nonce, 24, alice_pk, 32, bob_sk, 32, dec, &declen));
   CHECK(declen != msglen);
   CHECK(memcmp(dec, msg, msglen));
   printf("OK\n");
   printf("  ltc create -> sodium open ... ");
   boxlen = sizeof(lbox);
   CHECK(ltc_cryptobox_create((const unsigned char *)msg, msglen, nonce, 24, bob_pk, 32, alice_sk, 32, lbox, &boxlen));
   CHECK(boxlen != msglen + 16);
   CHECK(crypto_box_open_easy(dec, lbox, boxlen, nonce, alice_pk, bob_sk));
   CHECK(memcmp(dec, msg, msglen));
   printf("OK\n");
   printf("  identical ciphertext ... ");
   CHECK(memcmp(sbox, lbox, msglen + 16));
   printf("OK\n");
   return 0;
}

static int test_sealbox(void)
{
   unsigned char pk[32], sk[32];
   const char *msg = "Sealed box: anonymous public-key authenticated encryption!";
   unsigned long msglen = strlen(msg);
   unsigned long sealedlen_expected = msglen + 48;   /* 32 eph_pk + 16 tag */
   unsigned char sealed[256], dec[256];
   unsigned long sealedlen, declen;
   prng_state prng;

   crypto_box_keypair(pk, sk);
   printf("  sodium create -> ltc open ... ");
   CHECK(crypto_box_seal(sealed, (const unsigned char *)msg, msglen, pk));
   declen = sizeof(dec);
   CHECK(ltc_sealedbox_open(sealed, sealedlen_expected, sk, 32, dec, &declen));
   CHECK(declen != msglen);
   CHECK(memcmp(dec, msg, msglen));
   printf("OK\n");
   printf("  ltc create -> sodium open ... ");
   sealedlen = sizeof(sealed);
   CHECK(ltc_sealedbox_create((const unsigned char *)msg, msglen, pk, 32, &prng, find_prng("sprng"), sealed, &sealedlen));
   CHECK(sealedlen != sealedlen_expected);
   CHECK(crypto_box_seal_open(dec, sealed, sealedlen, pk, sk));
   CHECK(memcmp(dec, msg, msglen));
   printf("OK\n");
   return 0;
}

static int test_secretbox_ck(void)
{
   /* Demonstrates the keyed (_ck) cryptobox variants and the size-query path. */
   unsigned char alice_pk_raw[32], alice_sk_raw[32];
   unsigned char bob_pk_raw[32], bob_sk_raw[32];
   curve25519_key alice_pk, alice_sk, bob_pk, bob_sk;
   const unsigned char nonce[24] = {
      0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,
      0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11
   };
   const char *msg = "_ck variants accept already-imported curve25519_key objects.";
   unsigned long msglen = strlen(msg);
   unsigned char sbox[256], lbox[256], dec[256];
   unsigned long boxlen, declen, need;

   crypto_box_keypair(alice_pk_raw, alice_sk_raw);
   crypto_box_keypair(bob_pk_raw, bob_sk_raw);
   CHECK(x25519_import_raw(alice_pk_raw, 32, PK_PUBLIC,  &alice_pk));
   CHECK(x25519_import_raw(alice_sk_raw, 32, PK_PRIVATE, &alice_sk));
   CHECK(x25519_import_raw(bob_pk_raw,   32, PK_PUBLIC,  &bob_pk));
   CHECK(x25519_import_raw(bob_sk_raw,   32, PK_PRIVATE, &bob_sk));

   printf("  size-query (out=NULL) returns required length ... ");
   need = 0;
   if (ltc_cryptobox_create_ck((const unsigned char *)msg, msglen, nonce, 24, &bob_pk, &alice_sk, NULL, &need) != CRYPT_BUFFER_OVERFLOW) {
      fprintf(stderr, "FAIL line %d\n", __LINE__);
      return 1;
   }
   CHECK(need != msglen + 16);
   printf("OK\n");

   printf("  sodium create -> ltc_cryptobox_open_ck ... ");
   CHECK(crypto_box_easy(sbox, (const unsigned char *)msg, msglen, nonce, bob_pk_raw, alice_sk_raw));
   declen = sizeof(dec);
   CHECK(ltc_cryptobox_open_ck(sbox, msglen + 16, nonce, 24, &alice_pk, &bob_sk, dec, &declen));
   CHECK(declen != msglen);
   CHECK(memcmp(dec, msg, msglen));
   printf("OK\n");

   printf("  ltc_cryptobox_create_ck -> sodium open ... ");
   boxlen = sizeof(lbox);
   CHECK(ltc_cryptobox_create_ck((const unsigned char *)msg, msglen, nonce, 24, &bob_pk, &alice_sk, lbox, &boxlen));
   CHECK(boxlen != msglen + 16);
   CHECK(crypto_box_open_easy(dec, lbox, boxlen, nonce, alice_pk_raw, bob_sk_raw));
   CHECK(memcmp(dec, msg, msglen));
   printf("OK\n");

   printf("  identical ciphertext ... ");
   CHECK(memcmp(sbox, lbox, msglen + 16));
   printf("OK\n");
   return 0;
}

int main(void)
{
   if (sodium_init() < 0) {
      fprintf(stderr, "sodium_init() failed\n");
      return 1;
   }
   if (register_prng(&sprng_desc) == -1) {
      fprintf(stderr, "register_prng(sprng) failed\n");
      return 1;
   }
   printf("Test 1: secretbox (XSalsa20-Poly1305)\n");
   if (test_secretbox() != 0) return 1;
   printf("Test 2: cryptobox (X25519 + HSalsa20 + secretbox)\n");
   if (test_cryptobox() != 0) return 1;
   printf("Test 3: sealbox (ephemeral X25519 + BLAKE2b + cryptobox)\n");
   if (test_sealbox() != 0) return 1;
   printf("Test 4: cryptobox _ck variants and size-query path\n");
   if (test_secretbox_ck() != 0) return 1;
   printf("All tests passed.\n");
   return 0;
}
