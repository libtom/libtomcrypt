#include <tomcrypt_test.h>

#ifdef LTC_MRSA

#define RSA_MSGSIZE 78

/* These are test keys [see file test.key] that I use to test my import/export against */
static const unsigned char openssl_private_rsa[] = {
   0x30, 0x82, 0x02, 0x5e, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xcf, 0x9a, 0xde, 0x64, 0x8a,
   0xda, 0xc8, 0x33, 0x20, 0xa9, 0xd7, 0x83, 0x31, 0x19, 0x54, 0xb2, 0x9a, 0x85, 0xa7, 0xa1, 0xb7,
   0x75, 0x33, 0xb6, 0xa9, 0xac, 0x84, 0x24, 0xb3, 0xde, 0xdb, 0x7d, 0x85, 0x2d, 0x96, 0x65, 0xe5,
   0x3f, 0x72, 0x95, 0x24, 0x9f, 0x28, 0x68, 0xca, 0x4f, 0xdb, 0x44, 0x1c, 0x3e, 0x60, 0x12, 0x8a,
   0xdd, 0x26, 0xa5, 0xeb, 0xff, 0x0b, 0x5e, 0xd4, 0x88, 0x38, 0x49, 0x2a, 0x6e, 0x5b, 0xbf, 0x12,
   0x37, 0x47, 0xbd, 0x05, 0x6b, 0xbc, 0xdb, 0xf3, 0xee, 0xe4, 0x11, 0x8e, 0x41, 0x68, 0x7c, 0x61,
   0x13, 0xd7, 0x42, 0xc8, 0x80, 0xbe, 0x36, 0x8f, 0xdc, 0x08, 0x8b, 0x4f, 0xac, 0xa4, 0xe2, 0x76,
   0x0c, 0xc9, 0x63, 0x6c, 0x49, 0x58, 0x93, 0xed, 0xcc, 0xaa, 0xdc, 0x25, 0x3b, 0x0a, 0x60, 0x3f,
   0x8b, 0x54, 0x3a, 0xc3, 0x4d, 0x31, 0xe7, 0x94, 0xa4, 0x44, 0xfd, 0x02, 0x03, 0x01, 0x00, 0x01,
   0x02, 0x81, 0x81, 0x00, 0xc8, 0x62, 0xb9, 0xea, 0xde, 0x44, 0x53, 0x1d, 0x56, 0x97, 0xd9, 0x97,
   0x9e, 0x1a, 0xcf, 0x30, 0x1e, 0x0a, 0x88, 0x45, 0x86, 0x29, 0x30, 0xa3, 0x4d, 0x9f, 0x61, 0x65,
   0x73, 0xe0, 0xd6, 0x87, 0x8f, 0xb6, 0xf3, 0x06, 0xa3, 0x82, 0xdc, 0x7c, 0xac, 0xfe, 0x9b, 0x28,
   0x9a, 0xae, 0xfd, 0xfb, 0xfe, 0x2f, 0x0e, 0xd8, 0x97, 0x04, 0xe3, 0xbb, 0x1f, 0xd1, 0xec, 0x0d,
   0xba, 0xa3, 0x49, 0x7f, 0x47, 0xac, 0x8a, 0x44, 0x04, 0x7e, 0x86, 0xb7, 0x39, 0x42, 0x3f, 0xad,
   0x1e, 0xb7, 0x0e, 0xa5, 0x51, 0xf4, 0x40, 0x63, 0x1e, 0xfd, 0xbd, 0xea, 0x9f, 0x41, 0x9f, 0xa8,
   0x90, 0x1d, 0x6f, 0x0a, 0x5a, 0x95, 0x13, 0x11, 0x0d, 0x80, 0xaf, 0x5f, 0x64, 0x98, 0x8a, 0x2c,
   0x78, 0x68, 0x65, 0xb0, 0x2b, 0x8b, 0xa2, 0x53, 0x87, 0xca, 0xf1, 0x64, 0x04, 0xab, 0xf2, 0x7b,
   0xdb, 0x83, 0xc8, 0x81, 0x02, 0x41, 0x00, 0xf7, 0xbe, 0x5e, 0x23, 0xc3, 0x32, 0x3f, 0xbf, 0x8b,
   0x8e, 0x3a, 0xee, 0xfc, 0xfc, 0xcb, 0xe5, 0xf7, 0xf1, 0x0b, 0xbc, 0x42, 0x82, 0xae, 0xd5, 0x7a,
   0x3e, 0xca, 0xf7, 0xd5, 0x69, 0x3f, 0x64, 0x25, 0xa2, 0x1f, 0xb7, 0x75, 0x75, 0x05, 0x92, 0x42,
   0xeb, 0xb8, 0xf1, 0xf3, 0x0a, 0x05, 0xe3, 0x94, 0xd1, 0x55, 0x78, 0x35, 0xa0, 0x36, 0xa0, 0x9b,
   0x7c, 0x92, 0x84, 0x6c, 0xdd, 0xdc, 0x4d, 0x02, 0x41, 0x00, 0xd6, 0x86, 0x0e, 0x85, 0x42, 0x0b,
   0x04, 0x08, 0x84, 0x21, 0x60, 0xf0, 0x0e, 0x0d, 0x88, 0xfd, 0x1e, 0x36, 0x10, 0x65, 0x4f, 0x1e,
   0x53, 0xb4, 0x08, 0x72, 0x80, 0x5c, 0x3f, 0x59, 0x66, 0x17, 0xe6, 0x98, 0xf2, 0xe9, 0x6c, 0x7a,
   0x06, 0x4c, 0xac, 0x76, 0x3d, 0xed, 0x8c, 0xa1, 0xce, 0xad, 0x1b, 0xbd, 0xb4, 0x7d, 0x28, 0xbc,
   0xe3, 0x0e, 0x38, 0x8d, 0x99, 0xd8, 0x05, 0xb5, 0xa3, 0x71, 0x02, 0x40, 0x6d, 0xeb, 0xc3, 0x2d,
   0x2e, 0xf0, 0x5e, 0xa4, 0x88, 0x31, 0x05, 0x29, 0x00, 0x8a, 0xd1, 0x95, 0x29, 0x9b, 0x83, 0xcf,
   0x75, 0xdb, 0x31, 0xe3, 0x7a, 0x27, 0xde, 0x3a, 0x74, 0x30, 0x0c, 0x76, 0x4c, 0xd4, 0x50, 0x2a,
   0x40, 0x2d, 0x39, 0xd9, 0x99, 0x63, 0xa9, 0x5d, 0x80, 0xae, 0x53, 0xca, 0x94, 0x3f, 0x05, 0x23,
   0x1e, 0xf8, 0x05, 0x04, 0xe1, 0xb8, 0x35, 0xf2, 0x17, 0xb3, 0xa0, 0x89, 0x02, 0x41, 0x00, 0xab,
   0x90, 0x88, 0xfa, 0x60, 0x08, 0x29, 0x50, 0x9a, 0x43, 0x8b, 0xa0, 0x50, 0xcc, 0xd8, 0x5a, 0xfe,
   0x97, 0x64, 0x63, 0x71, 0x74, 0x22, 0xa3, 0x20, 0x02, 0x5a, 0xcf, 0xeb, 0xc6, 0x16, 0x95, 0x54,
   0xd1, 0xcb, 0xab, 0x8d, 0x1a, 0xc6, 0x00, 0xfa, 0x08, 0x92, 0x9c, 0x71, 0xd5, 0x52, 0x52, 0x35,
   0x96, 0x71, 0x4b, 0x8b, 0x92, 0x0c, 0xd0, 0xe9, 0xbf, 0xad, 0x63, 0x0b, 0xa5, 0xe9, 0xb1, 0x02,
   0x41, 0x00, 0xdc, 0xcc, 0x27, 0xc8, 0xe4, 0xdc, 0x62, 0x48, 0xd5, 0x9b, 0xaf, 0xf5, 0xab, 0x60,
   0xf6, 0x21, 0xfd, 0x53, 0xe2, 0xb7, 0x5d, 0x09, 0xc9, 0x1a, 0xa1, 0x04, 0xa9, 0xfc, 0x61, 0x2c,
   0x5d, 0x04, 0x58, 0x3a, 0x5a, 0x39, 0xf1, 0x4a, 0x21, 0x56, 0x67, 0xfd, 0xcc, 0x20, 0xa3, 0x8f,
   0x78, 0x18, 0x5a, 0x79, 0x3d, 0x2e, 0x8e, 0x7e, 0x86, 0x0a, 0xe6, 0xa8, 0x33, 0xc1, 0x04, 0x17,
   0x4a, 0x9f,  };


/*** openssl public RSA key in DER format */
static const unsigned char openssl_public_rsa[] = {
   0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
   0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xcf, 0x9a, 0xde,
   0x64, 0x8a, 0xda, 0xc8, 0x33, 0x20, 0xa9, 0xd7, 0x83, 0x31, 0x19, 0x54, 0xb2, 0x9a, 0x85, 0xa7,
   0xa1, 0xb7, 0x75, 0x33, 0xb6, 0xa9, 0xac, 0x84, 0x24, 0xb3, 0xde, 0xdb, 0x7d, 0x85, 0x2d, 0x96,
   0x65, 0xe5, 0x3f, 0x72, 0x95, 0x24, 0x9f, 0x28, 0x68, 0xca, 0x4f, 0xdb, 0x44, 0x1c, 0x3e, 0x60,
   0x12, 0x8a, 0xdd, 0x26, 0xa5, 0xeb, 0xff, 0x0b, 0x5e, 0xd4, 0x88, 0x38, 0x49, 0x2a, 0x6e, 0x5b,
   0xbf, 0x12, 0x37, 0x47, 0xbd, 0x05, 0x6b, 0xbc, 0xdb, 0xf3, 0xee, 0xe4, 0x11, 0x8e, 0x41, 0x68,
   0x7c, 0x61, 0x13, 0xd7, 0x42, 0xc8, 0x80, 0xbe, 0x36, 0x8f, 0xdc, 0x08, 0x8b, 0x4f, 0xac, 0xa4,
   0xe2, 0x76, 0x0c, 0xc9, 0x63, 0x6c, 0x49, 0x58, 0x93, 0xed, 0xcc, 0xaa, 0xdc, 0x25, 0x3b, 0x0a,
   0x60, 0x3f, 0x8b, 0x54, 0x3a, 0xc3, 0x4d, 0x31, 0xe7, 0x94, 0xa4, 0x44, 0xfd, 0x02, 0x03, 0x01,
   0x00, 0x01,  };

/* same key but with extra headers stripped */
static const unsigned char openssl_public_rsa_stripped[] = {
   0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xcf, 0x9a, 0xde,
   0x64, 0x8a, 0xda, 0xc8, 0x33, 0x20, 0xa9, 0xd7, 0x83, 0x31, 0x19, 0x54, 0xb2, 0x9a, 0x85, 0xa7,
   0xa1, 0xb7, 0x75, 0x33, 0xb6, 0xa9, 0xac, 0x84, 0x24, 0xb3, 0xde, 0xdb, 0x7d, 0x85, 0x2d, 0x96,
   0x65, 0xe5, 0x3f, 0x72, 0x95, 0x24, 0x9f, 0x28, 0x68, 0xca, 0x4f, 0xdb, 0x44, 0x1c, 0x3e, 0x60,
   0x12, 0x8a, 0xdd, 0x26, 0xa5, 0xeb, 0xff, 0x0b, 0x5e, 0xd4, 0x88, 0x38, 0x49, 0x2a, 0x6e, 0x5b,
   0xbf, 0x12, 0x37, 0x47, 0xbd, 0x05, 0x6b, 0xbc, 0xdb, 0xf3, 0xee, 0xe4, 0x11, 0x8e, 0x41, 0x68,
   0x7c, 0x61, 0x13, 0xd7, 0x42, 0xc8, 0x80, 0xbe, 0x36, 0x8f, 0xdc, 0x08, 0x8b, 0x4f, 0xac, 0xa4,
   0xe2, 0x76, 0x0c, 0xc9, 0x63, 0x6c, 0x49, 0x58, 0x93, 0xed, 0xcc, 0xaa, 0xdc, 0x25, 0x3b, 0x0a,
   0x60, 0x3f, 0x8b, 0x54, 0x3a, 0xc3, 0x4d, 0x31, 0xe7, 0x94, 0xa4, 0x44, 0xfd, 0x02, 0x03, 0x01,
   0x00, 0x01,  };

static int rsa_compat_test(void)
{
   rsa_key key;
   unsigned char buf[1024];
   unsigned long len;

   /* try reading the key */
   DO(rsa_import(openssl_private_rsa, sizeof(openssl_private_rsa), &key));

   /* now try to export private/public and compare */
   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PRIVATE, &key));
   if (len != sizeof(openssl_private_rsa) || memcmp(buf, openssl_private_rsa, len)) {
      fprintf(stderr, "RSA private export failed to match OpenSSL output, %lu, %lu\n", len, (unsigned long)sizeof(openssl_private_rsa));
      return 1;
   }

   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PUBLIC, &key));
   if (len != sizeof(openssl_public_rsa_stripped) || memcmp(buf, openssl_public_rsa_stripped, len)) {
      fprintf(stderr, "RSA(private) public export failed to match OpenSSL output\n");
      return 1;
   }
   rsa_free(&key);

   /* try reading the public key */
   DO(rsa_import(openssl_public_rsa_stripped, sizeof(openssl_public_rsa_stripped), &key));
   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PUBLIC, &key));
   if (len != sizeof(openssl_public_rsa_stripped) || memcmp(buf, openssl_public_rsa_stripped, len)) {
      fprintf(stderr, "RSA(public) stripped public import failed to match OpenSSL output\n");
      return 1;
   }
   rsa_free(&key);

   /* try reading the public key */
   DO(rsa_import(openssl_public_rsa, sizeof(openssl_public_rsa), &key));
   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PUBLIC, &key));
   if (len != sizeof(openssl_public_rsa_stripped) || memcmp(buf, openssl_public_rsa_stripped, len)) {
      fprintf(stderr, "RSA(public) SSL public import failed to match OpenSSL output\n");
      return 1;
   }
   rsa_free(&key);

   /* try export in SubjectPublicKeyInfo format of the public key */
   DO(rsa_import(openssl_public_rsa, sizeof(openssl_public_rsa), &key));
   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PUBLIC | PK_STD, &key));
   if (len != sizeof(openssl_public_rsa) || memcmp(buf, openssl_public_rsa, len)) {
      fprintf(stderr, "RSA(public) SSL public X.509 export failed to match OpenSSL output\n");
      print_hex("should", openssl_public_rsa, sizeof(openssl_public_rsa));
      print_hex("is", buf, len);
      return 1;
   }
   rsa_free(&key);

   return 0;
}

int rsa_test(void)
{
   unsigned char in[1024], out[1024], tmp[1024];
   rsa_key       key, privKey, pubKey;
   int           hash_idx, prng_idx, stat, stat2, i;
   unsigned long rsa_msgsize, len, len2, len3, cnt, cnt2;
   static unsigned char lparam[] = { 0x01, 0x02, 0x03, 0x04 };

   if (rsa_compat_test() != 0) {
      return 1;
   }

   hash_idx = find_hash("sha1");
   prng_idx = find_prng("yarrow");
   if (hash_idx == -1 || prng_idx == -1) {
      fprintf(stderr, "rsa_test requires LTC_SHA1 and yarrow");
      return 1;
   }

   /* make 10 random key */
   for (cnt = 0; cnt < 10; cnt++) {
      DO(rsa_make_key(&yarrow_prng, prng_idx, 1024/8, 65537, &key));
      if (mp_count_bits(key.N) != 1024) {
         fprintf(stderr, "rsa_1024 key modulus has %d bits\n", mp_count_bits(key.N));

len = mp_unsigned_bin_size(key.N);
mp_to_unsigned_bin(key.N, tmp);
 fprintf(stderr, "N == \n");
for (cnt = 0; cnt < len; ) {
   fprintf(stderr, "%02x ", tmp[cnt]);
   if (!(++cnt & 15)) fprintf(stderr, "\n");
}

len = mp_unsigned_bin_size(key.p);
mp_to_unsigned_bin(key.p, tmp);
 fprintf(stderr, "p == \n");
for (cnt = 0; cnt < len; ) {
   fprintf(stderr, "%02x ", tmp[cnt]);
   if (!(++cnt & 15)) fprintf(stderr, "\n");
}

len = mp_unsigned_bin_size(key.q);
mp_to_unsigned_bin(key.q, tmp);
 fprintf(stderr, "\nq == \n");
for (cnt = 0; cnt < len; ) {
   fprintf(stderr, "%02x ", tmp[cnt]);
   if (!(++cnt & 15)) fprintf(stderr, "\n");
}
 fprintf(stderr, "\n");


         return 1;
      }
      if (cnt != 9) {
         rsa_free(&key);
      }
   }

   /* encrypt the key (without lparam) */
   for (cnt = 0; cnt < 4; cnt++) {
   for (rsa_msgsize = 1; rsa_msgsize <= 86; rsa_msgsize++) {
      /* make a random key/msg */
      yarrow_read(in, rsa_msgsize, &yarrow_prng);

      len  = sizeof(out);
      len2 = rsa_msgsize;

      DO(rsa_encrypt_key(in, rsa_msgsize, out, &len, NULL, 0, &yarrow_prng, prng_idx, hash_idx, &key));
      /* change a byte */
      out[8] ^= 1;
      DO(rsa_decrypt_key(out, len, tmp, &len2, NULL, 0, hash_idx, &stat2, &key));
      /* change a byte back */
      out[8] ^= 1;
      if (len2 != rsa_msgsize) {
         fprintf(stderr, "\nrsa_decrypt_key mismatch len %lu (first decrypt)", len2);
         return 1;
      }

      len2 = rsa_msgsize;
      DO(rsa_decrypt_key(out, len, tmp, &len2, NULL, 0, hash_idx, &stat, &key));
      if (!(stat == 1 && stat2 == 0)) {
         fprintf(stderr, "rsa_decrypt_key (without lparam) failed (rsa_msgsize = %lu)", rsa_msgsize);
         fprintf(stderr, "\n stat: %i   stat2: %i", stat, stat2);
         return 1;
      }
      if (len2 != rsa_msgsize || memcmp(tmp, in, rsa_msgsize)) {
         fprintf(stderr, "\nrsa_decrypt_key mismatch, len %lu (second decrypt)\n", len2);
         print_hex("Original", in, rsa_msgsize);
         print_hex("Output", tmp, len2);
         return 1;
      }
   }
   }

   /* encrypt the key (with lparam) */
   for (rsa_msgsize = 1; rsa_msgsize <= 86; rsa_msgsize++) {
      len  = sizeof(out);
      len2 = rsa_msgsize;
      DO(rsa_encrypt_key(in, rsa_msgsize, out, &len, lparam, sizeof(lparam), &yarrow_prng, prng_idx, hash_idx, &key));
      /* change a byte */
      out[8] ^= 1;
      DO(rsa_decrypt_key(out, len, tmp, &len2, lparam, sizeof(lparam), hash_idx, &stat2, &key));
      if (len2 != rsa_msgsize) {
         fprintf(stderr, "\nrsa_decrypt_key mismatch len %lu (first decrypt)", len2);
         return 1;
      }
      /* change a byte back */
      out[8] ^= 1;

      len2 = rsa_msgsize;
      DO(rsa_decrypt_key(out, len, tmp, &len2, lparam, sizeof(lparam), hash_idx, &stat, &key));
      if (!(stat == 1 && stat2 == 0)) {
         fprintf(stderr, "rsa_decrypt_key (with lparam) failed (rsa_msgsize = %lu)", rsa_msgsize);
         return 1;
      }
      if (len2 != rsa_msgsize || memcmp(tmp, in, rsa_msgsize)) {
         fprintf(stderr, "rsa_decrypt_key mismatch len %lu", len2);
         print_hex("Original", in, rsa_msgsize);
         print_hex("Output", tmp, len2);
         return 1;
      }
   }

   /* encrypt the key PKCS #1 v1.5 (payload from 1 to 117 bytes) */
   for (rsa_msgsize = 1; rsa_msgsize <= 117; rsa_msgsize++) {
      len  = sizeof(out);
      len2 = rsa_msgsize;
      /* make a random key/msg */
      yarrow_read(in, rsa_msgsize, &yarrow_prng);
      DO(rsa_encrypt_key_ex(in, rsa_msgsize, out, &len, NULL, 0, &yarrow_prng, prng_idx, 0, LTC_PKCS_1_V1_5, &key));

      len2 = rsa_msgsize;
      DO(rsa_decrypt_key_ex(out, len, tmp, &len2, NULL, 0, 0, LTC_PKCS_1_V1_5, &stat, &key));
      if (stat != 1) {
         fprintf(stderr, "rsa_decrypt_key_ex failed, %d, %d", stat, stat2);
         return 1;
      }
      if (len2 != rsa_msgsize) {
         fprintf(stderr, "rsa_decrypt_key_ex mismatch len %lu", len2);
         return 1;
      }
      if (memcmp(tmp, in, rsa_msgsize)) {
         fprintf(stderr, "rsa_decrypt_key_ex mismatch data");
         print_hex("Original", in, rsa_msgsize);
         print_hex("Output", tmp, rsa_msgsize);
         return 1;
      }
   }

   /* sign a message (unsalted, lower cholestorol and Atkins approved) now */
   len = sizeof(out);
   DO(rsa_sign_hash(in, 20, out, &len, &yarrow_prng, prng_idx, hash_idx, 0, &key));

/* export key and import as both private and public */
   len2 = sizeof(tmp);
   DO(rsa_export(tmp, &len2, PK_PRIVATE, &key));
   DO(rsa_import(tmp, len2, &privKey));
   len2 = sizeof(tmp);
   DO(rsa_export(tmp, &len2, PK_PUBLIC, &key));
   DO(rsa_import(tmp, len2, &pubKey));

   /* verify with original */
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat, &key));
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat2, &key));

   if (!(stat == 1 && stat2 == 0)) {
      fprintf(stderr, "rsa_verify_hash (unsalted, origKey) failed, %d, %d", stat, stat2);
      rsa_free(&key);
      rsa_free(&pubKey);
      rsa_free(&privKey);
      return 1;
   }

   /* verify with privKey */
   /* change byte back to original */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat, &privKey));
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat2, &privKey));

   if (!(stat == 1 && stat2 == 0)) {
      fprintf(stderr, "rsa_verify_hash (unsalted, privKey) failed, %d, %d", stat, stat2);
      rsa_free(&key);
      rsa_free(&pubKey);
      rsa_free(&privKey);
      return 1;
   }

   /* verify with pubKey */
   /* change byte back to original */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat, &pubKey));
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat2, &pubKey));

   if (!(stat == 1 && stat2 == 0)) {
      fprintf(stderr, "rsa_verify_hash (unsalted, pubkey) failed, %d, %d", stat, stat2);
      rsa_free(&key);
      rsa_free(&pubKey);
      rsa_free(&privKey);
      return 1;
   }

   /* sign a message (salted) now (use privKey to make, pubKey to verify) */
   len = sizeof(out);
   DO(rsa_sign_hash(in, 20, out, &len, &yarrow_prng, prng_idx, hash_idx, 8, &privKey));
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 8, &stat, &pubKey));
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 8, &stat2, &pubKey));

   if (!(stat == 1 && stat2 == 0)) {
      fprintf(stderr, "rsa_verify_hash (salted) failed, %d, %d", stat, stat2);
      rsa_free(&key);
      rsa_free(&pubKey);
      rsa_free(&privKey);
      return 1;
   }

   /* sign a message with PKCS #1 v1.5 */
   len = sizeof(out);
   DO(rsa_sign_hash_ex(in, 20, out, &len, LTC_PKCS_1_V1_5, &yarrow_prng, prng_idx, hash_idx, 8, &privKey));
   DO(rsa_verify_hash_ex(out, len, in, 20, LTC_PKCS_1_V1_5, hash_idx, 8, &stat, &pubKey));
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash_ex(out, len, in, 20, LTC_PKCS_1_V1_5, hash_idx, 8, &stat2, &pubKey));

   if (!(stat == 1 && stat2 == 0)) {
      fprintf(stderr, "rsa_verify_hash_ex failed, %d, %d", stat, stat2);
      rsa_free(&key);
      rsa_free(&pubKey);
      rsa_free(&privKey);
      return 1;
   }

   /* Testcase for Bleichenbacher attack
    *
    * (1) Create a valid signature
    * (2) Check that it can be verified
    * (3) Decrypt the package to fetch plain text
    * (4) Forge the structure of PKCS#1-EMSA encoded data
    * (4.1) Search for start and end of the padding string
    * (4.2) Move the signature to the front of the padding string
    * (4.3) Zero the message until the end
    * (5) Encrypt the package again
    * (6) Profit :)
    *     For PS lengths < 8:  the verification process should fail
    *     For PS lengths >= 8: the verification process should succeed
    *     For all PS lengths:  the result should not be valid
    */

   unsigned char* p = in;
   unsigned char* p2 = out;
   unsigned char* p3 = tmp;
   for (i = 0; i < 9; ++i) {
     len = sizeof(in);
     len2 = sizeof(out);
     cnt = rsa_get_size(&key);
     /* (1) */
     DO(rsa_sign_hash_ex(p, 20, p2, &len2, LTC_PKCS_1_V1_5, &yarrow_prng, prng_idx, hash_idx, 8, &privKey));
     /* (2) */
     DOX(rsa_verify_hash_ex(p2, len2, p, 20, LTC_PKCS_1_V1_5, hash_idx, -1, &stat, &pubKey), "should succeed");
     DOX(stat == 1?CRYPT_OK:CRYPT_FAIL_TESTVECTOR, "should succeed");
     len3 = sizeof(tmp);
     /* (3) */
     DO(ltc_mp.rsa_me(p2, len2, p3, &len3, PK_PUBLIC, &key));
     /* (4) */
#if 0
     printf("\nBefore:");
     for (cnt = 0; cnt < len3; ++cnt) {
       if (cnt%32 == 0)
         printf("\n%3lu:", cnt);
       printf(" %02x", p3[cnt]);
     }
#endif
     /* (4.1) */
     for (cnt = 0; cnt < len3; ++cnt) {
        if (p3[cnt] == 0xff)
          break;
     }
     for (cnt2 = cnt+1; cnt2 < len3; ++cnt2) {
        if (p3[cnt2] != 0xff)
          break;
     }
     /* (4.2) */
     memmove(&p3[cnt+i], &p3[cnt2], len3-cnt2);
     /* (4.3) */
     for (cnt = cnt + len3-cnt2+i; cnt < len; ++cnt) {
        p3[cnt] = 0;
     }
#if 0
     printf("\nAfter:");
     for (cnt = 0; cnt < len3; ++cnt) {
       if (cnt%32 == 0)
         printf("\n%3lu:", cnt);
       printf(" %02x", p3[cnt]);
     }
     printf("\n");
#endif

     len2 = sizeof(out);
     /* (5) */
     DO(ltc_mp.rsa_me(p3, len3, p2, &len2, PK_PRIVATE, &key));

     len3 = sizeof(tmp);
     /* (6) */
     if (i < 8)
       DOX(rsa_verify_hash_ex(p2, len2, p, 20, LTC_PKCS_1_V1_5, hash_idx, -1, &stat, &pubKey)
           == CRYPT_INVALID_PACKET ? CRYPT_OK:CRYPT_INVALID_PACKET, "should fail");
     else
       DOX(rsa_verify_hash_ex(p2, len2, p, 20, LTC_PKCS_1_V1_5, hash_idx, -1, &stat, &pubKey), "should succeed");
     DOX(stat == 0?CRYPT_OK:CRYPT_FAIL_TESTVECTOR, "should fail");
   }

   /* free the key and return */
   rsa_free(&key);
   rsa_free(&pubKey);
   rsa_free(&privKey);
   return 0;
}

#else

int rsa_test(void)
{
   fprintf(stderr, "NOP");
   return 0;
}

#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
