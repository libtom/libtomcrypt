/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_test.h"

/**
  @file ed25519_test.c
  Ed25519 tests, Steffen Jaeckel
*/

#ifdef LTC_CURVE25519

static int s_rfc_8410_10_test(void)
{
   const struct {
      const char* b64;
      int type;
   } rfc_8410_10[] = {
                         /* RFC 8410 - 10.1.  Example Ed25519 Public Key */
                       { "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=", PK_PUBLIC | PK_STD },
                         /* Okay this is not from RFC 8410, but a custom generated certificate with Ed25519 Public Key.
                          * Since RFC 8410 has no testvector for that case, one had to be created.
                          * ( openssl req -verbose -new -x509 -subj "/CN=Public domain ed25519 self-signed certificate" -days 36525 -key <( openssl genpkey -algorithm ed25519 2>/dev/null | tee /dev/fd/3) | openssl x509  ) 3>&1
                          * Thx @vdukhovni
                          */
                       { "MIIBhDCCATagAwIBAgIUHDa8kJUZeCuIhknPJ/wDeBW6gZgwBQYDK2VwMDgxNjA0"
                         "BgNVBAMMLVB1YmxpYyBkb21haW4gZWQyNTUxOSBzZWxmLXNpZ25lZCBjZXJ0aWZp"
                         "Y2F0ZTAgFw0xOTA1MjMyMTAxMTZaGA8yMTE5MDUyNDIxMDExNlowODE2MDQGA1UE"
                         "AwwtUHVibGljIGRvbWFpbiBlZDI1NTE5IHNlbGYtc2lnbmVkIGNlcnRpZmljYXRl"
                         "MCowBQYDK2VwAyEAUEiKvHT0KHXOtNjIhaImokxbiog+Ki6lcgce05tf9UKjUDBO"
                         "MB0GA1UdDgQWBBS3fmpWaPK2fNpblEmg4tG4ZHO2BDAfBgNVHSMEGDAWgBS3fmpW"
                         "aPK2fNpblEmg4tG4ZHO2BDAMBgNVHRMEBTADAQH/MAUGAytlcANBADOnwkj8etmx"
                         "mTaXUP29RaenxpN8dQoQ4wnnIJwxQxTcVWOt2PlUxCFoB9gs0+YZOzhXnQg4hfqk"
                         "t/HPExwoZQg=", -2 },
                         /* RFC 8410 - 10.3.  Examples of Ed25519 Private Key */
                       { "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC", PK_PRIVATE | PK_STD },
                         /* RFC 8410 - 10.3.  Examples of Ed25519 Private Key with attribute */
                       { "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC"
                         "oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB"
                         "Z9w7lshQhqowtrbLDFw4rXAxZuE=", -1 },
                         /* Another self-created testvector.
                          * `openssl genpkey -algorithm ed25519 -pass stdin -aes128`
                          */
                       { "MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAiFflnrBOdwjwICCAAw"
                         "DAYIKoZIhvcNAgkFADAdBglghkgBZQMEAQIEEMzFYoqiT6gxwFx2EA55MUYEQFD1"
                         "ZLxPNhm4YAsMZaxu5qpLjiZbkWsTHxURb6WhSW8GAbNbTwxeOaA02sUhJg8rx44/"
                         "N9PzN2QGzIQ1Yv/vHqQ=", -1 },
   };
   unsigned n;
   curve25519_key key;
   unsigned char buf[1024];
   char tmp[512];
   unsigned long buflen, tmplen;
   for (n = 0; n < sizeof(rfc_8410_10)/sizeof(rfc_8410_10[0]); ++n) {
      buflen = sizeof(buf);
      DO(base64_decode(rfc_8410_10[n].b64, XSTRLEN(rfc_8410_10[n].b64), buf, &buflen));
      switch (n) {
         case 0:
            DO(ed25519_import(buf, buflen, &key));
            break;
         case 1:
            DO(ed25519_import_x509(buf, buflen, &key));
            break;
         case 2:
         case 3:
            DO(ed25519_import_pkcs8(buf, buflen, NULL, 0, &key));
            break;
         case 4:
            DO(ed25519_import_pkcs8(buf, buflen, "123456", 6, &key));
            break;
         default:
            return CRYPT_FAIL_TESTVECTOR;
      }
      zeromem(buf, sizeof(buf));
      if (rfc_8410_10[n].type > 0) {
         buflen = sizeof(buf);
         DO(ed25519_export(buf, &buflen, rfc_8410_10[n].type, &key));
         tmplen = sizeof(tmp);
         DO(base64_encode(buf, buflen, tmp, &tmplen));
         DO(do_compare_testvector(tmp, tmplen, rfc_8410_10[n].b64, XSTRLEN(rfc_8410_10[n].b64), "Ed25519 export-import", n));
      }
   }
   return CRYPT_OK;
}

typedef struct {
   const char* secret_key;
   const char* public_key;
   const char* message;
   const char* signature;
} rfc_8032_7_1_t;

static int s_rfc_8032_7_1_test(void)
{
   const rfc_8032_7_1_t rfc_8032_7_1[] = {
      {
         /* SECRET KEY */
         "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         /* PUBLIC KEY */
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         /* MESSAGE (length 0 bytes) */
         "",
         /* SIGNATURE */
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
      },
      {
         /* SECRET KEY */
         "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         /* PUBLIC KEY */
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         /* MESSAGE (length 1 byte) */
         "72",
         /* SIGNATURE */
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
         "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
      },
      {
         /* SECRET KEY */
         "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         /* PUBLIC KEY */
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         /* MESSAGE (length 2 bytes) */
         "af82",
         /* SIGNATURE */
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
      },
      {
         /* SECRET KEY */
         "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
         /* PUBLIC KEY */
         "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
         /* MESSAGE (length 1023 bytes) */
         "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
         "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
         "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
         "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
         "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
         "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
         "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
         "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
         "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
         "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
         "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
         "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
         "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
         "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
         "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
         "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
         "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
         "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
         "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
         "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
         "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
         "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
         "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
         "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
         "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
         "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
         "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
         "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
         "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
         "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
         "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
         "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
         /* SIGNATURE */
         "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
         "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
      },
      {
         /* SECRET KEY */
         "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
         /* PUBLIC KEY */
         "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
         /* MESSAGE (length 64 bytes) */
         "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
         "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
         /* SIGNATURE */
         "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
         "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
      }
   };
   unsigned int n;
   unsigned long mlen, slen, plen, siglen, buflen;
   unsigned char msg[1024], sec[32], pub[32], sig[64], buf[64];
   curve25519_key key, key2;
   int ret;
   const int should = 1;
   for (n = 0; n < sizeof(rfc_8032_7_1)/sizeof(rfc_8032_7_1[0]); ++n) {
      slen = sizeof(sec);
      DO(base16_decode(rfc_8032_7_1[n].secret_key, XSTRLEN(rfc_8032_7_1[n].secret_key), sec, &slen));
      plen = sizeof(pub);
      DO(base16_decode(rfc_8032_7_1[n].public_key, XSTRLEN(rfc_8032_7_1[n].public_key), pub, &plen));
      mlen = sizeof(msg);
      DO(base16_decode(rfc_8032_7_1[n].message, XSTRLEN(rfc_8032_7_1[n].message), msg, &mlen));
      siglen = sizeof(sig);
      DO(base16_decode(rfc_8032_7_1[n].signature, XSTRLEN(rfc_8032_7_1[n].signature), sig, &siglen));
      DO(ed25519_import_raw(sec, slen, PK_PRIVATE, &key));
      buflen = sizeof(buf);
      DO(ed25519_sign(msg, mlen, buf, &buflen, &key));
      DO(do_compare_testvector(buf, buflen, sig, siglen, "Ed25519 RFC8032 7.1 - sign", n));
      DO(ed25519_verify(msg, mlen, sig, siglen, &ret, &key));
      DO(do_compare_testvector(&ret, sizeof(ret), &should, sizeof(should), "Ed25519 RFC8032 7.1 - verify w/ privkey", n));

      plen = sizeof(pub);
      DO(base16_decode(rfc_8032_7_1[n].public_key, XSTRLEN(rfc_8032_7_1[n].public_key), pub, &plen));
      mlen = sizeof(msg);
      DO(base16_decode(rfc_8032_7_1[n].message, XSTRLEN(rfc_8032_7_1[n].message), msg, &mlen));
      siglen = sizeof(sig);
      DO(base16_decode(rfc_8032_7_1[n].signature, XSTRLEN(rfc_8032_7_1[n].signature), sig, &siglen));
      DO(ed25519_import_raw(pub, plen, PK_PUBLIC, &key2));
      DO(ed25519_verify(msg, mlen, sig, siglen, &ret, &key2));
      DO(do_compare_testvector(&ret, sizeof(ret), &should, sizeof(should), "Ed25519 RFC8032 7.1 - verify w/ pubkey", n));

      zeromem(&key, sizeof(key));
      zeromem(&key2, sizeof(key2));
   }
   return CRYPT_OK;
}

/**
  Test the ed25519 system
  @return CRYPT_OK if successful
*/
int ed25519_test(void)
{
   int ret;
   curve25519_key key;

   if ((ret = ed25519_make_key(&yarrow_prng, find_prng("yarrow"), &key)) != CRYPT_OK) {
      return ret;
   }

   if (ltc_mp.name == NULL) return CRYPT_NOP;

   if ((ret = s_rfc_8410_10_test()) != CRYPT_OK) {
      return ret;
   }
   if ((ret = s_rfc_8032_7_1_test()) != CRYPT_OK) {
      return ret;
   }

   return ret;
}

#else

int ed25519_test(void)
{
   return CRYPT_NOP;
}

#endif
