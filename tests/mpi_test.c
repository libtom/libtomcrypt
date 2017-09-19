/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include  <tomcrypt_test.h>

#if defined(LTC_MPI) && defined(LTC_TEST_MPI)
static int _radix_to_bin_test(void)
{
   /* RADIX 16 */
   const char *ghex = "2";
   const char *phex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22"
                      "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6"
                      "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                      "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
                      "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8603"
                      "9B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                      "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
   const char *xhex = "A6681ADC386CE944C3DED9A7301DCC9C518250E3EDB62F959198F8DC0057DD6FB57ABAFD788198B1";
   const char *yhex = "39046632C834418DFA07B3091538B614D1FB5DBB785C0FBEA3B98B295BC0CD076A88D9452141A269"
                      "E8BAEB1DD654EBA03A5705318D129754CDF4003A8C399240FBB8F162490F6F0DC70E414B6FEE8808"
                      "6AFAA48E9F3A248EDC093452663D34E0E809D4F6BADBB36F80B6813EBF7C3281B862209E5604BDEA"
                      "8B8F5F7BFDC3EEB7ADB73048289BCEA0F5A5CDEE7DF91CD1F0BA632F06DBE9BA7EF014B84B02D497"
                      "CA7D0C60F734752A649DA496946B4E531B30D9F82EDD855636C0B0F2AE232E4186454E8887BB423E"
                      "32A5A2495EACBA99620ACD03A38345EBB6735E62330A8EE9AA6C8370410F5CD45AF37EE90A0DA95B"
                      "E96FC939E88FE0BD2CD09FC8F524208C";
   /* RADIX 47 */
   const char *gr47 = "2";
   const char *pr47 = "F27Mg1SadOFIRbDOJ5dHgHiVF02Z1LHHQ6G5SLG2U8aTdfH1ETk4GARRE7WW99dBUBLb9e2OHFIaSM1A"
                      "ag2LNNjgYa9I9CjQGJihL3J7A2SGQe8j5Ch8EHMj5jVbAYDiQKhhPhM6Hc56fKS40GUfJkGO7KJ6EXZQ"
                      "VgbSa2AkPC65F91g0PaYie8AGNVaFKaV9HOQf3ia1iW4i6eCOB9CcBbH7TbQij8AEgjZ0VRBcLKc6UYO"
                      "1Zc3I2Jc0h1H2HBEH8ONI3OYBbaPV6XhAd8WCc60D0RDBU3H9U7cWL28a0c90XNO0dh5RXEFBbUCE2ZG"
                      "gh9XQSVIHkVbFIS5F5IGVOkiWAVc9i8BHB2V0UbGW6UdRTZVV";
   const char *xr47 = "6bhO7O9NWFRgEMjdU0Y5POj3c1JP15MYEdIg3FO1PEjUY2aGYNSXcaF01R";
   const char *yr47 = "3GNPNWEYfKML1cIbI7Cc1Z0O7aQLJgB734dO2i56LLYDdI4gHYk2GAbQH2WI97hNeC7dj3fPEH8I9gV9"
                      "U323AXj1AJXbFPFIHGOTdC29QUUeH2SSc6NWhfQDDXd5Q5iXCKEAUGX3SKcNFIfVOYJgZCLjfHYQdgOQ"
                      "GCjKNgbEV7Hj34MU3b79iANX2DbMYfb9iGi78BWH2HYAd7IAhk7U0OYGHKJX1bIUUj1KBLhAUg46GaER"
                      "G9W3ARMfBCj6kSdDF9TdkWAjWTDj722IeVJERC4bKU2VDFG20kDhCMF985efD1SS8DfXcdCHF1kDUkSA"
                      "884FHYiFEPkaagQOBQaN9BNaEHNbbd002DCIIX5eMP4HgPJPF";
   /* RADIX 64 */
   const char *gr64 = "2";
   const char *pr64 = "3//////////yaFsg8XQC8qnCPYYu3S7D4f0au8YcVCT08BlgOx4viYKKe8UOuq1DtlbHcppJf36p0h2c"
                      "toNnGtJ+4rRMrHmaNaXRLsObv+nlHCGkccD+rh2/zSjlG6j+tkE6lxMecVfQwV915yIn/cIIXcKUpaMp"
                      "t207oueME/1PZQI3OSLTEQQHO/gFqapr+3PLqZtAEjbXnYyrOWXLAxdjKf1t2Mbcrd33LEIhoO1F5qR0"
                      "ZA625yCf1UHYuspZlZddSi60w60vidWwBi1wAFjSLTy6zCKidUAylsbLWN63cLINpgbMhb5T8c69Zw1H"
                      "0LSevQYgogQF//////////";
   const char *xr64 = "2cQ1hSE6pfHCFUsQSm7SoSKO9Gu+ssBvMHcFZS05VTRxLwklruWPYn";
   const char *yr64 = "v16Ooo3H1ZVe7imaLEBOKqVjTktXS3xwZkOifMy3D1sg8sKKXGQ9fwBhh7TPKww0wLmKnZHANLCtq03g"
                      "CEP90+xZnOaaFRmt73a5BR+w826hwf8wVEYIEt0aqKcOzDE3e2TJskjkpRu2sWJw/V3A1k68WdbO4lUg"
                      "BZrzx/SFkjwstC4WecywWzQNDxdtv7D7mkcCl1jlfkdxm5BXB0jINodqCOFSqTIfadQIMb6jEKnimsVW"
                      "ktOLMDi2myguZBa66HKw8Xxj2FZAbeabUhBgPOWhD0wE3HUksSrvYCmgEwQfiWt113rpKMlD+wGeDgLl"
                      "fRyavw8/WlIpGdyZr922C";
   /* RADIX 256 */
   unsigned char gbin[] = { 0x02 };
   unsigned char pbin[] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
      0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
      0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
      0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
      0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
      0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
      0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
      0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
      0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
      0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
      0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
      0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
      0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
      0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
      0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
      0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
   };
   unsigned char xbin[] = {
      0xA6, 0x68, 0x1A, 0xDC, 0x38, 0x6C, 0xE9, 0x44, 0xC3, 0xDE, 0xD9, 0xA7, 0x30, 0x1D, 0xCC, 0x9C,
      0x51, 0x82, 0x50, 0xE3, 0xED, 0xB6, 0x2F, 0x95, 0x91, 0x98, 0xF8, 0xDC, 0x00, 0x57, 0xDD, 0x6F,
      0xB5, 0x7A, 0xBA, 0xFD, 0x78, 0x81, 0x98, 0xB1
   };
   unsigned char ybin[] = {
      0x39, 0x04, 0x66, 0x32, 0xC8, 0x34, 0x41, 0x8D, 0xFA, 0x07, 0xB3, 0x09, 0x15, 0x38, 0xB6, 0x14,
      0xD1, 0xFB, 0x5D, 0xBB, 0x78, 0x5C, 0x0F, 0xBE, 0xA3, 0xB9, 0x8B, 0x29, 0x5B, 0xC0, 0xCD, 0x07,
      0x6A, 0x88, 0xD9, 0x45, 0x21, 0x41, 0xA2, 0x69, 0xE8, 0xBA, 0xEB, 0x1D, 0xD6, 0x54, 0xEB, 0xA0,
      0x3A, 0x57, 0x05, 0x31, 0x8D, 0x12, 0x97, 0x54, 0xCD, 0xF4, 0x00, 0x3A, 0x8C, 0x39, 0x92, 0x40,
      0xFB, 0xB8, 0xF1, 0x62, 0x49, 0x0F, 0x6F, 0x0D, 0xC7, 0x0E, 0x41, 0x4B, 0x6F, 0xEE, 0x88, 0x08,
      0x6A, 0xFA, 0xA4, 0x8E, 0x9F, 0x3A, 0x24, 0x8E, 0xDC, 0x09, 0x34, 0x52, 0x66, 0x3D, 0x34, 0xE0,
      0xE8, 0x09, 0xD4, 0xF6, 0xBA, 0xDB, 0xB3, 0x6F, 0x80, 0xB6, 0x81, 0x3E, 0xBF, 0x7C, 0x32, 0x81,
      0xB8, 0x62, 0x20, 0x9E, 0x56, 0x04, 0xBD, 0xEA, 0x8B, 0x8F, 0x5F, 0x7B, 0xFD, 0xC3, 0xEE, 0xB7,
      0xAD, 0xB7, 0x30, 0x48, 0x28, 0x9B, 0xCE, 0xA0, 0xF5, 0xA5, 0xCD, 0xEE, 0x7D, 0xF9, 0x1C, 0xD1,
      0xF0, 0xBA, 0x63, 0x2F, 0x06, 0xDB, 0xE9, 0xBA, 0x7E, 0xF0, 0x14, 0xB8, 0x4B, 0x02, 0xD4, 0x97,
      0xCA, 0x7D, 0x0C, 0x60, 0xF7, 0x34, 0x75, 0x2A, 0x64, 0x9D, 0xA4, 0x96, 0x94, 0x6B, 0x4E, 0x53,
      0x1B, 0x30, 0xD9, 0xF8, 0x2E, 0xDD, 0x85, 0x56, 0x36, 0xC0, 0xB0, 0xF2, 0xAE, 0x23, 0x2E, 0x41,
      0x86, 0x45, 0x4E, 0x88, 0x87, 0xBB, 0x42, 0x3E, 0x32, 0xA5, 0xA2, 0x49, 0x5E, 0xAC, 0xBA, 0x99,
      0x62, 0x0A, 0xCD, 0x03, 0xA3, 0x83, 0x45, 0xEB, 0xB6, 0x73, 0x5E, 0x62, 0x33, 0x0A, 0x8E, 0xE9,
      0xAA, 0x6C, 0x83, 0x70, 0x41, 0x0F, 0x5C, 0xD4, 0x5A, 0xF3, 0x7E, 0xE9, 0x0A, 0x0D, 0xA9, 0x5B,
      0xE9, 0x6F, 0xC9, 0x39, 0xE8, 0x8F, 0xE0, 0xBD, 0x2C, 0xD0, 0x9F, 0xC8, 0xF5, 0x24, 0x20, 0x8C
   };
   /* long HEX */
   const char *lhex =
      "308203423082023506072a8648ce3804013082022802820101008f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf3718"
      "e8eac4961f3efd3606e74351a9c4183339b809e7c2ae1c539ba7475b85d011adb8b47987754984695cac0e8f14b3360828a2"
      "2ffa27110a3d62a993453409a0fe696c4658f84bdd20819c3709a01057b195adcd00233dba5484b6291f9d648ef883448677"
      "979cec04b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e7338db792b730d7b9e349592f68099872153915ea3d6b8b"
      "4653c633458f803b32a4c2e0f27290256e4e3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff04903ed5cf1623e158"
      "d487c608e97f211cd81dca23cb6e380765f822e342be484c05763939601cd667021d00baf696a68578f7dfdee7fa67c977c7"
      "85ef32b233bae580c0bcd5695d0282010016a65c58204850704e7502a39757040d34da3a3478c154d4e4a5c02d242ee04f96"
      "e61e4bd0904abdac8f37eeb1e09f3182d23c9043cb642f88004160edf9ca09b32076a79c32a627f2473e91879ba2c4e744bd"
      "2081544cb55b802c368d1fa83ed489e94e0fa0688e32428a5c78c478c68d0527b71c9a3abb0b0be12c44689639e7d3ce74db"
      "101a65aa2b87f64c6826db3ec72f4b5599834bb4edb02f7c90e9a496d3a55d535bebfc45d4f619f63f3dedbb873925c2f224"
      "e07731296da887ec1e4748f87efb5fdeb75484316b2232dee553ddaf02112b0d1f02da30973224fe27aeda8b9d4b2922d9ba"
      "8be39ed9e103a63c52810bc688b7e2ed4316e1ef17dbde0382010500028201001e77f842b1ae0fcd9929d394161d41e14614"
      "ff7507a9a31f4a1f14d22e2a627a1f4e596624883f1a5b168e9425146f22d5f6ee28757414714bb994ba1129f015d6e04a71"
      "7edf9b530a5d5cab94f14631e8b4cf79aeb358cc741845553841e8ac461630e804a62f43676ba6794af66899c377b869ea61"
      "2a7b9fe6611aa96be52eb8b62c979117bbbcca8a7ec1e1ffab1c7dfcfc7048700d3ae3858136e897701d7c2921b5dfef1d1f"
      "897f50d96ca1b5c2edc58cada18919e35642f0807eebfa00c99a32f4d095c3188f78ed54711be0325c4b532aeccd6540a567"
      "c327225440ea15319bde06510479a1861799e25b57decc73c036d75a0702bd373ca231349931";

   struct {
     int radix;
     const void* g; int glen;
     const void* p; int plen;
     const void* x; int xlen;
     const void* y; int ylen;
   } test[4] = {
      { 256, gbin, sizeof(gbin),   pbin, sizeof(pbin),   xbin, sizeof(xbin),   ybin, sizeof(ybin)   },
      { 16,  ghex, strlen(ghex)+1, phex, strlen(phex)+1, xhex, strlen(xhex)+1, yhex, strlen(yhex)+1 },
      { 47,  gr47, strlen(gr47)+1, pr47, strlen(pr47)+1, xr47, strlen(xr47)+1, yr47, strlen(yr47)+1 },
      { 64,  gr64, strlen(gr64)+1, pr64, strlen(pr64)+1, xr64, strlen(xr64)+1, yr64, strlen(yr64)+1 },
   };
   int i, j;
   unsigned char key_parts[4][256];
   unsigned long key_lens[4];
   unsigned char lbuf[1000];
   unsigned long lbuflen = sizeof(lbuf);

   for (i = 1; i < 4; i++) {
      for (j = 0; j < 4; ++j) {
         key_lens[j] = sizeof(key_parts[j]);
      }
      DO(radix_to_bin(test[i].x, test[i].radix, key_parts[0], &key_lens[0]));
      DO(radix_to_bin(test[i].y, test[i].radix, key_parts[1], &key_lens[1]));
      DO(radix_to_bin(test[i].p, test[i].radix, key_parts[2], &key_lens[2]));
      DO(radix_to_bin(test[i].g, test[i].radix, key_parts[3], &key_lens[3]));

      if (compare_testvector(key_parts[0], key_lens[0], test[0].x, test[0].xlen, "radix_to_bin(x)", i)) return CRYPT_FAIL_TESTVECTOR;
      if (compare_testvector(key_parts[1], key_lens[1], test[0].y, test[0].ylen, "radix_to_bin(y)", i)) return CRYPT_FAIL_TESTVECTOR;
      if (compare_testvector(key_parts[2], key_lens[2], test[0].p, test[0].plen, "radix_to_bin(p)", i)) return CRYPT_FAIL_TESTVECTOR;
      if (compare_testvector(key_parts[3], key_lens[3], test[0].g, test[0].glen, "radix_to_bin(g)", i)) return CRYPT_FAIL_TESTVECTOR;
   }

   DO(radix_to_bin(lhex, 16, lbuf, &lbuflen));
   if (lbuflen != 838) {
      fprintf(stderr, "radix_to_bin failed, lbuflen=%lu (expected 838)\n", lbuflen);
      return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
}

int mpi_test(void)
{
   return _radix_to_bin_test();
}
#else
int mpi_test(void)
{
   return CRYPT_NOP;
}
#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
