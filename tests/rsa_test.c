/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include <tomcrypt_test.h>

#if defined(LTC_MRSA)
#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
#include <malloc.h>
#define dbg_malloc_stats() do{ malloc_stats(); }while(0)
#else
#define dbg_malloc_stats() do{ }while(0)
#endif

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

static const char x509_public_rsa[] =
    "MIICdTCCAd4CCQCYjCwz0l9JpjANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJD\
     WjEPMA0GA1UECAwGTW9yYXZhMQ0wCwYDVQQHDARCcm5vMRAwDgYDVQQKDAdMVEMg\
     THRkMQ8wDQYDVQQLDAZDcnlwdG8xEjAQBgNVBAMMCVRlc3QgQ2VydDEYMBYGCSqG\
     SIb3DQEJARYJdGVzdEBjZXJ0MCAXDTE3MDMwOTIzNDMzOVoYDzIyOTAxMjIyMjM0\
     MzM5WjB+MQswCQYDVQQGEwJDWjEPMA0GA1UECAwGTW9yYXZhMQ0wCwYDVQQHDARC\
     cm5vMRAwDgYDVQQKDAdMVEMgTHRkMQ8wDQYDVQQLDAZDcnlwdG8xEjAQBgNVBAMM\
     CVRlc3QgQ2VydDEYMBYGCSqGSIb3DQEJARYJdGVzdEBjZXJ0MIGfMA0GCSqGSIb3\
     DQEBAQUAA4GNADCBiQKBgQDPmt5kitrIMyCp14MxGVSymoWnobd1M7aprIQks97b\
     fYUtlmXlP3KVJJ8oaMpP20QcPmASit0mpev/C17UiDhJKm5bvxI3R70Fa7zb8+7k\
     EY5BaHxhE9dCyIC+No/cCItPrKTidgzJY2xJWJPtzKrcJTsKYD+LVDrDTTHnlKRE\
     /QIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAApwWqupmmLGHeKOLFLcthQpAXXYep6T\
     3S3e8X7fIG6TGhfvn5DHn+/V/C4184oOCwImI+VYRokdXdQ1AMGfVUomHJxsFPia\
     bv5Aw3hiKsIG3jigKHwmMScgkl3yn+8hLkx6thNbqQoa6Yyo20RqaEFBwlZ5G8lF\
     rZsdeO84SeCH";

static const unsigned char pkcs8_private_rsa[] = {
   0x30, 0x82, 0x02, 0x78, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
   0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x02, 0x62, 0x30, 0x82, 0x02, 0x5e, 0x02, 0x01,
   0x00, 0x02, 0x81, 0x81, 0x00, 0xcf, 0x9a, 0xde, 0x64, 0x8a, 0xda, 0xc8, 0x33, 0x20, 0xa9, 0xd7,
   0x83, 0x31, 0x19, 0x54, 0xb2, 0x9a, 0x85, 0xa7, 0xa1, 0xb7, 0x75, 0x33, 0xb6, 0xa9, 0xac, 0x84,
   0x24, 0xb3, 0xde, 0xdb, 0x7d, 0x85, 0x2d, 0x96, 0x65, 0xe5, 0x3f, 0x72, 0x95, 0x24, 0x9f, 0x28,
   0x68, 0xca, 0x4f, 0xdb, 0x44, 0x1c, 0x3e, 0x60, 0x12, 0x8a, 0xdd, 0x26, 0xa5, 0xeb, 0xff, 0x0b,
   0x5e, 0xd4, 0x88, 0x38, 0x49, 0x2a, 0x6e, 0x5b, 0xbf, 0x12, 0x37, 0x47, 0xbd, 0x05, 0x6b, 0xbc,
   0xdb, 0xf3, 0xee, 0xe4, 0x11, 0x8e, 0x41, 0x68, 0x7c, 0x61, 0x13, 0xd7, 0x42, 0xc8, 0x80, 0xbe,
   0x36, 0x8f, 0xdc, 0x08, 0x8b, 0x4f, 0xac, 0xa4, 0xe2, 0x76, 0x0c, 0xc9, 0x63, 0x6c, 0x49, 0x58,
   0x93, 0xed, 0xcc, 0xaa, 0xdc, 0x25, 0x3b, 0x0a, 0x60, 0x3f, 0x8b, 0x54, 0x3a, 0xc3, 0x4d, 0x31,
   0xe7, 0x94, 0xa4, 0x44, 0xfd, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x81, 0x81, 0x00, 0xc8, 0x62,
   0xb9, 0xea, 0xde, 0x44, 0x53, 0x1d, 0x56, 0x97, 0xd9, 0x97, 0x9e, 0x1a, 0xcf, 0x30, 0x1e, 0x0a,
   0x88, 0x45, 0x86, 0x29, 0x30, 0xa3, 0x4d, 0x9f, 0x61, 0x65, 0x73, 0xe0, 0xd6, 0x87, 0x8f, 0xb6,
   0xf3, 0x06, 0xa3, 0x82, 0xdc, 0x7c, 0xac, 0xfe, 0x9b, 0x28, 0x9a, 0xae, 0xfd, 0xfb, 0xfe, 0x2f,
   0x0e, 0xd8, 0x97, 0x04, 0xe3, 0xbb, 0x1f, 0xd1, 0xec, 0x0d, 0xba, 0xa3, 0x49, 0x7f, 0x47, 0xac,
   0x8a, 0x44, 0x04, 0x7e, 0x86, 0xb7, 0x39, 0x42, 0x3f, 0xad, 0x1e, 0xb7, 0x0e, 0xa5, 0x51, 0xf4,
   0x40, 0x63, 0x1e, 0xfd, 0xbd, 0xea, 0x9f, 0x41, 0x9f, 0xa8, 0x90, 0x1d, 0x6f, 0x0a, 0x5a, 0x95,
   0x13, 0x11, 0x0d, 0x80, 0xaf, 0x5f, 0x64, 0x98, 0x8a, 0x2c, 0x78, 0x68, 0x65, 0xb0, 0x2b, 0x8b,
   0xa2, 0x53, 0x87, 0xca, 0xf1, 0x64, 0x04, 0xab, 0xf2, 0x7b, 0xdb, 0x83, 0xc8, 0x81, 0x02, 0x41,
   0x00, 0xf7, 0xbe, 0x5e, 0x23, 0xc3, 0x32, 0x3f, 0xbf, 0x8b, 0x8e, 0x3a, 0xee, 0xfc, 0xfc, 0xcb,
   0xe5, 0xf7, 0xf1, 0x0b, 0xbc, 0x42, 0x82, 0xae, 0xd5, 0x7a, 0x3e, 0xca, 0xf7, 0xd5, 0x69, 0x3f,
   0x64, 0x25, 0xa2, 0x1f, 0xb7, 0x75, 0x75, 0x05, 0x92, 0x42, 0xeb, 0xb8, 0xf1, 0xf3, 0x0a, 0x05,
   0xe3, 0x94, 0xd1, 0x55, 0x78, 0x35, 0xa0, 0x36, 0xa0, 0x9b, 0x7c, 0x92, 0x84, 0x6c, 0xdd, 0xdc,
   0x4d, 0x02, 0x41, 0x00, 0xd6, 0x86, 0x0e, 0x85, 0x42, 0x0b, 0x04, 0x08, 0x84, 0x21, 0x60, 0xf0,
   0x0e, 0x0d, 0x88, 0xfd, 0x1e, 0x36, 0x10, 0x65, 0x4f, 0x1e, 0x53, 0xb4, 0x08, 0x72, 0x80, 0x5c,
   0x3f, 0x59, 0x66, 0x17, 0xe6, 0x98, 0xf2, 0xe9, 0x6c, 0x7a, 0x06, 0x4c, 0xac, 0x76, 0x3d, 0xed,
   0x8c, 0xa1, 0xce, 0xad, 0x1b, 0xbd, 0xb4, 0x7d, 0x28, 0xbc, 0xe3, 0x0e, 0x38, 0x8d, 0x99, 0xd8,
   0x05, 0xb5, 0xa3, 0x71, 0x02, 0x40, 0x6d, 0xeb, 0xc3, 0x2d, 0x2e, 0xf0, 0x5e, 0xa4, 0x88, 0x31,
   0x05, 0x29, 0x00, 0x8a, 0xd1, 0x95, 0x29, 0x9b, 0x83, 0xcf, 0x75, 0xdb, 0x31, 0xe3, 0x7a, 0x27,
   0xde, 0x3a, 0x74, 0x30, 0x0c, 0x76, 0x4c, 0xd4, 0x50, 0x2a, 0x40, 0x2d, 0x39, 0xd9, 0x99, 0x63,
   0xa9, 0x5d, 0x80, 0xae, 0x53, 0xca, 0x94, 0x3f, 0x05, 0x23, 0x1e, 0xf8, 0x05, 0x04, 0xe1, 0xb8,
   0x35, 0xf2, 0x17, 0xb3, 0xa0, 0x89, 0x02, 0x41, 0x00, 0xab, 0x90, 0x88, 0xfa, 0x60, 0x08, 0x29,
   0x50, 0x9a, 0x43, 0x8b, 0xa0, 0x50, 0xcc, 0xd8, 0x5a, 0xfe, 0x97, 0x64, 0x63, 0x71, 0x74, 0x22,
   0xa3, 0x20, 0x02, 0x5a, 0xcf, 0xeb, 0xc6, 0x16, 0x95, 0x54, 0xd1, 0xcb, 0xab, 0x8d, 0x1a, 0xc6,
   0x00, 0xfa, 0x08, 0x92, 0x9c, 0x71, 0xd5, 0x52, 0x52, 0x35, 0x96, 0x71, 0x4b, 0x8b, 0x92, 0x0c,
   0xd0, 0xe9, 0xbf, 0xad, 0x63, 0x0b, 0xa5, 0xe9, 0xb1, 0x02, 0x41, 0x00, 0xdc, 0xcc, 0x27, 0xc8,
   0xe4, 0xdc, 0x62, 0x48, 0xd5, 0x9b, 0xaf, 0xf5, 0xab, 0x60, 0xf6, 0x21, 0xfd, 0x53, 0xe2, 0xb7,
   0x5d, 0x09, 0xc9, 0x1a, 0xa1, 0x04, 0xa9, 0xfc, 0x61, 0x2c, 0x5d, 0x04, 0x58, 0x3a, 0x5a, 0x39,
   0xf1, 0x4a, 0x21, 0x56, 0x67, 0xfd, 0xcc, 0x20, 0xa3, 0x8f, 0x78, 0x18, 0x5a, 0x79, 0x3d, 0x2e,
   0x8e, 0x7e, 0x86, 0x0a, 0xe6, 0xa8, 0x33, 0xc1, 0x04, 0x17, 0x4a, 0x9f };

/* private key - hexadecimal */
enum {
   pk_d ,
   pk_dP,
   pk_dQ,
   pk_e ,
   pk_N ,
   pk_p ,
   pk_q ,
   pk_qP,
};
static const char *hex_key[] = {
     "C862B9EADE44531D5697D9979E1ACF301E0A8845862930A34D9F616573E0D6878FB6F306A382DC7CACFE9B289AAEFDFBFE2F0ED89704E3BB1FD1EC0DBAA3497F47AC8A44047E86B739423FAD1EB70EA551F440631EFDBDEA9F419FA8901D6F0A5A9513110D80AF5F64988A2C786865B02B8BA25387CAF16404ABF27BDB83C881",
     "6DEBC32D2EF05EA488310529008AD195299B83CF75DB31E37A27DE3A74300C764CD4502A402D39D99963A95D80AE53CA943F05231EF80504E1B835F217B3A089",
     "AB9088FA600829509A438BA050CCD85AFE976463717422A320025ACFEBC6169554D1CBAB8D1AC600FA08929C71D552523596714B8B920CD0E9BFAD630BA5E9B1",
     "010001",
     "CF9ADE648ADAC83320A9D783311954B29A85A7A1B77533B6A9AC8424B3DEDB7D852D9665E53F7295249F2868CA4FDB441C3E60128ADD26A5EBFF0B5ED48838492A6E5BBF123747BD056BBCDBF3EEE4118E41687C6113D742C880BE368FDC088B4FACA4E2760CC9636C495893EDCCAADC253B0A603F8B543AC34D31E794A444FD",
     "F7BE5E23C3323FBF8B8E3AEEFCFCCBE5F7F10BBC4282AED57A3ECAF7D5693F6425A21FB77575059242EBB8F1F30A05E394D1557835A036A09B7C92846CDDDC4D",
     "D6860E85420B0408842160F00E0D88FD1E3610654F1E53B40872805C3F596617E698F2E96C7A064CAC763DED8CA1CEAD1BBDB47D28BCE30E388D99D805B5A371",
     "DCCC27C8E4DC6248D59BAFF5AB60F621FD53E2B75D09C91AA104A9FC612C5D04583A5A39F14A215667FDCC20A38F78185A793D2E8E7E860AE6A833C104174A9F" };

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


/* generated with the private key above as:
   echo -n 'test' | openssl rsautl -sign -inkey rsa_private.pem -pkcs -hexdump
 */
static const unsigned char openssl_rsautl_pkcs[] = {
   0x24, 0xef, 0x54, 0xea, 0x1a, 0x12, 0x0c, 0xf4, 0x04, 0x0c, 0x48, 0xc8, 0xe8, 0x17, 0xd2, 0x6f,
   0xc3, 0x41, 0xb3, 0x97, 0x5c, 0xbc, 0xa3, 0x2d, 0x21, 0x00, 0x10, 0x0e, 0xbb, 0xf7, 0x30, 0x21,
   0x7e, 0x12, 0xd2, 0xdf, 0x26, 0x28, 0xd8, 0x0f, 0x6d, 0x4d, 0xc8, 0x4d, 0xa8, 0x78, 0xe7, 0x03,
   0xee, 0xbc, 0x68, 0xba, 0x98, 0xea, 0xe9, 0xb6, 0x06, 0x8d, 0x85, 0x5b, 0xdb, 0xa6, 0x49, 0x86,
   0x6f, 0xc7, 0x3d, 0xe0, 0x53, 0x83, 0xe0, 0xea, 0xb1, 0x08, 0x6a, 0x7b, 0xbd, 0xeb, 0xb5, 0x4a,
   0xdd, 0xbc, 0x64, 0x97, 0x8c, 0x17, 0x20, 0xa3, 0x5c, 0xd4, 0xb8, 0x87, 0x43, 0xc5, 0x13, 0xad,
   0x41, 0x6e, 0x45, 0x41, 0x32, 0xd4, 0x09, 0x12, 0x7f, 0xdc, 0x59, 0x1f, 0x28, 0x3f, 0x1e, 0xbc,
   0xef, 0x57, 0x23, 0x4b, 0x3a, 0xa3, 0x24, 0x91, 0x4d, 0xfb, 0xb2, 0xd4, 0xe7, 0x5e, 0x41, 0x7e,
};

extern const char ltc_der_tests_cacert_root_cert[];
extern const unsigned long ltc_der_tests_cacert_root_cert_size;

static int rsa_compat_test(void)
{
   rsa_key key, pubkey;
   int stat, i;
   unsigned char buf[1024], key_parts[8][128];
   unsigned long len, key_lens[8];

   /* try reading the key */
   DO(rsa_import(openssl_private_rsa, sizeof(openssl_private_rsa), &key));
   DO(rsa_import(openssl_public_rsa, sizeof(openssl_public_rsa), &pubkey));

   /* sign-verify a message with PKCS #1 v1.5 no ASN.1 */
   len = sizeof(buf);
   DO(rsa_sign_hash_ex((unsigned char*)"test", 4, buf, &len, LTC_PKCS_1_V1_5_NA1, NULL, 0, 0, 0, &key));
   if (len != sizeof(openssl_rsautl_pkcs) || memcmp(buf, openssl_rsautl_pkcs, len)) {
      fprintf(stderr, "RSA rsa_sign_hash_ex + LTC_PKCS_1_V1_5_NA1 failed\n");
      return 1;
   }
   stat = 0;
   DO(rsa_verify_hash_ex(openssl_rsautl_pkcs, sizeof(openssl_rsautl_pkcs), (unsigned char*)"test", 4, LTC_PKCS_1_V1_5_NA1, 0, 0, &stat, &pubkey));
   if (stat != 1) {
      fprintf(stderr, "RSA rsa_verify_hash_ex + LTC_PKCS_1_V1_5_NA1 failed\n");
      return 1;
   }
   rsa_free(&pubkey);

   /* now try to export private/public and compare */
   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PRIVATE, &key));
   DO(do_compare_testvector(buf, len, openssl_private_rsa, sizeof(openssl_private_rsa), "RSA private export (from OpenSSL)", 0));

   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PUBLIC, &key));
   DO(do_compare_testvector(buf, len, openssl_public_rsa_stripped, sizeof(openssl_public_rsa_stripped), "RSA public export (from OpenSSL private key)", 0));
   rsa_free(&key);

   /* try reading the public key */
   DO(rsa_import(openssl_public_rsa_stripped, sizeof(openssl_public_rsa_stripped), &key));
   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PUBLIC, &key));
   DO(do_compare_testvector(buf, len, openssl_public_rsa_stripped, sizeof(openssl_public_rsa_stripped), "RSA public export (from stripped OpenSSL)", 0));
   rsa_free(&key);

   /* try reading the public key */
   DO(rsa_import(openssl_public_rsa, sizeof(openssl_public_rsa), &key));
   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PUBLIC, &key));
   DO(do_compare_testvector(buf, len, openssl_public_rsa_stripped, sizeof(openssl_public_rsa_stripped), "RSA public export (from OpenSSL)", 0));
   rsa_free(&key);

   /* try import private key in pkcs8 format */
   DO(rsa_import_pkcs8(pkcs8_private_rsa, sizeof(pkcs8_private_rsa), NULL, 0, &key));
   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PRIVATE, &key));
   DO(do_compare_testvector(buf, len, openssl_private_rsa, sizeof(openssl_private_rsa), "RSA private export (from PKCS#8)", 0));
   rsa_free(&key);

   /* convert raw hexadecimal numbers to binary */
   for (i = 0; i < 8; ++i) {
      key_lens[i] = sizeof(key_parts[i]);
      DO(radix_to_bin(hex_key[i], 16, key_parts[i], &key_lens[i]));
   }
   /* try import private key from converted raw hexadecimal numbers */
   DO(rsa_set_key(key_parts[pk_N], key_lens[pk_N], key_parts[pk_e], key_lens[pk_e], key_parts[pk_d], key_lens[pk_d], &key));
   DO(rsa_set_factors(key_parts[pk_p], key_lens[pk_p], key_parts[pk_q], key_lens[pk_q], &key));
   DO(rsa_set_crt_params(key_parts[pk_dP], key_lens[pk_dP], key_parts[pk_dQ], key_lens[pk_dQ], key_parts[pk_qP], key_lens[pk_qP], &key));
   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PRIVATE, &key));
   DO(do_compare_testvector(buf, len, openssl_private_rsa, sizeof(openssl_private_rsa), "RSA private export (from hex)", 0));
   rsa_free(&key);

   /* try import public key from converted raw hexadecimal numbers */
   DO(rsa_set_key(key_parts[pk_N], key_lens[pk_N], key_parts[pk_e], key_lens[pk_e], NULL, 0, &key));
   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PUBLIC, &key));
   DO(do_compare_testvector(buf, len, openssl_public_rsa_stripped, sizeof(openssl_public_rsa_stripped), "RSA public export (from hex)", 0));
   rsa_free(&key);

   /* try export in SubjectPublicKeyInfo format of the public key */
   DO(rsa_import(openssl_public_rsa, sizeof(openssl_public_rsa), &key));
   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PUBLIC | PK_STD, &key));
   DO(do_compare_testvector(buf, len, openssl_public_rsa, sizeof(openssl_public_rsa),  "RSA public export (X.509)", 0));
   rsa_free(&key);

   return 0;
}

static int s_rsa_key_cmp(const int should_type, const rsa_key *should, const rsa_key *is)
{
   if(should_type != is->type)
      return CRYPT_ERROR;
   if(should_type == PK_PRIVATE) {
      if(mp_cmp(should->q, is->q) != LTC_MP_EQ)
         return CRYPT_ERROR;
      if(mp_cmp(should->p, is->p) != LTC_MP_EQ)
         return CRYPT_ERROR;
      if(mp_cmp(should->qP, is->qP) != LTC_MP_EQ)
         return CRYPT_ERROR;
      if(mp_cmp(should->dP, is->dP) != LTC_MP_EQ)
         return CRYPT_ERROR;
      if(mp_cmp(should->dQ, is->dQ) != LTC_MP_EQ)
         return CRYPT_ERROR;
      if(mp_cmp(should->d, is->d) != LTC_MP_EQ)
         return CRYPT_ERROR;
   }
   if(mp_cmp(should->N, is->N) != LTC_MP_EQ)
      return CRYPT_ERROR;
   if(mp_cmp(should->e, is->e) != LTC_MP_EQ)
      return CRYPT_ERROR;
   return CRYPT_OK;
}

/* https://github.com/DCIT/perl-CryptX/issues/69 */
static int s_rsa_cryptx_issue_69(void)
{
   static const char *e = "03";
   static const char *N = "E932AC92252F585B3A80A4DD76A897C8B7652952FE788F6EC8DD640587A1EE5647670A8AD4C2BE0F9FA6E49C605ADF77B5174230"
         "AF7BD50E5D6D6D6D28CCF0A886A514CC72E51D209CC772A52EF419F6A953F3135929588EBE9B351FCA61CED78F346FE00DBB6306"
         "E5C2A4C6DFC3779AF85AB417371CF34D8387B9B30AE46D7A5FF5A655B8D8455F1B94AE736989D60A6F2FD5CADBFFBD504C5A756A"
         "2E6BB5CECC13BCA7503F6DF8B52ACE5C410997E98809DB4DC30D943DE4E812A47553DCE54844A78E36401D13F77DC650619FED88"
         "D8B3926E3D8E319C80C744779AC5D6ABE252896950917476ECE5E8FC27D5F053D6018D91B502C4787558A002B9283DA7";

   static const char *sig1 = "8df69d774c6ac8b5f8aa16576ca37a4f948706c5daecb3c15cfd247a7657616b2bbb786b50158cac8c23e3"
         "289d300d3fbb82380b8746d929df36bdaf43a5fc5d1d04c61c98d47c22de02d051be3ba9e42b1c47aa5192"
         "66d4cae244e5ce99b24771a13a7c8c7b08868a3eccf70b4bc7570d5131a1ac8943d91b0151c39da2ad75cd"
         "1b9a697d100eef6747217df581b272cfd1f549a901ff4951036a4eb28fd2ea1e9df3fa9fa457663f4259be"
         "8e5f2f2fb84f831a0ca5320e2b79f04a17830f43062c4c8fc0d0b1ff90567f3342d524f682ca26661caadf"
         "4272f2585e6013a92bfa68de72fe6174096890e4296aedd72da43aa508007df53fb852bd7162ab635b";
   static const char *sig2 = "1ee08947536e6b11d8923c3b00061d26a6933b5345077ea0214fdcbcc1ad68395008ff709117047e6b01dd"
         "2a371dfa032c0732abc86ab2e0273bbd0dfe6b1c769e21bb9079982801d8f72e01be3244959312ab09bb8f"
         "88572dc23216719b9810c73edf826749604feb8da1345f83f0209271aca462c1235b4cb4ba538f85a9c03d"
         "d1dde1856fe73fd86b95566df2dfe8b0895c34489b97e02c8e48dabad7067619edec6267a776fa416fbcac"
         "0fcacf3efa7852ce33ed63a9149c685c303d98c3dc37ee87521bc5b130377345fc95c87aa48505470deaf6"
         "fb1064df041e3f03322b1ec90d3608deb17bf77f47066ecc6c511bfba69eed6da42881dcce603fcb2a";

   static const char *hash = "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9";
   rsa_key       key;
   unsigned char buf0[512], buf1[512];
   unsigned long l0, l1;
   int stat;

   l0 = sizeof(buf0);
   l1 = sizeof(buf1);
   DO(radix_to_bin(e, 16, buf0, &l0));
   DO(radix_to_bin(N, 16, buf1, &l1));

   DO(rsa_set_key(buf1, l1, buf0, l0, NULL, 0, &key));

   l0 = sizeof(buf0);
   l1 = sizeof(buf1);
   DO(radix_to_bin(sig1, 16, buf0, &l0));
   DO(radix_to_bin(hash, 16, buf1, &l1));
   SHOULD_FAIL(rsa_verify_hash_ex(buf0, l0, buf1, l1, LTC_PKCS_1_V1_5, 0, 0, &stat, &key));
   DO(radix_to_bin(sig2, 16, buf0, &l0));
   SHOULD_FAIL(rsa_verify_hash_ex(buf0, l0, buf1, l1, LTC_PKCS_1_V1_5, 0, 0, &stat, &key));
   rsa_free(&key);
   return CRYPT_OK;
}

static int s_rsa_issue_301(int prng_idx)
{
   rsa_key       key, key_in;
   unsigned char buf[4096];
   unsigned long len;

   DO(rsa_make_key(&yarrow_prng, prng_idx, sizeof(buf)/8, 65537, &key));

   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PRIVATE, &key));
   DO(rsa_import(buf, len, &key_in));

   DO(s_rsa_key_cmp(PK_PRIVATE, &key, &key_in));
   rsa_free(&key_in);

   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PUBLIC, &key));
   DO(rsa_import(buf, len, &key_in));

   DO(s_rsa_key_cmp(PK_PUBLIC, &key, &key_in));
   rsa_free(&key_in);

   len = sizeof(buf);
   DO(rsa_export(buf, &len, PK_PUBLIC | PK_STD, &key));
   DO(rsa_import(buf, len, &key_in));

   DO(s_rsa_key_cmp(PK_PUBLIC, &key, &key_in));
   rsa_free(&key_in);

   rsa_free(&key);
   return CRYPT_OK;
}

static int s_rsa_public_ubin_e(int prng_idx)
{
   rsa_key       key;
   unsigned char e[32] = {0};
   unsigned long elen = sizeof(e);

   /* Check public exponent too small */
   e[elen - 1] = 1;
   SHOULD_FAIL_WITH(rsa_make_key_ubin_e(&yarrow_prng, prng_idx, 128, e, elen, &key),
                    CRYPT_INVALID_ARG);

   /*
    * Generate about 256 bits to check error when public exponent
    * overflow.
    */
   DO(rng_make_prng(elen * 8, prng_idx, &yarrow_prng, NULL));
   LTC_ARGCHK(yarrow_read(e, elen, &yarrow_prng) == elen);

   /* Ensure that public exponent is:
    *  - odd value
    *  - MSB is even
    */
   e[elen - 1] |= 0x1;
   e[0] &= ~0x1;

   /* Check public exponent overflow */
   /* Set high bit of MSB set to get 256 bits, to get e overflow */
   e[0] |= 0x80;
   SHOULD_FAIL_WITH(rsa_make_key_ubin_e(&yarrow_prng, prng_idx, 128, e, elen, &key),
                    CRYPT_INVALID_ARG);


  /* Check public exponent not odd but e value < 256 bits */
   e[elen - 1] &= ~0x1;
   e[0] &= ~0x80;
   SHOULD_FAIL_WITH(rsa_make_key_ubin_e(&yarrow_prng, prng_idx, 128, e, elen, &key),
                    CRYPT_INVALID_ARG);

   /* Ensure that public exponent is odd value and e value < 256 bits */
   e[elen - 1] |= 0x1;
   DO(rsa_make_key_ubin_e(&yarrow_prng, prng_idx, 128, e, elen, &key));
   rsa_free(&key);

   return CRYPT_OK;
}

#ifdef LTC_TEST_READDIR
static int s_rsa_import_x509(const void *in, unsigned long inlen, void *key)
{
   /* here we use the filesize as indicator for the rsa size
    * that would fail to import for tfm because it's fixed-size
    */
   if ((strcmp(ltc_mp.name, "TomsFastMath") == 0) && (inlen > 2048)) {
#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
      fprintf(stderr, "Skipping testcase because of TomsFastMath\n");
#endif
      return CRYPT_NOP;
   }
   return rsa_import_x509(in, inlen, key);
}

#if defined(LTC_MD2) && defined(LTC_MD5) && defined(LTC_RC2)
static int s_rsa_import_pkcs8(const void *in, unsigned long inlen, void *key)
{
   return rsa_import_pkcs8(in, inlen, "secret", 6, key);
}
#endif
#endif

int rsa_test(void)
{
   unsigned char in[1024], out[1024], tmp[3072];
   rsa_key       key, privKey, pubKey;
   int           hash_idx, prng_idx, stat, stat2, i;
   unsigned long rsa_msgsize, len, len2, len3, cnt, cnt2;
   static unsigned char lparam[] = { 0x01, 0x02, 0x03, 0x04 };
   void* dP;
   unsigned char* p;
   unsigned char* p2;
   unsigned char* p3;

   if (ltc_mp.name == NULL) return CRYPT_NOP;

   if (rsa_compat_test() != 0) {
      return 1;
   }

   hash_idx = find_hash("sha1");
   prng_idx = find_prng("yarrow");
   if (hash_idx == -1 || prng_idx == -1) {
      fprintf(stderr, "rsa_test requires LTC_SHA1 and yarrow");
      return 1;
   }

#ifdef LTC_TEST_READDIR
   DO(test_process_dir("tests/rsa", &key, s_rsa_import_x509, (dir_cleanup_cb)rsa_free, "rsa_test"));
#if defined(LTC_MD2) && defined(LTC_MD5) && defined(LTC_RC2)
   DO(test_process_dir("tests/rsa-pkcs8", &key, s_rsa_import_pkcs8, (dir_cleanup_cb)rsa_free, "rsa_pkcs8_test"));
#endif
#endif

   DO(s_rsa_cryptx_issue_69());
   DO(s_rsa_issue_301(prng_idx));
   DO(s_rsa_public_ubin_e(prng_idx));

   /* make 10 random key */
   for (cnt = 0; cnt < 10; cnt++) {
      DO(rsa_make_key(&yarrow_prng, prng_idx, 1024/8, 65537, &key));
      if (mp_count_bits(key.N) != 1024) {
         fprintf(stderr, "rsa_1024 key modulus has %d bits\n", mp_count_bits(key.N));

len = mp_unsigned_bin_size(key.N);
mp_to_unsigned_bin(key.N, tmp);
print_hex("N", tmp, len);

len = mp_unsigned_bin_size(key.p);
mp_to_unsigned_bin(key.p, tmp);
print_hex("p", tmp, len);

len = mp_unsigned_bin_size(key.q);
mp_to_unsigned_bin(key.q, tmp);
print_hex("q", tmp, len);

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
      SHOULD_FAIL(rsa_decrypt_key(out, len, tmp, &len2, NULL, 0, hash_idx, &stat2, &key));
      /* change a byte back */
      out[8] ^= 1;
      ENSURE(len2 == rsa_msgsize);

      len2 = rsa_msgsize;
      DO(rsa_decrypt_key(out, len, tmp, &len2, NULL, 0, hash_idx, &stat, &key));
      ENSUREX(stat == 1 && stat2 == 0, "rsa_decrypt_key (without lparam)");
      DO(do_compare_testvector(tmp, len2, in, rsa_msgsize,  "rsa_decrypt_key (without lparam)", cnt << 8 | rsa_msgsize));
   }
   }

   /* encrypt the key (with lparam) */
   for (rsa_msgsize = 1; rsa_msgsize <= 86; rsa_msgsize++) {
      len  = sizeof(out);
      len2 = rsa_msgsize;
      DO(rsa_encrypt_key(in, rsa_msgsize, out, &len, lparam, sizeof(lparam), &yarrow_prng, prng_idx, hash_idx, &key));
      /* change a byte */
      out[8] ^= 1;
      SHOULD_FAIL(rsa_decrypt_key(out, len, tmp, &len2, lparam, sizeof(lparam), hash_idx, &stat2, &key));
      ENSURE(len2 == rsa_msgsize);

      /* change a byte back */
      out[8] ^= 1;

      len2 = rsa_msgsize;
      DO(rsa_decrypt_key(out, len, tmp, &len2, lparam, sizeof(lparam), hash_idx, &stat, &key));
      ENSURE(stat == 1 && stat2 == 0);
      DO(do_compare_testvector(tmp, len2, in, rsa_msgsize,  "rsa_decrypt_key (with lparam)", rsa_msgsize));
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
      ENSURE(stat == 1);
      DO(do_compare_testvector(tmp, len2, in, rsa_msgsize,  "rsa_decrypt_key_ex", rsa_msgsize));
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

   dbg_malloc_stats();
   rsa_shrink_key(&key);
   dbg_malloc_stats();
   rsa_shrink_key(&pubKey);
   dbg_malloc_stats();
   rsa_shrink_key(&privKey);
   dbg_malloc_stats();

   /* verify with original */
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat, &key));
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat2, &key));

   ENSUREX(stat == 1 && stat2 == 0, "rsa_verify_hash (unsalted, origKey) failed");

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

   /* verify with privKey but remove pointer to dP to test without CRT */

   dP = privKey.dP;
   privKey.dP = NULL;
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
   privKey.dP = dP;

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

   p = in;
   p2 = out;
   p3 = tmp;
   for (i = 0; i < 9; ++i) {
     len = sizeof(in);
     len2 = sizeof(out);
     /* (1) */
     DO(rsa_sign_hash_ex(p, 20, p2, &len2, LTC_PKCS_1_V1_5, &yarrow_prng, prng_idx, hash_idx, 8, &privKey));
     /* (2) */
     DOX(rsa_verify_hash_ex(p2, len2, p, 20, LTC_PKCS_1_V1_5, hash_idx, -1, &stat, &pubKey), "should succeed");
     DOX(stat == 1?CRYPT_OK:CRYPT_FAIL_TESTVECTOR, "should succeed");
     len3 = sizeof(tmp);
     /* (3) */
     DO(ltc_mp.rsa_me(p2, len2, p3, &len3, PK_PUBLIC, &key));
     /* (4) */
#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
     print_hex("Original signature", p3, len3);
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
#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
     print_hex("Forged signature", p3, len3);
#endif

     len2 = sizeof(out);
     /* (5) */
     DO(ltc_mp.rsa_me(p3, len3, p2, &len2, PK_PRIVATE, &key));

     len3 = sizeof(tmp);
     /* (6) */
     SHOULD_FAIL(rsa_verify_hash_ex(p2, len2, p, 20, LTC_PKCS_1_V1_5, hash_idx, -1, &stat, &pubKey));
     DOX(stat == 0?CRYPT_OK:CRYPT_FAIL_TESTVECTOR, "should fail");
   }
   rsa_free(&key);

   /* try reading the public RSA key from a X509 certificate */
   len3 = sizeof(tmp);
   DO(base64_decode(x509_public_rsa, sizeof(x509_public_rsa), tmp, &len3));
   DO(rsa_import_x509(tmp, len3, &key));
   len = sizeof(tmp);
   DO(rsa_export(tmp, &len, PK_PUBLIC, &key));
   DO(do_compare_testvector(tmp, len, openssl_public_rsa_stripped, sizeof(openssl_public_rsa_stripped),  "RSA public export failed to match rsa_import_x509", 0));
   rsa_free(&key);

   len3 = sizeof(tmp);
   DO(base64_decode(ltc_der_tests_cacert_root_cert, ltc_der_tests_cacert_root_cert_size, tmp, &len3));

   DO(rsa_import_x509(tmp, len3, &key));

   /* free the key and return */
   rsa_free(&key);
   rsa_free(&pubKey);
   rsa_free(&privKey);
   return 0;
}

#else

int rsa_test(void)
{
   return CRYPT_NOP;
}

#endif
