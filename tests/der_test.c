/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include <tomcrypt_test.h>

#if !defined(LTC_DER)

int der_test(void)
{
   return CRYPT_NOP;
}

#else

#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
#define LTC_DER_TESTS_PRINT_FLEXI
#endif

static const char _der_tests_stinky_root_cert[] =
   "MIIFETCCA/mgAwIBAgIQbv53JNmv518t5lkCHE272jANBgkqhkiG9w0BAQUFADCB"
   "lTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlVUMRcwFQYDVQQHEw5TYWx0IExha2Ug"
   "Q2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMSEwHwYDVQQLExho"
   "dHRwOi8vd3d3LnVzZXJ0cnVzdC5jb20xHTAbBgNVBAMTFFVUTi1VU0VSRmlyc3Qt"
   "T2JqZWN0MB4XDTA4MDQyOTAwMDAwMFoXDTEwMDQyOTIzNTk1OVowgbUxCzAJBgNV"
   "BAYTAlVTMQ4wDAYDVQQRDAU0NDE0MzELMAkGA1UECAwCT0gxGTAXBgNVBAcMEE1h"
   "eWZpZWxkIFZpbGxhZ2UxEDAOBgNVBAkMB1N1aXRlIEExFDASBgNVBAkMCzc2NyBC"
   "ZXRhIERyMSIwIAYDVQQKDBlQcmVlbXB0aXZlIFNvbHV0aW9ucywgTExDMSIwIAYD"
   "VQQDDBlQcmVlbXB0aXZlIFNvbHV0aW9ucywgTExDMIIBIjANBgkqhkiG9w0BAQEF"
   "AAOCAQ8AMIIBCgKCAQEAzH7ZBkMcBuHx8d2f10RGTHAf7gzzVteGbOihJGH2BwlS"
   "ZvNp6WEE4DfL+s1vp0wzk1XeLN5tRjg2qum9YqyCk7okh7pXGy46f5mWbLQiefGA"
   "j5UXRcr6WJ3xeACdbXxKrYMV0REia+4Jb2UbFA8S81PjhRon6vcRz76ziUWwt8NC"
   "igX+4ZC0skhhKzKszel6KGL7bJCtLG7ukw9DZCrvPCRcKFeM/GwQ6ACMgP88CSCL"
   "t1fbIXDH1vd/x2XM3QlaSDN6hYDbef8m1T+9TCkXVKeqG1GYjSUrHzYnCZUmTRrR"
   "38jgC3qXxiIpDKW105uM0nlXe2XF9c+ot2MdWvV4TwIDAQABo4IBOTCCATUwHwYD"
   "VR0jBBgwFoAU2u1kdBScFDyr3ZmpvVsoTYs8ydgwHQYDVR0OBBYEFK+1HzZE4i28"
   "oLIzuqlFR9SspiCIMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1Ud"
   "JQQMMAoGCCsGAQUFBwMDMBEGCWCGSAGG+EIBAQQEAwIEEDBGBgNVHSAEPzA9MDsG"
   "DCsGAQQBsjEBAgEDAjArMCkGCCsGAQUFBwIBFh1odHRwczovL3NlY3VyZS5jb21v"
   "ZG8ubmV0L0NQUzBCBgNVHR8EOzA5MDegNaAzhjFodHRwOi8vY3JsLnVzZXJ0cnVz"
   "dC5jb20vVVROLVVTRVJGaXJzdC1PYmplY3QuY3JsMCEGA1UdEQQaMBiBFnN1cHBv"
   "cnRAcHJlZW1wdGl2ZS5jb20wDQYJKoZIhvcNAQEFBQADggEBAC+JM26Dokvonudl"
   "JXe/Yun7IBhimkagZUjbk9l/GQWN6i+v1o95UJ1wGJtBdm2+MxbSaPoNTDZR4B+2"
   "lYL9MW57UVmePrnfUPXQKZZG+8gTRDz8+7ol/CEAKmS3MLKCRcH5oe+J5345sGxi"
   "FC/KWNKedTNraW95xlg8NTlL2yRP7TMsjvBxgLmkbaFUoXzPTbQWmtovIagIT8GC"
   "JeXwdFaRjbamiz3Irl+u7x/mhxdza6RvgBYylXRFMudANpeGsV7gDXlnfzpFDKHQ"
   "niVwB7P5sbPFIlmIc+4/xRItkLIRjCVXaepgN9KYu3VOgiSDI6wXiTwP44/LUXQM"
   "hetwa7s=";
const char _der_tests_cacert_root_cert[] =
   "MIIHPTCCBSWgAwIBAgIBADANBgkqhkiG9w0BAQQFADB5MRAwDgYDVQQKEwdSb290"
   "IENBMR4wHAYDVQQLExVodHRwOi8vd3d3LmNhY2VydC5vcmcxIjAgBgNVBAMTGUNB"
   "IENlcnQgU2lnbmluZyBBdXRob3JpdHkxITAfBgkqhkiG9w0BCQEWEnN1cHBvcnRA"
   "Y2FjZXJ0Lm9yZzAeFw0wMzAzMzAxMjI5NDlaFw0zMzAzMjkxMjI5NDlaMHkxEDAO"
   "BgNVBAoTB1Jvb3QgQ0ExHjAcBgNVBAsTFWh0dHA6Ly93d3cuY2FjZXJ0Lm9yZzEi"
   "MCAGA1UEAxMZQ0EgQ2VydCBTaWduaW5nIEF1dGhvcml0eTEhMB8GCSqGSIb3DQEJ"
   "ARYSc3VwcG9ydEBjYWNlcnQub3JnMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC"
   "CgKCAgEAziLA4kZ97DYoB1CW8qAzQIxL8TtmPzHlawI229Z89vGIj053NgVBlfkJ"
   "8BLPRoZzYLdufujAWGSuzbCtRRcMY/pnCujW0r8+55jE8Ez64AO7NV1sId6eINm6"
   "zWYyN3L69wj1x81YyY7nDl7qPv4coRQKFWyGhFtkZip6qUtTefWIonvuLwphK42y"
   "fk1WpRPs6tqSnqxEQR5YYGUFZvjARL3LlPdCfgv3ZWiYUQXw8wWRBB0bF4LsyFe7"
   "w2t6iPGwcswlWyCR7BYCEo8y6RcYSNDHBS4CMEK4JZwFaz+qOqfrU0j36NK2B5jc"
   "G8Y0f3/JHIJ6BVgrCFvzOKKrF11myZjXnhCLotLddJr3cQxyYN/Nb5gznZY0dj4k"
   "epKwDpUeb+agRThHqtdB7Uq3EvbXG4OKDy7YCbZZ16oE/9KTfWgu3YtLq1i6L43q"
   "laegw1SJpfvbi1EinbLDvhG+LJGGi5Z4rSDTii8aP8bQUWWHIbEZAWV/RRyH9XzQ"
   "QUxPKZgh/TMfdQwEUfoZd9vUFBzugcMd9Zi3aQaRIt0AUMyBMawSB3s42mhb5ivU"
   "fslfrejrckzzAeVLIL+aplfKkQABi6F1ITe1Yw1nPkZPcCBnzsXWWdsC4PDSy826"
   "YreQQejdIOQpvGQpQsgi3Hia/0PsmBsJUUtaWsJx8cTLc6nloQsCAwEAAaOCAc4w"
   "ggHKMB0GA1UdDgQWBBQWtTIb1Mfz4OaO873SsDrusjkY0TCBowYDVR0jBIGbMIGY"
   "gBQWtTIb1Mfz4OaO873SsDrusjkY0aF9pHsweTEQMA4GA1UEChMHUm9vdCBDQTEe"
   "MBwGA1UECxMVaHR0cDovL3d3dy5jYWNlcnQub3JnMSIwIAYDVQQDExlDQSBDZXJ0"
   "IFNpZ25pbmcgQXV0aG9yaXR5MSEwHwYJKoZIhvcNAQkBFhJzdXBwb3J0QGNhY2Vy"
   "dC5vcmeCAQAwDwYDVR0TAQH/BAUwAwEB/zAyBgNVHR8EKzApMCegJaAjhiFodHRw"
   "czovL3d3dy5jYWNlcnQub3JnL3Jldm9rZS5jcmwwMAYJYIZIAYb4QgEEBCMWIWh0"
   "dHBzOi8vd3d3LmNhY2VydC5vcmcvcmV2b2tlLmNybDA0BglghkgBhvhCAQgEJxYl"
   "aHR0cDovL3d3dy5jYWNlcnQub3JnL2luZGV4LnBocD9pZD0xMDBWBglghkgBhvhC"
   "AQ0ESRZHVG8gZ2V0IHlvdXIgb3duIGNlcnRpZmljYXRlIGZvciBGUkVFIGhlYWQg"
   "b3ZlciB0byBodHRwOi8vd3d3LmNhY2VydC5vcmcwDQYJKoZIhvcNAQEEBQADggIB"
   "ACjH7pyCArpcgBLKNQodgW+JapnM8mgPf6fhjViVPr3yBsOQWqy1YPaZQwGjiHCc"
   "nWKdpIevZ1gNMDY75q1I08t0AoZxPuIrA2jxNGJARjtT6ij0rPtmlVOKTV39O9lg"
   "18p5aTuxZZKmxoGCXJzN600BiqXfEVWqFcofN8CCmHBh22p8lqOOLlQ+TyGpkO/c"
   "gr/c6EWtTZBzCDyUZbAEmXZ/4rzCahWqlwQ3JNgelE5tDlG+1sSPypZt90Pf6DBl"
   "Jzt7u0NDY8RD97LsaMzhGY4i+5jhe1o+ATc7iwiwovOVThrLm82asduycPAtStvY"
   "sONvRUgzEv/+PDIqVPfE94rwiCPCR/5kenHA0R6mY7AHfqQv0wGP3J8rtsYIqQ+T"
   "SCX8Ev2fQtzzxD72V7DX3WnRBnc0CkvSyqD/HMaMyRa+xMwyN2hzXwj7UfdJUzYF"
   "CpUCTPJ5GhD22Dp1nPMd8aINcGeGG7MW9S/lpOt5hvk9C8JzC6WZrG/8Z7jlLwum"
   "GCSNe9FINSkYQKyTYOGWhlC0elnYjyELn8+CkcY7v2vcB5G5l1YjqrZslMZIBjzk"
   "zk6q5PYvCdxTby78dOs6Y5nCpqyJvKeyRKANihDjbPIky/qbn3BHLt4Ui9SyIAmW"
   "omTxJBzcoTWcFbLUvFUufQb1nA5V9FrWk9p2rSVzTMVD";
const unsigned long _der_tests_cacert_root_cert_size = sizeof(_der_tests_cacert_root_cert);

/*
SEQUENCE(3 elem)
    SEQUENCE(8 elem)
        [0](1)
            INTEGER  2
        INTEGER  0
        SEQUENCE(2 elem)
            OBJECT IDENTIFIER 1.2.840.113549.1.1.4
            NULL
        SEQUENCE(4 elem)
            SET(1 elem)
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.5.4.10
                    PrintableString  Root CA
            SET(1 elem)
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.5.4.11
                    PrintableString  http://www.cacert.org
            SET(1 elem)
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.5.4.3
                    PrintableString  CA Cert Signing Authority
            SET(1 elem)
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 1.2.840.113549.1.9.1
                    IA5String support@cacert.org
        SEQUENCE(2 elem)
            UTCTime03-03-30 12:29:49 UTC
            UTCTime33-03-29 12:29:49 UTC
        SEQUENCE(4 elem)
            SET(1 elem)
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.5.4.10
                    PrintableString Root CA
            SET(1 elem)
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.5.4.11
                    PrintableString http://www.cacert.org
            SET(1 elem)
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.5.4.3
                    PrintableString CA Cert Signing Authority
            SET(1 elem)
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 1.2.840.113549.1.9.1
                    IA5String support@cacert.org
        SEQUENCE(2 elem)
            SEQUENCE(2 elem)
                OBJECT IDENTIFIER 1.2.840.113549.1.1.1
                NULL
            BIT STRING(1 elem)
        SEQUENCE(2 elem)
            INTEGER (4096 bit)
            INTEGER 65537
        [3](1)
            SEQUENCE(7 elem)
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.5.29.14
                    OCTET STRING(1 elem)
                        OCTET STRING(20 byte) 16B5321BD4C7F3E0E68EF3BDD2B03AEEB23918D1
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.5.29.35
                    OCTET STRING(1 elem)
                        SEQUENCE(3 elem)
                            [0]
                            [1](1)
                                [4](1)
                                SEQUENCE(4 elem)
                                    SET(1 elem)
                                        SEQUENCE(2 elem)
                                            OBJECT IDENTIFIER 2.5.4.10
                                            PrintableString Root CA
                                    SET(1 elem)
                                        SEQUENCE(2 elem)
                                            OBJECT IDENTIFIER 2.5.4.11
                                            PrintableString http://www.cacert.org
                                    SET(1 elem)
                                        SEQUENCE(2 elem)
                                            OBJECT IDENTIFIER 2.5.4.3
                                            PrintableString CA Cert Signing Authority
                                    SET(1 elem)
                                        SEQUENCE(2 elem)
                                            OBJECT IDENTIFIER 1.2.840.113549.1.9.1
                                            IA5String support@cacert.org
                            [2]
                SEQUENCE(3 elem)
                    OBJECT IDENTIFIER 2.5.29.19
                    BOOLEAN true
                    OCTET STRING(1 elem)
                        SEQUENCE(1 elem)
                            BOOLEAN true
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.5.29.31
                    OCTET STRING(1 elem)
                        SEQUENCE(1 elem)
                            SEQUENCE(1 elem)
                                [0](1)
                                    [0](1)
                                        [6]
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.16.840.1.113730.1.4
                    OCTET STRING(1 elem)
                        IA5String https://www.cacert.org/revoke.crl
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.16.840.1.113730.1.8
                    OCTET STRING(1 elem)
                        IA5String http://www.cacert.org/index.php?id=10
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.16.840.1.113730.1.13
                    OCTET STRING(1 elem)
                        IA5String To get your own certificate for FREE head over to http://www.cacert.org
    SEQUENCE(2 elem)
        OBJECT IDENTIFIER 1.2.840.113549.1.1.4
        NULL
    BIT STRING(4096 bit)
 */

#define __ASN1_FMTSTRING_FMT "line: %d, type=%d, size=%lu, data=%p, self=%p, next=%p, prev=%p, parent=%p, child=%p"
#define __ASN1_FMTSTRING_VAL(l)  __LINE__, (l)->type, (l)->size, (l)->data, (l), (l)->next, (l)->prev, (l)->parent, (l)->child

#define __ASN1_ERR(l) fprintf(stderr, __ASN1_FMTSTRING_FMT "\n", __ASN1_FMTSTRING_VAL(l)); \
    exit(EXIT_FAILURE)

#define __CHECK_ASN1_HAS(l, w) do { if ((l)->w == NULL) { \
    __ASN1_ERR(l);\
} } while(0)

#define __CHECK_ASN1_HAS_NO(l, w) do { if ((l)->w != NULL) { \
    __ASN1_ERR(l);\
} } while(0)



#define CHECK_ASN1_TYPE(l, t) do { if ((l)->type != (t)) { \
    __ASN1_ERR(l);\
} } while(0)

#define CHECK_ASN1_HAS_CHILD(l) __CHECK_ASN1_HAS(l, child)
#define CHECK_ASN1_HAS_NO_CHILD(l) __CHECK_ASN1_HAS_NO(l, child)
#define CHECK_ASN1_HAS_NEXT(l) __CHECK_ASN1_HAS(l, next)
#define CHECK_ASN1_HAS_NO_NEXT(l) __CHECK_ASN1_HAS_NO(l, next)
#define CHECK_ASN1_HAS_DATA(l) __CHECK_ASN1_HAS(l, data)
#define CHECK_ASN1_HAS_NO_DATA(l) __CHECK_ASN1_HAS_NO(l, data)

#ifdef LTC_DER_TESTS_PRINT_FLEXI
static void _der_tests_print_flexi(ltc_asn1_list* l, unsigned int level)
{
  char buf[1024];
  const char* name = NULL;
  const char* text = NULL;
  ltc_asn1_list* ostring = NULL;
  unsigned int n;

  switch (l->type)
    {
  case LTC_ASN1_EOL:
    name = "EOL";
    snprintf(buf, sizeof(buf),__ASN1_FMTSTRING_FMT "\n", __ASN1_FMTSTRING_VAL(l));
    text = buf;
    break;
  case LTC_ASN1_BOOLEAN:
    name = "BOOLEAN";
    {
      if (*(int*)l->data)
        text = "true";
      else
        text = "false";
    }
    break;
  case LTC_ASN1_INTEGER:
    name = "INTEGER";
    mp_toradix(l->data, buf, 10);
    text = buf;
    break;
  case LTC_ASN1_SHORT_INTEGER:
    name = "SHORT INTEGER";
    break;
  case LTC_ASN1_BIT_STRING:
    name = "BIT STRING";
    break;
  case LTC_ASN1_OCTET_STRING:
    name = "OCTET STRING";
    {
      unsigned long ostring_l = l->size;
      /* sometimes there's another sequence in an octet string...
       * try to decode that... if it fails print out the octet string
       */
      if (der_decode_sequence_flexi(l->data, &ostring_l, &ostring) == CRYPT_OK) {
          text = "";
      }
      else {
          int r;
          char* s = buf;
          int sz = sizeof(buf);
          for (n = 0; n < l->size; ++n) {
              r = snprintf(s, sz, "%02X", ((unsigned char*)l->data)[n]);
              if (r < 0 || r >= sz) {
                  fprintf(stderr, "%s boom\n", name);
                  exit(EXIT_FAILURE);
              }
              s += r;
              sz -= r;
          }
          text = buf;
      }
    }
    break;
  case LTC_ASN1_NULL:
    name = "NULL";
    text = "";
    break;
  case LTC_ASN1_OBJECT_IDENTIFIER:
    name = "OBJECT IDENTIFIER";
    {
      unsigned long i;
      int r;
      char* s = buf;
      int sz = sizeof(buf);
      for (i = 0; i < l->size; ++i) {
        r = snprintf(s, sz, "%lu.", ((unsigned long*)l->data)[i]);
        if (r < 0 || r >= sz) {
            fprintf(stderr, "%s boom\n", name);
            exit(EXIT_FAILURE);
        }
        s += r;
        sz -= r;
      }
      /* replace the last . with a \0 */
      *(s - 1) = '\0';
      text = buf;
    }
    break;
  case LTC_ASN1_IA5_STRING:
    name = "IA5 STRING";
    text = l->data;
    break;
  case LTC_ASN1_PRINTABLE_STRING:
    name = "PRINTABLE STRING";
    text = l->data;
    break;
  case LTC_ASN1_UTF8_STRING:
    name = "UTF8 STRING";
    break;
  case LTC_ASN1_UTCTIME:
    name = "UTCTIME";
    {
      ltc_utctime* ut = l->data;
      snprintf(buf, sizeof(buf), "%02d-%02d-%02d %02d:%02d:%02d %c%02d:%02d",
          ut->YY, ut->MM, ut->DD, ut->hh, ut->mm, ut->ss,
          ut->off_dir ? '-' : '+', ut->off_hh, ut->off_mm);
      text = buf;
    }
    break;
  case LTC_ASN1_GENERALIZEDTIME:
    name = "GENERALIZED TIME";
    {
      ltc_generalizedtime* gt = l->data;
      if(gt->fs)
         snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%02dZ",
          gt->YYYY, gt->MM, gt->DD, gt->hh, gt->mm, gt->ss, gt->fs);
      else
         snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02dZ",
          gt->YYYY, gt->MM, gt->DD, gt->hh, gt->mm, gt->ss);
      text = buf;
    }
    break;
  case LTC_ASN1_CHOICE:
    name = "CHOICE";
    break;
  case LTC_ASN1_SEQUENCE:
    name = "SEQUENCE";
    text = "";
    break;
  case LTC_ASN1_SET:
    name = "SET";
    text = "";
    break;
  case LTC_ASN1_SETOF:
    name = "SETOF";
    text = "";
    break;
  case LTC_ASN1_RAW_BIT_STRING:
    name = "RAW BIT STRING";
    break;
  case LTC_ASN1_TELETEX_STRING:
    name = "TELETEX STRING";
    text = l->data;
    break;
  case LTC_ASN1_CUSTOM_TYPE:
    name = "NON STANDARD";
    {
       int r;
       char* s = buf;
       int sz = sizeof(buf);

       r = snprintf(s, sz, "[%s %s %llu]", der_asn1_class_to_string_map[l->klass], der_asn1_pc_to_string_map[l->pc], l->tag);
       if (r < 0 || r >= sz) {
           fprintf(stderr, "%s boom\n", name);
           exit(EXIT_FAILURE);
       }
       s += r;
       sz -= r;

       text = buf;
    }
    break;
  }

  for (n = 0; n < level; ++n) {
     fprintf(stderr, "    ");
  }
  if (name) {
      if (text)
         fprintf(stderr, "%s %s\n", name, text);
      else
         fprintf(stderr, "%s <missing decoding>\n", name);
  }
  else
     fprintf(stderr, "WTF type=%i\n", l->type);

  if (ostring) {
      _der_tests_print_flexi(ostring, level + 1);
      der_free_sequence_flexi(ostring);
  }

  if (l->child)
    _der_tests_print_flexi(l->child, level + 1);

  if (l->next)
    _der_tests_print_flexi(l->next, level);
}
#endif

static void der_cacert_test(void)
{
  unsigned char buf[sizeof(_der_tests_cacert_root_cert)];
  unsigned long len1 = sizeof(buf), len2;

  ltc_asn1_list *decoded_list, *l, *l1, *l2;

  DO(base64_decode(_der_tests_stinky_root_cert, sizeof(_der_tests_stinky_root_cert), buf, &len1));
  len2 = len1;
  DO(der_decode_sequence_flexi(buf, &len2, &decoded_list));
  der_free_sequence_flexi(decoded_list);

  len1 = sizeof(buf);
  DO(base64_decode(_der_tests_cacert_root_cert, sizeof(_der_tests_cacert_root_cert), buf, &len1));
  len2 = len1;
  DO(der_decode_sequence_flexi(buf, &len2, &decoded_list));
  CHECK_ASN1_TYPE(decoded_list, LTC_ASN1_SEQUENCE);
  CHECK_ASN1_HAS_DATA(decoded_list);

  der_sequence_shrink(decoded_list);

  CHECK_ASN1_TYPE(decoded_list, LTC_ASN1_SEQUENCE);
  CHECK_ASN1_HAS_NO_DATA(decoded_list);

#ifdef LTC_DER_TESTS_PRINT_FLEXI
  printf("\n\n--- test print start ---\n\n");
  _der_tests_print_flexi(decoded_list, 0);
  printf("\n\n--- test print end ---\n\n");
#endif

  l = decoded_list;

  /*
SEQUENCE(3 elem)
    SEQUENCE(8 elem)
   */

  CHECK_ASN1_TYPE(l, LTC_ASN1_SEQUENCE);
  CHECK_ASN1_HAS_CHILD(l);
  CHECK_ASN1_HAS_NO_NEXT(l);

  l = l->child;

  CHECK_ASN1_TYPE(l, LTC_ASN1_SEQUENCE);
  CHECK_ASN1_HAS_CHILD(l);
  CHECK_ASN1_HAS_NEXT(l);

  l1 = l->child;

  /*
        [0](1)
            INTEGER  2
   */

  CHECK_ASN1_TYPE(l1, LTC_ASN1_CUSTOM_TYPE);
  CHECK_ASN1_HAS_CHILD(l1);
  CHECK_ASN1_HAS_NEXT(l1);

  l2 = l1->child;

  CHECK_ASN1_TYPE(l2, LTC_ASN1_INTEGER);
  CHECK_ASN1_HAS_NO_CHILD(l2);
  CHECK_ASN1_HAS_NO_NEXT(l2);

  l1 = l1->next;

  /*
        INTEGER  0
   */

  CHECK_ASN1_TYPE(l1, LTC_ASN1_INTEGER);
  CHECK_ASN1_HAS_NO_CHILD(l1);
  CHECK_ASN1_HAS_NEXT(l1);

  l1 = l1->next;

  /*
        SEQUENCE(2 elem)
            OBJECT IDENTIFIER 1.2.840.113549.1.1.4
            NULL
   */

  CHECK_ASN1_TYPE(l1, LTC_ASN1_SEQUENCE);
  CHECK_ASN1_HAS_CHILD(l1);
  CHECK_ASN1_HAS_NEXT(l1);

  l2 = l1->child;

  CHECK_ASN1_TYPE(l2, LTC_ASN1_OBJECT_IDENTIFIER);
  CHECK_ASN1_HAS_NO_CHILD(l2);
  CHECK_ASN1_HAS_NEXT(l2);

  l2 = l2->next;

  CHECK_ASN1_TYPE(l2, LTC_ASN1_NULL);
  CHECK_ASN1_HAS_NO_CHILD(l2);
  CHECK_ASN1_HAS_NO_NEXT(l2);

  /*
        SEQUENCE(4 elem)
            SET(1 elem)
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.5.4.10
                    PrintableString  Root CA
            SET(1 elem)
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.5.4.11
                    PrintableString  http://www.cacert.org
            SET(1 elem)
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 2.5.4.3
                    PrintableString  CA Cert Signing Authority
            SET(1 elem)
                SEQUENCE(2 elem)
                    OBJECT IDENTIFIER 1.2.840.113549.1.9.1
                    IA5String support@cacert.org
   */

  l = l->next;

  /*
    SEQUENCE(2 elem)
        OBJECT IDENTIFIER 1.2.840.113549.1.1.4
        NULL
   */

  CHECK_ASN1_TYPE(l, LTC_ASN1_SEQUENCE);
  CHECK_ASN1_HAS_CHILD(l);
  CHECK_ASN1_HAS_NEXT(l);

  l1 = l->child;

  CHECK_ASN1_TYPE(l1, LTC_ASN1_OBJECT_IDENTIFIER);
  CHECK_ASN1_HAS_NO_CHILD(l1);
  CHECK_ASN1_HAS_NEXT(l1);

  l1 = l1->next;

  CHECK_ASN1_TYPE(l1, LTC_ASN1_NULL);
  CHECK_ASN1_HAS_NO_CHILD(l1);
  CHECK_ASN1_HAS_NO_NEXT(l1);

  l = l->next;

  /*
    BIT STRING(4096 bit)
   */

  CHECK_ASN1_TYPE(l, LTC_ASN1_BIT_STRING);
  CHECK_ASN1_HAS_NO_CHILD(l);
  CHECK_ASN1_HAS_NO_NEXT(l);

  der_free_sequence_flexi(decoded_list);
}

static void der_set_test(void)
{
   ltc_asn1_list list[10];
   static const unsigned char oct_str[] = { 1, 2, 3, 4 };
   static const unsigned char bin_str[] = { 1, 0, 0, 1 };
   static const unsigned long int_val   = 12345678UL;

   unsigned char strs[10][10], outbuf[128];
   unsigned long x, val, outlen;

   /* make structure and encode it */
   LTC_SET_ASN1(list, 0, LTC_ASN1_OCTET_STRING,  oct_str, sizeof(oct_str));
   LTC_SET_ASN1(list, 1, LTC_ASN1_BIT_STRING,    bin_str, sizeof(bin_str));
   LTC_SET_ASN1(list, 2, LTC_ASN1_SHORT_INTEGER, &int_val, 1);

   /* encode it */
   outlen = sizeof(outbuf);
   DO(der_encode_set(list, 3, outbuf, &outlen));

   /* first let's test the set_decoder out of order to see what happens, we should get all the fields we expect even though they're in a diff order */
   LTC_SET_ASN1(list, 0, LTC_ASN1_BIT_STRING,    strs[1], sizeof(strs[1]));
   LTC_SET_ASN1(list, 1, LTC_ASN1_SHORT_INTEGER, &val, 1);
   LTC_SET_ASN1(list, 2, LTC_ASN1_OCTET_STRING,  strs[0], sizeof(strs[0]));

   DO(der_decode_set(outbuf, outlen, list, 3));

   /* now compare the items */
   if (memcmp(strs[0], oct_str, sizeof(oct_str))) {
      fprintf(stderr, "error decoding set using der_decode_set (oct_str is wrong):\n");
      exit(EXIT_FAILURE);
   }

   if (memcmp(strs[1], bin_str, sizeof(bin_str))) {
      fprintf(stderr, "error decoding set using der_decode_set (bin_str is wrong):\n");
      exit(EXIT_FAILURE);
   }

   if (val != int_val) {
      fprintf(stderr, "error decoding set using der_decode_set (int_val is wrong):\n");
      exit(EXIT_FAILURE);
   }

   strcpy((char*)strs[0], "one");
   strcpy((char*)strs[1], "one2");
   strcpy((char*)strs[2], "two");
   strcpy((char*)strs[3], "aaa");
   strcpy((char*)strs[4], "aaaa");
   strcpy((char*)strs[5], "aab");
   strcpy((char*)strs[6], "aaab");
   strcpy((char*)strs[7], "bbb");
   strcpy((char*)strs[8], "bbba");
   strcpy((char*)strs[9], "bbbb");

   for (x = 0; x < 10; x++) {
       LTC_SET_ASN1(list, x, LTC_ASN1_PRINTABLE_STRING, strs[x], strlen((char*)strs[x]));
   }

   outlen = sizeof(outbuf);
   DO(der_encode_setof(list, 10, outbuf, &outlen));

   for (x = 0; x < 10; x++) {
       LTC_SET_ASN1(list, x, LTC_ASN1_PRINTABLE_STRING, strs[x], sizeof(strs[x]) - 1);
   }
   XMEMSET(strs, 0, sizeof(strs));

   DO(der_decode_set(outbuf, outlen, list, 10));

   /* now compare */
   for (x = 1; x < 10; x++) {
      if (!(strlen((char*)strs[x-1]) <= strlen((char*)strs[x])) && strcmp((char*)strs[x-1], (char*)strs[x]) >= 0) {
         fprintf(stderr, "error SET OF order at %lu is wrong\n", x);
         exit(EXIT_FAILURE);
      }
   }

}


/* we are encoding

  SEQUENCE {
     PRINTABLE "printable"
     IA5       "ia5"
     SEQUENCE {
        INTEGER 12345678
        UTCTIME { 91, 5, 6, 16, 45, 40, 1, 7, 0 }
        GENERALIZEDTIME { 2017, 03, 21, 10, 21, 12, 4, 1, 2, 0 }
        SEQUENCE {
           OCTET STRING { 1, 2, 3, 4 }
           BIT STRING   { 1, 0, 0, 1 }
           SEQUENCE {
              OID       { 1, 2, 840, 113549 }
              NULL
              SET OF {
                 PRINTABLE "333"  -- WILL GET SORTED
                 PRINTABLE "222"
           }
        }
     }
  }

*/

static void der_flexi_test(void)
{
   static const char printable_str[]    = "printable";
   static const char set1_str[]         = "333";
   static const char set2_str[]         = "222";
   static const char ia5_str[]          = "ia5";
   static const unsigned long int_val   = 12345678UL;
   static const ltc_utctime   utctime   = { 91, 5, 6, 16, 45, 40, 1, 7, 0 };
   static const ltc_generalizedtime gtime = { 2017, 03, 21, 10, 21, 12, 421, 1, 2, 0 };
   static const unsigned char oct_str[] = { 1, 2, 3, 4 };
   static const unsigned char bit_str[] = { 1, 0, 0, 1 };
   static const unsigned long oid_str[] = { 1, 2, 840, 113549 };

   unsigned char encode_buf[192];
   unsigned long encode_buf_len, decode_len;

   ltc_asn1_list static_list[5][4], *decoded_list, *l;

   /* build list */
   LTC_SET_ASN1(static_list[0], 0, LTC_ASN1_PRINTABLE_STRING, (void *)printable_str, strlen(printable_str));
   LTC_SET_ASN1(static_list[0], 1, LTC_ASN1_IA5_STRING,       (void *)ia5_str,       strlen(ia5_str));
   LTC_SET_ASN1(static_list[0], 2, LTC_ASN1_SEQUENCE,         static_list[1],   4);

   LTC_SET_ASN1(static_list[1], 0, LTC_ASN1_SHORT_INTEGER,    (void *)&int_val,         1);
   LTC_SET_ASN1(static_list[1], 1, LTC_ASN1_UTCTIME,          (void *)&utctime,         1);
   LTC_SET_ASN1(static_list[1], 2, LTC_ASN1_GENERALIZEDTIME,  (void *)&gtime,           1);
   LTC_SET_ASN1(static_list[1], 3, LTC_ASN1_SEQUENCE,         static_list[2],   3);

   LTC_SET_ASN1(static_list[2], 0, LTC_ASN1_OCTET_STRING,     (void *)oct_str,          4);
   LTC_SET_ASN1(static_list[2], 1, LTC_ASN1_BIT_STRING,       (void *)bit_str,          4);
   LTC_SET_ASN1(static_list[2], 2, LTC_ASN1_SEQUENCE,         static_list[3],   3);

   LTC_SET_ASN1(static_list[3], 0, LTC_ASN1_OBJECT_IDENTIFIER,(void *)oid_str,          4);
   LTC_SET_ASN1(static_list[3], 1, LTC_ASN1_NULL,             NULL,             0);
   LTC_SET_ASN1(static_list[3], 2, LTC_ASN1_SETOF,            static_list[4],   2);

   LTC_SET_ASN1(static_list[4], 0, LTC_ASN1_PRINTABLE_STRING, set1_str, strlen(set1_str));
   LTC_SET_ASN1(static_list[4], 1, LTC_ASN1_PRINTABLE_STRING, set2_str, strlen(set2_str));

   /* encode it */
   encode_buf_len = sizeof(encode_buf);
   DO(der_encode_sequence(&static_list[0][0], 3, encode_buf, &encode_buf_len));

#if 0
   {
     FILE *f;
     f = fopen("t.bin", "wb");
     fwrite(encode_buf, 1, encode_buf_len, f);
     fclose(f);
   }
#endif

   /* decode with flexi */
   decode_len = encode_buf_len;
   DO(der_decode_sequence_flexi(encode_buf, &decode_len, &decoded_list));

   if (decode_len != encode_buf_len) {
      fprintf(stderr, "Decode len of %lu does not match encode len of %lu \n", decode_len, encode_buf_len);
      exit(EXIT_FAILURE);
   }

   /* we expect l->next to be NULL and l->child to not be */
   l = decoded_list;
   if (l->next != NULL || l->child == NULL) {
      fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
      exit(EXIT_FAILURE);
   }

   /* we expect a SEQUENCE */
      if (l->type != LTC_ASN1_SEQUENCE) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      l = l->child;

   /* PRINTABLE STRING */
      /* we expect printable_str */
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->type != LTC_ASN1_PRINTABLE_STRING) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->size != strlen(printable_str) || memcmp(printable_str, l->data, l->size)) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      /* move to next */
      l = l->next;

   /* IA5 STRING */
      /* we expect ia5_str */
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->type != LTC_ASN1_IA5_STRING) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->size != strlen(ia5_str) || memcmp(ia5_str, l->data, l->size)) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      /* move to next */
      l = l->next;

   /* expect child anve move down */

      if (l->next != NULL || l->child == NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->type != LTC_ASN1_SEQUENCE) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      l = l->child;


   /* INTEGER */

      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->type != LTC_ASN1_INTEGER) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (mp_cmp_d(l->data, 12345678UL) != LTC_MP_EQ) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      /* move to next */
      l = l->next;

   /* UTCTIME */

      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->type != LTC_ASN1_UTCTIME) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (memcmp(l->data, &utctime, sizeof(utctime))) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      /* move to next */
      l = l->next;

   /* GeneralizedTime */

      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->type != LTC_ASN1_GENERALIZEDTIME) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (memcmp(l->data, &gtime, sizeof(gtime))) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      /* move to next */
      l = l->next;

   /* expect child anve move down */

      if (l->next != NULL || l->child == NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->type != LTC_ASN1_SEQUENCE) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      l = l->child;


   /* OCTET STRING */
      /* we expect oct_str */
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->type != LTC_ASN1_OCTET_STRING) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->size != sizeof(oct_str) || memcmp(oct_str, l->data, l->size)) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      /* move to next */
      l = l->next;

   /* BIT STRING */
      /* we expect oct_str */
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->type != LTC_ASN1_BIT_STRING) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->size != sizeof(bit_str) || memcmp(bit_str, l->data, l->size)) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      /* move to next */
      l = l->next;

   /* expect child anve move down */

      if (l->next != NULL || l->child == NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->type != LTC_ASN1_SEQUENCE) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      l = l->child;


   /* OID STRING */
      /* we expect oid_str */
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->type != LTC_ASN1_OBJECT_IDENTIFIER) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->size != sizeof(oid_str)/sizeof(oid_str[0]) || memcmp(oid_str, l->data, l->size*sizeof(oid_str[0]))) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      /* move to next */
      l = l->next;

   /* NULL */
      if (l->type != LTC_ASN1_NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      /* move to next */
      l = l->next;

   /* expect child anve move down */
      if (l->next != NULL || l->child == NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->type != LTC_ASN1_SET) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      l = l->child;

   /* PRINTABLE STRING */
      /* we expect printable_str */
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->type != LTC_ASN1_PRINTABLE_STRING) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

/* note we compare set2_str FIRST because the SET OF is sorted and "222" comes before "333" */
      if (l->size != strlen(set2_str) || memcmp(set2_str, l->data, l->size)) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      /* move to next */
      l = l->next;

   /* PRINTABLE STRING */
      /* we expect printable_str */
      if (l->type != LTC_ASN1_PRINTABLE_STRING) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }

      if (l->size != strlen(set1_str) || memcmp(set1_str, l->data, l->size)) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }


   der_sequence_free(l);

}

static int der_choice_n_custom_test(void)
{
   ltc_asn1_list types[10], host[1], custom[1], root[1], child[1];
   int boolean[1];
   unsigned char bitbuf[10], octetbuf[10], ia5buf[10], printbuf[10], outbuf[256], custbuf[256], x, y;
   wchar_t utf8buf[10];
   unsigned long integer, oidbuf[10], outlen, custlen, inlen, n;
   void          *mpinteger;
   ltc_utctime   utctime = { 91, 5, 6, 16, 45, 40, 1, 7, 0 };
   ltc_generalizedtime gtime = { 2038, 01, 19, 3, 14, 8, 0, 0, 0, 0 };

   /* setup variables */
   for (x = 0; x < sizeof(bitbuf); x++)   { bitbuf[x]   = x & 1; }
   for (x = 0; x < sizeof(octetbuf); x++) { octetbuf[x] = x;     }
   for (x = 0; x < sizeof(ia5buf); x++)   { ia5buf[x]   = 'a';   }
   for (x = 0; x < sizeof(printbuf); x++) { printbuf[x] = 'a';   }
   for (x = 0; x < sizeof(utf8buf)/sizeof(utf8buf[0]); x++) { utf8buf[x] = L'a';   }
   integer = 1;
   boolean[0] = 1;
   for (x = 0; x < sizeof(oidbuf)/sizeof(oidbuf[0]); x++)   { oidbuf[x] = x + 1;   }
   DO(mp_init(&mpinteger));

   n = sizeof(types)/sizeof(types[0]);
   for (x = 0; x < n * 2; x++) {
       /* setup list */
       y = 0;
       LTC_SET_ASN1(types, y++, LTC_ASN1_PRINTABLE_STRING, printbuf, sizeof(printbuf));
       if (x > n) {
          LTC_SET_ASN1(types, y++, LTC_ASN1_BIT_STRING, bitbuf, sizeof(bitbuf));
       } else {
          LTC_SET_ASN1(types, y++, LTC_ASN1_RAW_BIT_STRING, bitbuf, sizeof(bitbuf));
       }
       LTC_SET_ASN1(types, y++, LTC_ASN1_OCTET_STRING, octetbuf, sizeof(octetbuf));
       LTC_SET_ASN1(types, y++, LTC_ASN1_IA5_STRING, ia5buf, sizeof(ia5buf));
       LTC_SET_ASN1(types, y++, LTC_ASN1_BOOLEAN, boolean, sizeof(boolean)/sizeof(boolean[0]));
       if (x > n) {
          LTC_SET_ASN1(types, y++, LTC_ASN1_SHORT_INTEGER, &integer, 1);
       } else {
          LTC_SET_ASN1(types, y++, LTC_ASN1_INTEGER, mpinteger, 1);
       }
       LTC_SET_ASN1(types, y++, LTC_ASN1_OBJECT_IDENTIFIER, oidbuf, sizeof(oidbuf)/sizeof(oidbuf[0]));
       if (x > n) {
          LTC_SET_ASN1(types, y++, LTC_ASN1_UTCTIME, &utctime, 1);
       } else {
          LTC_SET_ASN1(types, y++, LTC_ASN1_GENERALIZEDTIME, &gtime, 1);
       }

       LTC_SET_ASN1(custom, 0, LTC_ASN1_NULL, NULL, 0);
       LTC_SET_ASN1_CUSTOM_CONSTRUCTED(types, y++, LTC_ASN1_CL_CONTEXT_SPECIFIC, 0, custom);

       LTC_SET_ASN1(types, y++, LTC_ASN1_UTF8_STRING, utf8buf, sizeof(utf8buf)/sizeof(utf8buf[0]));

       LTC_SET_ASN1(host, 0, LTC_ASN1_CHOICE, types, n);


       /* encode */
       outlen = sizeof(outbuf);
       DO(der_encode_sequence(&types[x % n], 1, outbuf, &outlen));

       /* custom encode */
       child[0] = types[x % n];
       if (x < n) {
          LTC_SET_ASN1_CUSTOM_CONSTRUCTED(root, 0, LTC_ASN1_CL_CONTEXT_SPECIFIC, 1U << (x % n), child);
       } else {
          LTC_SET_ASN1_CUSTOM_PRIMITIVE(root, 0, LTC_ASN1_CL_CONTEXT_SPECIFIC, 1U << (x % n), child->type, child->data, child->size);
       }
       custlen = sizeof(custbuf);
       /* don't try to custom-encode a primitive custom-type */
       if (child[0].type != LTC_ASN1_CUSTOM_TYPE || root->pc != LTC_ASN1_PC_PRIMITIVE) {
          DO(der_encode_custom_type(root, custbuf, &custlen));
       }

       /* decode it */
       inlen = outlen;
       DO(der_decode_sequence(outbuf, inlen, host, 1));

       for (y = 0; y < n; y++) {
           if (types[y].used && y != (x % n)) {
               fprintf(stderr, "CHOICE, flag %u in trial %u was incorrectly set to one\n", y, x);
               return 1;
           }
           if (!types[y].used && y == (x % n)) {
               fprintf(stderr, "CHOICE, flag %u in trial %u was incorrectly set to zero\n", y, x);
               return 1;
           }
      }

      /* custom decode */
      if (child[0].type != LTC_ASN1_CUSTOM_TYPE || root->pc != LTC_ASN1_PC_PRIMITIVE) {
         DO(der_decode_custom_type(custbuf, custlen, root));
      }
  }
  mp_clear(mpinteger);
  return 0;
}

static void _der_decode_print(const void* p, unsigned long* plen)
{
   ltc_asn1_list *list;
   DO(der_decode_sequence_flexi(p, plen, &list));
#ifdef LTC_DER_TESTS_PRINT_FLEXI
   fprintf(stderr, "\n\n");
   _der_tests_print_flexi(list, 0);
   fprintf(stderr, "\n\n");
#endif
   der_sequence_free(list);
}

static const unsigned char eckey_privc_der[] = {
  0x30, 0x81, 0xf0, 0x02, 0x01, 0x01, 0x04, 0x18, 0x96, 0x9d, 0x28, 0xf2, 0x40, 0x48, 0x19, 0x11,
  0x79, 0xb0, 0x47, 0x8e, 0x8c, 0x6b, 0x3d, 0x9b, 0xf2, 0x31, 0x16, 0x10, 0x08, 0x72, 0xb1, 0x86,
  0xa0, 0x81, 0xb2, 0x30, 0x81, 0xaf, 0x02, 0x01, 0x01, 0x30, 0x24, 0x06, 0x07, 0x2a, 0x86, 0x48,
  0xce, 0x3d, 0x01, 0x01, 0x02, 0x19, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x30,
  0x4b, 0x04, 0x18, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x04, 0x18, 0x22, 0x12, 0x3d,
  0xc2, 0x39, 0x5a, 0x05, 0xca, 0xa7, 0x42, 0x3d, 0xae, 0xcc, 0xc9, 0x47, 0x60, 0xa7, 0xd4, 0x62,
  0x25, 0x6b, 0xd5, 0x69, 0x16, 0x03, 0x15, 0x00, 0xc4, 0x69, 0x68, 0x44, 0x35, 0xde, 0xb3, 0x78,
  0xc4, 0xb6, 0x5c, 0xa9, 0x59, 0x1e, 0x2a, 0x57, 0x63, 0x05, 0x9a, 0x2e, 0x04, 0x19, 0x02, 0x7d,
  0x29, 0x77, 0x81, 0x00, 0xc6, 0x5a, 0x1d, 0xa1, 0x78, 0x37, 0x16, 0x58, 0x8d, 0xce, 0x2b, 0x8b,
  0x4a, 0xee, 0x8e, 0x22, 0x8f, 0x18, 0x96, 0x02, 0x19, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7a, 0x62, 0xd0, 0x31, 0xc8, 0x3f, 0x42, 0x94, 0xf6, 0x40,
  0xec, 0x13, 0x02, 0x01, 0x01, 0xa1, 0x1c, 0x03, 0x1a, 0x00, 0x02, 0x55, 0x2c, 0xb8, 0x73, 0x5c,
  0x9d, 0x98, 0xe4, 0x57, 0xfe, 0xd5, 0x96, 0x0a, 0x73, 0x8d, 0x82, 0xd7, 0xce, 0x05, 0xa9, 0x79,
  0x91, 0x5c, 0xf9
};

static const unsigned char eckey_privs_der[] = {
  0x30, 0x50, 0x02, 0x01, 0x01, 0x04, 0x14, 0x82, 0xef, 0x42, 0x0b, 0xc7, 0xe2, 0x9f, 0x3a, 0x84,
  0xe5, 0x74, 0xec, 0x9c, 0xc5, 0x10, 0x26, 0x63, 0x8d, 0xb5, 0x46, 0xa0, 0x07, 0x06, 0x05, 0x2b,
  0x81, 0x04, 0x00, 0x09, 0xa1, 0x2c, 0x03, 0x2a, 0x00, 0x04, 0xb5, 0xb1, 0x5a, 0xb0, 0x2a, 0x10,
  0xd1, 0xf5, 0x4d, 0x6a, 0x41, 0xde, 0xcd, 0x69, 0x09, 0xb3, 0x5f, 0x26, 0xb0, 0xa2, 0xaf, 0xd3,
  0x02, 0x89, 0x5e, 0xd4, 0x96, 0x5c, 0xbc, 0x2a, 0x7e, 0x75, 0x85, 0x86, 0x29, 0xb3, 0x29, 0x13,
  0x77, 0xc3
};
static void der_custom_test(void)
{
   ltc_asn1_list bool_ean[1], seq1[1], custom[1];
   int boolean;
   unsigned long len;
   unsigned char buf[1024];
   unsigned char buf1[] = { 0xbf, 0xa0, 0x00, 0x04, 0x30, 0x02, 0x05, 0x00 };
   unsigned char buf2[] = { 0x30, 0x08, 0xbf, 0xa0, 0x00, 0x04, 0x30, 0x02, 0x05, 0x00 };

   boolean = 0x1;
   LTC_SET_ASN1(bool_ean, 0, LTC_ASN1_BOOLEAN, &boolean, 1);
   LTC_SET_ASN1(seq1, 0, LTC_ASN1_SEQUENCE, bool_ean, 1);
   LTC_SET_ASN1_CUSTOM_CONSTRUCTED(custom, 0, LTC_ASN1_CL_CONTEXT_SPECIFIC, 0x1000, seq1);

   DO(der_length_custom_type(custom, &len, NULL));
   len = sizeof(buf);
   DO(der_encode_custom_type(custom, buf, &len));
   _der_decode_print(buf, &len);

   boolean = 0x0;
   DO(der_decode_custom_type(buf, len, custom));

   DO(der_length_sequence(custom, 1, &len));
   len = sizeof(buf);
   DO(der_encode_sequence(custom, 1, buf, &len));
   _der_decode_print(buf, &len);

   boolean = 0x0;
   DO(der_decode_sequence(buf, len, custom, 1));

   LTC_SET_ASN1_CUSTOM_PRIMITIVE(bool_ean, 0, LTC_ASN1_CL_CONTEXT_SPECIFIC, 0x8000, LTC_ASN1_BOOLEAN, &boolean, 1);
   DO(der_length_custom_type(bool_ean, &len, NULL));
   len = sizeof(buf);
   DO(der_encode_custom_type(bool_ean, buf, &len));
   _der_decode_print(buf, &len);

   LTC_SET_ASN1_CUSTOM_PRIMITIVE(bool_ean, 0, LTC_ASN1_CL_CONTEXT_SPECIFIC, 0x8000, LTC_ASN1_BOOLEAN, &boolean, 1);
   DO(der_decode_custom_type(buf, len, bool_ean));

   len = sizeof(buf1);
   _der_decode_print(buf1, &len);

   len = sizeof(buf2);
   _der_decode_print(buf2, &len);

   len = sizeof(eckey_privc_der);
   _der_decode_print(eckey_privc_der, &len);

   len = sizeof(eckey_privs_der);
   _der_decode_print(eckey_privs_der, &len);
}

typedef int (*_der_Xcode)(const void*, unsigned long, void*, unsigned long*);

typedef struct {
   _der_Xcode encode;
   _der_Xcode decode;
   const void* in;
   size_t in_sz;
   size_t factor;
   size_t type_sz;
   const char* what;
} der_Xcode_t;

static void der_Xcode_run(const der_Xcode_t* x)
{
   unsigned long l1, l2, sz;
   void *d1, *d2;
   int err;

   l1 = 1;
   d1 = XMALLOC(l1 * x->type_sz);
   sz = (x->in_sz * x->factor)/x->type_sz;

   if ((err = x->encode(x->in, sz, d1, &l1)) == CRYPT_BUFFER_OVERFLOW) {
      d1 = XREALLOC(d1, l1 * x->type_sz);
   }
   DO(x->encode(x->in, sz, d1, &l1));
   l2 = 1;
   d2 = XMALLOC(l2 * x->type_sz);
   while ((err = x->decode(d1, l1, d2, &l2)) == CRYPT_BUFFER_OVERFLOW) {
      d2 = XREALLOC(d2, l2 * x->type_sz);
   }
   DO(x->decode(d1, l1, d2, &l2));
   DO(do_compare_testvector(d2, (l2/x->factor) * x->type_sz, x->in, x->in_sz, x->what, __LINE__));
   XFREE(d2);
   XFREE(d1);
}

#define DER_XCODE_X(n, b, x) {  \
      (_der_Xcode)der_encode_ ## n,    \
      (_der_Xcode)der_decode_ ## n,    \
      b,                   \
      sizeof(b),           \
      x,                   \
      sizeof(typeof(b[0])),\
      #n                   \
}

#define DER_XCODE(n, b) DER_XCODE_X(n, b, 1)

static void der_Xcode_test(void)
{
   unsigned long i;
   ltc_asn1_list *list;
   ltc_asn1_list ttex_neg_int[2];
   unsigned char buf[128];
   void* mpinteger;
   const unsigned long oid[3] = { 1, 23, 42 };
   const unsigned char bit_string[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
   const unsigned char multi_buf[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
   const char multi_string[] = {'l','i','b','t','o','m','c','r','y','p','t'};
   const wchar_t wchar_string[] = L"libtomcrypt";

   const unsigned char teletex_neg_int[] = {   0x30, 0x11, 0x14, 0x0b, 0x6c, 0x69, 0x62, 0x74,
                                               0x6f, 0x6d, 0x63, 0x72, 0x79, 0x70, 0x74, 0x02,
                                               0x02, 0xfc, 0x19 };

   const der_Xcode_t xcode_tests[] =
   {
    DER_XCODE(bit_string, bit_string),
    DER_XCODE_X(raw_bit_string, multi_buf, 8),
    DER_XCODE(octet_string, multi_buf),
    DER_XCODE(object_identifier, oid),
    DER_XCODE(ia5_string, multi_string),
    DER_XCODE(printable_string, multi_string),
    DER_XCODE(utf8_string, wchar_string),
   };

   for (i = 0; i < sizeof(xcode_tests)/sizeof(xcode_tests[0]); ++i) {
      der_Xcode_run(&xcode_tests[i]);
   }

   i = sizeof(teletex_neg_int);
   DO(der_decode_sequence_flexi(teletex_neg_int, &i, &list));
#ifdef LTC_DER_TESTS_PRINT_FLEXI
   fprintf(stderr, "\n\n");
   _der_tests_print_flexi(list, 0);
   fprintf(stderr, "\n\n");
#endif
   if (list->child == NULL || list->child->next == NULL)
      exit(EXIT_FAILURE);
   ttex_neg_int[0] = *list->child->next;
   i = sizeof(buf);
   DO(der_encode_sequence(ttex_neg_int, 1, buf, &i));
   der_sequence_free(list);

   DO(mp_init(&mpinteger));
   LTC_SET_ASN1(ttex_neg_int, 0, LTC_ASN1_TELETEX_STRING, buf, sizeof(buf));
   LTC_SET_ASN1(ttex_neg_int, 1, LTC_ASN1_INTEGER, mpinteger, 1);

   DO(der_decode_sequence(teletex_neg_int, sizeof(teletex_neg_int), ttex_neg_int, 2));

   mp_clear(mpinteger);
}

#if !((defined(_WIN32) || defined(_WIN32_WCE)) && !defined(__GNUC__))

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

static off_t fsize(const char *filename)
{
   struct stat st;

   if (stat(filename, &st) == 0) return st.st_size;

   return -1;
}

static void der_asn1_test(void)
{
   DIR *d = opendir("tests/asn1");
   struct dirent *de;
   char fname[PATH_MAX];
   void* buf = NULL;
   FILE *f = NULL;
   off_t fsz;
   unsigned long sz;
   ltc_asn1_list *list;
   int err;
   if (d == NULL)
      return;
   while((de = readdir(d)) != NULL) {
      fname[0] = '\0';
      if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
         continue;
      strcat(fname, "tests/asn1/");
      strcat(fname, de->d_name);
      fsz = fsize(fname);
      if (fsz == -1)
         break;
#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
      fprintf(stderr, "Try to decode %s\n", fname);
#endif
      f = fopen(fname, "rb");
      sz = fsz;
      buf = XMALLOC(fsz);
      if (fread(buf, 1, sz, f) != sz)
         break;

      if ((err = der_decode_sequence_flexi(buf, &sz, &list)) == CRYPT_OK) {
#ifdef LTC_DER_TESTS_PRINT_FLEXI
         fprintf(stderr, "\n\n");
         _der_tests_print_flexi(list, 0);
         fprintf(stderr, "\n\n");
#endif
         der_sequence_free(list);
      } else {
#if defined(LTC_TEST_DBG)
         fprintf(stderr, "Could not decode %s: %s\n\n", fname, error_to_string(err));
#endif
      }
      XFREE(buf);
      buf = NULL;
      fclose(f);
      f = NULL;
   }
   if (buf != NULL) XFREE(buf);
   if (f != NULL) fclose(f);
   closedir(d);
}
#endif


static void _der_regression_test(void)
{
   static const unsigned char _broken_sequence[] = {
     0x30,0x41,0x02,0x84,0x7f,0xff,0xff,0xff,0x1e,0x41,0xb4,0x79,0xad,0x57,0x69,
     0x05,0xb9,0x60,0xfe,0x14,0xea,0xdb,0x91,0xb0,0xcc,0xf3,0x48,0x43,0xda,0xb9,
     0x16,0x17,0x3b,0xb8,0xc9,0xcd,0x02,0x1d,0x00,0xad,0xe6,0x59,0x88,0xd2,0x37,
     0xd3,0x0f,0x9e,0xf4,0x1d,0xd4,0x24,0xa4,0xe1,0xc8,0xf1,0x69,0x67,0xcf,0x33,
     0x65,0x81,0x3f,0xe8,0x78,0x62,0x36
   };
   static const unsigned char _addtl_bytes[] = {
     0x30,0x45,0x02,0x21,0x00,0xb7,0xba,0xba,0xe9,0x33,0x2b,0x54,0xb8,0xa3,0xa0,0x5b,0x70,0x04,0x57,
     0x98,0x21,0xa8,0x87,0xa1,0xb2,0x14,0x65,0xf7,0xdb,0x8a,0x3d,0x49,0x1b,0x39,0xfd,0x2c,0x3f,0x02,
     0x20,0x74,0x72,0x91,0xdd,0x2f,0x3f,0x44,0xaf,0x7a,0xce,0x68,0xea,0x33,0x43,0x1d,0x6f,0x94,0xe4,
     0x18,0xc1,0x06,0xa6,0xe7,0x62,0x85,0xcd,0x59,0xf4,0x32,0x60,0xec,0xce,0x00,0x00
   };
   unsigned long len;
   void *x, *y;
   ltc_asn1_list seq[2];
   mp_init_multi(&x, &y, NULL);
   LTC_SET_ASN1(seq, 0, LTC_ASN1_INTEGER, x, 1UL);
   LTC_SET_ASN1(seq, 1, LTC_ASN1_INTEGER, y, 1UL);
   DO(der_decode_sequence(_broken_sequence, sizeof(_broken_sequence), seq, 2) != CRYPT_OK ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
   mp_cleanup_multi(&y, &x, NULL);
   len = sizeof(_broken_sequence);

   mp_init_multi(&x, &y, NULL);
   LTC_SET_ASN1(seq, 0, LTC_ASN1_INTEGER, x, 1UL);
   LTC_SET_ASN1(seq, 1, LTC_ASN1_INTEGER, y, 1UL);
   DO(der_decode_sequence(_addtl_bytes, sizeof(_addtl_bytes), seq, 2) == CRYPT_INPUT_TOO_LONG ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR);
   mp_cleanup_multi(&y, &x, NULL);
   len = sizeof(_addtl_bytes);
   _der_decode_print(_addtl_bytes, &len);
}

static void der_toolong_test(void)
{
   int n, err, failed = 0;
   ltc_asn1_list *list;
   unsigned long len, oid[16];
   unsigned char buf5[5], buf12[12], buf32[32];
   static const unsigned char invalid1[] = {
         0x30,0x19, /* SEQUENCE len=25 bytes */
              0x30,0x0a, /* SEQUENCE len=10 bytes (which is wrong, should be 9) */
                   0x04,0x05, /* OCTET STRING len=5 */ 0x2b,0x0e,0x03,0x02,0x1a,
                   0x05,0x00, /* NULL */
              0x04,0x0c, /* OCTET STRING len=12 */ 0xf7,0xff,0x9e,0x8b,0x7b,0xb2,0xe0,0x9b,0x70,0x93,0x5a,0x5d,
   };
   static const unsigned char invalid2[] = {
         0x30,0x0d, /* SEQUENCE len=13 bytes*/
              0x02,0x05, /* INTEGER len=5 */ 0x00,0xb7,0xba,0xba,0xe9,
              0x02,0x04, /* INTEGER len=4 */ 0x74,0x72,0x91,0xdd,
         0x00,0x00 /* garbage after the sequence, der_decode_sequence_flexi should ignore this */
   };
   static const unsigned char invalid3[] = {
         0x30,0x0f, /* SEQUENCE len=15 bytes*/
              0x02,0x05, /* INTEGER len=5 */ 0x00,0xb7,0xba,0xba,0xe9,
              0x02,0x04, /* INTEGER len=4 */ 0x74,0x72,0x91,0xdd,
              0x00,0x00  /* garbage inside the sequence */
   };
   static const unsigned char invalid4[] = {
         0x30, 0x30,
               0x30, 0x0d,
                     0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                     0x05, 0x00,
               0x04, 0x20, 0x53, 0x2e, 0xaa, 0xbd, 0x95, 0x74, 0x88, 0x0d, 0xbf, 0x76, 0xb9, 0xb8, 0xcc, 0x00, 0x83, 0x2c,
                           0x20, 0xa6, 0xec, 0x11, 0x3d, 0x68, 0x22, 0x99, 0x55, 0x0d, 0x7a, 0x6e, 0x0f, 0x34, 0x5e, 0x25

   };
   static const unsigned char invalid5[] = {
          0x30, 0x31,
                0x30, 0x0e,
                      0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                      0x05, 0x00,
                0x04, 0x20, 0x53, 0x2e, 0xaa, 0xbd, 0x95,0x74, 0x88, 0x0d, 0xbf, 0x76, 0xb9, 0xb8, 0xcc,0x00, 0x83, 0x2c,
                            0x20, 0xa6, 0xec, 0x11, 0x3d,0x68, 0x22, 0x99, 0x55, 0x0d, 0x7a, 0x6e, 0x0f,0x34, 0x5e, 0x25

   };
   static const unsigned char invalid6[] = {
          0x30, 0x31,
                0x30, 0x0c,
                      0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                      0x05, 0x00,
                0x04, 0x20, 0x53, 0x2e, 0xaa, 0xbd, 0x95,0x74, 0x88, 0x0d, 0xbf, 0x76, 0xb9, 0xb8, 0xcc,0x00, 0x83, 0x2c,
                            0x20, 0xa6, 0xec, 0x11, 0x3d,0x68, 0x22, 0x99, 0x55, 0x0d, 0x7a, 0x6e, 0x0f,0x34, 0x5e, 0x25

   };

   ltc_asn1_list seqsub[2], seqoid[2], seqmain[2], seqint[2];
   void *int1, *int2;

   LTC_SET_ASN1(seqsub,  0, LTC_ASN1_OCTET_STRING, buf5,   5);
   LTC_SET_ASN1(seqsub,  1, LTC_ASN1_NULL,         NULL,   0);
   LTC_SET_ASN1(seqmain, 0, LTC_ASN1_SEQUENCE,     seqsub, 2);
   LTC_SET_ASN1(seqmain, 1, LTC_ASN1_OCTET_STRING, buf12,  12);

   n = 1;
   len = sizeof(invalid1);
   err = der_decode_sequence_strict(invalid1, len, seqmain, 2);
   if (err == CRYPT_OK) {
      fprintf(stderr,"Sequence invalid%d accepted by der_decode_sequence\n", n);
      failed = 1;
   }
   len = sizeof(invalid1);
   err = der_decode_sequence_flexi(invalid1, &len, &list);
   if (err == CRYPT_OK) {
      fprintf(stderr,"Sequence invalid%d accepted by der_decode_sequence_flexi\n", n);
      failed = 1;
      der_sequence_free(list);
   }

   mp_init_multi(&int1, &int2, NULL);
   LTC_SET_ASN1(seqint,  0, LTC_ASN1_INTEGER,      int1,   1);
   LTC_SET_ASN1(seqint,  1, LTC_ASN1_INTEGER,      int2,   1);

   n++;
   len = sizeof(invalid2);
   err = der_decode_sequence_strict(invalid2, len, seqint, 2);
   if (err == CRYPT_OK) {
      fprintf(stderr,"Sequence invalid%d accepted by der_decode_sequence\n", n);
      failed = 1;
   }
   len = sizeof(invalid2);
   err = der_decode_sequence_flexi(invalid2, &len, &list);
   /* flexi parser should decode this; however returning "len" shorter than "sizeof(invalid2)" */
   if (err != CRYPT_OK || len != 15) {
      fprintf(stderr,"der_decode_sequence_flexi failed, err=%d (expected 0) len=%lu (expected 15)\n", err, len);
      failed = 1;
   }
   if (err == CRYPT_OK)
      der_sequence_free(list);

   n++;
   len = sizeof(invalid3);
   err = der_decode_sequence_strict(invalid3, len, seqint, 2);
   if (err == CRYPT_OK) {
      fprintf(stderr,"Sequence invalid%d accepted by der_decode_sequence\n", n);
      failed = 1;
   }
   len = sizeof(invalid3);
   err = der_decode_sequence_flexi(invalid3, &len, &list);
   if (err == CRYPT_OK) {
      fprintf(stderr,"Sequence invalid%d accepted by der_decode_sequence_flexi\n", n);
      failed = 1;
      der_sequence_free(list);
   }

   mp_clear_multi(int1, int2, NULL);

   LTC_SET_ASN1(seqoid,  0, LTC_ASN1_OBJECT_IDENTIFIER, oid, sizeof(oid)/sizeof(oid[0]));
   LTC_SET_ASN1(seqoid,  1, LTC_ASN1_NULL,              NULL,   0);
   LTC_SET_ASN1(seqmain, 0, LTC_ASN1_SEQUENCE,          seqoid, 2);
   LTC_SET_ASN1(seqmain, 1, LTC_ASN1_OCTET_STRING,      buf32,  32);

   n++;
   len = sizeof(invalid4);
   err = der_decode_sequence_strict(invalid4, len, seqmain, 2);
   if (err == CRYPT_OK) {
      fprintf(stderr,"Sequence invalid%d accepted by der_decode_sequence\n", n);
      failed = 1;
   }
   len = sizeof(invalid4);
   err = der_decode_sequence_flexi(invalid4, &len, &list);
   if (err == CRYPT_OK) {
      fprintf(stderr,"Sequence invalid%d accepted by der_decode_sequence_flexi\n", n);
      failed = 1;
      der_sequence_free(list);
   }

   n++;
   len = sizeof(invalid5);
   err = der_decode_sequence_strict(invalid5, len, seqmain, 2);
   if (err == CRYPT_OK) {
      fprintf(stderr,"Sequence invalid%d accepted by der_decode_sequence\n", n);
      failed = 1;
   }
   len = sizeof(invalid5);
   err = der_decode_sequence_flexi(invalid5, &len, &list);
   if (err == CRYPT_OK) {
      fprintf(stderr,"Sequence invalid%d accepted by der_decode_sequence_flexi\n", n);
      failed = 1;
      der_sequence_free(list);
   }
   n++;
   len = sizeof(invalid6);
   err = der_decode_sequence_strict(invalid6, len, seqmain, 2);
   if (err == CRYPT_OK) {
      fprintf(stderr,"Sequence invalid%d accepted by der_decode_sequence\n", n);
      failed = 1;
   }
   len = sizeof(invalid6);
   err = der_decode_sequence_flexi(invalid6, &len, &list);
   if (err == CRYPT_OK) {
      fprintf(stderr,"Sequence invalid%d accepted by der_decode_sequence_flexi\n", n);
      failed = 1;
      der_sequence_free(list);
   }

   if (failed) exit(EXIT_FAILURE);
}

static void _der_recursion_limit(void)
{
   int failed = 0;
   unsigned int n;
   unsigned long integer = 123, s;
   ltc_asn1_list seqs[LTC_DER_MAX_RECURSION + 2], dummy[1], *flexi;
   unsigned char buf[2048];
   LTC_SET_ASN1(dummy, 0, LTC_ASN1_SHORT_INTEGER, &integer, 1);
   LTC_SET_ASN1(seqs, LTC_DER_MAX_RECURSION + 1, LTC_ASN1_SEQUENCE, dummy, 1);
   for (n = 0; n < LTC_DER_MAX_RECURSION + 1; ++n) {
      LTC_SET_ASN1(seqs, LTC_DER_MAX_RECURSION - n, LTC_ASN1_SEQUENCE, &seqs[LTC_DER_MAX_RECURSION - n + 1], 1);
   }
   s = sizeof(buf);
   DO(der_encode_sequence(seqs, 1, buf, &s));
   DO(der_decode_sequence(buf, s, seqs, 1));
   SHOULD_FAIL(der_decode_sequence_flexi(buf, &s, &flexi));
   if (failed) exit(EXIT_FAILURE);
}

int der_test(void)
{
   unsigned long x, y, z, zz, oid[2][32];
   unsigned char buf[3][2048];
   void *a, *b, *c, *d, *e, *f, *g;

   static const unsigned char rsa_oid_der[] = { 0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d };
   static const unsigned long rsa_oid[]     = { 1, 2, 840, 113549 };

   static const unsigned char rsa_ia5[]     = "test1@rsa.com";
   static const unsigned char rsa_ia5_der[] = { 0x16, 0x0d, 0x74, 0x65, 0x73, 0x74, 0x31,
                                                0x40, 0x72, 0x73, 0x61, 0x2e, 0x63, 0x6f, 0x6d };

   static const unsigned char rsa_printable[] = "Test User 1";
   static const unsigned char rsa_printable_der[] = { 0x13, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x55,
                                                      0x73, 0x65, 0x72, 0x20, 0x31 };

   static const ltc_utctime   rsa_time1 = { 91, 5, 6, 16, 45, 40, 1, 7, 0 };
   static const ltc_utctime   rsa_time2 = { 91, 5, 6, 23, 45, 40, 0, 0, 0 };
   ltc_utctime                tmp_time;

   static const unsigned char rsa_time1_der[] = { 0x17, 0x11, 0x39, 0x31, 0x30, 0x35, 0x30, 0x36, 0x31, 0x36, 0x34, 0x35, 0x34, 0x30, 0x2D, 0x30, 0x37, 0x30, 0x30 };
   static const unsigned char rsa_time2_der[] = { 0x17, 0x0d, 0x39, 0x31, 0x30, 0x35, 0x30, 0x36, 0x32, 0x33, 0x34, 0x35, 0x34, 0x30, 0x5a };

   static const wchar_t utf8_1[]           = { 0x0041, 0x2262, 0x0391, 0x002E };
   static const unsigned char utf8_1_der[] = { 0x0C, 0x07, 0x41, 0xE2, 0x89, 0xA2, 0xCE, 0x91, 0x2E };
   static const wchar_t utf8_2[]           = { 0xD55C, 0xAD6D, 0xC5B4 };
   static const unsigned char utf8_2_der[] = { 0x0C, 0x09, 0xED, 0x95, 0x9C, 0xEA, 0xB5, 0xAD, 0xEC, 0x96, 0xB4 };

   unsigned char utf8_buf[32];
   wchar_t utf8_out[32];

   if (ltc_mp.name == NULL) return CRYPT_NOP;

   _der_recursion_limit();

   der_Xcode_test();

#if !((defined(_WIN32) || defined(_WIN32_WCE)) && !defined(__GNUC__))
   der_asn1_test();
#endif

   der_custom_test();

   _der_regression_test();

   der_toolong_test();

   der_cacert_test();

   y = 0xffffff00;
#if ULONG_MAX == ULLONG_MAX
   y <<= 32;
#endif
   while (y != 0) {
      /* we have to modify x to be larger than the encoded
       * length as der_decode_asn1_length() checks also if
       * the encoded length is reasonable in regards to the
       * available buffer size.
       */
      x = sizeof(buf[0]);
      DO(der_encode_asn1_length(y, buf[0], &x));
      x = y + x;
      DO(der_decode_asn1_length(buf[0], &x, &z));
      if (y != z) {
         fprintf(stderr, "Failed to en- or decode length correctly! %lu != %lu\n", y, z);
         return 1;
      }
      y >>= 3;
   }

   DO(mp_init_multi(&a, &b, &c, &d, &e, &f, &g, NULL));
   for (zz = 0; zz < 16; zz++) {
#ifdef USE_TFM
      for (z = 0; z < 256; z++) {
#else
      for (z = 0; z < 1024; z++) {
#endif
         if (yarrow_read(buf[0], z, &yarrow_prng) != z) {
            fprintf(stderr, "Failed to read %lu bytes from yarrow\n", z);
            return 1;
         }
         DO(mp_read_unsigned_bin(a, buf[0], z));
/*          if (mp_iszero(a) == LTC_MP_NO) { a.sign = buf[0][0] & 1 ? LTC_MP_ZPOS : LTC_MP_NEG; } */
         x = sizeof(buf[0]);
         DO(der_encode_integer(a, buf[0], &x));
         DO(der_length_integer(a, &y));
         if (y != x) { fprintf(stderr, "DER INTEGER size mismatch %lu != %lu\n", y, x); return 1; }
         mp_set_int(b, 0);
         DO(der_decode_integer(buf[0], y, b));
         if (y != x || mp_cmp(a, b) != LTC_MP_EQ) {
            fprintf(stderr, "%lu: %lu vs %lu\n", z, x, y);
            mp_clear_multi(a, b, c, d, e, f, g, NULL);
            return 1;
         }
      }
   }

/* test short integer */
   for (zz = 0; zz < 256; zz++) {
      for (z = 1; z < 4; z++) {
         if (yarrow_read(buf[2], z, &yarrow_prng) != z) {
            fprintf(stderr, "Failed to read %lu bytes from yarrow\n", z);
            return 1;
         }
         /* encode with normal */
         DO(mp_read_unsigned_bin(a, buf[2], z));

         x = sizeof(buf[0]);
         DO(der_encode_integer(a, buf[0], &x));

         /* encode with short */
         y = sizeof(buf[1]);
         DO(der_encode_short_integer(mp_get_int(a), buf[1], &y));
         if (x != y || memcmp(buf[0], buf[1], x)) {
            fprintf(stderr, "DER INTEGER short encoding failed, %lu, %lu, 0x%lX\n", x, y, mp_get_int(a));
            for (zz = 0; zz < z; zz++) fprintf(stderr, "%02x ", buf[2][zz]);
            fprintf(stderr, "\n");
            for (z = 0; z < x; z++) fprintf(stderr, "%02x ", buf[0][z]);
            fprintf(stderr, "\n");
            for (z = 0; z < y; z++) fprintf(stderr, "%02x ", buf[1][z]);
            fprintf(stderr, "\n");
            mp_clear_multi(a, b, c, d, e, f, g, NULL);
            return 1;
         }

         /* decode it */
         x = 0;
         DO(der_decode_short_integer(buf[1], y, &x));
         if (x != mp_get_int(a)) {
            fprintf(stderr, "DER INTEGER short decoding failed, %lu, %lu\n", x, mp_get_int(a));
            mp_clear_multi(a, b, c, d, e, f, g, NULL);
            return 1;
         }
      }
   }
   mp_clear_multi(a, b, c, d, e, f, g, NULL);


/* Test bit string */
   for (zz = 1; zz < 1536; zz++) {
       yarrow_read(buf[0], zz, &yarrow_prng);
       for (z = 0; z < zz; z++) {
           buf[0][z] &= 0x01;
       }
       x = sizeof(buf[1]);
       DO(der_encode_bit_string(buf[0], zz, buf[1], &x));
       DO(der_length_bit_string(zz, &y));
       if (y != x) {
          fprintf(stderr, "\nDER BIT STRING length of encoded not match expected : %lu, %lu, %lu\n", z, x, y);
          return 1;
       }

       y = sizeof(buf[2]);
       DO(der_decode_bit_string(buf[1], x, buf[2], &y));
       if (y != zz || memcmp(buf[0], buf[2], zz)) {
          fprintf(stderr, "%lu, %lu, %d\n", y, zz, memcmp(buf[0], buf[2], zz));
          return 1;
       }
   }

/* Test octet string */
   for (zz = 1; zz < 1536; zz++) {
       yarrow_read(buf[0], zz, &yarrow_prng);
       x = sizeof(buf[1]);
       DO(der_encode_octet_string(buf[0], zz, buf[1], &x));
       DO(der_length_octet_string(zz, &y));
       if (y != x) {
          fprintf(stderr, "\nDER OCTET STRING length of encoded not match expected : %lu, %lu, %lu\n", z, x, y);
          return 1;
       }
       y = sizeof(buf[2]);
       DO(der_decode_octet_string(buf[1], x, buf[2], &y));
       if (y != zz || memcmp(buf[0], buf[2], zz)) {
          fprintf(stderr, "%lu, %lu, %d\n", y, zz, memcmp(buf[0], buf[2], zz));
          return 1;
       }
   }

/* test OID */
   x = sizeof(buf[0]);
   DO(der_encode_object_identifier((unsigned long*)rsa_oid, sizeof(rsa_oid)/sizeof(rsa_oid[0]), buf[0], &x));
   if (x != sizeof(rsa_oid_der) || memcmp(rsa_oid_der, buf[0], x)) {
      fprintf(stderr, "rsa_oid_der encode failed to match, %lu, ", x);
      for (y = 0; y < x; y++) fprintf(stderr, "%02x ", buf[0][y]);
      fprintf(stderr, "\n");
      return 1;
   }

   y = sizeof(oid[0])/sizeof(oid[0][0]);
   DO(der_decode_object_identifier(buf[0], x, oid[0], &y));
   if (y != sizeof(rsa_oid)/sizeof(rsa_oid[0]) || memcmp(rsa_oid, oid[0], sizeof(rsa_oid))) {
      fprintf(stderr, "rsa_oid_der decode failed to match, %lu, ", y);
      for (z = 0; z < y; z++) fprintf(stderr, "%lu ", oid[0][z]);
      fprintf(stderr, "\n");
      return 1;
   }

   /* do random strings */
   for (zz = 0; zz < 5000; zz++) {
       /* pick a random number of words */
       yarrow_read(buf[0], 4, &yarrow_prng);
       LOAD32L(z, buf[0]);
       z = 2 + (z % ((sizeof(oid[0])/sizeof(oid[0][0])) - 2));

       /* fill them in */
       oid[0][0] = buf[0][0] % 3;
       oid[0][1] = buf[0][1] % 40;

       for (y = 2; y < z; y++) {
          yarrow_read(buf[0], 4, &yarrow_prng);
          LOAD32L(oid[0][y], buf[0]);
       }

       /* encode it */
       x = sizeof(buf[0]);
       DO(der_encode_object_identifier(oid[0], z, buf[0], &x));
       DO(der_length_object_identifier(oid[0], z, &y));
       if (x != y) {
          fprintf(stderr, "Random OID %lu test failed, length mismatch: %lu, %lu\n", z, x, y);
          for (x = 0; x < z; x++) fprintf(stderr, "%lu\n", oid[0][x]);
          return 1;
       }

       /* decode it */
       y = sizeof(oid[0])/sizeof(oid[0][0]);
       DO(der_decode_object_identifier(buf[0], x, oid[1], &y));
       if (y != z) {
          fprintf(stderr, "Random OID %lu test failed, decode length mismatch: %lu, %lu\n", z, x, y);
          return 1;
       }
       if (memcmp(oid[0], oid[1], sizeof(oid[0][0]) * z)) {
          fprintf(stderr, "Random OID %lu test failed, decoded values wrong\n", z);
          for (x = 0; x < z; x++) fprintf(stderr, "%lu\n", oid[0][x]);
          fprintf(stderr, "\n\n Got \n\n");
          for (x = 0; x < z; x++) fprintf(stderr, "%lu\n", oid[1][x]);
          return 1;
       }
   }

/* IA5 string */
   x = sizeof(buf[0]);
   DO(der_encode_ia5_string(rsa_ia5, strlen((char*)rsa_ia5), buf[0], &x));
   if (x != sizeof(rsa_ia5_der) || memcmp(buf[0], rsa_ia5_der, x)) {
      fprintf(stderr, "IA5 encode failed: %lu, %lu\n", x, (unsigned long)sizeof(rsa_ia5_der));
      return 1;
   }
   DO(der_length_ia5_string(rsa_ia5, strlen((char*)rsa_ia5), &y));
   if (y != x) {
      fprintf(stderr, "IA5 length failed to match: %lu, %lu\n", x, y);
      return 1;
   }
   y = sizeof(buf[1]);
   DO(der_decode_ia5_string(buf[0], x, buf[1], &y));
   if (y != strlen((char*)rsa_ia5) || memcmp(buf[1], rsa_ia5, strlen((char*)rsa_ia5))) {
       fprintf(stderr, "DER IA5 failed test vector\n");
       return 1;
   }

/* Printable string */
   x = sizeof(buf[0]);
   DO(der_encode_printable_string(rsa_printable, strlen((char*)rsa_printable), buf[0], &x));
   if (x != sizeof(rsa_printable_der) || memcmp(buf[0], rsa_printable_der, x)) {
      fprintf(stderr, "PRINTABLE encode failed: %lu, %lu\n", x, (unsigned long)sizeof(rsa_printable_der));
      return 1;
   }
   DO(der_length_printable_string(rsa_printable, strlen((char*)rsa_printable), &y));
   if (y != x) {
      fprintf(stderr, "printable length failed to match: %lu, %lu\n", x, y);
      return 1;
   }
   y = sizeof(buf[1]);
   DO(der_decode_printable_string(buf[0], x, buf[1], &y));
   if (y != strlen((char*)rsa_printable) || memcmp(buf[1], rsa_printable, strlen((char*)rsa_printable))) {
       fprintf(stderr, "DER printable failed test vector\n");
       return 1;
   }

/* Test UTC time */
   x = sizeof(buf[0]);
   DO(der_encode_utctime((ltc_utctime*)&rsa_time1, buf[0], &x));
   if (x != sizeof(rsa_time1_der) || memcmp(buf[0], rsa_time1_der, x)) {
      fprintf(stderr, "UTCTIME encode of rsa_time1 failed: %lu, %lu\n", x, (unsigned long)sizeof(rsa_time1_der));
      fprintf(stderr, "\n\n");
      for (y = 0; y < x; y++) fprintf(stderr, "%02x ", buf[0][y]);
      fprintf(stderr, "\n");
      return 1;
   }
   DO(der_length_utctime((ltc_utctime*)&rsa_time1, &y));
   if (y != x) {
      fprintf(stderr, "UTCTIME length failed to match for rsa_time1: %lu, %lu\n", x, y);
      return 1;
   }
   DO(der_decode_utctime(buf[0], &y, &tmp_time));
   if (y != x || memcmp(&rsa_time1, &tmp_time, sizeof(ltc_utctime))) {
      fprintf(stderr, "UTCTIME decode failed for rsa_time1: %lu %lu\n", x, y);
fprintf(stderr, "\n\n%u %u %u %u %u %u %u %u %u\n\n",
tmp_time.YY,
tmp_time.MM,
tmp_time.DD,
tmp_time.hh,
tmp_time.mm,
tmp_time.ss,
tmp_time.off_dir,
tmp_time.off_mm,
tmp_time.off_hh);
      return 1;
   }

   x = sizeof(buf[0]);
   DO(der_encode_utctime((ltc_utctime*)&rsa_time2, buf[0], &x));
   if (x != sizeof(rsa_time2_der) || memcmp(buf[0], rsa_time2_der, x)) {
      fprintf(stderr, "UTCTIME encode of rsa_time2 failed: %lu, %lu\n", x, (unsigned long)sizeof(rsa_time1_der));
      fprintf(stderr, "\n\n");
      for (y = 0; y < x; y++) fprintf(stderr, "%02x ", buf[0][y]);
      fprintf(stderr, "\n");
      return 1;
   }
   DO(der_length_utctime((ltc_utctime*)&rsa_time2, &y));
   if (y != x) {
      fprintf(stderr, "UTCTIME length failed to match for rsa_time2: %lu, %lu\n", x, y);
      return 1;
   }
   DO(der_decode_utctime(buf[0], &y, &tmp_time));
   if (y != x || memcmp(&rsa_time2, &tmp_time, sizeof(ltc_utctime))) {
      fprintf(stderr, "UTCTIME decode failed for rsa_time2: %lu %lu\n", x, y);
fprintf(stderr, "\n\n%u %u %u %u %u %u %u %u %u\n\n",
tmp_time.YY,
tmp_time.MM,
tmp_time.DD,
tmp_time.hh,
tmp_time.mm,
tmp_time.ss,
tmp_time.off_dir,
tmp_time.off_mm,
tmp_time.off_hh);


      return 1;
   }

   /* UTF 8 */
     /* encode it */
     x = sizeof(utf8_buf);
     DO(der_encode_utf8_string(utf8_1, sizeof(utf8_1) / sizeof(utf8_1[0]), utf8_buf, &x));
     DO(der_length_utf8_string(utf8_1, sizeof(utf8_1) / sizeof(utf8_1[0]), &y));
     if (x != sizeof(utf8_1_der) || memcmp(utf8_buf, utf8_1_der, x) || x != y) {
        fprintf(stderr, "DER UTF8_1 encoded to %lu bytes\n", x);
        for (y = 0; y < x; y++) fprintf(stderr, "%02x ", (unsigned)utf8_buf[y]);
        fprintf(stderr, "\n");
        return 1;
     }
     /* decode it */
     y = sizeof(utf8_out) / sizeof(utf8_out[0]);
     DO(der_decode_utf8_string(utf8_buf, x, utf8_out, &y));
     if (y != (sizeof(utf8_1) / sizeof(utf8_1[0])) || memcmp(utf8_1, utf8_out, y * sizeof(wchar_t))) {
        fprintf(stderr, "DER UTF8_1 decoded to %lu wchar_t\n", y);
        for (x = 0; x < y; x++) fprintf(stderr, "%04lx ", (unsigned long)utf8_out[x]);
        fprintf(stderr, "\n");
        return 1;
     }

     /* encode it */
     x = sizeof(utf8_buf);
     DO(der_encode_utf8_string(utf8_2, sizeof(utf8_2) / sizeof(utf8_2[0]), utf8_buf, &x));
     if (x != sizeof(utf8_2_der) || memcmp(utf8_buf, utf8_2_der, x)) {
        fprintf(stderr, "DER UTF8_2 encoded to %lu bytes\n", x);
        for (y = 0; y < x; y++) fprintf(stderr, "%02x ", (unsigned)utf8_buf[y]);
        fprintf(stderr, "\n");
        return 1;
     }
     /* decode it */
     y = sizeof(utf8_out) / sizeof(utf8_out[0]);
     DO(der_decode_utf8_string(utf8_buf, x, utf8_out, &y));
     if (y != (sizeof(utf8_2) / sizeof(utf8_2[0])) || memcmp(utf8_2, utf8_out, y * sizeof(wchar_t))) {
        fprintf(stderr, "DER UTF8_2 decoded to %lu wchar_t\n", y);
        for (x = 0; x < y; x++) fprintf(stderr, "%04lx ", (unsigned long)utf8_out[x]);
        fprintf(stderr, "\n");
        return 1;
     }


   der_set_test();
   der_flexi_test();
   return der_choice_n_custom_test();
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
