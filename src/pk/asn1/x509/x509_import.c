/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"
#include <wchar.h>

/**
  @file x509_import.c
  Import an X.509 cert, Steffen Jaeckel
*/

#ifdef LTC_DER

#define LTC_ASN1_BMP_STRING 30

#define ASN1_STRING LTC_BIT(LTC_ASN1_TELETEX_STRING) \
   | LTC_BIT(LTC_ASN1_PRINTABLE_STRING) \
   | LTC_BIT(LTC_ASN1_UTF8_STRING) \
   | LTC_BIT(LTC_ASN1_CUSTOM_TYPE)
#define ASN1_IA5_STRING LTC_BIT(LTC_ASN1_IA5_STRING)

#define OID_DETAIL_ELEMENT(detail, oid, types, ub) { detail, oid, types, ub, NULL }
#define OID_DETAIL_ELEMENT_5(detail, arc, oid, types, ub) { detail, arc "." # oid, types, ub, NULL }

#define st_oid_detail st_x509_import_oid_detail

typedef struct st_oid_detail {
   ltc_x509_details detail;
   const char *oid;
   ulong32 types;
   unsigned long upper_bound;
   ltc_x509_string *str;
} st_oid_detail;

#define X509_NAME_ARC "2.5.4"
#define X509_NAME_ELEMENT(detail, oid, ub) OID_DETAIL_ELEMENT_5(detail, X509_NAME_ARC, oid, ASN1_STRING, ub)

static const st_oid_detail name_elements_map[] = {
                       X509_NAME_ELEMENT(LTC_X509_CN, 3,  64),
                       X509_NAME_ELEMENT(LTC_X509_C,  6,  2),
                       X509_NAME_ELEMENT(LTC_X509_L,  7,  128),
                       X509_NAME_ELEMENT(LTC_X509_ST, 8,  128),
                       X509_NAME_ELEMENT(LTC_X509_O,  10, 64),
                       X509_NAME_ELEMENT(LTC_X509_OU, 11, 64),
                       OID_DETAIL_ELEMENT(LTC_X509_EMAIL, "1.2.840.113549.1.9.1", ASN1_IA5_STRING, 255),
};

static LTC_INLINE const st_oid_detail* s_get_name_element(const char *oid)
{
   unsigned long i;
   for (i = 0; i < LTC_ARRAY_SIZE(name_elements_map); ++i) {
      if (XSTRCMP(oid, name_elements_map[i].oid) == 0) {
         return &name_elements_map[i];
      }
   }
   return NULL;
}

static LTC_INLINE int s_get_as_string(const ltc_asn1_list *value, char **str)
{
   char *work = NULL;
   size_t str_len;
   switch (value->type) {
      case LTC_ASN1_UTF8_STRING:
         str_len = wcstombs(NULL, value->data, 0);
         if (str_len == (size_t)-1) {
            /* In case `wcstombs()` can't decode the string, we
             * don't error out, but leave it up to the user.
             */
            break;
         }
         str_len++;
         work = XMALLOC(str_len);
         if (work == NULL)
            return CRYPT_MEM;
         str_len = wcstombs(work, value->data, str_len);
         if (str_len == (size_t)-1) {
            XFREE(work);
            return CRYPT_ERROR;
         }
         break;
      case LTC_ASN1_IA5_STRING:
      case LTC_ASN1_PRINTABLE_STRING:
      case LTC_ASN1_TELETEX_STRING:
         work = XMALLOC(value->size + 1);
         if (work == NULL)
            return CRYPT_MEM;
         XMEMCPY(work, value->data, value->size);
         work[value->size] = '\0';
         break;
      case LTC_ASN1_CUSTOM_TYPE:
         if (value->tag == LTC_ASN1_BMP_STRING) {
            /* We don't decode BMP Strings, but the user
             * is free to do so themselves.
             */
            break;
         }
         /* FALLTHROUGH */
      default:
         return CRYPT_INVALID_ARG;
   }
   *str = work;
   return CRYPT_OK;
}

static LTC_INLINE int s_get_name_element_by_oid(const ltc_asn1_list *oid, st_oid_detail *name_element)
{
   char oid_str[LTC_OID_MAX_STRLEN] = { 0 }, *str = NULL;
   unsigned long oid_str_len = sizeof(oid_str);
   ltc_asn1_list *value;
   const st_oid_detail *detail;
   static const st_oid_detail unknown_detail = { .detail = LTC_X509_UNKNOWN };
   int err;
   if (oid == NULL
         || oid->type != LTC_ASN1_OBJECT_IDENTIFIER
         || oid->next == NULL) {
      return CRYPT_PK_ASN1_ERROR;
   }
   value = oid->next;
   if ((err = pk_oid_num_to_str(oid->data, oid->size, oid_str, &oid_str_len)) != CRYPT_OK) {
      return err;
   }
   detail = s_get_name_element(oid_str);
   if (detail) {
      if (!(LTC_BIT(value->type) & detail->types))
         return CRYPT_PK_ASN1_ERROR;
      if (value->size > detail->upper_bound)
         return CRYPT_PK_ASN1_ERROR;
      if ((err = s_get_as_string(value, &str)) != CRYPT_OK) {
         return err;
      }
   } else {
      detail = &unknown_detail;
   }
   if (name_element) {
      ltc_x509_string *orig_str = name_element->str;
      orig_str->type = detail->detail;
      orig_str->asn1 = value;
      orig_str->str = str;
      *name_element = *detail;
      name_element->str = orig_str;
   }
   return CRYPT_OK;
}

static LTC_INLINE int s_x509_get_name_process(const ltc_asn1_list *set, st_oid_detail *name_elements, unsigned long name_elements_num)
{
   unsigned long num = 0;
   for (; set != NULL; set = set->next) {
      ltc_asn1_list *inner = set->child;
      int err;
      if (num >= name_elements_num) {
         return CRYPT_BUFFER_OVERFLOW;
      }
      if (set->type != LTC_ASN1_SET
            || inner == NULL
            || inner->type != LTC_ASN1_SEQUENCE) {
         return CRYPT_PK_ASN1_ERROR;
      }
      if ((err = s_get_name_element_by_oid(inner->child, &name_elements[num])) != CRYPT_OK) {
         return err;
      }
      num++;
   }
   return CRYPT_OK;
}

#ifndef S_FREE
#define S_FREE
#define s_free(p) s_free_((void*) p)
static LTC_INLINE void s_free_(void* p)
{
   if (p == NULL) {
      return;
   }
   XFREE((void*)p);
}
#endif

#ifndef S_FREE_X509_STRING_ARRAY
#define S_FREE_X509_STRING_ARRAY
#define s_free_x509_string_array(s, n) s_free_x509_string_array_((ltc_x509_string*)s, n)
static LTC_INLINE void s_free_x509_string_array_(ltc_x509_string *strings, unsigned long num)
{
   unsigned long n;
   for (n = num; n --> 0;) {
      s_free(strings[n].str);
   }
   s_free(strings);
}
#endif

#define SETBIT(v, n)    (v=((unsigned char)(v) | (1U << (unsigned char)(n))))
#define CLRBIT(v, n)    (v=((unsigned char)(v) & ~(1U << (unsigned char)(n))))

static LTC_INLINE int s_bit_string_to_raw_bit_string(const ltc_asn1_list *bs, unsigned char **out, unsigned long *outlen)
{
   unsigned char *r = bs->data, *w = XCALLOC((bs->size + 7) / 8, 1);
   unsigned long y;

   if (w == NULL) {
      return CRYPT_MEM;
   }

   /* decode/store the bits */
   for (y = 0; y < bs->size; y++) {
      if (r[y]) {
         SETBIT(w[y/8], 7-(y%8));
      } else {
         CLRBIT(w[y/8], 7-(y%8));
      }
   }

   *out = w;
   *outlen = bs->size;
   return CRYPT_OK;
}

static LTC_INLINE int s_x509_check_version(unsigned long version)
{
   /* RFC5280 Ch. 4.1
    *    Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
    * We only accept x.509v3 */
   if (version != 2) {
      return CRYPT_PK_ASN1_ERROR;
   }
   return CRYPT_OK;
}

static int s_x509_get_version(const ltc_asn1_list *seq, unsigned long *version)
{
   int err;
   ltc_asn1_list work[2];
   LTC_SET_ASN1_CUSTOM_CONSTRUCTED(work, 0, LTC_ASN1_CL_CONTEXT_SPECIFIC, 0, work + 1);
   LTC_SET_ASN1(work, 1, LTC_ASN1_SHORT_INTEGER, version,       1UL);
   if ((err = der_decode_custom_type(seq->data, seq->size, work)) != CRYPT_OK) {
      return err;
   }
   return s_x509_check_version(*version);
}

int x509_get_serial(const ltc_asn1_list *asn1, ltc_x509_string *serial)
{
   void *tmp;
   unsigned long len;
   int err;
   /* We're printing the serial number as hex string.
    * The length of the hex string is double the binary size + 3.
    * 3 comes from: eventually sign + reserve byte if value is 0 + terminating NUL byte.
    */
   len = ltc_mp_unsigned_bin_size(asn1->data) * 2 + 3;
   tmp = XMALLOC(len);
   if (tmp == NULL)
      return CRYPT_MEM;
   if ((err = ltc_mp_tohex(asn1->data, tmp)) != CRYPT_OK) {
      XFREE(tmp);
      return err;
   }
   serial->type = LTC_X509_SERIAL;
   serial->asn1 = asn1;
   serial->str = tmp;
   return CRYPT_OK;
}

static int s_x509_get_sig_alg(const ltc_asn1_list *seq, ltc_x509_signature_algorithm *sig_alg)
{
   int err;
   ltc_asn1_list fake_sig_parent = {0};

   fake_sig_parent.type = LTC_ASN1_SEQUENCE;
   fake_sig_parent.child = (ltc_asn1_list*)seq;

   if ((err = x509_get_sig_alg(&fake_sig_parent, sig_alg)) != CRYPT_OK) {
      return err;
   }
   if (sig_alg->pka == LTC_PKA_RSA_PSS && seq->child && seq->child->next) {
      if ((err = rsa_decode_pss_parameters(seq->child->next, &sig_alg->u.rsa_params)) != CRYPT_OK) {
         return err;
      }
   }
   sig_alg->asn1 = seq;
   return err;
}

/* Decode a Name according to RFC 5280
 *
 *    Name ::= CHOICE { -- only one possibility for now --
 *      rdnSequence  RDNSequence }
 *
 *    RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *    RelativeDistinguishedName ::=
 *      SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 *    AttributeTypeAndValue ::= SEQUENCE {
 *      type     AttributeType,
 *      value    AttributeValue }
 *
 *    AttributeType ::= OBJECT IDENTIFIER
 *
 *    AttributeValue ::= ANY -- DEFINED BY AttributeType
 */
static int s_x509_get_name(const ltc_asn1_list *seq, ltc_x509_name *name)
{
   ltc_asn1_list *set = seq->child;
   st_oid_detail *name_elements;
   ltc_x509_string *names;
   unsigned long n, names_num = 0;
   int err;
   for (; set != NULL && set->type != LTC_ASN1_EOL; set = set->next) {
      names_num++;
   }
   if (names_num == 0) {
      name->asn1 = seq;
      name->names = NULL;
      name->names_num = 0;
      return CRYPT_OK;
   }
   name_elements = XCALLOC(names_num, sizeof(*name_elements));
   if (name_elements == NULL) {
      return CRYPT_MEM;
   }
   names = XCALLOC(names_num, sizeof(*names));
   if (names == NULL) {
      err = CRYPT_MEM;
      goto err_out;
   }
   for (n = 0; n < names_num; ++n) {
      name_elements[n].str = &names[n];
   }
   if ((err = s_x509_get_name_process(seq->child, name_elements, names_num)) != CRYPT_OK) {
      goto err_out;
   }
   name->asn1 = seq;
   name->names = names;
   name->names_num = names_num;
err_out:
   if (err != CRYPT_OK) {
      s_free_x509_string_array(names, names_num);
   }
   XFREE(name_elements);
   return err;
}

/* Decode the Validity according to RFC 5280
 *
 *    Validity ::= SEQUENCE {
 *         notBefore      Time,
 *         notAfter       Time }
 *
 *    Time ::= CHOICE {
 *         utcTime        UTCTime,
 *         generalTime    GeneralizedTime }
 */

static int s_x509_get_validity(const ltc_asn1_list *seq, ltc_x509_validity *validity)
{
   int n, err, ret;
   ltc_asn1_list *source = seq->child;
   ltc_x509_time *value = &validity->not_before;
   validity->not_before.str = NULL;
   validity->not_after.str = NULL;
   for (n = 0; n < 2; ++n) {
      if (source == NULL) {
         err = CRYPT_PK_ASN1_ERROR;
         goto err_out;
      }
      if (source->type == LTC_ASN1_GENERALIZEDTIME) {
         ltc_generalizedtime *gt = source->data;
         value->utc = 0;
         value->u.generalized = gt;
         /* RFC5280 Ch. 4.1.2.5.2
          *    GeneralizedTime values MUST be expressed in Greenwich Mean Time [...]
          *    GeneralizedTime values MUST NOT include fractional seconds. */
         if (gt->off_hh || gt->off_mm || gt->fs) {
            err = CRYPT_PK_ASN1_ERROR;
            goto err_out;
         } else {
            void *str = XMALLOC(24);
            if (str == NULL) {
               err = CRYPT_MEM;
               goto err_out;
            }
            ret = snprintf(str, 24, "%04d-%02d-%02d %02d:%02d:%02dZ",
                               gt->YYYY, gt->MM, gt->DD, gt->hh, gt->mm, gt->ss);
            if (ret < 0 || ret >= 24) {
               err = CRYPT_ERROR;
               XFREE(str);
               goto err_out;
            }
            value->str = str;
            value->asn1 = source;
         }
      } else if (source->type == LTC_ASN1_UTCTIME) {
         ltc_utctime* ut = source->data;
         value->utc = 1;
         value->u.utc = ut;
         /* RFC5280 Ch. 4.1.2.5.1
          *    UTCTime values MUST be expressed in Greenwich Mean Time */
         if (ut->off_hh || ut->off_mm) {
            err = CRYPT_PK_ASN1_ERROR;
            goto err_out;
         } else {
            const char *YY;
            void *str = XMALLOC(24);
            if (str == NULL) {
               err = CRYPT_MEM;
               goto err_out;
            }
            /* Let's hope this software is not used after 2049...
             * RFC5280 Ch. 4.1.2.5.1
             *    Where YY is greater than or equal to 50, the year SHALL be
             *    interpreted as 19YY; and
             *
             *    Where YY is less than 50, the year SHALL be interpreted as 20YY.
             */
            YY = ut->YY >= 50 ? "19" : "20";
            ret = snprintf(str, 24, "%s%02d-%02d-%02d %02d:%02d:%02dZ",
                               YY, ut->YY, ut->MM, ut->DD, ut->hh, ut->mm, ut->ss);
            if (ret < 0 || ret >= 24) {
               err = CRYPT_ERROR;
               XFREE(str);
               goto err_out;
            }
            value->str = str;
            value->asn1 = source;
         }
      } else {
         err = CRYPT_PK_ASN1_ERROR;
         goto err_out;
      }
      source = source->next;
      value = &validity->not_after;
   }
   return CRYPT_OK;
err_out:
   if (validity->not_after.str) {
      s_free(validity->not_after.str);
      validity->not_after.str = NULL;
   }
   if (validity->not_before.str) {
      s_free(validity->not_before.str);
      validity->not_before.str = NULL;
   }
   return err;
}

static int s_x509_check_spki(const ltc_asn1_list *seq, const ltc_pka_key *spki)
{
   LTC_UNUSED_PARAM(seq);
   if (spki->id > LTC_PKA_UNDEF && spki->id < LTC_PKA_NUM) {
      return CRYPT_OK;
   }
   return CRYPT_PK_INVALID_TYPE;
}

#ifndef S_IS_CONTEXT_SPECIFIC
#define S_IS_CONTEXT_SPECIFIC
static LTC_INLINE int s_is_context_specific(const ltc_asn1_list *seq)
{
   if (seq->type != LTC_ASN1_CUSTOM_TYPE)
      return 0;
   if (seq->klass != LTC_ASN1_CL_CONTEXT_SPECIFIC)
      return 0;
   return 1;
}
#endif

#ifndef S_IS_CONTEXT_SPECIFIC_PRIMITIVE
#define S_IS_CONTEXT_SPECIFIC_PRIMITIVE
static LTC_INLINE int s_is_context_specific_primitive(const ltc_asn1_list *seq)
{
   if (!s_is_context_specific(seq))
      return 0;
   if (seq->pc != LTC_ASN1_PC_PRIMITIVE)
      return 0;
   return 1;
}
#endif

static LTC_INLINE int s_is_context_specific_constructed(const ltc_asn1_list *seq)
{
   if (!s_is_context_specific(seq))
      return 0;
   if (seq->pc != LTC_ASN1_PC_CONSTRUCTED)
      return 0;
   return 1;
}

static int s_x509_get_optionals(const ltc_asn1_list *seq, ltc_x509_tbs_certificate *tbs_cert)
{
   switch (seq->tag) {
      /* Context specific tags [1] and [2] are of type UniqueIdentifier
       *
       * RFC5280 Ch. 4.1.2.8.  Unique Identifiers
       *    [...] Applications conforming to
       *    this profile SHOULD be capable of parsing certificates that include
       *    unique identifiers, but there are no processing requirements
       *    associated with the unique identifiers.
       *
       * Good luck decoding them yourself :)
       */
      case 1:
         if (!s_is_context_specific_primitive(seq))
            return CRYPT_PK_ASN1_ERROR;
         tbs_cert->issuer_uid = seq;
         return CRYPT_OK;
      case 2:
         if (!s_is_context_specific_primitive(seq))
            return CRYPT_PK_ASN1_ERROR;
         tbs_cert->subject_uid = seq;
         return CRYPT_OK;
      case 3:
         if (!s_is_context_specific_constructed(seq))
            return CRYPT_PK_ASN1_ERROR;
         return x509_get_extensions(seq->child, &tbs_cert->extensions);
      default:
         return CRYPT_PK_ASN1_ERROR;
   }
   return CRYPT_PK_ASN1_ERROR;
}

/* Decode a TBSCertificate according to RFC 5280
 *
 *  TBSCertificate  ::=  SEQUENCE  {
 *       version         [0]  EXPLICIT Version DEFAULT v1,
 *       serialNumber         CertificateSerialNumber,
 *       signature            AlgorithmIdentifier,
 *       issuer               Name,
 *       validity             Validity,
 *       subject              Name,
 *       subjectPublicKeyInfo SubjectPublicKeyInfo,
 *       issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                            -- If present, version MUST be v2 or v3
 *       subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                            -- If present, version MUST be v2 or v3
 *       extensions      [3]  EXPLICIT Extensions OPTIONAL
 *                            -- If present, version MUST be v3
 *       }
 */
static int s_x509_import_tbs_certificate(const ltc_asn1_list *asn1, ltc_x509_tbs_certificate *tbs_cert)
{
   int err;
   der_flexi_check flexi_should[11];
   LTC_SET_DER_FLEXI_HANDLER_OPT(flexi_should, 0, LTC_ASN1_CUSTOM_TYPE, s_x509_get_version, &tbs_cert->version);
   LTC_SET_DER_FLEXI_HANDLER(flexi_should, 1, LTC_ASN1_INTEGER, x509_get_serial, &tbs_cert->serial_number);
   LTC_SET_DER_FLEXI_HANDLER(flexi_should, 2, LTC_ASN1_SEQUENCE, s_x509_get_sig_alg, &tbs_cert->signature_algorithm);
   LTC_SET_DER_FLEXI_HANDLER(flexi_should, 3, LTC_ASN1_SEQUENCE, s_x509_get_name, &tbs_cert->issuer);
   LTC_SET_DER_FLEXI_HANDLER(flexi_should, 4, LTC_ASN1_SEQUENCE, s_x509_get_validity, &tbs_cert->validity);
   LTC_SET_DER_FLEXI_HANDLER(flexi_should, 5, LTC_ASN1_SEQUENCE, s_x509_get_name, &tbs_cert->subject);
   LTC_SET_DER_FLEXI_HANDLER(flexi_should, 6, LTC_ASN1_SEQUENCE, s_x509_check_spki, &tbs_cert->subject_public_key_info);
   LTC_SET_DER_FLEXI_HANDLER_OPT(flexi_should, 7, LTC_ASN1_CUSTOM_TYPE, s_x509_get_optionals, tbs_cert);
   LTC_SET_DER_FLEXI_HANDLER_OPT(flexi_should, 8, LTC_ASN1_CUSTOM_TYPE, s_x509_get_optionals, tbs_cert);
   LTC_SET_DER_FLEXI_HANDLER_OPT(flexi_should, 9, LTC_ASN1_CUSTOM_TYPE, s_x509_get_optionals, tbs_cert);
   LTC_SET_DER_FLEXI_CHECK(flexi_should, 10, LTC_ASN1_EOL, NULL);
   if ((err = der_flexi_sequence_cmp(asn1, flexi_should)) == CRYPT_OK) {
      tbs_cert->asn1 = asn1;
      err = s_x509_check_version(tbs_cert->version);
   }
   return err;
}

/**
  Import an X.509 certificate from ASN.1 DER-encoded data.

  @param asn1_cert   Pointer to the ASN.1 DER-encoded data.
  @param asn1_len    Length of the ASN.1 DER-encoded data.
  @param out         The resulting X.509 certificate.
  @return CRYPT_OK if successful.
*/
int x509_import(const unsigned char *asn1_cert, unsigned long asn1_len, const ltc_x509_certificate **out)
{
   ltc_x509_certificate *cert;
   ltc_asn1_list *root, *tbs_cert, *sig_alg, *sig;
   int err;
   cert = XCALLOC(1, sizeof(*cert));
   if (cert == NULL) {
      return CRYPT_MEM;
   }
   if ((err = x509_import_spki(asn1_cert, asn1_len, &cert->tbs_certificate.subject_public_key_info, &root)) != CRYPT_OK) {
      goto err_out;
   }

   tbs_cert = root->child;
   if (tbs_cert == NULL || tbs_cert->next == NULL || tbs_cert->next->next == NULL) {
      err = CRYPT_PK_ASN1_ERROR;
      goto err_out;
   }
   sig_alg = tbs_cert->next;
   sig = sig_alg->next;
   cert->signature.asn1 = sig;
   cert->asn1 = root;

   if ((err = s_x509_import_tbs_certificate(tbs_cert, &cert->tbs_certificate)) != CRYPT_OK) {
      goto err_out;
   }

   if ((err = s_x509_get_sig_alg(sig_alg, &cert->signature_algorithm)) != CRYPT_OK) {
      goto err_out;
   }
   if ((err = s_bit_string_to_raw_bit_string(sig, (unsigned char**)&cert->signature.signature, &cert->signature.signature_len)) != CRYPT_OK) {
      goto err_out;
   }
   *out = cert;
   return err;
err_out:
   x509_free((const ltc_x509_certificate **)&cert);
   return err;
}

#ifdef LTC_PEM
extern const struct pem_header_id pem_std_headers[];

static int s_x509_import_pem(struct get_char *g, unsigned long *pem_len, const ltc_x509_certificate **out)
{
   int err;
   struct pem_headers hdr = { .id = &pem_std_headers[0] };
   unsigned long len = 0;
   unsigned char *asn1_cert = NULL;
   if ((err = pem_read((void**)&asn1_cert, &len, &hdr, g)) != CRYPT_OK) {
      return err;
   }

   err = x509_import(asn1_cert, len, out);

   *pem_len = g->total_read;

   XFREE(asn1_cert);

   return err;
}

/**
  Import an X.509 certificate from PEM-encoded data.

  @param pem         Pointer to the PEM-encoded data.
  @param pem_len     [in] Length of the PEM-encoded data.
                     [out] The length of the data used.
  @param out         The resulting X.509 certificate.
  @return CRYPT_OK if successful.
*/
int x509_import_pem(const char *pem, unsigned long *pem_len, const ltc_x509_certificate **out)
{
   struct get_char g = pem_get_char_init(pem, *pem_len);
   return s_x509_import_pem(&g, pem_len, out);
}

#ifndef LTC_NO_FILE
/**
  Import an X.509 certificate from PEM-encoded data from a FILE handle.

  @param f     The FILE handle.
  @param out   The resulting X.509 certificate.
  @return CRYPT_OK if successful.
*/
int x509_import_pem_filehandle(FILE *f, const ltc_x509_certificate **out)
{
   unsigned long pem_len;
   struct get_char g = pem_get_char_init_filehandle(f);
   return s_x509_import_pem(&g, &pem_len, out);
}
#endif /* LTC_NO_FILE */
#endif /* LTC_PEM */

static void s_free_x509_name(const ltc_x509_name *name)
{
   s_free_x509_string_array(name->names, name->names_num);
}

static void s_free_x509_tbs_cert(const ltc_x509_tbs_certificate *tbs_cert)
{
   x509_free_extensions(&tbs_cert->extensions);
   s_free_x509_name(&tbs_cert->subject);
   s_free(tbs_cert->validity.not_after.str);
   s_free(tbs_cert->validity.not_before.str);
   s_free_x509_name(&tbs_cert->issuer);
   s_free(tbs_cert->serial_number.str);
   pka_key_free((void*)&tbs_cert->subject_public_key_info);
}

/**
  Free an X.509 certificate from memory

  @param cert   The X.509 certificate to free.
*/
void x509_free(const ltc_x509_certificate **cert)
{
   const ltc_x509_certificate *c;
   LTC_ARGCHKVD(cert != NULL);
   c = *cert;
   LTC_ARGCHKVD(c != NULL);
   s_free(c->signature.signature);
   s_free_x509_tbs_cert(&c->tbs_certificate);
   der_free_sequence_flexi((void*)c->asn1);
   s_free(c);
   *cert = NULL;
}

#undef st_oid_detail

#endif /* LTC_DER */
