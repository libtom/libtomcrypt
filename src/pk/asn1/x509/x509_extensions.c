/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file x509_extensions.c
  Extensions part of an X.509 cert, Steffen Jaeckel
*/

#ifdef LTC_DER

#define OID_DETAIL_ELEMENT_VA(d, n, ...) { .detail = d, .node = # n, __VA_ARGS__ }

#define st_oid_detail st_x509_extension_oid_detail

typedef struct st_oid_detail {
   ltc_x509_details detail;
   const char *node;
   union {
      struct {
         ltc_asn1_type type;
         der_flexi_handler handler;
      } ce;
      struct {
         ulong32 bit;
      } eku;
   } u;
   ltc_x509_string *str;
} st_oid_detail;

static LTC_INLINE int s_get_element_(const st_oid_detail* details, unsigned long num, const char *arc, unsigned long arclen, const ltc_asn1_list *oid, const st_oid_detail **result)
{
   char oid_str[LTC_OID_MAX_STRLEN] = { 0 };
   unsigned long i, oid_str_len = sizeof(oid_str);
   const char *node;
   int err;
   *result = NULL;
   if (oid->type != LTC_ASN1_OBJECT_IDENTIFIER) {
      return CRYPT_INVALID_PACKET;
   }
   if ((err = pk_oid_num_to_str(oid->data, oid->size, oid_str, &oid_str_len)) != CRYPT_OK) {
      return err;
   }
   if (XMEMCMP(oid_str, arc, arclen)) {
      return CRYPT_OK;
   }
   node = oid_str + arclen;
   if (*node != '.') {
      return CRYPT_INVALID_PACKET;
   }
   node++;
   for (i = 0; i < num; ++i) {
      if (XSTRCMP(node, details[i].node) == 0) {
         *result = &details[i];
         break;
      }
   }
   return CRYPT_OK;
}
#define s_get_element(arr, arc, oid, res) s_get_element_(arr, LTC_ARRAY_SIZE(arr), arc, sizeof(arc) - 1, oid, res)


#ifndef S_FREE
#define S_FREE
#define s_free(p) s_free_((void*) p)
static LTC_INLINE void s_free_(void* p)
{
   if (p == NULL) {
      return;
   }
   XFREE(p);
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

static LTC_INLINE int s_looks_like_general_name(const ltc_asn1_list *name)
{
   if (!s_is_context_specific(name)
         || (name->pc == LTC_ASN1_PC_PRIMITIVE && name->tag > 8))
      return CRYPT_PK_ASN1_ERROR;
   return CRYPT_OK;
}

typedef unsigned short int ushort16;
#define LTC_NTOHS(y)  ( ((ushort16)((y)[0] & 255)<<8) | ((ushort16)((y)[1] & 255)) )

/* RFC 5280, Ch. 4.2.1.6.  Subject Alternative Name
 *    [...]
 *    GeneralName ::= CHOICE {
 *         otherName                       [0]     OtherName,
 *         rfc822Name                      [1]     IA5String,
 *         dNSName                         [2]     IA5String,
 *         x400Address                     [3]     ORAddress,
 *         directoryName                   [4]     Name,
 *         ediPartyName                    [5]     EDIPartyName,
 *         uniformResourceIdentifier       [6]     IA5String,
 *         iPAddress                       [7]     OCTET STRING,
 *         registeredID                    [8]     OBJECT IDENTIFIER }
 *
 *    OtherName ::= SEQUENCE {
 *         type-id    OBJECT IDENTIFIER,
 *         value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 *    EDIPartyName ::= SEQUENCE {
 *         nameAssigner            [0]     DirectoryString OPTIONAL,
 *         partyName               [1]     DirectoryString }
 */
static int s_get_general_name(const ltc_asn1_list *seq, ltc_x509_string *name)
{
   int err = CRYPT_OK;
   char *str = NULL;
   unsigned long len;

   switch (seq->tag) {
      case 1:
      case 2:
      case 6:
         len = seq->size + 1;
         str = XMALLOC(len);
         if (str == NULL) {
            err = CRYPT_MEM;
            break;
         }
         if ((err = der_decode_ia5_string_data(seq->data, seq->size, str, &len)) != CRYPT_OK) {
            break;
         }
         str[len] = '\0';
         break;
      case 7:
      {
         int nbytes;
         unsigned char *ip = seq->data;
         if (seq->size == 4) {
            str = XMALLOC(4 * 4);
            if (str == NULL) {
               err = CRYPT_MEM;
               break;
            }
            nbytes = snprintf(str, 16, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
            if (nbytes < 0) {
               err = CRYPT_ERROR;
            }
         } else if (seq->size == 16) {
            str = XMALLOC(8 * 5);
            if (str == NULL) {
               err = CRYPT_MEM;
               break;
            }
            nbytes = snprintf(str, 40, "%x:%x:%x:%x:%x:%x:%x:%x", LTC_NTOHS(&ip[0]),  LTC_NTOHS(&ip[2]),
                                                                  LTC_NTOHS(&ip[4]),  LTC_NTOHS(&ip[6]),
                                                                  LTC_NTOHS(&ip[8]),  LTC_NTOHS(&ip[10]),
                                                                  LTC_NTOHS(&ip[12]), LTC_NTOHS(&ip[14]));
            if (nbytes < 0) {
               err = CRYPT_ERROR;
            }
         } else {
            err = CRYPT_PK_ASN1_ERROR;
         }
      }
         break;
      case 8:
      {
         unsigned long oid[LTC_DER_OID_DEFAULT_NODES], oid_len = LTC_DER_OID_DEFAULT_NODES;
         if ((err = der_decode_object_identifier_data(seq->data, seq->size, oid, &oid_len)) != CRYPT_OK) {
            break;
         }
         if ((err = pk_oid_num_to_str(oid, oid_len, NULL, &len)) != CRYPT_BUFFER_OVERFLOW) {
            break;
         }
         str = XMALLOC(len);
         if (str == NULL) {
            err = CRYPT_MEM;
            break;
         }
         err = pk_oid_num_to_str(oid, oid_len, str, &len);
      }
         break;
      case 0:
      case 3:
      case 4:
      case 5:
         break;
      default:
         err = CRYPT_PK_ASN1_ERROR;
         break;
   }
   if (err != CRYPT_OK) {
      if (str != NULL) {
         XFREE(str);
         str = NULL;
      }
      return err;
   }
   name->type = LTC_X509_OTHER_NAME + seq->tag;
   name->asn1 = seq;
   name->str = str;

   return err;
}

static int s_octet_string_to_hex_string(const ltc_asn1_list *asn1, ltc_x509_string *hex)
{
   unsigned long len;
   char *str;
   int err;
   len = asn1->size * 2 + 1;
   str = XMALLOC(len);
   if (str == NULL) {
      return CRYPT_MEM;
   }
   if ((err = base16_encode(asn1->data, asn1->size, str, &len, 1)) != CRYPT_OK) {
      XFREE(str);
      return err;
   }
   hex->asn1 = asn1;
   hex->str = str;
   hex->type = LTC_X509_OCTET_STRING;
   return CRYPT_OK;
}

/* RFC 5280, Ch. 4.2.1.1.  Authority Key Identifier
 *    AuthorityKeyIdentifier ::= SEQUENCE {
 *       keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *       authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *       authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
 *
 *    KeyIdentifier ::= OCTET STRING
 */
static int s_get_aki(const ltc_asn1_list *seq, ltc_x509_extension *san)
{
   int err;
   ltc_asn1_list *element = seq->child;
   while(element && s_is_context_specific_primitive(element)) {
      switch (element->tag) {
         case 0:
            if ((err = s_octet_string_to_hex_string(element, &san->u.authority_key_id.key_identifier)) != CRYPT_OK) {
               return err;
            }
            break;
         case 1:
            if ((err = s_looks_like_general_name(element->child)) != CRYPT_OK) {
               return err;
            }
            if ((err = s_get_general_name(element->child, &san->u.authority_key_id.authority_cert_issuer)) != CRYPT_OK) {
               return err;
            }
            break;
         case 2:
            if ((err = x509_get_serial(element->child, &san->u.authority_key_id.authority_cert_serial_number)) != CRYPT_OK) {
               return err;
            }
            break;
         default:
            return CRYPT_PK_ASN1_ERROR;
      }
      element = element->next;
   }
   return CRYPT_OK;
}

/* RFC 5280, Ch. 4.2.1.2.  Subject Key Identifier
 *    SubjectKeyIdentifier ::= KeyIdentifier
 *
 *    KeyIdentifier ::= OCTET STRING
 */
static int s_get_ski(const ltc_asn1_list *seq, ltc_x509_extension *san)
{
   void *buf;
   unsigned long len, outlen;
   int err;
   if (seq->type != LTC_ASN1_OCTET_STRING) {
      return CRYPT_PK_ASN1_ERROR;
   }
   /* `size` still contains the ASN.1 header and length, so we're safe length-wise */
   len = seq->size * 2;
   buf = XMALLOC(len);
   if (buf == NULL) {
      return CRYPT_MEM;
   }
   outlen = len;
   if ((err = der_decode_octet_string(seq->data, seq->size, buf, &outlen)) != CRYPT_OK) {
      XFREE(buf);
      return err;
   }
   if ((err = base16_encode(buf, outlen, buf, &len, 1)) != CRYPT_OK) {
      XFREE(buf);
      return err;
   }
   san->u.subject_key_identifier.asn1 = seq;
   san->u.subject_key_identifier.str = buf;
   san->u.subject_key_identifier.type = LTC_X509_OCTET_STRING;
   return err;
}

/* RFC 5280, Ch. 4.2.1.3.  Key Usage
 *    KeyUsage ::= BIT STRING {
 *         digitalSignature        (0),
 *         [...]
 *         decipherOnly            (8) }
 */
static int s_get_ku(const ltc_asn1_list *bitstr, ltc_x509_extension *eku)
{
   unsigned char ku[9];
   unsigned long n, kulen = sizeof(ku);
   int err;
   eku->u.key_usage = 0;
   if ((err = der_decode_bit_string(bitstr->data, bitstr->size, ku, &kulen)) != CRYPT_OK) {
      return err;
   }
   for (n = 0; n < kulen; ++n) {
      eku->u.key_usage |= ku[n] ? (1 << n) : 0;
   }
   return err;
}

/* RFC 5280, Ch. 4.2.1.9.  Basic Constraints
 *    BasicConstraints ::= SEQUENCE {
 *       cA                      BOOLEAN DEFAULT FALSE,
 *       pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 */
static int s_get_bc(const ltc_asn1_list *seq, ltc_x509_extension *bc)
{
   ltc_asn1_list *element = seq->child;
   bc->u.basic_constraints.ca = 0;
   bc->u.basic_constraints.path_len = -1;
   if (element == NULL || element->type == LTC_ASN1_EOL)
      return CRYPT_OK;
   if (element->type == LTC_ASN1_BOOLEAN) {
      bc->u.basic_constraints.ca = *(int*)element->data ? 1 : 0;
      element = element->next;
   }
   if (element == NULL)
      return CRYPT_OK;
   if (element->type == LTC_ASN1_INTEGER) {
      if (ltc_mp_count_bits(element->data) > (int)((sizeof(bc->u.basic_constraints.path_len) * CHAR_BIT) - 1))
         return CRYPT_OVERFLOW;
      bc->u.basic_constraints.path_len = (int)ltc_mp_get_int(element->data);
   }
   return CRYPT_OK;
}

/* RFC 5280, Ch. 4.2.1.12.  Extended Key Usage
 *    id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
 *    ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *    KeyPurposeId ::= OBJECT IDENTIFIER
 */

#define X509_EKU_ELEMENT(detail, node, type) OID_DETAIL_ELEMENT_VA(detail, node, .u.eku.bit = type)

/* anyExtendedKeyUsage is allocated under the id-ce-extKeyUsage arc
 *
 * anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
 */
static const char x509_eku_arc[] = "2.5.29.37";
static const st_oid_detail eku_any_map[] = {
                       X509_EKU_ELEMENT(LTC_X509_CE_EXT_KEY_USAGE, 0, LTC_EKU_ANY),
};

/* all other key purpose OID's are allocated under the id-pkix arc
 *
 * id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
 */
static const char x509_kp_arc[] = "1.3.6.1.5.5.7.3";
static const st_oid_detail eku_elements_map[] = {
                       X509_EKU_ELEMENT(LTC_X509_CE_EXT_KEY_USAGE, 1, LTC_EKU_SA),
                       X509_EKU_ELEMENT(LTC_X509_CE_EXT_KEY_USAGE, 2, LTC_EKU_CA),
                       X509_EKU_ELEMENT(LTC_X509_CE_EXT_KEY_USAGE, 3, LTC_EKU_CS),
                       X509_EKU_ELEMENT(LTC_X509_CE_EXT_KEY_USAGE, 4, LTC_EKU_EP),
                       X509_EKU_ELEMENT(LTC_X509_CE_EXT_KEY_USAGE, 8, LTC_EKU_TS),
                       X509_EKU_ELEMENT(LTC_X509_CE_EXT_KEY_USAGE, 9, LTC_EKU_OS),
};

static int s_get_eku(const ltc_asn1_list *seq, ltc_x509_extension *eku)
{
   int err = CRYPT_INVALID_PACKET;
   ltc_asn1_list *oid = seq->child;
   eku->u.ext_key_usage = 0;
   while (oid) {
      const st_oid_detail *ce = NULL;
      err = s_get_element(eku_any_map, x509_eku_arc, oid, &ce);
      if (err == CRYPT_OK && ce) {
         eku->u.ext_key_usage |= ce->u.eku.bit;
         oid = oid->next;
         continue;
      } else if (err != CRYPT_OK) {
         break;
      }
      err = s_get_element(eku_elements_map, x509_kp_arc, oid, &ce);
      if (err == CRYPT_OK && ce) {
         eku->u.ext_key_usage |= ce->u.eku.bit;
      } else if (err != CRYPT_OK) {
         break;
      }
      oid = oid->next;
   }
   if (eku->u.ext_key_usage == 0) {
      err = CRYPT_INVALID_PACKET;
   }
   return err;
}

/* RFC 5280, Ch. 4.2.1.6.  Subject Alternative Name
 *    SubjectAltName ::= GeneralNames
 *
 *    GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 */
static int s_get_san(const ltc_asn1_list *seq, ltc_x509_extension *san)
{
   int err = CRYPT_PK_ASN1_ERROR;
   ltc_x509_string *names;
   unsigned long num = 0, cur = 0;
   ltc_asn1_list *name = seq->child;

   while (name) {
      if ((err = s_looks_like_general_name(name)) != CRYPT_OK) {
         return err;
      }
      num++;
      name = name->next;
   }

   names = XCALLOC(num, sizeof(*names));
   if (names == NULL) {
      return CRYPT_MEM;
   }
   name = seq->child;

   while (name && cur < num) {
      if ((err = s_get_general_name(name, &names[cur])) != CRYPT_OK) {
         break;
      }
      name = name->next;
      cur++;
   }
   if (err == CRYPT_OK) {
      san->u.subject_alt_name.asn1 = seq;
      san->u.subject_alt_name.names = names;
      san->u.subject_alt_name.names_num = num;
   } else {
      s_free_x509_string_array(names, num);
   }
   return err;
}

#define X509_CE_ELEMENT(detail, oid, type_, hndl) OID_DETAIL_ELEMENT_VA(detail, oid, .u.ce.type = type_, .u.ce.handler = (der_flexi_handler)hndl)

/* The certificate extension OID's arc is defined as follows
 *
 * id-ce   OBJECT IDENTIFIER ::=  { joint-iso-ccitt(2) ds(5) 29 }
 */
static const char x509_ce_arc[] = "2.5.29";
static const st_oid_detail ce_elements_map[] = {
                       X509_CE_ELEMENT(LTC_X509_CE_AUTHORITY_KEY_ID,  35, LTC_ASN1_SEQUENCE, s_get_aki),
                       X509_CE_ELEMENT(LTC_X509_CE_SUBJECT_KEY_ID,    14, LTC_ASN1_OCTET_STRING, s_get_ski),
                       X509_CE_ELEMENT(LTC_X509_CE_KEY_USAGE,         15, LTC_ASN1_BIT_STRING, s_get_ku),
                       X509_CE_ELEMENT(LTC_X509_CE_SUBJECT_ALT_NAME,  17, LTC_ASN1_SEQUENCE, s_get_san),
                       X509_CE_ELEMENT(LTC_X509_CE_BASIC_CONSTRAINTS, 19, LTC_ASN1_SEQUENCE, s_get_bc),
                       X509_CE_ELEMENT(LTC_X509_CE_EXT_KEY_USAGE,     37, LTC_ASN1_SEQUENCE, s_get_eku),
};

typedef struct st_ce_value {
   const st_oid_detail* ce;
   ltc_asn1_list *crit;
   ltc_x509_extension value;
} st_ce_value;

static int s_get_ce_element(const ltc_asn1_list *oid, st_ce_value *ce)
{
   int err = s_get_element(ce_elements_map, x509_ce_arc, oid, &ce->ce);
   ce->value.oid = (err == CRYPT_OK) ? oid : NULL;
   return err;
}

static int s_get_ce_value(const ltc_asn1_list *os, st_ce_value *ce)
{
   int err = CRYPT_OK;
   ce->value.asn1 = os;
   if (ce->ce == NULL) {
      ce->value.type = LTC_X509_UNKNOWN;
      return CRYPT_OK;
   }
   if (ce->ce->u.ce.type == LTC_ASN1_SEQUENCE) {
      ltc_asn1_list *value;
      unsigned long len = os->size;
      if ((err = der_decode_sequence_flexi_limited(os->data, &len, 2, &value)) != CRYPT_OK) {
         return err;
      }
      if (value->type != LTC_ASN1_SEQUENCE) {
         der_free_sequence_flexi(value);
         return CRYPT_INVALID_PACKET;
      } else {
         err = ce->ce->u.ce.handler(value, &ce->value);
      }
      if (err != CRYPT_OK) {
         der_free_sequence_flexi(value);
         return err;
      }
      /* store the flexi tree root so it can be freed in s_free_extension, handlers store pointers into this tree */
      ce->value.asn1 = value;
   } else {
      err = ce->ce->u.ce.handler(os, &ce->value);
   }
   if (err == CRYPT_OK) {
      ce->value.type = ce->ce->detail;
   }
   return err;
}

static LTC_INLINE void s_free_extension(const ltc_x509_extension *ext)
{
   switch (ext->type) {
      case LTC_X509_CE_AUTHORITY_KEY_ID:
         s_free(ext->u.authority_key_id.key_identifier.str);
         s_free(ext->u.authority_key_id.authority_cert_issuer.str);
         s_free(ext->u.authority_key_id.authority_cert_serial_number.str);
         der_free_sequence_flexi((void*)ext->asn1);
         break;
      case LTC_X509_CE_SUBJECT_KEY_ID:
         s_free(ext->u.subject_key_identifier.str);
         break;
      case LTC_X509_CE_SUBJECT_ALT_NAME:
         s_free_x509_string_array(ext->u.subject_alt_name.names, ext->u.subject_alt_name.names_num);
         der_free_sequence_flexi((void*)ext->asn1);
         break;
      case LTC_X509_CE_BASIC_CONSTRAINTS:
      case LTC_X509_CE_EXT_KEY_USAGE:
         der_free_sequence_flexi((void*)ext->asn1);
         break;
      case LTC_X509_CE_KEY_USAGE:
      default:
         break;
   }
}

static LTC_INLINE void s_free_extensions(const ltc_x509_extension *extensions, unsigned long num)
{
   unsigned long n;
   for (n = num; n --> 0;) {
      s_free_extension(&extensions[n]);
   }
   s_free(extensions);
}

void x509_free_extensions(const ltc_x509_extensions *extensions)
{
   s_free_extensions(extensions->extensions, extensions->extensions_num);
}

int x509_get_extensions(const ltc_asn1_list *seq, ltc_x509_extensions *extensions)
{
   ltc_x509_extension *extensions_;
   unsigned long extensions_num = 0;
   ltc_asn1_list *cur;
   unsigned long cur_num = 0;
   int err;
   if (seq->type != LTC_ASN1_SEQUENCE)
      return CRYPT_INVALID_PACKET;
   cur = seq->child;
   while (cur) {
      extensions_num++;
      cur = cur->next;
   }
   extensions_ = XCALLOC(extensions_num, sizeof(*extensions->extensions));
   if (extensions_ == NULL) {
      return CRYPT_MEM;
   }
   cur = seq->child;
   while (cur) {
      st_ce_value val = {0};
      der_flexi_check flexi_should[4];
      if (cur_num >= extensions_num) {
         err = CRYPT_ERROR;
         goto error_out;
      }
      LTC_SET_DER_FLEXI_HANDLER(flexi_should, 0, LTC_ASN1_OBJECT_IDENTIFIER, s_get_ce_element, &val);
      LTC_SET_DER_FLEXI_CHECK_OPT(flexi_should, 1, LTC_ASN1_BOOLEAN, &val.crit);
      LTC_SET_DER_FLEXI_HANDLER(flexi_should, 2, LTC_ASN1_OCTET_STRING, s_get_ce_value, &val);
      LTC_SET_DER_FLEXI_CHECK(flexi_should, 3, LTC_ASN1_EOL, NULL);
      if ((err = der_flexi_sequence_cmp(cur, flexi_should)) != CRYPT_OK) {
         goto error_out;
      }
      extensions_[cur_num] = val.value;
      if (val.crit) {
         extensions_[cur_num].critical = *(int*)val.crit->data;
      }
      cur_num++;
      cur = cur->next;
   }
   for (cur_num = 0; cur_num < extensions_num; ++cur_num) {
      switch (extensions_[cur_num].type) {
         case LTC_X509_CE_AUTHORITY_KEY_ID:
            extensions->authority_key_id = &extensions_[cur_num];
            break;
         case LTC_X509_CE_SUBJECT_KEY_ID:
            extensions->subject_key_identifier = &extensions_[cur_num];
            break;
         case LTC_X509_CE_KEY_USAGE:
            extensions->key_usage = &extensions_[cur_num];
            break;
         case LTC_X509_CE_SUBJECT_ALT_NAME:
            extensions->subject_alt_name = &extensions_[cur_num];
            break;
         case LTC_X509_CE_BASIC_CONSTRAINTS:
            extensions->basic_constraints = &extensions_[cur_num];
            break;
         case LTC_X509_CE_EXT_KEY_USAGE:
            extensions->ext_key_usage = &extensions_[cur_num];
            break;
         default:
            break;
      }
   }
   extensions->asn1 = seq;
   extensions->extensions = extensions_;
   extensions->extensions_num = cur_num;
   return CRYPT_OK;
error_out:
   s_free_extensions(extensions_, extensions_num);
   return err;
}

#undef st_oid_detail

#endif
