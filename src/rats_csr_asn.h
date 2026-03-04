/*-
 * @file   src/rats_csr_asn.h
 * @brief  Local ASN.1 types for AttestationBundle
 *         (draft-ietf-lamps-csr-attestation-23).
 *
 * These are temporary stand-ins until OSSL_CSR_ATTESTATION_STATEMENT and
 * OSSL_CSR_ATTESTATION_BUNDLE are added to crypto/crmf/crmf_asn.c in the
 * Guiliano99/openssl fork.  Once the fork provides those types, replace
 * LOCAL_ATT_STMT / LOCAL_ATT_BUNDLE with the upstream definitions.
 *
 * Encoded structure (draft-ietf-lamps-csr-attestation-23 §4,
 *   pending PR #236 which removes bindsPublicKey and attrs):
 *
 *   AttestationStatement ::= SEQUENCE {
 *       type  ATTESTATION-STATEMENT.&id,   -- OID
 *       stmt  ATTESTATION-STATEMENT.&Type  -- ANY, typed by OID
 *   }
 *   AttestationBundle ::= SEQUENCE {
 *       attestations  SEQUENCE SIZE (1..MAX) OF AttestationStatement,
 *       certs         SEQUENCE SIZE (1..MAX) OF LimitedCertChoices OPTIONAL
 *   }
 *
 * stmt: ASN1_TYPE (ANY) — currently wraps the ATG token as V_ASN1_OCTET_STRING
 *       pending allocation of a real format OID.
 * certs: STACK_OF(X509) — OPTIONAL; NULL means omitted.
 *        Only the `certificate` arm of LimitedCertChoices is supported for now.
 */

#ifndef RATS_CSR_ASN_H
#define RATS_CSR_ASN_H

#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

typedef struct local_att_stmt_st {
    ASN1_OBJECT  *type;
    ASN1_TYPE    *stmt; /* ANY — typed by type OID */
} LOCAL_ATT_STMT;

DECLARE_ASN1_FUNCTIONS(LOCAL_ATT_STMT)
DEFINE_STACK_OF(LOCAL_ATT_STMT)

typedef struct local_att_bundle_st {
    STACK_OF(LOCAL_ATT_STMT) *attestations;
    STACK_OF(X509)           *certs;   /* LimitedCertChoices OPTIONAL */
} LOCAL_ATT_BUNDLE;

DECLARE_ASN1_FUNCTIONS(LOCAL_ATT_BUNDLE)

/*
 * ATT_BUNDLE_get_certs_from_der - extract the certificate chain from an
 * AttestationBundle DER blob.
 *
 * Decodes the DER-encoded AttestationBundle at |der| (length |der_len|) and
 * returns the `certs` field as a newly-allocated STACK_OF(X509).  Returns NULL
 * if the bundle cannot be decoded or contains no certificate chain.
 *
 * Caller is responsible for freeing the returned stack:
 *   sk_X509_pop_free(result, X509_free);
 */
STACK_OF(X509) *ATT_BUNDLE_get_certs_from_der(const unsigned char *der,
                                               long der_len);

#endif /* RATS_CSR_ASN_H */

