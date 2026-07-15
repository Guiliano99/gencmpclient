/*-
 * @file   src/rats_csr_asn.c
 * @brief  ASN.1 type definitions for AttestationBundle
 *         (draft-ietf-lamps-csr-attestation-24).
 *
 * Provides the IMPLEMENT_ASN1_FUNCTIONS for LOCAL_ATT_STMT and
 * LOCAL_ATT_BUNDLE, and the ATT_BUNDLE_get_certs_from_der() helper.
 *
 * This file is shared between src/cmpClient.c and test/test_attestation_bundle.c
 * to avoid duplicating the struct definitions and ASN.1 codec tables.
 */

#include "rats_csr_asn.h"

ASN1_SEQUENCE(LOCAL_ATT_STMT) = {
    ASN1_SIMPLE(LOCAL_ATT_STMT, type, ASN1_OBJECT),
    ASN1_SIMPLE(LOCAL_ATT_STMT, stmt, ASN1_ANY),
} ASN1_SEQUENCE_END(LOCAL_ATT_STMT)
IMPLEMENT_ASN1_FUNCTIONS(LOCAL_ATT_STMT)

ASN1_SEQUENCE(LOCAL_ATT_BUNDLE) = {
    ASN1_SEQUENCE_OF(LOCAL_ATT_BUNDLE, attestations, LOCAL_ATT_STMT),
    ASN1_SEQUENCE_OF_OPT(LOCAL_ATT_BUNDLE, certs, X509),
} ASN1_SEQUENCE_END(LOCAL_ATT_BUNDLE)
IMPLEMENT_ASN1_FUNCTIONS(LOCAL_ATT_BUNDLE)

/* The TcgAttestCertify / TcgAttestQuote statement DER is generated in
 * libattest-py (formats/tpm/tcg.py) and crosses the tpm_py_bridge.c bridge as
 * opaque bytes; gencmpclient no longer declares those structures. */

/* ── KeyAttestPoP types (SPEC §DR-1) ─────────────────────────────────────── */

ASN1_SEQUENCE(LOCAL_KEY_POP_PROOF) = {
    ASN1_SIMPLE(LOCAL_KEY_POP_PROOF, algorithm, X509_ALGOR),
    ASN1_SIMPLE(LOCAL_KEY_POP_PROOF, value,     ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(LOCAL_KEY_POP_PROOF)
IMPLEMENT_ASN1_FUNCTIONS(LOCAL_KEY_POP_PROOF)

/* v2: LOCAL_KEY_POP_EVIDENCE removed — the AttestationBundle no longer
 * carries a KeyAttestPoP statement.  See rats_csr_asn.h. */

ASN1_SEQUENCE(LOCAL_KEY_POP_CHALLENGE) = {
    ASN1_SIMPLE(LOCAL_KEY_POP_CHALLENGE, algorithm, X509_ALGOR),
    ASN1_SIMPLE(LOCAL_KEY_POP_CHALLENGE, value,     ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(LOCAL_KEY_POP_CHALLENGE)
IMPLEMENT_ASN1_FUNCTIONS(LOCAL_KEY_POP_CHALLENGE)

/* ── TPM 2.0 quote freshness open types (attestation-freshness draft) ────────
 *
 *   TPM20QuoteReqInfo ::= SEQUENCE {
 *       certificateName   [0] SEQUENCE OF UTF8String OPTIONAL,
 *       supportedHashAlgo [1] SEQUENCE OF TPMAlgId    OPTIONAL }
 *   TPM20QuoteRespInfo ::= SEQUENCE {
 *       certificateName UTF8String         OPTIONAL,
 *       pcrSelection    SEQUENCE OF PCRIndex,   -- MANDATORY
 *       hashAlgo        TPMAlgId }              -- MANDATORY
 *
 * TPM20QuoteReqInfo's two OPTIONAL fields are IMPLICIT [0]/[1] tagged so they
 * decode unambiguously (without a distinguishing tag both would carry the same
 * universal SEQUENCE OF tag). MUST match libattest's TPM20QuoteReqInfoASN1
 * (quote_profile.py) tag-for-tag — see rats_csr_asn.h. TPM20QuoteRespInfo's
 * fields need no tagging: certificateName is a plain UTF8String (not a
 * SEQUENCE OF) and the other two are mandatory, so it stays untagged. */
ASN1_SEQUENCE(TPM20_QUOTE_REQ_INFO) = {
    ASN1_IMP_SEQUENCE_OF_OPT(TPM20_QUOTE_REQ_INFO, certificateName,   ASN1_UTF8STRING, 0),
    ASN1_IMP_SEQUENCE_OF_OPT(TPM20_QUOTE_REQ_INFO, supportedHashAlgo, ASN1_INTEGER,    1),
} ASN1_SEQUENCE_END(TPM20_QUOTE_REQ_INFO)
IMPLEMENT_ASN1_FUNCTIONS(TPM20_QUOTE_REQ_INFO)

ASN1_SEQUENCE(TPM20_QUOTE_RESP_INFO) = {
    ASN1_OPT        (TPM20_QUOTE_RESP_INFO, certificateName, ASN1_UTF8STRING),
    ASN1_SEQUENCE_OF(TPM20_QUOTE_RESP_INFO, pcrSelection,    ASN1_INTEGER),
    ASN1_SIMPLE     (TPM20_QUOTE_RESP_INFO, hashAlgo,        ASN1_INTEGER),
} ASN1_SEQUENCE_END(TPM20_QUOTE_RESP_INFO)
IMPLEMENT_ASN1_FUNCTIONS(TPM20_QUOTE_RESP_INFO)

STACK_OF(X509) *ATT_BUNDLE_get_certs_from_der(const unsigned char *der,
                                               long der_len)
{
    const unsigned char *p = der;
    LOCAL_ATT_BUNDLE *bundle;
    STACK_OF(X509) *certs;

    bundle = d2i_LOCAL_ATT_BUNDLE(NULL, &p, der_len);
    if (bundle == NULL)
        return NULL;

    /* Transfer ownership: pull certs out before freeing the bundle shell. */
    certs = bundle->certs;
    bundle->certs = NULL; /* prevent LOCAL_ATT_BUNDLE_free from releasing them */
    LOCAL_ATT_BUNDLE_free(bundle);
    return certs; /* NULL if the certs field was absent */
}

