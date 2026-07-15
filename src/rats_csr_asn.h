/*-
 * @file   src/rats_csr_asn.h
 * @brief  Local ASN.1 types for AttestationBundle
 *         (draft-ietf-lamps-csr-attestation-24).
 *
 * These are temporary stand-ins until OSSL_CSR_ATTESTATION_STATEMENT and
 * OSSL_CSR_ATTESTATION_BUNDLE are added to crypto/crmf/crmf_asn.c in the
 * Guiliano99/openssl fork.  Once the fork provides those types, replace
 * LOCAL_ATT_STMT / LOCAL_ATT_BUNDLE with the upstream definitions.
 *
 * Encoded structure per draft-ietf-lamps-csr-attestation-24 Appendix B:
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
#include <openssl/crmf.h>     /* OSSL_CRMF_PBMPARAMETER for KeyAttestPoP */
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

/* The TcgAttestCertify / TcgAttestQuote statement structures are NOT declared
 * here.  Their DER is generated in libattest-py (formats/tpm/tcg.py) and handed
 * to gencmpclient as opaque bytes across the tpm_py_bridge.c CPython bridge,
 * so the statement ASN.1 has a single source of truth in Python.  The C side
 * only wraps the opaque statement DER into LOCAL_ATT_STMT / LOCAL_ATT_BUNDLE. */

/* ── KeyAttestPoP ASN.1 types (SPEC §DR-1, v2) ─────────────────────────────
 *
 * Two SEQUENCEs:
 *
 *   KeyAttestPoPChallenge ::= SEQUENCE {
 *       algorithm  AlgorithmIdentifier, -- decryption alg (rsaEncryption | RSAES-OAEP)
 *       value      OCTET STRING         -- ciphertext of the challenge nonce C
 *   }
 *
 *   KeyAttestPoPProof ::= SEQUENCE {
 *       algorithm  AlgorithmIdentifier, -- proof form (id-PasswordBasedMac | sha256WithRSAEncryption)
 *       value      OCTET STRING         -- MAC bytes or RSA-SSA-PKCS1-v1.5 sig bytes
 *   }
 *
 * ``LOCAL_KEY_POP_CHALLENGE`` is what the attester DECODES off the wire
 * from ``OSSL_CMP_CTX_get0_rats_response_params(ctx, slot=0)``.  The
 * MockCA places it inside ``NonceResponse.responseParams`` as a
 * ``ChallengeParam {type=KEY_ATTEST_POP_OID, value=DER(challenge)}``.
 *
 * ``LOCAL_KEY_POP_PROOF`` is what the attester PUSHES as a CSR / cert
 * extension under ``KEY_ATTEST_POP_OID`` (SPEC §DR-8).  In v2 the bundle
 * NO LONGER carries a KeyAttestPoP statement — the PoP loop is strictly
 * between attester and MockCA, so the matching ``LOCAL_KEY_POP_EVIDENCE``
 * type from v1 has been removed.
 *
 * Placeholder ``LOCAL_`` prefix mirrors the convention used for the rest
 * of this file — these types live here until upstream OpenSSL gains
 * matching definitions in ``crypto/cmp/`` or ``crypto/crmf/``.
 *
 * Note: <openssl/crmf.h> is kept here so callers (cmpClient.c) can use
 * OSSL_CRMF_PBMPARAMETER locally when building the PBMParameter DER block
 * that populates the algorithm.parameter field of LOCAL_KEY_POP_PROOF.
 */
typedef struct local_key_pop_challenge_st {
    X509_ALGOR        *algorithm;   /* rsaEncryption | id-RSAES-OAEP */
    ASN1_OCTET_STRING *value;       /* ciphertext bytes */
} LOCAL_KEY_POP_CHALLENGE;

DECLARE_ASN1_FUNCTIONS(LOCAL_KEY_POP_CHALLENGE)

typedef struct local_key_pop_proof_st {
    X509_ALGOR        *algorithm;   /* AlgorithmIdentifier — OID + params */
    ASN1_OCTET_STRING *value;       /* proof bytes (HMAC or RSA-SHA256 sig) */
} LOCAL_KEY_POP_PROOF;

DECLARE_ASN1_FUNCTIONS(LOCAL_KEY_POP_PROOF)

/* ── TPM 2.0 quote freshness open types (attestation-freshness draft) ────────
 *
 *   TPM20QuoteReqInfo ::= SEQUENCE {         -- attester → RA (NonceRequest.reqInfo)
 *       certificateName   [0] SEQUENCE OF UTF8String OPTIONAL,   -- candidate AK certs
 *       supportedHashAlgo [1] SEQUENCE OF TPMAlgId    OPTIONAL }  -- proposed banks
 *   TPM20QuoteRespInfo ::= SEQUENCE {        -- RA → attester (NonceResponse.respInfo)
 *       certificateName UTF8String         OPTIONAL,  -- RA-selected AK cert
 *       pcrSelection    SEQUENCE OF PCRIndex,         -- MANDATORY, RA-mandated PCRs
 *       hashAlgo        TPMAlgId }                     -- MANDATORY, selected bank
 *
 * TPMAlgId 1..65535 (SHA-256=11), PCRIndex 0..23 — ranges checked in code.
 * Req fields are IMPLICIT [0]/[1] tagged (ASN1_IMP_SEQUENCE_OF_OPT in
 * rats_csr_asn.c): without a distinguishing tag both OPTIONAL fields would
 * carry the same universal SEQUENCE OF tag and a lone one would be ambiguous.
 * MUST match libattest's TPM20QuoteReqInfoASN1 (quote_profile.py) tag-for-tag —
 * a one-sided retag previously broke every real genm capture (see the "Revert
 * TPM20QuoteReqInfo to universal tags for C-wire interop" libattest commit).
 * Resp fields need no tagging (certificateName is a plain UTF8String, not a
 * SEQUENCE OF; the other two are mandatory) and stay untagged.
 * Replaces TpmAttestationParams.
 */
typedef struct tpm20_quote_req_info_st {
    STACK_OF(ASN1_UTF8STRING) *certificateName;   /* [0] SEQUENCE OF UTF8String OPTIONAL */
    STACK_OF(ASN1_INTEGER)    *supportedHashAlgo; /* [1] SEQUENCE OF TPMAlgId    OPTIONAL */
} TPM20_QUOTE_REQ_INFO;

DECLARE_ASN1_FUNCTIONS(TPM20_QUOTE_REQ_INFO)

typedef struct tpm20_quote_resp_info_st {
    ASN1_UTF8STRING        *certificateName; /* UTF8String OPTIONAL              */
    STACK_OF(ASN1_INTEGER) *pcrSelection;    /* SEQUENCE OF PCRIndex (MANDATORY) */
    ASN1_INTEGER           *hashAlgo;        /* TPMAlgId (MANDATORY)             */
} TPM20_QUOTE_RESP_INFO;

DECLARE_ASN1_FUNCTIONS(TPM20_QUOTE_RESP_INFO)

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

