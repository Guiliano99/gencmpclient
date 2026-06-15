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

/* ── TCG TPM2 attestation statement types ────────────────────────────────────
 *
 * draft-birkholz-rats-tcg-tpm2-attestation defines two statement types:
 *
 *   TcgAttestCertify ::= SEQUENCE {      -- OID 2.23.133.20.1 (key attestation)
 *       tpmSAttest  OCTET STRING,
 *       signature   OCTET STRING,
 *       tpmTPublic  OCTET STRING OPTIONAL
 *   }
 *
 *   TcgAttestQuote ::= SEQUENCE {        -- OID 2.23.133.20.2 (platform attestation)
 *       tpmSAttest  OCTET STRING,
 *       signature   OCTET STRING,
 *       pcrValues   OCTET STRING OPTIONAL
 *   }
 *
 * These types are used by getTPMAttestExtFromFiles() in cmpClient.c to build
 * an id-aa-attestation CSR extension directly from on-disk TPM binary blobs,
 * without going through the ATG library.
 */
typedef struct tcg_attest_certify_st {
    ASN1_OCTET_STRING *tpmSAttest;
    ASN1_OCTET_STRING *signature;
    ASN1_OCTET_STRING *tpmTPublic; /* OPTIONAL */
} TCG_ATTEST_CERTIFY;

DECLARE_ASN1_FUNCTIONS(TCG_ATTEST_CERTIFY)

typedef struct tcg_attest_quote_st {
    ASN1_OCTET_STRING *tpmSAttest;
    ASN1_OCTET_STRING *signature;
    ASN1_OCTET_STRING *pcrValues;  /* OPTIONAL */
} TCG_ATTEST_QUOTE;

DECLARE_ASN1_FUNCTIONS(TCG_ATTEST_QUOTE)

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

/* ── TpmAttestationParams ASN.1 type (SPEC §DR-11, replaces TpmPcrSelection) ─
 *
 *   TpmAttestationParams ::= SEQUENCE {
 *       pcrs       SEQUENCE OF INTEGER OPTIONAL,
 *       hashAlgId  INTEGER             OPTIONAL
 *   }
 *
 * Used under ``TPM_PCR_SELECTION_OID`` in both CMP directions:
 *
 * Attester → MockCA (genm reqInfo):
 *   {hashAlgId=0x000B}  — SHA-256 proposal; pcrs absent.
 *
 * MockCA → attester (genp respInfo):
 *   {pcrs=[0..4], hashAlgId=0x000B}  — PCR list + accepted/counter-proposed alg.
 *
 * Both fields are OPTIONAL.  When ``pcrs`` is absent in the response the
 * attester falls back to the default PCR list (0..4).  When ``hashAlgId``
 * is absent the attester uses SHA-256.
 */
typedef struct local_tpm_attestation_params_st {
    STACK_OF(ASN1_INTEGER) *pcrs;      /* SEQUENCE OF INTEGER OPTIONAL */
    ASN1_INTEGER           *hashAlgId; /* INTEGER OPTIONAL              */
} LOCAL_TPM_ATTESTATION_PARAMS;

DECLARE_ASN1_FUNCTIONS(LOCAL_TPM_ATTESTATION_PARAMS)

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

