/*-
 * @file   src/tpm_py_bridge.h
 * @brief  In-process TPM evidence generation via an embedded Python
 *         interpreter running libattest-py (tpm2-pytss), replacing the
 *         direct TSS2 ESYS calls + hand-built TcgAttestQuote/TcgAttestCertify
 *         ASN.1 that used to live in tpm_ops.c.
 *
 * gencmpclient no longer knows the TPM 2.0 wire structures or the
 * TcgAttestQuote/TcgAttestCertify ASN.1 shape for the native (in-process) TPM
 * path: libattest.attester.evidence_bridge.generate_tpm_evidence() drives the
 * TPM AND builds the DER-encoded evidence statement in one call; these two
 * functions are thin wrappers over the embedded CPython C-API that hand back
 * the resulting (evidence_der, type_oid) pair as opaque bytes plus a
 * dotted-decimal OID string. The caller (getTPMAttestExtNative[Certify] in
 * cmpClient.c) wraps that pair in an AttestationStatement / AttestationBundle
 * — it never parses evidence_der itself, mirroring how the ATG/EAT path
 * (getattestationExt, #ifdef USE_ATGLIB) treats atg_generate_evidence()'s
 * token as opaque.
 *
 * Requires the embedded interpreter to have libattest-py importable —
 * installed into its site-packages, or reachable via PYTHONPATH (see the
 * TPMPCRDemo/TPMKeyAttestDemo attester Dockerfiles, which set PYTHONPATH to
 * the libattest source tree plus its dependencies' site-packages).
 *
 * Interpreter lifecycle
 * ----------------------
 * The embedded interpreter is initialized lazily on first use and is never
 * finalized (process exit reclaims it) — gencmpclient is a short-lived CLI
 * that calls at most one of these functions per run, so there is nothing to
 * gain from explicit teardown and Py_Finalize() after native extensions
 * (tpm2-pytss) have loaded is a known source of interpreter-shutdown crashes.
 */

#ifndef GENCMP_TPM_PY_BRIDGE_H
# define GENCMP_TPM_PY_BRIDGE_H

# include <stddef.h>
# include <stdint.h>

# ifdef __cplusplus
extern "C" {
# endif

/*
 * tpm2_quote_generate_evidence
 * -----------------------------
 * Drive TPM2_Quote (via libattest-py) with |ak_handle| and hand back the
 * DER-encoded TcgAttestQuote evidence statement plus its
 * AttestationStatement.type OID (dotted-decimal, NUL-terminated).
 *
 * |nonce|/|nonce_len| populate the qualifyingData (freshness).
 *
 * |pcr_indices|/|pcr_count| describe the verifier-selected SHA-256 PCR set
 * (from NonceResponse.respInfo — TPM20QuoteRespInfo). Pass NULL/0 to fall
 * back to libattest-py's own default PCR set (0..4).  Only SHA-256 is
 * supported in this profile, matching the hard reject already applied by the
 * caller before this is invoked.
 *
 * |corrupt_signature| is a negative-test-only hook — see
 * libattest.attester.evidence_bridge.generate_tpm_evidence's docstring for
 * exactly what it flips and why the hook lives there and not here (gencmpclient
 * has no structured access to the opaque DER bytes to corrupt them itself).
 * Never set this outside a negative-test run.
 *
 * On success:
 *   |*evidence_der_out|  Newly-allocated opaque DER bytes (OPENSSL_malloc'd).
 *   |*evidence_der_len|  Length of |*evidence_der_out|.
 *   |*type_oid_out|      Newly-allocated NUL-terminated OID string
 *                        (OPENSSL_malloc'd).
 * Both output buffers must be freed with OPENSSL_free() by the caller.
 *
 * Returns 1 on success, 0 on any failure (the Python-side exception, if any,
 * is logged via LOG_err before returning).
 */
int tpm2_quote_generate_evidence(const char *tcti_str,
                                 uint32_t ak_handle,
                                 const unsigned char *nonce, size_t nonce_len,
                                 const unsigned int *pcr_indices, size_t pcr_count,
                                 int corrupt_signature,
                                 unsigned char **evidence_der_out, size_t *evidence_der_len,
                                 char **type_oid_out);

/*
 * tpm2_key_attest_generate_evidence
 * -----------------------------------
 * Drive the v5 credential-activation key-attestation flow (via libattest-py) for
 * the subject key loaded from the "TSS2 PRIVATE KEY" PEM at |subject_key_pem_path|,
 * certified by the AK at |ak_handle|: recover the verifier seed via
 * TPM2_ActivateCredential from the MakeCredential blobs, TPM2_Certify the subject,
 * Esys_Sign H(seed), and hand back the DER-encoded KeyAttestEvidence statement
 * plus its AttestationStatement.type OID.
 *
 * |nonce|/|nonce_len| populate the qualifyingData (freshness).
 * |key_attest_resp_der|/|key_attest_resp_len| are the DER KeyAttestResp the CA
 * returned in NonceResponse.respInfo (carrying encSeed/encSecret) — the Python
 * bridge decodes it, so the C caller stays free of the KeyAttestResp ASN.1.
 * |corrupt_signature| — see tpm2_quote_generate_evidence.
 *
 * Output ownership: same as tpm2_quote_generate_evidence.
 *
 * Returns 1 on success, 0 on any failure (a Python-side exception, if any, is
 * logged via LOG_err before returning).
 */
int tpm2_key_attest_generate_evidence(const char *tcti_str,
                                      uint32_t ak_handle,
                                      const char *subject_key_pem_path,
                                      const unsigned char *nonce, size_t nonce_len,
                                      const unsigned char *key_attest_resp_der,
                                      size_t key_attest_resp_len,
                                      int corrupt_signature,
                                      unsigned char **evidence_der_out, size_t *evidence_der_len,
                                      char **type_oid_out);

/*
 * tpm2_build_key_attest_chall
 * ----------------------------
 * Build the DER KeyAttestChall for the CMP NonceRequest.reqInfo (via libattest-py):
 * read the AK Name and the deterministic EK public from the TPM at |ak_handle|, and
 * pair them with the EK certificate chain at |ek_cert_chain| (a PEM file path or
 * inline PEM — the -ekCertChain flag passes a path). The Verifier uses ekPublic to
 * run TPM2_MakeCredential and akName as the bound Name.  The C caller treats the
 * result as opaque DER.
 *
 * On success |*chall_der_out| is newly-allocated (OPENSSL_malloc'd) and must be
 * freed by the caller with OPENSSL_free().
 *
 * Returns 1 on success, 0 on any failure (a Python-side exception, if any, is
 * logged via LOG_err before returning).
 */
int tpm2_build_key_attest_chall(const char *tcti_str,
                                uint32_t ak_handle,
                                const char *ek_cert_chain,
                                unsigned char **chall_der_out, size_t *chall_der_len);

/*
 * eareat_hpke_encrypt_ear
 * ------------------------
 * Privacy-wrap an already signed ATG EAT/JWT token with JOSE-HPKE-0 and return
 * DER(CMW json UTF8String) bytes for AttestationStatement.stmt.
 *
 * |enc_private_key_pem| is a verifier P-256 HPKE recipient private key PEM; the
 * Python helper derives its public key and encrypts to that public key. This is
 * a PoC seam for the local EarEatHpkeDemo worktree; production should pass a
 * pinned public verifier encryption credential instead.
 *
 * Output ownership: |*cmw_der_out| is OPENSSL_malloc'd and must be freed by the
 * caller with OPENSSL_free().
 */
int eareat_hpke_encrypt_ear(const char *enc_private_key_pem,
                            const unsigned char *ear, size_t ear_len,
                            unsigned char **cmw_der_out, size_t *cmw_der_len);

/*
 * eareat_cose_hpke_encrypt_ear
 * -----------------------------
 * Privacy-wrap an already signed ATG EAT/JWT token with COSE-HPKE
 * (draft-ietf-cose-hpke) and return DER(CMW json UTF8String) bytes for
 * AttestationStatement.stmt. Same call/ownership contract as
 * eareat_hpke_encrypt_ear (JOSE-HPKE); this is the COSE counterpart, resolved
 * from a separate Python module (src/eareat_cose_hpke_bridge.py) so the two
 * wire formats stay independently selectable via distinct AttestationStatement
 * OIDs (ATG_HPKE_STMT_TYPE_OID vs ATG_COSE_HPKE_STMT_TYPE_OID in cmpClient.c).
 *
 * |enc_private_key_pem| is a verifier P-256 HPKE recipient private key PEM; the
 * Python helper derives its public key and encrypts to that public key.
 *
 * Output ownership: |*cmw_der_out| is OPENSSL_malloc'd and must be freed by the
 * caller with OPENSSL_free().
 */
int eareat_cose_hpke_encrypt_ear(const char *enc_private_key_pem,
                                 const unsigned char *ear, size_t ear_len,
                                 unsigned char **cmw_der_out, size_t *cmw_der_len);

# ifdef __cplusplus
}
# endif

#endif /* GENCMP_TPM_PY_BRIDGE_H */
