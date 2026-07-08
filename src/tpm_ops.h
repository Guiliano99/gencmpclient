/*-
 * @file   src/tpm_ops.h
 * @brief  Direct TPM 2.0 operations via the TSS2 ESYS API.
 *
 * Provides in-process TPM2_Certify for CMP IR attestation evidence, without
 * going through the tpm2-openssl provider (which does not expose Certify/Quote).
 *
 * Linked against libtss2-esys and libtss2-tctildr at build time.  All TPM
 * handles passed here must be persistent (NV-persisted) so the same call works
 * against the TCG mssim simulator and a real TPM via /dev/tpmrm0.
 *
 * TCTI coexistence with tpm2-openssl provider
 * --------------------------------------------
 * On mssim the simulator is single-threaded; opening a second TCTI while one
 * is already open deadlocks.  Callers MUST ensure this module's tpm_certify*
 * calls complete (TCTI opened, op executed, TCTI closed) BEFORE any operation
 * that triggers the tpm2-openssl provider to open its own TCTI.
 *
 * On real hardware /dev/tpmrm0 is backed by the kernel resource manager, which
 * arbitrates concurrent TCTI contexts transparently — no ordering required.
 */

#ifndef GENCMP_TPM_OPS_H
# define GENCMP_TPM_OPS_H

# include <stddef.h>
# include <stdint.h>

# ifdef __cplusplus
extern "C" {
# endif

/*
 * tpm_certify_key_from_pem
 * ------------------------
 * Invoke TPM2_Certify with |ak_handle| attesting the key encoded in the
 * TSS2_PRIVATE_KEY PEM file at |subject_key_pem_path|.
 *
 * The subject key is loaded transiently (Esys_Load) under the persistent
 * parent encoded in the PEM, certified, then flushed.  The AK is assumed to
 * already be persistent at |ak_handle| with empty auth.
 *
 * |nonce| / |nonce_len| populate the qualifyingData of the TPM2_Certify
 * command; the verifier uses this for freshness.
 *
 * On success:
 *   |*attest_out|       Newly-allocated TPMS_ATTEST bytes (no TPM2B prefix).
 *   |*sig_out|          Newly-allocated TPMT_SIGNATURE bytes (full wire format:
 *                       2-byte sigAlg + 2-byte hashAlg + 2-byte size + sig).
 *   |*tpmt_public_out|  Newly-allocated marshalled TPMT_PUBLIC of the certified
 *                       key.  Embedded in TcgAttestCertify.tpmTPublic so the
 *                       verifier can check TPMS_CERTIFY_INFO.name == H(TPMT_PUBLIC)
 *                       (G1 key-binding check).
 *
 * All three output buffers must be freed with OPENSSL_free() by the caller.
 *
 * Returns 1 on success, 0 on any failure.
 */
int tpm_certify_key_from_pem(const char *tcti_str,
                             uint32_t ak_handle,
                             const char *subject_key_pem_path,
                             const unsigned char *nonce, size_t nonce_len,
                             unsigned char **attest_out, size_t *attest_len,
                             unsigned char **sig_out, size_t *sig_len,
                             unsigned char **tpmt_public_out,
                             size_t *tpmt_public_len);

/*
 * tpm_quote_pcrs
 * --------------
 * Invoke TPM2_Quote with |ak_handle| over the verifier-selected SHA-256 PCR
 * set so the verifier can perform the G2 PCR appraisal (SPEC §DR-11).
 *
 * |nonce| / |nonce_len| populate the qualifyingData of TPM2_Quote so the
 * verifier can correlate the quote with its open challenge-response session.
 * The platform profile uses the single RATS nonce from NonceResponse
 * (OSSL_CMP_CTX_get0_rats_nonce); there is no second nonce or Certify pairing
 * in this cycle.
 *
 * |pcr_indices| / |pcr_count| describe the SHA-256 PCR set to quote.  Only
 * SHA-256 is supported in the current scope: the hash-algorithm negotiation
 * carried in TPM20QuoteRespInfo.hashAlgo must therefore converge on
 * 0x000B (TPM2_ALG_SHA256) — callers should reject any verifier response
 * that picks a different value rather than silently quoting SHA-256.
 * Each index must be in 0..23 (PCR registers).  Pass NULL / 0 to fall back
 * to the E2E default set PCRs 0..4.
 *
 * On success:
 *   |*attest_out|  Newly-allocated TPMS_ATTEST bytes (no TPM2B prefix).
 *                  magic=0xFF544347, type=0x8018 (QUOTE),
 *                  attested.quote = { pcrSelect, pcrDigest }.
 *   |*sig_out|     Newly-allocated TPMT_SIGNATURE bytes (full wire format).
 *   |*pcr_values_out|  When |pcr_values_out| / |pcr_values_len| are non-NULL,
 *                  the raw per-PCR values for the SAME selection, concatenated
 *                  in canonical ascending order — i.e. exactly the preimage of
 *                  TPMS_QUOTE_INFO.pcrDigest.  The verifier recomputes
 *                  H(values) == pcrDigest to bind the individual values to the
 *                  AK-signed quote before surfacing them (G_PCR_VALUES_BIND).
 *                  Pass NULL for both to skip the PCR read.
 *
 * All output buffers must be freed with OPENSSL_free() by the caller.
 *
 * Returns 1 on success, 0 on any failure.
 */
int tpm_quote_pcrs(const char *tcti_str,
                   uint32_t ak_handle,
                   const unsigned char *nonce, size_t nonce_len,
                   const unsigned int *pcr_indices, size_t pcr_count,
                   unsigned char **attest_out, size_t *attest_len,
                   unsigned char **sig_out, size_t *sig_len,
                   unsigned char **pcr_values_out, size_t *pcr_values_len);

/*
 * tpm_rsa_oaep_decrypt
 * --------------------
 * Decrypt an RSA-OAEP-SHA256 ciphertext with the TPM-resident subject key
 * loaded from |subject_key_pem_path| (TSS2_PRIVATE_KEY PEM, same format as
 * the file consumed by tpm_certify_key_from_pem).
 *
 * The subject key MUST have been provisioned with attributes
 * ``decrypt=1, sign=1`` and ``scheme=RSA_OAEP, halg=SHA-256`` (SPEC §C-2);
 * otherwise Esys_RSA_Decrypt returns TPM_RC_KEY (0x9c).
 *
 * Recovering the plaintext nonce from the ciphertext returned in the GenP
 * is the proof-of-possession step of the KeyAttestPoP scheme.
 *
 * On success:
 *   |*plaintext_out|  Newly-allocated buffer with the recovered plaintext.
 *
 * |*plaintext_out| must be freed with OPENSSL_free() by the caller.
 *
 * Returns 1 on success, 0 on any failure.
 */
int tpm_rsa_oaep_decrypt(const char *tcti_str,
                         const char *subject_key_pem_path,
                         const unsigned char *ciphertext, size_t ciphertext_len,
                         unsigned char **plaintext_out, size_t *plaintext_len);


# ifdef __cplusplus
}
# endif

#endif /* GENCMP_TPM_OPS_H */
