/*-
 * @file   test/tpm_py_bridge_smoke.c
 * @brief  Minimal runtime smoke test for src/tpm_py_bridge.c.
 *
 * Drives tpm2_quote_generate_evidence() — the embedded-CPython bridge into
 * libattest.attester.evidence_bridge.generate_tpm_evidence(kind="quote") —
 * against a TPM (an isolated swtpm/mssim simulator in normal use, or a real
 * device:/dev/tpmrm0).  A success with non-empty, well-formed DER + OID
 * proves the whole chain works end to end: Py_Initialize, import libattest,
 * drive TPM2_Quote via tpm2-pytss, and DER-encode the TcgAttestQuote
 * evidence statement.
 *
 * This is a smoke test — "does it run and produce a structurally valid DER
 * SEQUENCE with a well-formed OID?" — not a cryptographic appraisal of the
 * quote; that is the verifier's job (tpm_verifier.py).
 *
 * Optionally also drives tpm2_build_key_attest_chall(), which needs no
 * verifier round trip (only an EK certificate chain PEM — its contents are
 * opaque to the TPM side, so a throwaway self-signed PEM is fine for a smoke
 * run), if a 3rd argument is given.
 *
 * NOT exercised here: tpm2_key_attest_generate_evidence() needs a
 * KeyAttestResp DER minted by a live CA (MakeCredential encSeed/encSecret
 * blobs) — no such party exists in an isolated TPM-simulator smoke run.
 * eareat_hpke_encrypt_ear() is not a TPM operation at all (it HPKE-wraps an
 * already-signed ATG/EAT token) — out of scope for this harness.
 *
 * Usage:
 *   tpm_py_bridge_smoke <tcti> <ak_handle_hex> [ek_cert_chain_pem]
 *
 * Exit code: 0 = every attempted path passed, 1 = a failure or bad usage.
 *
 * Requires PYTHONPATH to resolve libattest.attester.evidence_bridge (and its
 * tpm2-pytss/cryptography/pyasn1 dependencies) — see src/tpm_py_bridge.h.
 */

#include "tpm_py_bridge.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>   /* OPENSSL_free */

/* A DER-encoded ASN.1 SEQUENCE (both TcgAttestQuote and KeyAttestChall are
 * SEQUENCEs) always starts with tag 0x30 — a cheap structural check that we
 * got real DER back, not an empty/garbage buffer.  Not a full ASN.1 decode:
 * this is a smoke test, not a conformance check. */
#define DER_SEQUENCE_TAG 0x30u

static int check_der_sequence(const unsigned char *der, size_t len, const char *what)
{
    if (der == NULL || len < 2) {
        fprintf(stderr, "  FAIL: %s DER too short (%zu bytes)\n", what, len);
        return 0;
    }
    if (der[0] != DER_SEQUENCE_TAG) {
        fprintf(stderr, "  FAIL: %s DER tag 0x%02X (want SEQUENCE 0x%02X)\n",
                what, der[0], DER_SEQUENCE_TAG);
        return 0;
    }
    fprintf(stderr, "  %s DER: tag=0x%02X len=%zuB — OK\n", what, der[0], len);
    return 1;
}

static int check_type_oid(const char *oid, const char *what)
{
    size_t i;

    if (oid == NULL || oid[0] == '\0') {
        fprintf(stderr, "  FAIL: %s type OID missing/empty\n", what);
        return 0;
    }
    for (i = 0; oid[i] != '\0'; i++) {
        if (!isdigit((unsigned char)oid[i]) && oid[i] != '.') {
            fprintf(stderr, "  FAIL: %s type OID '%s' is not dotted-decimal\n", what, oid);
            return 0;
        }
    }
    fprintf(stderr, "  %s type OID: %s — OK\n", what, oid);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s <tcti> <ak_handle_hex> [ek_cert_chain_pem]\n"
                "  e.g. %s mssim:host=127.0.0.1,port=2321 0x81010002\n",
                argv[0], argv[0]);
        return 1;
    }
    const char *tcti          = argv[1];
    uint32_t    ak_handle     = (uint32_t)strtoul(argv[2], NULL, 0);
    const char *ek_cert_chain = (argc > 3) ? argv[3] : NULL;

    /* Deterministic, non-zero stand-in for the RATS nonce / qualifyingData. */
    unsigned char nonce[20];
    memset(nonce, 0xA5, sizeof nonce);

    int failures = 0;

    /* ── 1. Quote evidence (always) ────────────────────────────────────── */
    fprintf(stderr, "[1/2] tpm2_quote_generate_evidence (ak=0x%08X, default PCRs)\n",
            ak_handle);
    {
        unsigned char *der = NULL;
        char *oid = NULL;
        size_t der_len = 0;
        int ok = tpm2_quote_generate_evidence(tcti, ak_handle, nonce, sizeof nonce,
                                              NULL, 0, /*corrupt_signature=*/0,
                                              &der, &der_len, &oid);
        if (!ok || !check_der_sequence(der, der_len, "quote")
                || !check_type_oid(oid, "quote")) {
            fprintf(stderr, "  FAIL: tpm2_quote_generate_evidence (ok=%d)\n", ok);
            failures++;
        } else {
            fprintf(stderr, "  PASS: evidence=%zuB oid=%s\n", der_len, oid);
        }
        OPENSSL_free(der);
        OPENSSL_free(oid);
    }

    /* ── 2. KeyAttestChall (only with an EK cert chain PEM) ──────────────── */
    if (ek_cert_chain != NULL) {
        fprintf(stderr, "[2/2] tpm2_build_key_attest_chall (ek_cert_chain=%s)\n",
                ek_cert_chain);
        unsigned char *der = NULL;
        size_t der_len = 0;
        int ok = tpm2_build_key_attest_chall(tcti, ak_handle, ek_cert_chain,
                                             &der, &der_len);
        if (!ok || !check_der_sequence(der, der_len, "KeyAttestChall")) {
            fprintf(stderr, "  FAIL: tpm2_build_key_attest_chall (ok=%d)\n", ok);
            failures++;
        } else {
            fprintf(stderr, "  PASS: chall=%zuB\n", der_len);
        }
        OPENSSL_free(der);
    } else {
        fprintf(stderr, "[2/2] tpm2_build_key_attest_chall — SKIPPED "
                        "(no ek_cert_chain_pem argument)\n");
    }

    fprintf(stderr, "\n%s (%d failure(s))\n",
            failures == 0 ? "SMOKE TEST PASSED" : "SMOKE TEST FAILED", failures);
    return failures == 0 ? 0 : 1;
}
