/*-
 * @file   test/tpm_ops_smoke.c
 * @brief  Minimal runtime smoke test for src/tpm_ops.c.
 *
 * Drives the three TPM entry points that share the extracted esys_setup()
 * helper against a TPM (an isolated swtpm/mssim simulator in normal use, or a
 * real device:/dev/tpmrm0):
 *
 *   1. tpm_quote_pcrs            (TPM2_Quote + TPM2_PCR_Read)  — always run
 *   2. tpm_certify_key_from_pem  (TPM2_Load + TPM2_Certify)    — if subject PEM given
 *   3. tpm_rsa_oaep_decrypt      (TPM2_Load + TPM2_RSA_Decrypt)— if subject PEM
 *                                                                + ciphertext given
 *
 * Each path that returns 1 with non-empty, well-formed output proves that
 * esys_setup()/esys_teardown() open and close the TCTI+ESYS context correctly
 * after the refactor.  This is a smoke test — "does it run and produce a
 * structurally valid TPMS_ATTEST?" — not a cryptographic appraisal of the
 * quote; that is the verifier's job (tpm_verifier.py).
 *
 * Usage:
 *   tpm_ops_smoke <tcti> <ak_handle_hex> [subject_pem [ciphertext_file]]
 *
 * Exit code: 0 = every attempted path passed, 1 = a failure or bad usage.
 */

#include "tpm_ops.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>   /* OPENSSL_free */

/* TPM_GENERATED_VALUE: every TPMS_ATTEST begins with this magic (big-endian),
 * so a quick check confirms we got a real attestation structure back and not
 * an empty/garbage buffer. */
#define TPM_GENERATED_MAGIC 0xFF544347u
#define TPM_ST_ATTEST_QUOTE   0x8018u
#define TPM_ST_ATTEST_CERTIFY 0x8017u

static int check_attest(const unsigned char *att, size_t len, uint16_t want_type)
{
    if (att == NULL || len < 6) {
        fprintf(stderr, "  FAIL: TPMS_ATTEST too short (%zu bytes)\n", len);
        return 0;
    }
    uint32_t magic = ((uint32_t)att[0] << 24) | ((uint32_t)att[1] << 16)
                   | ((uint32_t)att[2] << 8) | (uint32_t)att[3];
    uint16_t type  = (uint16_t)(((uint16_t)att[4] << 8) | att[5]);
    if (magic != TPM_GENERATED_MAGIC) {
        fprintf(stderr, "  FAIL: bad magic 0x%08X (want 0x%08X)\n",
                magic, TPM_GENERATED_MAGIC);
        return 0;
    }
    if (type != want_type) {
        fprintf(stderr, "  FAIL: attest type 0x%04X (want 0x%04X)\n",
                type, want_type);
        return 0;
    }
    fprintf(stderr, "  magic=0x%08X type=0x%04X attest=%zuB — OK\n",
            magic, type, len);
    return 1;
}

static unsigned char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    unsigned char *buf = malloc((size_t)sz ? (size_t)sz : 1);
    if (buf == NULL) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return NULL; }
    *out_len = got;
    return buf;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s <tcti> <ak_handle_hex> [subject_pem [ciphertext_file]]\n"
                "  e.g. %s mssim:host=127.0.0.1,port=2321 0x81010002\n",
                argv[0], argv[0]);
        return 1;
    }
    const char *tcti        = argv[1];
    uint32_t    ak_handle   = (uint32_t)strtoul(argv[2], NULL, 0);
    const char *subject_pem = (argc > 3) ? argv[3] : NULL;
    const char *cipher_path = (argc > 4) ? argv[4] : NULL;

    /* Deterministic, non-zero stand-in for the RATS nonce / qualifyingData. */
    unsigned char nonce[20];
    memset(nonce, 0xA5, sizeof nonce);

    int failures = 0;

    /* ── 1. Quote (always) ─────────────────────────────────────────────── */
    fprintf(stderr, "[1/3] tpm_quote_pcrs (ak=0x%08X, default PCRs)\n", ak_handle);
    {
        unsigned char *att = NULL, *sig = NULL, *pcr = NULL;
        size_t al = 0, sl = 0, pl = 0;
        int ok = tpm_quote_pcrs(tcti, ak_handle, nonce, sizeof nonce,
                                NULL, 0, &att, &al, &sig, &sl, &pcr, &pl);
        if (!ok || sl == 0 || !check_attest(att, al, TPM_ST_ATTEST_QUOTE)) {
            fprintf(stderr, "  FAIL: tpm_quote_pcrs (ok=%d sig=%zuB pcr=%zuB)\n",
                    ok, sl, pl);
            failures++;
        } else {
            fprintf(stderr, "  PASS: sig=%zuB pcrValues=%zuB\n", sl, pl);
        }
        OPENSSL_free(att); OPENSSL_free(sig); OPENSSL_free(pcr);
    }

    /* ── 2. Certify (only with a subject TSS2 PRIVATE KEY PEM) ──────────── */
    if (subject_pem != NULL) {
        fprintf(stderr, "[2/3] tpm_certify_key_from_pem (subject=%s)\n", subject_pem);
        unsigned char *att = NULL, *sig = NULL, *pub = NULL;
        size_t al = 0, sl = 0, pl = 0;
        int ok = tpm_certify_key_from_pem(tcti, ak_handle, subject_pem,
                                          nonce, sizeof nonce,
                                          &att, &al, &sig, &sl, &pub, &pl);
        if (!ok || sl == 0 || pl == 0
                || !check_attest(att, al, TPM_ST_ATTEST_CERTIFY)) {
            fprintf(stderr, "  FAIL: tpm_certify_key_from_pem "
                            "(ok=%d sig=%zuB tpmtPublic=%zuB)\n", ok, sl, pl);
            failures++;
        } else {
            fprintf(stderr, "  PASS: sig=%zuB tpmtPublic=%zuB\n", sl, pl);
        }
        OPENSSL_free(att); OPENSSL_free(sig); OPENSSL_free(pub);
    } else {
        fprintf(stderr, "[2/3] tpm_certify_key_from_pem — SKIPPED "
                        "(no subject PEM argument)\n");
    }

    /* ── 3. RSA-OAEP decrypt (only with subject PEM + ciphertext file) ──── */
    if (subject_pem != NULL && cipher_path != NULL) {
        fprintf(stderr, "[3/3] tpm_rsa_oaep_decrypt (ciphertext=%s)\n", cipher_path);
        size_t ctl = 0;
        unsigned char *ct = read_file(cipher_path, &ctl);
        if (ct == NULL || ctl == 0) {
            fprintf(stderr, "  FAIL: could not read ciphertext file\n");
            failures++;
        } else {
            unsigned char *pt = NULL;
            size_t ptl = 0;
            int ok = tpm_rsa_oaep_decrypt(tcti, subject_pem, ct, ctl, &pt, &ptl);
            if (!ok || ptl == 0) {
                fprintf(stderr, "  FAIL: tpm_rsa_oaep_decrypt (ok=%d pt=%zuB)\n",
                        ok, ptl);
                failures++;
            } else {
                fprintf(stderr, "  PASS: recovered %zuB plaintext\n", ptl);
            }
            OPENSSL_free(pt);
        }
        free(ct);
    } else {
        fprintf(stderr, "[3/3] tpm_rsa_oaep_decrypt — SKIPPED "
                        "(needs subject PEM + ciphertext arguments)\n");
    }

    fprintf(stderr, "\n%s (%d failure(s))\n",
            failures == 0 ? "SMOKE TEST PASSED" : "SMOKE TEST FAILED", failures);
    return failures == 0 ? 0 : 1;
}
