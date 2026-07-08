/*-
 * @file   src/tpm_ops.c
 * @brief  Direct TPM 2.0 operations via TSS2 ESYS, for CMP IR attestation.
 *
 * See src/tpm_ops.h for the public interface contract and TCTI ordering rules.
 *
 * Design notes
 * ------------
 * 1. TSS2_PRIVATE_KEY PEM parsing — the tpm2-openssl provider writes the
 *    subject key as a "TSS2 PRIVATE KEY" PEM.  Structure (per tpm2-tss-engine
 *    and tpm2-openssl):
 *
 *      TSSPrivKey ::= SEQUENCE {
 *          type        OBJECT IDENTIFIER,       -- 2.23.133.10.1.3
 *          emptyAuth   [0] EXPLICIT BOOLEAN OPTIONAL,
 *          parent      INTEGER,                 -- persistent parent handle
 *          pubkey      OCTET STRING,            -- marshalled TPM2B_PUBLIC
 *          privkey     OCTET STRING,            -- marshalled TPM2B_PRIVATE
 *          -- (optional trailing fields are ignored here)
 *      }
 *
 *    Any optional trailing fields (policy, secret, authPolicy, description,
 *    rsaParent) are silently skipped by d2i.
 *
 * 2. Esys flow:
 *
 *      Tss2_TctiLdr_Initialize(tcti_str, &tcti)
 *      Esys_Initialize(&esys, tcti, NULL)
 *      Esys_TR_FromTPMPublic(esys, <parent_handle>, ..., &parent_tr)
 *      Esys_TR_FromTPMPublic(esys, <ak_handle>, ..., &ak_tr)
 *      Esys_Load(esys, parent_tr, ..., &subject_priv, &subject_pub, &subject_tr)
 *      Esys_Certify(esys, subject_tr, ak_tr, ..., &attest, &sig)
 *      Esys_FlushContext(esys, subject_tr)
 *      Esys_Finalize(&esys)
 *      Tss2_TctiLdr_Finalize(&tcti)
 *
 *    The parent and AK are persistent so we do NOT flush them.  We do flush
 *    the transient subject key after certifying so we don't hit the mssim
 *    transient-object limit.
 *
 * 3. Marshalling TPMS_ATTEST / TPMT_SIGNATURE — we use Tss2_MU_* helpers to
 *    turn the ESYS-returned structures into the on-the-wire byte strings that
 *    the CMP attestation bundle embeds.  The verifier re-parses using the same
 *    TPM2 wire format.
 *
 * 4. Logging — libsecutils LOG_err takes a single plain string only.  For
 *    printf-style formatting we use LOG(FL_ERR, fmt, args...) directly.
 */

#include "tpm_ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#include <secutils/util/log.h>

/* ── ASN.1 parser for TSS2 PRIVATE KEY PEM ──────────────────────────────────
 *
 * Only the required fields are declared.  Optional tagged fields at the tail
 * of the SEQUENCE are ignored by OpenSSL's d2i_* helpers.
 */
typedef struct {
    ASN1_OBJECT       *type;
    ASN1_BOOLEAN       emptyAuth;     /* [0] EXPLICIT BOOLEAN OPTIONAL */
    ASN1_INTEGER      *parent;
    ASN1_OCTET_STRING *pubkey;
    ASN1_OCTET_STRING *privkey;
} TSSPRIVKEY;

DECLARE_ASN1_FUNCTIONS(TSSPRIVKEY)

ASN1_SEQUENCE(TSSPRIVKEY) = {
    ASN1_SIMPLE(TSSPRIVKEY, type, ASN1_OBJECT),
    ASN1_EXP_OPT(TSSPRIVKEY, emptyAuth, ASN1_BOOLEAN, 0),
    ASN1_SIMPLE(TSSPRIVKEY, parent, ASN1_INTEGER),
    ASN1_SIMPLE(TSSPRIVKEY, pubkey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(TSSPRIVKEY, privkey, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(TSSPRIVKEY)

IMPLEMENT_ASN1_FUNCTIONS(TSSPRIVKEY)

static TSSPRIVKEY *read_tsspem(const char *path)
{
    BIO *bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        LOG(FL_ERR, "tpm_ops: cannot open TSS2 PRIVATE KEY PEM at %s", path);
        return NULL;
    }

    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long len = 0;
    if (!PEM_read_bio(bio, &name, &header, &data, &len)) {
        LOG(FL_ERR, "tpm_ops: PEM_read_bio failed for %s", path);
        BIO_free(bio);
        return NULL;
    }
    BIO_free(bio);

    if (name == NULL || strcmp(name, "TSS2 PRIVATE KEY") != 0) {
        LOG(FL_ERR, "tpm_ops: expected 'TSS2 PRIVATE KEY' PEM, got '%s'",
            name != NULL ? name : "(null)");
        OPENSSL_free(name); OPENSSL_free(header); OPENSSL_free(data);
        return NULL;
    }

    const unsigned char *p = data;
    TSSPRIVKEY *tk = d2i_TSSPRIVKEY(NULL, &p, len);

    OPENSSL_free(name); OPENSSL_free(header); OPENSSL_free(data);

    if (tk == NULL)
        LOG_err("tpm_ops: d2i_TSSPRIVKEY failed");
    return tk;
}

/* Unmarshal TPM2B_PUBLIC from the pubkey OCTET STRING in the TSS2 PEM. */
static int unmarshal_tpm2b_public(const ASN1_OCTET_STRING *os, TPM2B_PUBLIC *out)
{
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(
        ASN1_STRING_get0_data(os), ASN1_STRING_length(os), &offset, out);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: TPM2B_PUBLIC unmarshal failed: %s", Tss2_RC_Decode(rc));
        return 0;
    }
    return 1;
}

/* Unmarshal TPM2B_PRIVATE from the privkey OCTET STRING in the TSS2 PEM. */
static int unmarshal_tpm2b_private(const ASN1_OCTET_STRING *os, TPM2B_PRIVATE *out)
{
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(
        ASN1_STRING_get0_data(os), ASN1_STRING_length(os), &offset, out);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: TPM2B_PRIVATE unmarshal failed: %s", Tss2_RC_Decode(rc));
        return 0;
    }
    return 1;
}

/* Marshal TPMS_ATTEST to a newly-allocated buffer.
 * The verifier decodes the same structure; see tpm_verifier.py _parse_tpms_attest.
 */
static int marshal_attest(const TPM2B_ATTEST *attest,
                          unsigned char **out, size_t *out_len)
{
    /* TPM2B_ATTEST has a 2-byte size prefix + attestationData.
     * The verifier handles either TPM2B_ATTEST or bare TPMS_ATTEST.  We emit
     * the bare TPMS_ATTEST (skip the 2-byte prefix) to mirror what tpm2-tools
     * emits by default, keeping the two compatible.
     */
    if (attest->size < 1) {
        LOG_err("tpm_ops: Esys_Certify returned empty TPM2B_ATTEST");
        return 0;
    }
    unsigned char *buf = OPENSSL_malloc(attest->size);
    if (buf == NULL) {
        LOG_err("tpm_ops: OPENSSL_malloc failed for TPMS_ATTEST");
        return 0;
    }
    memcpy(buf, attest->attestationData, attest->size);
    *out = buf;
    *out_len = attest->size;
    return 1;
}

/* Marshal the TPMT_PUBLIC part of a TPM2B_PUBLIC into a newly-allocated buffer.
 * The verifier uses this to compute the TPM name H(TPMT_PUBLIC) and check it
 * against TPMS_CERTIFY_INFO.name (G1 key-binding check).
 */
static int marshal_tpmt_public(const TPM2B_PUBLIC *pub,
                               unsigned char **out, size_t *out_len)
{
    size_t max_len = sizeof(TPMT_PUBLIC);
    unsigned char *buf = OPENSSL_malloc(max_len);
    if (buf == NULL) {
        LOG_err("tpm_ops: OPENSSL_malloc failed for TPMT_PUBLIC");
        return 0;
    }
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPMT_PUBLIC_Marshal(&pub->publicArea, buf, max_len, &offset);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: TPMT_PUBLIC marshal failed: %s", Tss2_RC_Decode(rc));
        OPENSSL_free(buf);
        return 0;
    }
    *out = buf;
    *out_len = offset;
    return 1;
}

/* Marshal TPMT_SIGNATURE to a newly-allocated buffer (full wire format:
 * 2B sigAlg + 2B hashAlg + 2B size + sig bytes for RSASSA-SHA256).  The
 * verifier's _extract_raw_sig_rsassa() parses exactly this format.
 */
static int marshal_signature(const TPMT_SIGNATURE *sig,
                             unsigned char **out, size_t *out_len)
{
    /* Tss2_MU produces the canonical wire format. */
    size_t len = sizeof(TPMT_SIGNATURE);   /* upper bound */
    unsigned char *buf = OPENSSL_malloc(len);
    if (buf == NULL) {
        LOG_err("tpm_ops: OPENSSL_malloc failed for TPMT_SIGNATURE");
        return 0;
    }
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPMT_SIGNATURE_Marshal(sig, buf, len, &offset);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: TPMT_SIGNATURE marshal failed: %s", Tss2_RC_Decode(rc));
        OPENSSL_free(buf);
        return 0;
    }
    *out = buf;
    *out_len = offset;
    return 1;
}

/* Initialize the TCTI then ESYS, mirroring esys_teardown().  On success
 * *tcti and *esys are set and the caller must release both with
 * esys_teardown().  On failure both are left NULL (any partially-opened TCTI
 * is finalized here) and the caller can simply return.  Returns 1/0. */
static int esys_setup(const char *tcti_str,
                      TSS2_TCTI_CONTEXT **tcti, ESYS_CONTEXT **esys)
{
    *tcti = NULL;
    *esys = NULL;

    TSS2_RC rc = Tss2_TctiLdr_Initialize(tcti_str, tcti);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: Tss2_TctiLdr_Initialize(%s) failed: %s",
            tcti_str, Tss2_RC_Decode(rc));
        return 0;
    }

    rc = Esys_Initialize(esys, *tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: Esys_Initialize failed: %s", Tss2_RC_Decode(rc));
        Tss2_TctiLdr_Finalize(tcti);
        return 0;
    }
    return 1;
}

static void esys_teardown(ESYS_CONTEXT *esys, TSS2_TCTI_CONTEXT *tcti)
{
    if (esys != NULL)
        Esys_Finalize(&esys);
    if (tcti != NULL)
        Tss2_TctiLdr_Finalize(&tcti);
}

int tpm_certify_key_from_pem(const char *tcti_str,
                             uint32_t ak_handle,
                             const char *subject_key_pem_path,
                             const unsigned char *nonce, size_t nonce_len,
                             unsigned char **attest_out, size_t *attest_len,
                             unsigned char **sig_out, size_t *sig_len,
                             unsigned char **tpmt_public_out,
                             size_t *tpmt_public_len)
{
    if (tcti_str == NULL || subject_key_pem_path == NULL
            || attest_out == NULL || attest_len == NULL
            || sig_out == NULL || sig_len == NULL
            || tpmt_public_out == NULL || tpmt_public_len == NULL) {
        LOG_err("tpm_ops: invalid NULL argument to tpm_certify_key_from_pem");
        return 0;
    }
    if (nonce_len > sizeof(((TPM2B_DATA *)0)->buffer)) {
        LOG(FL_ERR, "tpm_ops: nonce too large for TPM2B_DATA (%zu > %zu)",
            nonce_len, sizeof(((TPM2B_DATA *)0)->buffer));
        return 0;
    }

    int ok = 0;

    /* 1. Parse the TSS2 PRIVATE KEY PEM so we learn the parent handle plus the
     *    wrapped key blobs we need to Esys_Load. */
    TSSPRIVKEY *tk = read_tsspem(subject_key_pem_path);
    if (tk == NULL)
        return 0;

    long parent_long = ASN1_INTEGER_get(tk->parent);
    if (parent_long <= 0 || parent_long > 0xFFFFFFFFL) {
        LOG(FL_ERR, "tpm_ops: TSS2 PEM parent handle out of range: %ld", parent_long);
        TSSPRIVKEY_free(tk);
        return 0;
    }
    TPM2_HANDLE parent_handle = (TPM2_HANDLE)parent_long;

    TPM2B_PUBLIC  in_public  = { 0 };
    TPM2B_PRIVATE in_private = { 0 };
    if (!unmarshal_tpm2b_public(tk->pubkey, &in_public)
            || !unmarshal_tpm2b_private(tk->privkey, &in_private)) {
        TSSPRIVKEY_free(tk);
        return 0;
    }
    TSSPRIVKEY_free(tk);

    /* 2. Initialize TCTI + ESYS. */
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    if (!esys_setup(tcti_str, &tcti, &esys))
        return 0;
    TSS2_RC rc;

    ESYS_TR parent_tr = ESYS_TR_NONE;
    ESYS_TR ak_tr     = ESYS_TR_NONE;
    ESYS_TR subject_tr = ESYS_TR_NONE;
    TPM2B_ATTEST  *attest_out_b = NULL;
    TPMT_SIGNATURE *sig_out_s   = NULL;

    /* 3. Map persistent handles to ESYS_TR references. */
    rc = Esys_TR_FromTPMPublic(esys, parent_handle,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &parent_tr);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: Esys_TR_FromTPMPublic(parent=0x%08x) failed: %s",
            parent_handle, Tss2_RC_Decode(rc));
        goto done;
    }

    rc = Esys_TR_FromTPMPublic(esys, ak_handle,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &ak_tr);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: Esys_TR_FromTPMPublic(ak=0x%08x) failed: %s",
            ak_handle, Tss2_RC_Decode(rc));
        goto done;
    }

    /* 4. Load the subject key transiently under the parent. */
    rc = Esys_Load(esys, parent_tr,
                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   &in_private, &in_public, &subject_tr);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: Esys_Load failed: %s", Tss2_RC_Decode(rc));
        goto done;
    }

    /* 5. Certify the subject with the AK.  The scheme comes from the AK's
     *    public area (which in our provisioning is RSASSA-SHA256).  We pass
     *    TPMT_SIG_SCHEME.scheme = TPM2_ALG_NULL so the TPM uses the AK's
     *    default scheme. */
    TPM2B_DATA qualifying = { 0 };
    qualifying.size = (UINT16)nonce_len;
    if (nonce_len > 0)
        memcpy(qualifying.buffer, nonce, nonce_len);

    TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_NULL };

    rc = Esys_Certify(esys,
                      subject_tr,        /* objectHandle      */
                      ak_tr,             /* signHandle (AK)   */
                      ESYS_TR_PASSWORD,  /* subject auth      */
                      ESYS_TR_PASSWORD,  /* AK auth           */
                      ESYS_TR_NONE,
                      &qualifying,
                      &scheme,
                      &attest_out_b,
                      &sig_out_s);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: Esys_Certify failed: %s", Tss2_RC_Decode(rc));
        goto done;
    }

    /* 6. Marshal results to byte buffers the caller can embed in the CSR. */
    if (!marshal_attest(attest_out_b, attest_out, attest_len))
        goto done;
    if (!marshal_signature(sig_out_s, sig_out, sig_len)) {
        OPENSSL_free(*attest_out);
        *attest_out = NULL;
        *attest_len = 0;
        goto done;
    }
    /* Marshal the subject key's TPMT_PUBLIC so the verifier can check
     * TPMS_CERTIFY_INFO.name == H(TPMT_PUBLIC) (G1 key-binding check). */
    if (!marshal_tpmt_public(&in_public, tpmt_public_out, tpmt_public_len)) {
        OPENSSL_free(*attest_out);
        OPENSSL_free(*sig_out);
        *attest_out = NULL; *attest_len = 0;
        *sig_out    = NULL; *sig_len    = 0;
        goto done;
    }

    ok = 1;

done:
    if (subject_tr != ESYS_TR_NONE)
        (void)Esys_FlushContext(esys, subject_tr);

    Esys_Free(attest_out_b);
    Esys_Free(sig_out_s);

    esys_teardown(esys, tcti);
    return ok;
}

/* Read the selected PCR bank values and concatenate them (canonical ascending
 * order) into a newly-allocated buffer.  The concatenation is exactly the
 * preimage of TPMS_QUOTE_INFO.pcrDigest, so the verifier recomputes
 * H(concat) == pcrDigest to bind the per-PCR values to the AK-signed quote
 * (see tpm_verifier.py _check_quote, gate G_PCR_VALUES_BIND). */
static int read_pcr_values(ESYS_CONTEXT *esys,
                           const TPML_PCR_SELECTION *pcr_select,
                           unsigned char **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;

    /* Count requested PCRs from the selection bitmap so we can detect a short
     * read (a single TPM2_PCR_Read returns at most 8 PCRs). */
    size_t requested = 0;
    for (UINT32 b = 0; b < pcr_select->count; b++) {
        const TPMS_PCR_SELECTION *s = &pcr_select->pcrSelections[b];
        for (UINT32 i = 0; i < s->sizeofSelect; i++)
            for (int bit = 0; bit < 8; bit++)
                if (s->pcrSelect[i] & (1u << bit))
                    requested++;
    }

    UINT32 update_counter = 0;
    TPML_PCR_SELECTION *sel_out = NULL;
    TPML_DIGEST *vals = NULL;
    TSS2_RC rc = Esys_PCR_Read(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               pcr_select, &update_counter, &sel_out, &vals);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: Esys_PCR_Read failed: %s", Tss2_RC_Decode(rc));
        return 0;
    }

    int ok = 0;
    /* Require an exact match: never ship a partial / mis-ordered value set the
     * verifier would reject against the signed digest. */
    if (vals->count != requested) {
        LOG(FL_ERR, "tpm_ops: Esys_PCR_Read returned %u value(s), requested %zu "
                    "(>8 PCRs need multiple reads — unsupported in this profile)",
            vals->count, (unsigned long)requested);
        goto cleanup;
    }

    size_t total = 0;
    for (UINT32 i = 0; i < vals->count; i++)
        total += vals->digests[i].size;

    unsigned char *buf = OPENSSL_malloc(total ? total : 1);
    if (buf == NULL) {
        LOG_err("tpm_ops: OPENSSL_malloc failed for pcrValues");
        goto cleanup;
    }
    {
        size_t off = 0;
        for (UINT32 i = 0; i < vals->count; i++) {
            memcpy(buf + off, vals->digests[i].buffer, vals->digests[i].size);
            off += vals->digests[i].size;
        }
    }
    *out = buf;
    *out_len = total;
    ok = 1;
    LOG(FL_INFO, "tpm_ops: read %u PCR value(s), %zu raw bytes for pcrValues "
                 "binding", vals->count, (unsigned long)total);

cleanup:
    Esys_Free(sel_out);
    Esys_Free(vals);
    return ok;
}

int tpm_quote_pcrs(const char *tcti_str,
                   uint32_t ak_handle,
                   const unsigned char *nonce, size_t nonce_len,
                   const unsigned int *pcr_indices, size_t pcr_count,
                   unsigned char **attest_out, size_t *attest_len,
                   unsigned char **sig_out, size_t *sig_len,
                   unsigned char **pcr_values_out, size_t *pcr_values_len)
{
    if (tcti_str == NULL
            || attest_out == NULL || attest_len == NULL
            || sig_out == NULL || sig_len == NULL) {
        LOG_err("tpm_ops: invalid NULL argument to tpm_quote_pcrs");
        return 0;
    }
    /* pcr_values_out / pcr_values_len are optional but must be paired. */
    if ((pcr_values_out == NULL) != (pcr_values_len == NULL)) {
        LOG_err("tpm_ops: pcr_values_out and pcr_values_len must both be set "
                "or both NULL");
        return 0;
    }
    if (pcr_values_out != NULL) {
        *pcr_values_out = NULL;
        *pcr_values_len = 0;
    }
    if (nonce_len > sizeof(((TPM2B_DATA *)0)->buffer)) {
        LOG(FL_ERR, "tpm_ops: nonce too large for TPM2B_DATA (%zu > %zu)",
            nonce_len, sizeof(((TPM2B_DATA *)0)->buffer));
        return 0;
    }
    /* PCR-selection bitmap is 3 bytes (24 PCRs); reject indices outside that. */
    for (size_t i = 0; i < pcr_count; i++) {
        if (pcr_indices == NULL) break;
        if (pcr_indices[i] >= 24) {
            LOG(FL_ERR, "tpm_ops: PCR index %u out of range (must be < 24)",
                pcr_indices[i]);
            return 0;
        }
    }

    int ok = 0;

    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    if (!esys_setup(tcti_str, &tcti, &esys))
        return 0;
    TSS2_RC rc;

    ESYS_TR ak_tr = ESYS_TR_NONE;
    TPM2B_ATTEST  *attest_b = NULL;
    TPMT_SIGNATURE *sig_s   = NULL;

    rc = Esys_TR_FromTPMPublic(esys, ak_handle,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &ak_tr);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: Esys_TR_FromTPMPublic(ak=0x%08x) failed: %s",
            ak_handle, Tss2_RC_Decode(rc));
        goto done;
    }

    /* PCR selection: SHA-256 bank, indices supplied by the verifier
     * (NonceResponse.respInfo TPM20QuoteRespInfo).
     * pcrSelect is a little-endian bitmap by byte:
     *   byte 0 bits 0..7 → PCRs 0..7
     *   byte 1 bits 0..7 → PCRs 8..15
     *   byte 2 bits 0..7 → PCRs 16..23
     *
     * When pcr_indices is NULL/empty (legacy callers), fall back to
     * 0x1F in byte 0 (PCRs 0..4), matching the E2E platform stack's
     * default PCR reference baseline. */
    TPML_PCR_SELECTION pcr_select;
    memset(&pcr_select, 0, sizeof(pcr_select));
    pcr_select.count = 1;
    pcr_select.pcrSelections[0].hash         = TPM2_ALG_SHA256;
    pcr_select.pcrSelections[0].sizeofSelect = 3;
    if (pcr_indices != NULL && pcr_count > 0) {
        for (size_t i = 0; i < pcr_count; i++) {
            unsigned int idx = pcr_indices[i];
            pcr_select.pcrSelections[0].pcrSelect[idx / 8] |= (1u << (idx % 8));
        }
        LOG(FL_INFO, "tpm_ops: Quoting verifier-selected PCRs: sha256 (%zu indices)",
            pcr_count);
    } else {
        pcr_select.pcrSelections[0].pcrSelect[0] = 0x1F;
        LOG(FL_INFO, "tpm_ops: Quoting fallback PCR set: sha256 [0..4]");
    }

    TPM2B_DATA qualifying = { 0 };
    qualifying.size = (UINT16)nonce_len;
    if (nonce_len > 0)
        memcpy(qualifying.buffer, nonce, nonce_len);

    /* TPMT_SIG_SCHEME.scheme = TPM2_ALG_NULL → TPM uses the AK's default
     * scheme (RSASSA-SHA256 in our provisioning). */
    TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_NULL };

    rc = Esys_Quote(esys,
                    ak_tr,             /* signHandle (AK)   */
                    ESYS_TR_PASSWORD,  /* AK auth           */
                    ESYS_TR_NONE, ESYS_TR_NONE,
                    &qualifying,
                    &scheme,
                    &pcr_select,
                    &attest_b,
                    &sig_s);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: Esys_Quote failed: %s", Tss2_RC_Decode(rc));
        goto done;
    }

    if (!marshal_attest(attest_b, attest_out, attest_len))
        goto done;
    if (!marshal_signature(sig_s, sig_out, sig_len)) {
        OPENSSL_free(*attest_out);
        *attest_out = NULL;
        *attest_len = 0;
        goto done;
    }

    /* Read the raw per-PCR values for the SAME selection the quote covered, so
     * the verifier can recompute pcrDigest = H(values) and bind the individual
     * values to the AK-signed quote.  All-or-nothing: on failure discard the
     * already-marshalled attest/sig so the caller never sees partial output. */
    if (pcr_values_out != NULL
            && !read_pcr_values(esys, &pcr_select, pcr_values_out, pcr_values_len)) {
        LOG_err("tpm_ops: read_pcr_values failed after quote");
        OPENSSL_free(*attest_out); *attest_out = NULL; *attest_len = 0;
        OPENSSL_free(*sig_out);    *sig_out = NULL;    *sig_len = 0;
        goto done;
    }

    ok = 1;

done:
    Esys_Free(attest_b);
    Esys_Free(sig_s);
    esys_teardown(esys, tcti);
    return ok;
}

/*
 * tpm_rsa_oaep_decrypt — see tpm_ops.h for the contract.
 *
 * Pattern mirrors tpm_certify_key_from_pem:
 *   1. Parse the TSS2_PRIVATE_KEY PEM → parent handle + wrapped subject key.
 *   2. Initialize TCTI + ESYS.
 *   3. Map parent handle to ESYS_TR; Esys_Load the subject key transiently.
 *   4. Esys_RSA_Decrypt with TPM_ALG_OAEP / TPM_ALG_SHA256, no label.
 *   5. Marshal plaintext into a caller-owned buffer; flush subject; teardown.
 */
int tpm_rsa_oaep_decrypt(const char *tcti_str,
                         const char *subject_key_pem_path,
                         const unsigned char *ciphertext,
                         size_t ciphertext_len,
                         unsigned char **plaintext_out,
                         size_t *plaintext_len)
{
    if (tcti_str == NULL || subject_key_pem_path == NULL
            || ciphertext == NULL || ciphertext_len == 0
            || plaintext_out == NULL || plaintext_len == NULL) {
        LOG_err("tpm_ops: invalid NULL/zero argument to tpm_rsa_oaep_decrypt");
        return 0;
    }
    if (ciphertext_len > sizeof(((TPM2B_PUBLIC_KEY_RSA *)0)->buffer)) {
        LOG(FL_ERR,
            "tpm_ops: ciphertext too large for TPM2B_PUBLIC_KEY_RSA (%zu > %zu)",
            ciphertext_len,
            sizeof(((TPM2B_PUBLIC_KEY_RSA *)0)->buffer));
        return 0;
    }

    int ok = 0;

    /* 1. Parse the TSS2 PRIVATE KEY PEM. */
    TSSPRIVKEY *tk = read_tsspem(subject_key_pem_path);
    if (tk == NULL)
        return 0;

    long parent_long = ASN1_INTEGER_get(tk->parent);
    if (parent_long <= 0 || parent_long > 0xFFFFFFFFL) {
        LOG(FL_ERR, "tpm_ops: TSS2 PEM parent handle out of range: %ld", parent_long);
        TSSPRIVKEY_free(tk);
        return 0;
    }
    TPM2_HANDLE parent_handle = (TPM2_HANDLE)parent_long;

    TPM2B_PUBLIC  in_public  = { 0 };
    TPM2B_PRIVATE in_private = { 0 };
    if (!unmarshal_tpm2b_public(tk->pubkey, &in_public)
            || !unmarshal_tpm2b_private(tk->privkey, &in_private)) {
        TSSPRIVKEY_free(tk);
        return 0;
    }
    TSSPRIVKEY_free(tk);

    /* 2. Initialize TCTI + ESYS. */
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    if (!esys_setup(tcti_str, &tcti, &esys))
        return 0;
    TSS2_RC rc;

    ESYS_TR parent_tr  = ESYS_TR_NONE;
    ESYS_TR subject_tr = ESYS_TR_NONE;
    TPM2B_PUBLIC_KEY_RSA *plaintext_b = NULL;

    /* 3. Map parent handle, Load subject key transiently. */
    rc = Esys_TR_FromTPMPublic(esys, parent_handle,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &parent_tr);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: Esys_TR_FromTPMPublic(parent=0x%08x) failed: %s",
            parent_handle, Tss2_RC_Decode(rc));
        goto done;
    }

    rc = Esys_Load(esys, parent_tr,
                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   &in_private, &in_public, &subject_tr);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: Esys_Load(subject) failed: %s", Tss2_RC_Decode(rc));
        goto done;
    }

    /* 4. Decrypt.  RSA-OAEP with SHA-256 hash, no label. */
    TPM2B_PUBLIC_KEY_RSA cipher_in = { 0 };
    cipher_in.size = (UINT16)ciphertext_len;
    memcpy(cipher_in.buffer, ciphertext, ciphertext_len);

    TPMT_RSA_DECRYPT scheme = {
        .scheme  = TPM2_ALG_OAEP,
        .details = { .oaep = { .hashAlg = TPM2_ALG_SHA256 } },
    };
    TPM2B_DATA label = { 0 };

    rc = Esys_RSA_Decrypt(esys,
                          subject_tr,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          &cipher_in,
                          &scheme,
                          &label,
                          &plaintext_b);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(FL_ERR, "tpm_ops: Esys_RSA_Decrypt failed: %s — verify the subject "
            "key was provisioned with decrypt=1, scheme=RSA_OAEP, "
            "halg=SHA-256 (SPEC §C-2)", Tss2_RC_Decode(rc));
        goto done;
    }

    /* 5. Copy plaintext into a caller-owned buffer. */
    if (plaintext_b == NULL || plaintext_b->size == 0) {
        LOG_err("tpm_ops: Esys_RSA_Decrypt returned empty plaintext");
        goto done;
    }
    *plaintext_out = OPENSSL_malloc(plaintext_b->size);
    if (*plaintext_out == NULL) {
        LOG_err("tpm_ops: out of memory marshalling OAEP plaintext");
        goto done;
    }
    memcpy(*plaintext_out, plaintext_b->buffer, plaintext_b->size);
    *plaintext_len = plaintext_b->size;

    LOG(FL_INFO,
        "tpm_ops: RSA_OAEP decrypted %zu ciphertext bytes → %u plaintext bytes",
        ciphertext_len, plaintext_b->size);

    ok = 1;

done:
    if (subject_tr != ESYS_TR_NONE)
        (void)Esys_FlushContext(esys, subject_tr);

    Esys_Free(plaintext_b);
    esys_teardown(esys, tcti);
    return ok;
}
