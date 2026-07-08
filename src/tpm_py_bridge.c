/*-
 * @file   src/tpm_py_bridge.c
 * @brief  Embedded-CPython bridge into libattest.attester.evidence_bridge.
 *
 * See src/tpm_py_bridge.h for the public interface contract.
 *
 * Design notes
 * ------------
 * 1. Python.h must be the first include (CPython requirement — it may set
 *    feature-test macros that need to precede any system header).
 *
 * 2. Interpreter lifecycle: lazily initialized on first call, cached for the
 *    process lifetime, never finalized. gencmpclient is single-threaded and
 *    calls at most one of these two functions per run, so there is no other
 *    thread to coordinate the GIL with and no reason to pay for repeated
 *    init/teardown. See tpm_py_bridge.h for why Py_Finalize() is deliberately
 *    not called.
 *
 * 3. Argument marshalling uses Py_BuildValue-style format codes (the same
 *    table PyObject_CallFunction uses) — NOT the PyArg_ParseTuple table.
 *    Notably "p" (bool predicate) is PyArg_ParseTuple-only and raises
 *    "SystemError: bad format char" if used here; a plain "i" carries the
 *    corrupt_signature flag instead (Python's bool is int-like, so 0/1 is
 *    exactly as good as True/False at the call site).
 *
 * 4. PYTHONPATH: the embedded interpreter must be able to `import libattest`.
 *    An editable pip install's .pth redirect is NOT processed for arbitrary
 *    PYTHONPATH directories (only for a venv's own site-packages during site
 *    init), so the attester image sets PYTHONPATH to libattest's source tree
 *    directly (plus wherever its third-party dependencies are installed) —
 *    see the TPMPCRDemo/TPMKeyAttestDemo Dockerfiles.
 */

#include <Python.h>

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>

#include <secutils/util/log.h>

#include "tpm_py_bridge.h"

/* ── Interpreter + resolved-callable cache ──────────────────────────────── */

static PyObject *g_bridge_module = NULL;
static PyObject *g_generate_func = NULL;

/* Lazily initialize the embedded interpreter and resolve
 * libattest.attester.evidence_bridge.generate_tpm_evidence once.  Idempotent;
 * safe to call before every bridge invocation.  Returns 1/0. */
static int ensure_python_ready(void)
{
    if (g_generate_func != NULL)
        return 1;

    if (!Py_IsInitialized())
        Py_Initialize();

    if (g_bridge_module == NULL) {
        g_bridge_module = PyImport_ImportModule("libattest.attester.evidence_bridge");
        if (g_bridge_module == NULL) {
            PyErr_Print();
            LOG_err("tpm_py_bridge: could not import "
                    "libattest.attester.evidence_bridge — is libattest-py on "
                    "PYTHONPATH?");
            return 0;
        }
    }

    g_generate_func = PyObject_GetAttrString(g_bridge_module, "generate_tpm_evidence");
    if (g_generate_func == NULL || !PyCallable_Check(g_generate_func)) {
        PyErr_Print();
        LOG_err("tpm_py_bridge: generate_tpm_evidence not found/callable in "
                "libattest.attester.evidence_bridge");
        Py_CLEAR(g_generate_func);
        return 0;
    }
    return 1;
}

/* Log the current Python exception (context-prefixed, one line) and clear it. */
static void log_python_error(const char *context)
{
    PyObject *type = NULL, *value = NULL, *tb = NULL;

    if (!PyErr_Occurred()) {
        LOG(FL_ERR, "tpm_py_bridge: %s: (no Python exception set)", context);
        return;
    }
    PyErr_Fetch(&type, &value, &tb);
    PyErr_NormalizeException(&type, &value, &tb);
    if (value != NULL) {
        PyObject *msg = PyObject_Str(value);
        const char *msg_c = (msg != NULL) ? PyUnicode_AsUTF8(msg) : NULL;
        LOG(FL_ERR, "tpm_py_bridge: %s: %s", context,
            msg_c != NULL ? msg_c : "<unprintable exception>");
        Py_XDECREF(msg);
    } else {
        LOG(FL_ERR, "tpm_py_bridge: %s: (exception with no value)", context);
    }
    Py_XDECREF(type);
    Py_XDECREF(value);
    Py_XDECREF(tb);
}

/* Build a tpm2-tools-style "sha256:idx,idx,..." selection string from
 * |pcr_indices|/|pcr_count| into |buf| (|buf_size| bytes).  Only SHA-256 is
 * ever reached here — the caller (cmpClient.c) already hard-rejects any other
 * verifier-proposed hash bank before calling into this bridge.  Returns 1 on
 * success, 0 if pcr_count is 0 (nothing to build — caller passes NULL and lets
 * libattest-py's own default PCR set apply) or the buffer would overflow. */
static int build_pcr_selection(const unsigned int *pcr_indices, size_t pcr_count,
                               char *buf, size_t buf_size)
{
    size_t offset;
    size_t i;
    int n;

    if (pcr_indices == NULL || pcr_count == 0)
        return 0;

    n = snprintf(buf, buf_size, "sha256:");
    if (n < 0 || (size_t)n >= buf_size)
        return 0;
    offset = (size_t)n;

    for (i = 0; i < pcr_count; i++) {
        n = snprintf(buf + offset, buf_size - offset, "%s%u",
                     i == 0 ? "" : ",", pcr_indices[i]);
        if (n < 0 || (size_t)n >= buf_size - offset)
            return 0;
        offset += (size_t)n;
    }
    return 1;
}

/* Shared core: call generate_tpm_evidence(kind, nonce, tcti, ak_handle,
 * pcr_selection, subject_key_pem, corrupt_signature), unpack the returned
 * (evidence_der, type_oid) tuple, and copy both into caller-owned
 * OPENSSL_malloc'd buffers. Returns 1/0. */
static int call_generate_tpm_evidence(const char *kind,
                                      const char *tcti_str, uint32_t ak_handle,
                                      const unsigned char *nonce, size_t nonce_len,
                                      const char *pcr_selection,
                                      const char *subject_key_pem_path,
                                      int corrupt_signature,
                                      unsigned char **evidence_der_out, size_t *evidence_der_len,
                                      char **type_oid_out)
{
    PyObject *result = NULL;
    const char *der_ptr = NULL, *oid_cstr = NULL;
    Py_ssize_t der_len = 0;
    int ok = 0;

    if (tcti_str == NULL || nonce == NULL
            || evidence_der_out == NULL || evidence_der_len == NULL
            || type_oid_out == NULL) {
        LOG_err("tpm_py_bridge: invalid NULL argument to call_generate_tpm_evidence");
        return 0;
    }
    *evidence_der_out = NULL;
    *evidence_der_len = 0;
    *type_oid_out = NULL;

    if (!ensure_python_ready())
        return 0;

    result = PyObject_CallFunction(g_generate_func, "sy#sIzzi",
                                   kind,
                                   (const char *)nonce, (Py_ssize_t)nonce_len,
                                   tcti_str,
                                   (unsigned int)ak_handle,
                                   pcr_selection,       /* "z": NULL -> None */
                                   subject_key_pem_path, /* "z": NULL -> None */
                                   corrupt_signature ? 1 : 0);
    if (result == NULL) {
        log_python_error("generate_tpm_evidence call failed");
        return 0;
    }

    if (!PyArg_ParseTuple(result, "y#s", &der_ptr, &der_len, &oid_cstr)) {
        log_python_error("generate_tpm_evidence returned an unexpected shape");
        goto done;
    }

    *evidence_der_out = OPENSSL_malloc((size_t)der_len);
    if (*evidence_der_out == NULL) {
        LOG_err("tpm_py_bridge: OPENSSL_malloc failed for evidence DER");
        goto done;
    }
    memcpy(*evidence_der_out, der_ptr, (size_t)der_len);
    *evidence_der_len = (size_t)der_len;

    *type_oid_out = OPENSSL_strdup(oid_cstr);
    if (*type_oid_out == NULL) {
        LOG_err("tpm_py_bridge: OPENSSL_strdup failed for type OID");
        OPENSSL_free(*evidence_der_out);
        *evidence_der_out = NULL;
        *evidence_der_len = 0;
        goto done;
    }

    LOG(FL_INFO, "tpm_py_bridge: generate_tpm_evidence(kind=%s) produced "
                "%zu-byte evidence DER, type OID %s",
        kind, *evidence_der_len, *type_oid_out);
    ok = 1;

done:
    Py_DECREF(result);
    return ok;
}

int tpm2_quote_generate_evidence(const char *tcti_str,
                                 uint32_t ak_handle,
                                 const unsigned char *nonce, size_t nonce_len,
                                 const unsigned int *pcr_indices, size_t pcr_count,
                                 int corrupt_signature,
                                 unsigned char **evidence_der_out, size_t *evidence_der_len,
                                 char **type_oid_out)
{
    char pcr_selection_buf[128];
    const char *pcr_selection = NULL;

    if (build_pcr_selection(pcr_indices, pcr_count,
                            pcr_selection_buf, sizeof(pcr_selection_buf)))
        pcr_selection = pcr_selection_buf;

    return call_generate_tpm_evidence("quote", tcti_str, ak_handle,
                                      nonce, nonce_len,
                                      pcr_selection, NULL,
                                      corrupt_signature,
                                      evidence_der_out, evidence_der_len, type_oid_out);
}

int tpm2_key_attest_generate_evidence(const char *tcti_str,
                                      uint32_t ak_handle,
                                      const char *subject_key_pem_path,
                                      const unsigned char *nonce, size_t nonce_len,
                                      int corrupt_signature,
                                      unsigned char **evidence_der_out, size_t *evidence_der_len,
                                      char **type_oid_out)
{
    if (subject_key_pem_path == NULL) {
        LOG_err("tpm_py_bridge: tpm2_key_attest_generate_evidence requires "
                "subject_key_pem_path (TSS2 PRIVATE KEY PEM of the subject key)");
        return 0;
    }

    return call_generate_tpm_evidence("certify", tcti_str, ak_handle,
                                      nonce, nonce_len,
                                      NULL, subject_key_pem_path,
                                      corrupt_signature,
                                      evidence_der_out, evidence_der_len, type_oid_out);
}
