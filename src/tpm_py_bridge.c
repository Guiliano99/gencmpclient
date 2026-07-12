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

/* Must be defined before including Python.h so the "#" length format codes
 * (y#, s#) below bind Py_ssize_t lengths, not int.  Python 3.10+ turns the
 * mismatch into a hard error ("PY_SSIZE_T_CLEAN macro must be defined for '#'
 * formats"), which aborts every generate_tpm_evidence call.  The length vars
 * here are already Py_ssize_t, so this define is all that was missing. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>

#include <secutils/util/log.h>

#include "tpm_py_bridge.h"

/* ── Interpreter + resolved-callable cache ──────────────────────────────── */

static PyObject *g_bridge_module = NULL;
static PyObject *g_generate_func = NULL;
static PyObject *g_key_attest_func = NULL;
static PyObject *g_build_chall_func = NULL;
static PyObject *g_hpke_module = NULL;
static PyObject *g_encrypt_ear_func = NULL;
static PyObject *g_cose_hpke_module = NULL;
static PyObject *g_encrypt_ear_cose_func = NULL;

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

/* Resolve an additional callable |name| from the (already-imported)
 * evidence_bridge module into |*cache| on first use.  Returns the cached
 * callable (borrowed — the cache owns the reference) or NULL on failure. */
static PyObject *ensure_bridge_callable(PyObject **cache, const char *name)
{
    if (*cache != NULL)
        return *cache;
    if (!ensure_python_ready())
        return NULL;

    *cache = PyObject_GetAttrString(g_bridge_module, name);
    if (*cache == NULL || !PyCallable_Check(*cache)) {
        PyErr_Print();
        LOG(FL_ERR, "tpm_py_bridge: %s not found/callable in "
                    "libattest.attester.evidence_bridge", name);
        Py_CLEAR(*cache);
        return NULL;
    }
    return *cache;
}

/* Resolve src/eareat_hpke_bridge.py::encrypt_ear_with_hpke. The module lives
 * next to this C file in the gencmpclient source tree, so the attester image
 * must include gencmpclient/src on PYTHONPATH when the HPKE path is enabled. */
static int ensure_hpke_ready(void)
{
    if (g_encrypt_ear_func != NULL)
        return 1;

    if (!Py_IsInitialized())
        Py_Initialize();

    if (g_hpke_module == NULL) {
        g_hpke_module = PyImport_ImportModule("eareat_hpke_bridge");
        if (g_hpke_module == NULL) {
            PyErr_Print();
            LOG_err("tpm_py_bridge: could not import eareat_hpke_bridge — "
                    "is gencmpclient/src on PYTHONPATH?");
            return 0;
        }
    }

    g_encrypt_ear_func = PyObject_GetAttrString(g_hpke_module, "encrypt_ear_with_hpke");
    if (g_encrypt_ear_func == NULL || !PyCallable_Check(g_encrypt_ear_func)) {
        PyErr_Print();
        LOG_err("tpm_py_bridge: encrypt_ear_with_hpke not found/callable in "
                "eareat_hpke_bridge");
        Py_CLEAR(g_encrypt_ear_func);
        return 0;
    }
    return 1;
}

/* Resolve src/eareat_cose_hpke_bridge.py::encrypt_ear_with_cose_hpke. Same
 * PYTHONPATH contract as ensure_hpke_ready(); a separate module so the JOSE
 * and COSE HPKE paths (distinct AttestationStatement OIDs) resolve independent
 * Python callables and neither needs the other's dependencies present. */
static int ensure_cose_hpke_ready(void)
{
    if (g_encrypt_ear_cose_func != NULL)
        return 1;

    if (!Py_IsInitialized())
        Py_Initialize();

    if (g_cose_hpke_module == NULL) {
        g_cose_hpke_module = PyImport_ImportModule("eareat_cose_hpke_bridge");
        if (g_cose_hpke_module == NULL) {
            PyErr_Print();
            LOG_err("tpm_py_bridge: could not import eareat_cose_hpke_bridge — "
                    "is gencmpclient/src on PYTHONPATH?");
            return 0;
        }
    }

    g_encrypt_ear_cose_func = PyObject_GetAttrString(g_cose_hpke_module, "encrypt_ear_with_cose_hpke");
    if (g_encrypt_ear_cose_func == NULL || !PyCallable_Check(g_encrypt_ear_cose_func)) {
        PyErr_Print();
        LOG_err("tpm_py_bridge: encrypt_ear_with_cose_hpke not found/callable in "
                "eareat_cose_hpke_bridge");
        Py_CLEAR(g_encrypt_ear_cose_func);
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

/* Unpack a Python (evidence_der: bytes, type_oid: str) 2-tuple into caller-owned
 * OPENSSL_malloc'd buffers.  Returns 1/0; does NOT DECREF |result| (the caller
 * owns it).  Shared by every evidence generator (quote / key-attest). */
static int unpack_evidence_result(PyObject *result,
                                  unsigned char **evidence_der_out, size_t *evidence_der_len,
                                  char **type_oid_out)
{
    const char *der_ptr = NULL, *oid_cstr = NULL;
    Py_ssize_t der_len = 0;

    if (!PyArg_ParseTuple(result, "y#s", &der_ptr, &der_len, &oid_cstr)) {
        log_python_error("evidence generator returned an unexpected shape");
        return 0;
    }

    *evidence_der_out = OPENSSL_malloc((size_t)der_len);
    if (*evidence_der_out == NULL) {
        LOG_err("tpm_py_bridge: OPENSSL_malloc failed for evidence DER");
        return 0;
    }
    memcpy(*evidence_der_out, der_ptr, (size_t)der_len);
    *evidence_der_len = (size_t)der_len;

    *type_oid_out = OPENSSL_strdup(oid_cstr);
    if (*type_oid_out == NULL) {
        LOG_err("tpm_py_bridge: OPENSSL_strdup failed for type OID");
        OPENSSL_free(*evidence_der_out);
        *evidence_der_out = NULL;
        *evidence_der_len = 0;
        return 0;
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

    ok = unpack_evidence_result(result, evidence_der_out, evidence_der_len, type_oid_out);
    Py_DECREF(result);
    if (ok)
        LOG(FL_INFO, "tpm_py_bridge: generate_tpm_evidence(kind=%s) produced "
                    "%zu-byte evidence DER, type OID %s",
            kind, *evidence_der_len, *type_oid_out);
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
                                      const unsigned char *key_attest_resp_der,
                                      size_t key_attest_resp_len,
                                      int corrupt_signature,
                                      unsigned char **evidence_der_out, size_t *evidence_der_len,
                                      char **type_oid_out)
{
    PyObject *fn = NULL, *result = NULL;
    int ok = 0;

    if (tcti_str == NULL || subject_key_pem_path == NULL || nonce == NULL
            || key_attest_resp_der == NULL
            || evidence_der_out == NULL || evidence_der_len == NULL
            || type_oid_out == NULL) {
        LOG_err("tpm_py_bridge: invalid NULL argument to "
                "tpm2_key_attest_generate_evidence");
        return 0;
    }
    *evidence_der_out = NULL;
    *evidence_der_len = 0;
    *type_oid_out = NULL;

    fn = ensure_bridge_callable(&g_key_attest_func, "generate_key_attest_evidence");
    if (fn == NULL)
        return 0;

    /* generate_key_attest_evidence(nonce, tcti, ak_handle, subject_key_pem,
     *                              key_attest_resp_der, corrupt_signature) */
    result = PyObject_CallFunction(fn, "y#sIsy#i",
                                   (const char *)nonce, (Py_ssize_t)nonce_len,
                                   tcti_str,
                                   (unsigned int)ak_handle,
                                   subject_key_pem_path,
                                   (const char *)key_attest_resp_der,
                                   (Py_ssize_t)key_attest_resp_len,
                                   corrupt_signature ? 1 : 0);
    if (result == NULL) {
        log_python_error("generate_key_attest_evidence call failed");
        return 0;
    }

    ok = unpack_evidence_result(result, evidence_der_out, evidence_der_len, type_oid_out);
    Py_DECREF(result);
    if (ok)
        LOG(FL_INFO, "tpm_py_bridge: generate_key_attest_evidence produced "
                    "%zu-byte evidence DER, type OID %s",
            *evidence_der_len, *type_oid_out);
    return ok;
}

int tpm2_build_key_attest_chall(const char *tcti_str,
                                uint32_t ak_handle,
                                const char *ek_cert_chain,
                                unsigned char **chall_der_out, size_t *chall_der_len)
{
    PyObject *fn = NULL, *result = NULL;
    const char *der_ptr = NULL;
    Py_ssize_t der_len = 0;
    int ok = 0;

    if (tcti_str == NULL || ek_cert_chain == NULL
            || chall_der_out == NULL || chall_der_len == NULL) {
        LOG_err("tpm_py_bridge: invalid NULL argument to tpm2_build_key_attest_chall");
        return 0;
    }
    *chall_der_out = NULL;
    *chall_der_len = 0;

    fn = ensure_bridge_callable(&g_build_chall_func, "build_key_attest_chall");
    if (fn == NULL)
        return 0;

    /* build_key_attest_chall(tcti, ak_handle, ek_cert_chain) -> bytes */
    result = PyObject_CallFunction(fn, "sIs",
                                   tcti_str,
                                   (unsigned int)ak_handle,
                                   ek_cert_chain);
    if (result == NULL) {
        log_python_error("build_key_attest_chall call failed");
        return 0;
    }

    if (!PyBytes_Check(result)) {
        LOG_err("tpm_py_bridge: build_key_attest_chall did not return bytes");
        goto done;
    }
    if (PyBytes_AsStringAndSize(result, (char **)&der_ptr, &der_len) < 0) {
        log_python_error("build_key_attest_chall bytes extraction failed");
        goto done;
    }

    *chall_der_out = OPENSSL_malloc((size_t)der_len);
    if (*chall_der_out == NULL) {
        LOG_err("tpm_py_bridge: OPENSSL_malloc failed for KeyAttestChall DER");
        goto done;
    }
    memcpy(*chall_der_out, der_ptr, (size_t)der_len);
    *chall_der_len = (size_t)der_len;
    LOG(FL_INFO, "tpm_py_bridge: build_key_attest_chall produced %zu-byte "
                "KeyAttestChall DER", *chall_der_len);
    ok = 1;

done:
    Py_DECREF(result);
    if (!ok) {
        OPENSSL_free(*chall_der_out);
        *chall_der_out = NULL;
        *chall_der_len = 0;
    }
    return ok;
}

int eareat_hpke_encrypt_ear(const char *enc_private_key_pem,
                            const unsigned char *ear, size_t ear_len,
                            unsigned char **cmw_der_out, size_t *cmw_der_len)
{
    PyObject *result = NULL;
    const char *der_ptr = NULL;
    Py_ssize_t der_len = 0;
    int ok = 0;

    if (enc_private_key_pem == NULL || ear == NULL || ear_len == 0
            || cmw_der_out == NULL || cmw_der_len == NULL) {
        LOG_err("tpm_py_bridge: invalid NULL/empty argument to eareat_hpke_encrypt_ear");
        return 0;
    }
    *cmw_der_out = NULL;
    *cmw_der_len = 0;

    if (!ensure_hpke_ready())
        return 0;

    result = PyObject_CallFunction(g_encrypt_ear_func, "sy#",
                                   enc_private_key_pem,
                                   (const char *)ear, (Py_ssize_t)ear_len);
    if (result == NULL) {
        log_python_error("encrypt_ear_with_hpke call failed");
        return 0;
    }

    if (!PyBytes_Check(result)) {
        LOG_err("tpm_py_bridge: encrypt_ear_with_hpke did not return bytes");
        goto done;
    }
    if (PyBytes_AsStringAndSize(result, (char **)&der_ptr, &der_len) < 0) {
        log_python_error("encrypt_ear_with_hpke bytes extraction failed");
        goto done;
    }

    *cmw_der_out = OPENSSL_malloc((size_t)der_len);
    if (*cmw_der_out == NULL) {
        LOG_err("tpm_py_bridge: OPENSSL_malloc failed for HPKE CMW DER");
        goto done;
    }
    memcpy(*cmw_der_out, der_ptr, (size_t)der_len);
    *cmw_der_len = (size_t)der_len;
    LOG(FL_INFO, "tpm_py_bridge: encrypt_ear_with_hpke produced %zu-byte CMW DER",
        *cmw_der_len);
    ok = 1;

done:
    Py_DECREF(result);
    if (!ok) {
        OPENSSL_free(*cmw_der_out);
        *cmw_der_out = NULL;
        *cmw_der_len = 0;
    }
    return ok;
}

int eareat_cose_hpke_encrypt_ear(const char *enc_private_key_pem,
                                 const unsigned char *ear, size_t ear_len,
                                 unsigned char **cmw_der_out, size_t *cmw_der_len)
{
    PyObject *result = NULL;
    const char *der_ptr = NULL;
    Py_ssize_t der_len = 0;
    int ok = 0;

    if (enc_private_key_pem == NULL || ear == NULL || ear_len == 0
            || cmw_der_out == NULL || cmw_der_len == NULL) {
        LOG_err("tpm_py_bridge: invalid NULL/empty argument to eareat_cose_hpke_encrypt_ear");
        return 0;
    }
    *cmw_der_out = NULL;
    *cmw_der_len = 0;

    if (!ensure_cose_hpke_ready())
        return 0;

    result = PyObject_CallFunction(g_encrypt_ear_cose_func, "sy#",
                                   enc_private_key_pem,
                                   (const char *)ear, (Py_ssize_t)ear_len);
    if (result == NULL) {
        log_python_error("encrypt_ear_with_cose_hpke call failed");
        return 0;
    }

    if (!PyBytes_Check(result)) {
        LOG_err("tpm_py_bridge: encrypt_ear_with_cose_hpke did not return bytes");
        goto done;
    }
    if (PyBytes_AsStringAndSize(result, (char **)&der_ptr, &der_len) < 0) {
        log_python_error("encrypt_ear_with_cose_hpke bytes extraction failed");
        goto done;
    }

    *cmw_der_out = OPENSSL_malloc((size_t)der_len);
    if (*cmw_der_out == NULL) {
        LOG_err("tpm_py_bridge: OPENSSL_malloc failed for COSE-HPKE CMW DER");
        goto done;
    }
    memcpy(*cmw_der_out, der_ptr, (size_t)der_len);
    *cmw_der_len = (size_t)der_len;
    LOG(FL_INFO, "tpm_py_bridge: encrypt_ear_with_cose_hpke produced %zu-byte CMW DER",
        *cmw_der_len);
    ok = 1;

done:
    Py_DECREF(result);
    if (!ok) {
        OPENSSL_free(*cmw_der_out);
        *cmw_der_out = NULL;
        *cmw_der_len = 0;
    }
    return ok;
}
