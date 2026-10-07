/*-
 * @file   src/ext_attester.h
 * @brief  Run an external attester helper that receives the RATS nonce and
 *         emits a raw evidence statement to a file.
 *
 * Shared spawn helper for the external-attester evidence paths: the xclaim
 * CWT path (src/cwt_cmd.c) and the NXP ELE path (src/cmpClient.c) both use
 * it so the fork/exec/wait/timeout/file-read logic lives in exactly one
 * place. The output is opaque to this module — structural checks (CWT
 * tags) and cryptographic appraisal are each path's own responsibility.
 */
#ifndef EXT_ATTESTER_H
# define EXT_ATTESTER_H

# include <stddef.h>

/*
 * Run `<cmd> <nonce-hex> <out-path>` (no shell) and return the bytes the
 * helper wrote to <out-path>.
 *
 * cmd          absolute path of an executable helper
 * nonce        server nonce (arbitrary length; passed hex-encoded)
 * max_out      maximum acceptable output size in bytes
 * tmp_template caller-owned mkostemp(3) template (e.g. "/tmp/cwt-XXXXXX");
 *              it ends in XXXXXX and is modified in place
 * out          out: malloc'd bytes (caller frees with free())
 * out_len      out: length
 *
 * Fails (returns 0) on: relative path, empty nonce, spawn error, timeout
 * (the helper's whole process group is killed), non-zero exit, or output
 * missing / empty / larger than max_out.
 */
int ext_attester_run(const char *cmd, const unsigned char *nonce, size_t nonce_len,
                     size_t max_out, char *tmp_template,
                     unsigned char **out, size_t *out_len);

#endif /* EXT_ATTESTER_H */
