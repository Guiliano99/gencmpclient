/*-
 * @file   src/cwt_cmd.h
 * @brief  Run an external helper (xclaim wrapper) that builds + signs the CWT.
 *
 * The helper is invoked AFTER the CMP GenP, so the server-issued RA nonce is
 * known and goes into the signed claims; see src/cose_hpke0.h for the sealing.
 */
#ifndef CWT_CMD_H
# define CWT_CMD_H

# include <stddef.h>

# define CWT_CMD_NONCE_MIN 8
# define CWT_CMD_NONCE_MAX 64

/*
 * Run `<cmd> <nonce-hex> <out-path>` (no shell) and return the CWT it wrote.
 *
 * cmd       absolute path of an executable helper
 * nonce     server nonce, CWT_CMD_NONCE_MIN..CWT_CMD_NONCE_MAX bytes
 * cwt       out: malloc'd CWT bytes (caller frees with free())
 *
 * Fails (returns 0) on: relative path, bad nonce length, spawn error, timeout,
 * non-zero exit, empty/oversized output, or a structurally invalid CWT.  The
 * exit status alone is NOT trusted (xclaim exits 0 on most errors), hence the
 * structural check; the signature and the nonce VALUE are the verifier's job.
 */
int cwt_cmd_run(const char *cmd, const unsigned char *nonce, size_t nonce_len,
                unsigned char **cwt, size_t *cwt_len);

#endif /* CWT_CMD_H */
