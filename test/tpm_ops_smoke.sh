#!/usr/bin/env bash
#
# test/tpm_ops_smoke.sh — minimal runtime smoke test for src/tpm_ops.c.
#
# Closes the "not verified against a TPM" gap from the esys_setup refactor by
# running the quote path end-to-end against an ISOLATED swtpm software TPM —
# the host's real /dev/tpmrm0 is never touched.  Steps:
#
#   1. start swtpm in a throwaway state dir (mssim protocol on localhost)
#   2. TPM2_Startup, create an SRK, create + persist a restricted signing AK
#   3. build test/tpm_ops_smoke from src/tpm_ops.c
#   4. run it against the simulator; AK quote must return a valid TPMS_ATTEST
#
# Requirements (all apt-installable; none touch the host TPM):
#   swtpm, tpm2-tools, libtss2-dev, gcc, the TSS2 mssim TCTI module
#
# Optional, to also exercise the certify + decrypt paths, export before running:
#   SUBJECT_PEM=/path/to/tss2-private-key.pem   (TSS2 PRIVATE KEY under a
#                                                 PERSISTENT parent handle)
#   CIPHERTEXT=/path/to/oaep-sha256-ciphertext.bin
#
# Usage:  test/tpm_ops_smoke.sh
# Env:    AK_HANDLE (default 0x81010002), PORT (default 2321), CC (default gcc)
set -euo pipefail

AK_HANDLE="${AK_HANDLE:-0x81010002}"
PORT="${PORT:-2321}"
CTRL_PORT="$((PORT + 1))"
CC="${CC:-gcc}"
TCTI="mssim:host=127.0.0.1,port=${PORT}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
SWTPM_PID=""

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
    [ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# ── prerequisite checks (fail fast with actionable messages) ────────────────
for tool in swtpm gcc tpm2_startup tpm2_createprimary tpm2_evictcontrol \
            tpm2_flushcontext; do
    command -v "$tool" >/dev/null 2>&1 \
        || fail "missing '$tool' — install swtpm + tpm2-tools (e.g. apt install swtpm tpm2-tools)"
done

# TSS2 dev headers needed to compile src/tpm_ops.c.
TSS2_INC=""
for d in /usr/include /usr/local/include; do
    [ -f "$d/tss2/tss2_esys.h" ] && TSS2_INC="$d" && break
done
[ -n "$TSS2_INC" ] || fail "tss2 headers not found — install libtss2-dev"

# ── 1. launch an isolated swtpm ─────────────────────────────────────────────
log "starting swtpm (state in $WORK, mssim port $PORT)"
mkdir -p "$WORK/state"
swtpm socket --tpm2 --tpmstate "dir=$WORK/state" \
    --ctrl "type=tcp,port=$CTRL_PORT" --server "type=tcp,port=$PORT" \
    --flags not-need-init,startup-clear --daemon --pid "file=$WORK/swtpm.pid"
SWTPM_PID="$(cat "$WORK/swtpm.pid")"
sleep 1

export TPM2TOOLS_TCTI="$TCTI"

# ── 2. provision a restricted signing AK, persist it ────────────────────────
log "TPM2_Startup + provisioning AK at $AK_HANDLE"
tpm2_startup -c 2>/dev/null || true   # swtpm started with startup-clear

# Create the AK as a restricted signing PRIMARY in the owner hierarchy.  This
# is a single transient object (works even on minimal simulators with a tiny
# object-memory limit, where SRK+load would exhaust it) and is a valid signer
# for TPM2_Quote.  The fixed rsassa-sha256 scheme is what tpm_quote_pcrs()
# relies on: its TPM2_ALG_NULL scheme resolves to the key's own scheme
# (see src/tpm_ops.c, Esys_Quote).  Note the third "-G" field is the symmetric
# detail (null for a signing key); the hash comes from "-g sha256".
tpm2_evictcontrol -C o -c "$AK_HANDLE" >/dev/null 2>&1 || true   # clear stale
tpm2_createprimary -C o -g sha256 -G "rsa2048:rsassa:null" \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign' \
    -c "$WORK/ak.ctx" >/dev/null
tpm2_evictcontrol -C o -c "$WORK/ak.ctx" "$AK_HANDLE" >/dev/null
tpm2_flushcontext -t >/dev/null 2>&1 || true   # free transient slots

# ── 3. build the harness ────────────────────────────────────────────────────
log "building tpm_ops_smoke"
BIN="$WORK/tpm_ops_smoke"
"$CC" -std=gnu11 -Wall -Wextra -Wno-unused-parameter \
    -I "$REPO/src" -I "$REPO/libsecutils/src/libsecutils/include" -I "$TSS2_INC" \
    "$REPO/test/tpm_ops_smoke.c" "$REPO/src/tpm_ops.c" \
    -L"$REPO" -lsecutils -lcrypto \
    -ltss2-esys -ltss2-tctildr -ltss2-mu -ltss2-rc \
    -Wl,-rpath,"$REPO" -o "$BIN"

# ── 4. run ──────────────────────────────────────────────────────────────────
# Pass the optional subject-PEM / ciphertext args only when set, so the harness
# sees a genuine NULL (not an empty string) for skipped paths.
ARGS=("$TCTI" "$AK_HANDLE")
[ -n "${SUBJECT_PEM:-}" ] && ARGS+=("$SUBJECT_PEM")
[ -n "${SUBJECT_PEM:-}" ] && [ -n "${CIPHERTEXT:-}" ] && ARGS+=("$CIPHERTEXT")

log "running smoke test against $TCTI"
LD_LIBRARY_PATH="$REPO:${LD_LIBRARY_PATH:-}" "$BIN" "${ARGS[@]}"
