#!/usr/bin/env bash
#
# test/tpm_py_bridge_smoke.sh — minimal runtime smoke test for src/tpm_py_bridge.c.
#
# Verifies the embedded-CPython bridge into libattest.attester.evidence_bridge
# end to end against an ISOLATED swtpm software TPM — the host's real
# /dev/tpmrm0 is never touched.  Steps:
#
#   1. start swtpm in a throwaway state dir (mssim protocol on localhost)
#   2. TPM2_Startup, create an SRK, create + persist a restricted signing AK
#   3. build test/tpm_py_bridge_smoke from src/tpm_py_bridge.c
#   4. run it against the simulator; must return a structurally valid DER
#      TcgAttestQuote evidence statement + type OID
#
# Requirements (all apt-installable; none touch the host TPM):
#   swtpm, tpm2-tools, gcc, python3-dev, the TSS2 mssim TCTI module
#
# libattest-py is NOT vendored in this repo (see src/tpm_py_bridge.h) — point
# LIBATTEST_SRC at a local checkout whose src/libattest is importable, e.g.
# the paired libattest-py worktree used during development of this bridge:
#   LIBATTEST_SRC=/path/to/libattest-py/src test/tpm_py_bridge_smoke.sh
# Its own dependencies (tpm2-pytss, cryptography, pyasn1, pyasn1-alt-modules)
# must already be importable by the `python3` on PATH (e.g. pip installed).
#
# Optional, to also exercise tpm2_build_key_attest_chall() (needs no verifier
# round trip — the EK cert chain's contents are opaque to the TPM side, so a
# throwaway self-signed PEM works fine): export before running to override
# the auto-generated throwaway one built by this script,
#   EK_CERT_CHAIN=/path/to/ek-chain.pem
#
# Usage:  test/tpm_py_bridge_smoke.sh
# Env:    LIBATTEST_SRC (required), AK_HANDLE (default 0x81010002),
#         PORT (default 2321), CC (default gcc)
set -euo pipefail

: "${LIBATTEST_SRC:?set LIBATTEST_SRC to a local libattest-py checkout src/ dir}"
[ -d "$LIBATTEST_SRC/libattest" ] \
    || { echo "ERROR: '$LIBATTEST_SRC/libattest' not found — LIBATTEST_SRC must point at" \
              "libattest-py's src/ dir (the one containing the 'libattest' package)" >&2; exit 1; }

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
for tool in swtpm gcc python3 python3-config openssl tpm2_startup tpm2_createprimary \
            tpm2_evictcontrol tpm2_flushcontext; do
    command -v "$tool" >/dev/null 2>&1 \
        || fail "missing '$tool' — install swtpm + tpm2-tools + python3-dev (e.g. apt install swtpm tpm2-tools python3-dev)"
done

SECUTILS_INC="$REPO/libsecutils/src/libsecutils/include"
[ -d "$SECUTILS_INC" ] || fail "libsecutils headers not found at $SECUTILS_INC (git submodule update --init libsecutils?)"

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
# for TPM2_Quote.  The fixed rsassa-sha256 scheme is what libattest-py's
# TpmClient.quote() relies on (its TPM2_ALG_NULL scheme resolves to the key's
# own scheme).  Note the third "-G" field is the symmetric detail (null for a
# signing key); the hash comes from "-g sha256".
tpm2_evictcontrol -C o -c "$AK_HANDLE" >/dev/null 2>&1 || true   # clear stale
tpm2_createprimary -C o -g sha256 -G "rsa2048:rsassa:null" \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign' \
    -c "$WORK/ak.ctx" >/dev/null
tpm2_evictcontrol -C o -c "$WORK/ak.ctx" "$AK_HANDLE" >/dev/null
tpm2_flushcontext -t >/dev/null 2>&1 || true   # free transient slots

# ── 3. throwaway EK "chain" PEM ──────────────────────────────────────────────
# tpm2_build_key_attest_chall() only packages this PEM's bytes into the
# KeyAttestChall DER — it does not validate the chain (that is the verifier's
# job once it receives the resulting AttestationStatement) — so a self-signed
# placeholder is fine for a smoke run.
EK_CERT_CHAIN="${EK_CERT_CHAIN:-}"
if [ -z "$EK_CERT_CHAIN" ]; then
    EK_CERT_CHAIN="$WORK/ek-chain.pem"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/CN=smoke-test-throwaway-ek" -days 1 -keyout /dev/null \
        -out "$EK_CERT_CHAIN" >/dev/null 2>&1
fi

# ── 4. build the harness ────────────────────────────────────────────────────
log "building tpm_py_bridge_smoke"
BIN="$WORK/tpm_py_bridge_smoke"
PYINC="$(python3-config --includes)"
PYLDFLAGS="$(python3-config --ldflags --embed 2>/dev/null || python3-config --ldflags)"
# shellcheck disable=SC2086
"$CC" -std=gnu11 -Wall -Wextra -Wno-unused-parameter \
    $PYINC -I "$REPO/src" -I "$SECUTILS_INC" \
    "$REPO/test/tpm_py_bridge_smoke.c" "$REPO/src/tpm_py_bridge.c" \
    -L"$REPO" -lsecutils -lcrypto $PYLDFLAGS \
    -Wl,-rpath,"$REPO" -o "$BIN"

# ── 5. run ──────────────────────────────────────────────────────────────────
log "running smoke test against $TCTI (PYTHONPATH=$LIBATTEST_SRC)"
PYTHONPATH="$LIBATTEST_SRC" LD_LIBRARY_PATH="$REPO:${LD_LIBRARY_PATH:-}" \
    "$BIN" "$TCTI" "$AK_HANDLE" "$EK_CERT_CHAIN"
