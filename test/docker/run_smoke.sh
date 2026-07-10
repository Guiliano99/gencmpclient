#!/usr/bin/env bash
#
# Shared entrypoint for the tpm_py_bridge smoke-test images (Dockerfile.ibm /
# Dockerfile.swtpm).  Starts the simulator named by $SIM, provisions a
# restricted-signing AK, and runs the harness built into the image.
#
# Env (set by each Dockerfile, overridable at `docker run`):
#   SIM        ibm | swtpm   (which simulator to launch)
#   PORT       simulator command port (default 2321; platform/ctrl = PORT+1)
#   AK_HANDLE  persistent AK handle (default 0x81010002)
#   BIN        path to the compiled harness
set -euo pipefail

SIM="${SIM:?SIM must be set to 'ibm' or 'swtpm'}"
PORT="${PORT:-2321}"
AK_HANDLE="${AK_HANDLE:-0x81010002}"
BIN="${BIN:-/opt/tpm-smoke/tpm_py_bridge_smoke}"
STATE="$(mktemp -d)"
SIM_PID=""

cleanup() { [ -n "$SIM_PID" ] && kill "$SIM_PID" 2>/dev/null || true; rm -rf "$STATE"; }
trap cleanup EXIT

case "$SIM" in
  ibm)
    # IBM reference simulator: mssim wire protocol, cmd on PORT, platform PORT+1.
    tpm_server -rm -port "$PORT" >"$STATE/sim.log" 2>&1 &
    SIM_PID=$!
    TCTI="mssim:host=127.0.0.1,port=$PORT"
    ;;
  swtpm)
    # swtpm daemon: data on PORT, control on PORT+1; reached via the native
    # swtpm TCTI.  --flags startup-clear lets the TPM self-Startup.
    swtpm socket --tpm2 --tpmstate "dir=$STATE" \
        --ctrl "type=tcp,port=$((PORT + 1))" --server "type=tcp,port=$PORT" \
        --flags not-need-init,startup-clear >"$STATE/sim.log" 2>&1 &
    SIM_PID=$!
    TCTI="swtpm:host=127.0.0.1,port=$PORT"
    ;;
  *)
    echo "unknown SIM='$SIM' (use 'ibm' or 'swtpm')" >&2
    exit 2
    ;;
esac

# Wait for the simulator's command port to accept connections.
for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then break; fi
    sleep 0.2
done

export TPM2TOOLS_TCTI="$TCTI"
echo "==> [$SIM] simulator up; TCTI=$TCTI"
tpm2_startup -c 2>/dev/null || true

# AK as a restricted-signing PRIMARY: a single transient object (survives the
# tiny object-memory limit of minimal simulators) and a valid TPM2_Quote signer
# whose fixed rsassa-sha256 scheme is what libattest-py's TpmClient.quote()
# resolves to.
echo "==> [$SIM] provisioning restricted-signing AK at $AK_HANDLE"
tpm2_evictcontrol -C o -c "$AK_HANDLE" >/dev/null 2>&1 || true   # clear stale
tpm2_createprimary -C o -g sha256 -G "rsa2048:rsassa:null" \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign' \
    -c "$STATE/ak.ctx" >/dev/null
tpm2_evictcontrol -C o -c "$STATE/ak.ctx" "$AK_HANDLE" >/dev/null
tpm2_flushcontext -t >/dev/null 2>&1 || true

echo "==> [$SIM] running smoke test"
if "$BIN" "$TCTI" "$AK_HANDLE"; then rc=0; else rc=$?; fi
echo "==> [$SIM] smoke test exit=$rc"
exit "$rc"
