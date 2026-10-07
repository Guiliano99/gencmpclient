/*-
 * @file   src/cwt_cmd.c
 * @brief  Run an external helper (xclaim wrapper) that builds + signs the CWT.
 */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE /* close_range, mkostemp */
#endif

#include "cwt_cmd.h"
#include "ext_attester.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_spiffy_decode.h>

#define CWT_CMD_TIMEOUT_S 30
#define CWT_CMD_MAX_CWT 16384
#define TAG_CWT 61
#define TAG_COSE_SIGN1 18
#define LABEL_EAT_NONCE 10

/* Not secutils' LOG(): its basic.h defines its own bool enum, which clashes with the
 * <stdbool.h> that the QCBOR headers pull in, so this file cannot include both. */
#define ERR(...) (fprintf(stderr, "cwt_cmd: " __VA_ARGS__), fputc('\n', stderr))

/*
 * Structural check of a CWT: optional tag 61, then tag 18 COSE_Sign1, a 4-item
 * array [bstr, map, bstr payload, bstr sig], whose payload is a CBOR map with a
 * byte-string claim at label 10 (eat_nonce) of CWT_CMD_NONCE_MIN..MAX bytes.
 * Returns 1 if well-formed, 0 otherwise.
 */
static int cwt_cmd_check_cwt(const unsigned char *cwt, size_t len)
{
    QCBORDecodeContext dc;
    QCBORItem item;
    UsefulBufC payload = NULLUsefulBufC, nonce = NULLUsefulBufC;
    uint64_t outer;
    int ok = 0;
    int i;

    QCBORDecode_Init(&dc, (UsefulBufC){cwt, len}, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_VGetNext(&dc, &item);
    if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS
            || item.uDataType != QCBOR_TYPE_ARRAY || item.val.uCount != 4) {
        ERR("output is not a COSE_Sign1 array of 4 items");
        goto done;
    }
    /* QCBOR numbers tags innermost-first: 61(18([...])) is [0]=18, [1]=61 */
    outer = QCBORDecode_GetNthTag(&dc, &item, 1);
    if (QCBORDecode_GetNthTag(&dc, &item, 0) != TAG_COSE_SIGN1
            || (outer != CBOR_TAG_INVALID64
                && (outer != TAG_CWT
                    || QCBORDecode_GetNthTag(&dc, &item, 2) != CBOR_TAG_INVALID64))) {
        ERR("output is not tag 18 (optionally inside tag 61)");
        goto done;
    }
    /* protected bstr, unprotected map (skipped whole), payload bstr, signature bstr */
    for (i = 0; i < 4; i++) {
        QCBORDecode_VGetNextConsume(&dc, &item);
        if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS
                || item.uDataType != (i == 1 ? QCBOR_TYPE_MAP : QCBOR_TYPE_BYTE_STRING)) {
            ERR("COSE_Sign1 item %d has the wrong type", i);
            goto done;
        }
        if (i == 2)
            payload = item.val.string;
    }
    if (QCBORDecode_Finish(&dc) != QCBOR_SUCCESS) {
        ERR("trailing data after the COSE_Sign1");
        goto done;
    }

    QCBORDecode_Init(&dc, payload, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&dc, NULL);
    QCBORDecode_GetByteStringInMapN(&dc, LABEL_EAT_NONCE, &nonce);
    QCBORDecode_ExitMap(&dc);
    if (QCBORDecode_Finish(&dc) != QCBOR_SUCCESS
            || nonce.len < CWT_CMD_NONCE_MIN || nonce.len > CWT_CMD_NONCE_MAX) {
        ERR("payload has no %d..%d byte eat_nonce (label %d)",
            CWT_CMD_NONCE_MIN, CWT_CMD_NONCE_MAX, LABEL_EAT_NONCE);
        goto done;
    }
    ok = 1;
 done:
    return ok;
}

int cwt_cmd_run(const char *cmd, const unsigned char *nonce, size_t nonce_len,
                unsigned char **cwt, size_t *cwt_len)
{
    char tmp_path[] = "/tmp/cwt-XXXXXX";
    unsigned char *buf = NULL;
    size_t len = 0;
    int ok = 0;

    if (cwt == NULL || cwt_len == NULL)
        return 0;
    *cwt = NULL;
    *cwt_len = 0;
    if (nonce == NULL || nonce_len < CWT_CMD_NONCE_MIN || nonce_len > CWT_CMD_NONCE_MAX) {
        ERR("nonce length %zu outside %d..%d",
            nonce == NULL ? 0 : nonce_len, CWT_CMD_NONCE_MIN, CWT_CMD_NONCE_MAX);
        return 0;
    }
    if (!ext_attester_run(cmd, nonce, nonce_len, CWT_CMD_MAX_CWT, tmp_path,
                          &buf, &len))
        return 0;
    if (cwt_cmd_check_cwt(buf, len)) {
        *cwt = buf;
        *cwt_len = len;
        buf = NULL;
        ok = 1;
    }
    free(buf);
    return ok;
}
