/*-
 * @file   src/cose_hpke0.c
 * @brief  COSE-HPKE-0 COSE_Encrypt0 sealing (OpenSSL HPKE + QCBOR framing).
 */
#include "cose_hpke0.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/hpke.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>

#include <qcbor/qcbor_encode.h>

/* Not secutils' LOG(): its basic.h defines its own bool enum, which clashes with the
 * <stdbool.h> that the QCBOR headers pull in, so this file cannot include both. */
#define ERR(...) (fprintf(stderr, "cose_hpke0: " __VA_ARGS__), fputc('\n', stderr))

#define COSE_ENCRYPT0_TAG 16
#define COSE_HEADER_EK (-4)
#define P256_SPKI_POINT_LEN 65 /* uncompressed point: 0x04 || X || Y */

/* CBOR {1: 35}: COSE header label alg (1) = HPKE-0 (35); deterministic. */
static const unsigned char PROTECTED[] = { 0xA1, 0x01, 0x18, 0x23 };
static const OSSL_HPKE_SUITE SUITE_HPKE0 = {
    OSSL_HPKE_KEM_ID_P256, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_128
};

int cose_hpke0_load_recipient(const char *pem_path, EVP_PKEY **pub)
{
    char group[32];
    FILE *fp = fopen(pem_path, "r");

    *pub = NULL;
    if (fp == NULL) {
        ERR("cannot open recipient key %s", pem_path);
        return 0;
    }
    *pub = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    (void)fclose(fp); /* read-only stream: nothing to flush */
    if (*pub == NULL || !EVP_PKEY_is_a(*pub, "EC")
            || !EVP_PKEY_get_group_name(*pub, group, sizeof(group), NULL)
            || strcmp(group, "prime256v1") != 0) {
        ERR("%s is not an EC P-256 public key", pem_path);
        EVP_PKEY_free(*pub);
        *pub = NULL;
        return 0;
    }
    return 1;
}

/* Finish a QCBOR encode into a malloc'd copy. */
static int finish_copy(QCBOREncodeContext *ec, unsigned char **out, size_t *out_len)
{
    UsefulBufC done;

    if (QCBOREncode_Finish(ec, &done) != QCBOR_SUCCESS)
        return 0;
    *out = malloc(done.len);
    if (*out == NULL)
        return 0;
    memcpy(*out, done.ptr, done.len);
    *out_len = done.len;
    return 1;
}

int cose_hpke0_seal_encrypt0(const unsigned char *pt, size_t pt_len, EVP_PKEY *pub,
                             unsigned char **out, size_t *out_len)
{
    OSSL_HPKE_CTX *hctx = NULL;
    unsigned char *raw = NULL, *enc = NULL, *ct = NULL, *cbor = NULL;
    unsigned char aad[64];
    UsefulBuf aadbuf = { aad, sizeof(aad) };
    UsefulBufC aadc;
    QCBOREncodeContext ec;
    size_t rawlen, enclen = OSSL_HPKE_get_public_encap_size(SUITE_HPKE0);
    size_t ctlen = OSSL_HPKE_get_ciphertext_size(SUITE_HPKE0, pt_len);
    size_t cborcap = ctlen + enclen + 64; /* ct + enc bstrs + tag/array/map/header overhead */
    int ok = 0;

    *out = NULL;
    *out_len = 0;
    rawlen = EVP_PKEY_get1_encoded_public_key(pub, &raw);
    if (rawlen != P256_SPKI_POINT_LEN || raw[0] != 0x04) {
        ERR("recipient key is not an uncompressed P-256 point");
        goto err;
    }
    enc = malloc(enclen);
    ct = malloc(ctlen);
    cbor = malloc(cborcap);
    if (enc == NULL || ct == NULL || cbor == NULL)
        goto err;

    /* aad = Enc_structure ["Encrypt0", protected, external_aad = h''] */
    QCBOREncode_Init(&ec, aadbuf);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddSZString(&ec, "Encrypt0");
    QCBOREncode_AddBytes(&ec, (UsefulBufC){ PROTECTED, sizeof(PROTECTED) });
    QCBOREncode_AddBytes(&ec, (UsefulBufC){ "", 0 });
    QCBOREncode_CloseArray(&ec);
    if (QCBOREncode_Finish(&ec, &aadc) != QCBOR_SUCCESS) {
        ERR("cannot encode Enc_structure");
        goto err;
    }

    hctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, SUITE_HPKE0, OSSL_HPKE_ROLE_SENDER, NULL, NULL);
    if (hctx == NULL
            || !OSSL_HPKE_encap(hctx, enc, &enclen, raw, rawlen, NULL, 0)
            || !OSSL_HPKE_seal(hctx, ct, &ctlen, aadc.ptr, aadc.len, pt, pt_len)) {
        ERR("HPKE encap/seal failed");
        goto err;
    }

    QCBOREncode_Init(&ec, (UsefulBuf){ cbor, cborcap });
    QCBOREncode_AddTag(&ec, COSE_ENCRYPT0_TAG);
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddBytes(&ec, (UsefulBufC){ PROTECTED, sizeof(PROTECTED) });
    QCBOREncode_OpenMap(&ec);
    QCBOREncode_AddBytesToMapN(&ec, COSE_HEADER_EK, (UsefulBufC){ enc, enclen });
    QCBOREncode_CloseMap(&ec);
    QCBOREncode_AddBytes(&ec, (UsefulBufC){ ct, ctlen });
    QCBOREncode_CloseArray(&ec);
    ok = finish_copy(&ec, out, out_len);
    if (!ok)
        ERR("cannot encode COSE_Encrypt0");

 err:
    OSSL_HPKE_CTX_free(hctx);
    OPENSSL_free(raw);
    free(enc);
    free(ct);
    free(cbor);
    return ok;
}

int cose_hpke0_cmw_record(const unsigned char *cose, size_t cose_len,
                          unsigned char **out, size_t *out_len)
{
    QCBOREncodeContext ec;
    size_t cap = cose_len + 64;
    unsigned char *buf = malloc(cap);
    int ok;

    *out = NULL;
    *out_len = 0;
    if (buf == NULL)
        return 0;
    QCBOREncode_Init(&ec, (UsefulBuf){ buf, cap });
    QCBOREncode_OpenArray(&ec);
    QCBOREncode_AddSZString(&ec, "application/cose");
    QCBOREncode_AddBytes(&ec, (UsefulBufC){ cose, cose_len });
    QCBOREncode_CloseArray(&ec);
    ok = finish_copy(&ec, out, out_len);
    free(buf);
    return ok;
}
