/*-
 * @file   src/cose_hpke0.h
 * @brief  COSE-HPKE-0 (draft-ietf-cose-hpke) COSE_Encrypt0 sealing + CMW record.
 *
 * Integrated mode, single recipient: HPKE-0 = DHKEM(P-256, HKDF-SHA256) +
 * HKDF-SHA256 + AES-128-GCM, base mode, info = "", COSE alg 35.  The HPKE
 * crypto is OpenSSL's OSSL_HPKE_*; this file only frames the COSE message
 * (QCBOR).  Keep the seal behind cose_hpke0_seal_encrypt0() so it can be
 * swapped for t_cose once its COSE-HPKE support is upstream.
 *
 *   COSE_Encrypt0 = 16([ h'A1011823' (protected {1: 35}),
 *                        { -4: enc },            (unprotected, no kid)
 *                        ct ])
 *   AEAD aad      = ["Encrypt0", h'A1011823', h'']
 */
#ifndef COSE_HPKE0_H
# define COSE_HPKE0_H

# include <stddef.h>
# include <openssl/evp.h>

/* Load an EC P-256 public key (SubjectPublicKeyInfo PEM). 1 on success, 0 on error. */
int cose_hpke0_load_recipient(const char *pem_path, EVP_PKEY **pub);

/* Seal pt to pub; *out is malloc'd (free with free()). 1 on success, 0 on error. */
int cose_hpke0_seal_encrypt0(const unsigned char *pt, size_t pt_len, EVP_PKEY *pub,
                             unsigned char **out, size_t *out_len);

/*
 * CMW CBOR record ["application/cose", bstr(cose)] (draft-ietf-rats-msg-wrap).
 * These bytes are the content of the CMW `cbor` OCTET STRING alternative, i.e.
 * what goes into AttestationStatement.stmt as an ASN.1 OCTET STRING.
 * *out is malloc'd (free with free()). 1 on success, 0 on error.
 */
int cose_hpke0_cmw_record(const unsigned char *cose, size_t cose_len,
                          unsigned char **out, size_t *out_len);

#endif /* COSE_HPKE0_H */
