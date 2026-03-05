/*-
 * @file   src/rats_csr_asn.c
 * @brief  ASN.1 type definitions for AttestationBundle
 *         (draft-ietf-lamps-csr-attestation-23).
 *
 * Provides the IMPLEMENT_ASN1_FUNCTIONS for LOCAL_ATT_STMT and
 * LOCAL_ATT_BUNDLE, and the ATT_BUNDLE_get_certs_from_der() helper.
 *
 * This file is shared between src/cmpClient.c and test/test_attestation_bundle.c
 * to avoid duplicating the struct definitions and ASN.1 codec tables.
 */

#include "rats_csr_asn.h"

ASN1_SEQUENCE(LOCAL_ATT_STMT) = {
    ASN1_SIMPLE(LOCAL_ATT_STMT, type, ASN1_OBJECT),
    ASN1_SIMPLE(LOCAL_ATT_STMT, stmt, ASN1_ANY),
} ASN1_SEQUENCE_END(LOCAL_ATT_STMT)
IMPLEMENT_ASN1_FUNCTIONS(LOCAL_ATT_STMT)

ASN1_SEQUENCE(LOCAL_ATT_BUNDLE) = {
    ASN1_SEQUENCE_OF(LOCAL_ATT_BUNDLE, attestations, LOCAL_ATT_STMT),
    ASN1_SEQUENCE_OF_OPT(LOCAL_ATT_BUNDLE, certs, X509),
} ASN1_SEQUENCE_END(LOCAL_ATT_BUNDLE)
IMPLEMENT_ASN1_FUNCTIONS(LOCAL_ATT_BUNDLE)

STACK_OF(X509) *ATT_BUNDLE_get_certs_from_der(const unsigned char *der,
                                               long der_len)
{
    const unsigned char *p = der;
    LOCAL_ATT_BUNDLE *bundle;
    STACK_OF(X509) *certs;

    bundle = d2i_LOCAL_ATT_BUNDLE(NULL, &p, der_len);
    if (bundle == NULL)
        return NULL;

    /* Transfer ownership: pull certs out before freeing the bundle shell. */
    certs = bundle->certs;
    bundle->certs = NULL; /* prevent LOCAL_ATT_BUNDLE_free from releasing them */
    LOCAL_ATT_BUNDLE_free(bundle);
    return certs; /* NULL if the certs field was absent */
}

