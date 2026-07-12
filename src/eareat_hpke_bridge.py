# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"""JOSE-HPKE wrapping helper for gencmpclient's ATG/EAR-EAT path.

The C client keeps using libatg to generate the signed software evidence token.
This module only performs the privacy-preserving wrapping step: parse the signed
EAT/JWT enough to recover its nonce, HPKE-seal the compact token to the verifier
recipient key, and return DER(CMW json UTF8String) bytes suitable for the
AttestationStatement.stmt ANY value.

The public API is intentionally small because it is called from embedded
CPython in src/tpm_py_bridge.c.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from libattest.formats import eareat_hpke as evidence
from libattest.formats import jose_hpke, jose_jws


def _parse_jwt_payload(token: bytes) -> dict[str, Any]:
    """Return the unverified JWT payload from a compact JWS token.

    The token has already been signed by ATG; the HPKE wrapper does not appraise
    it. The verifier later verifies the signature. Here we only need public
    header/payload fields to bind the encrypted object to the same nonce.
    """
    text = token.decode("ascii")
    parts = text.split(".")
    if len(parts) != 3:
        raise ValueError("ATG evidence is not a compact JWS")
    return json.loads(jose_jws.b64u_decode(parts[1]))


def _load_hpke_private_key(enc_private_key_pem: str) -> ec.EllipticCurvePrivateKey:
    """Load and validate the verifier HPKE-0 recipient private key."""
    with open(enc_private_key_pem, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("HPKE-0 requires an EC P-256 private key")
    return key


def encrypt_ear_with_hpke(enc_private_key_pem: str, ear: bytes) -> bytes:
    """Return DER(CMW json UTF8String) carrying a JOSE-HPKE JWE of ``ear``.

    ``ear`` is the already-signed compact EAT/JWT bytes returned by ATG. The
    parameter name is kept as requested by the design note even though the value
    is evidence, not the final verifier-issued EAR result. ``enc_private_key_pem``
    is the verifier HPKE recipient private key; this helper derives the public
    key from it and encrypts to that public key. Production deployments should
    pass a pinned verifier public encryption credential instead.

    The cryptographic operation, protected header, and CMW wrapping are
    deliberately delegated to :mod:`libattest.formats.eareat_hpke`, which uses
    :mod:`libattest.formats.jose_hpke`'s fixed ``HPKE-0`` profile
    (DHKEM(P-256,HKDF-SHA256)+HKDF-SHA256+AES-128-GCM). This bridge only adapts
    gencmpclient's requested function shape to the libattest-py API.
    """
    payload = _parse_jwt_payload(ear)
    nonce = payload.get("eat_nonce") or payload.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise ValueError("ATG evidence JWT does not contain eat_nonce/nonce")

    recipient_priv = _load_hpke_private_key(enc_private_key_pem)
    statement = evidence.build_evidence_statement(
        ear.decode("ascii"),
        recipient_priv.public_key(),
        nonce=jose_jws.b64u_decode(nonce),
    )
    return bytes(statement["stmt"])


def decrypt_ear_with_hpke(enc_private_key_pem: str, encrypted: bytes) -> bytes:
    """Open DER(CMW json UTF8String) produced by :func:`encrypt_ear_with_hpke`.

    This verification/test helper uses libattest-py's fixed HPKE-0 decrypt path.
    ``jose_hpke.open_integrated`` validates the protected header and raises if
    the JWE is malformed, uses a non-``HPKE-0`` algorithm, has non-empty IV/Tag,
    or fails HPKE AEAD authentication.
    """
    recipient_priv = _load_hpke_private_key(enc_private_key_pem)
    jwe = evidence.extract_jwe_from_statement(encrypted)
    header, plaintext = jose_hpke.open_integrated(jwe, recipient_priv)
    if header.get("alg") != jose_hpke.ALG:
        raise ValueError(f"unexpected HPKE alg {header.get('alg')!r}")
    return plaintext
