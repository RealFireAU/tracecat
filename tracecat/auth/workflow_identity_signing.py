"""ES256 signing key derivation and JWT operations for workflow identity tokens.

Uses ES256 (ECDSA with P-256) — the private key is just a scalar derived
directly from TRACECAT__SIGNING_SECRET via HKDF, so no prime generation is needed.
All replicas share one signing identity without key distribution.
"""

from __future__ import annotations

import base64
import hashlib
from functools import lru_cache
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    derive_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from tracecat.auth.secrets import get_signing_secret

_HKDF_SALT = b"tracecat-workflow-identity-signing-v1"
_HKDF_INFO = b"ec-p256-signing-key"
_ALGORITHM = "ES256"
_CURVE = SECP256R1()
# P-256 curve order n
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _derive_ec_private_key() -> EllipticCurvePrivateKey:
    """Derive a deterministic P-256 private key from TRACECAT__SIGNING_SECRET via HKDF."""
    secret = get_signing_secret()
    seed = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(secret.encode("utf-8"))
    # Map seed into valid scalar range [1, n-1]
    private_value = int.from_bytes(seed, "big") % (_P256_ORDER - 1) + 1
    return derive_private_key(private_value, _CURVE)


@lru_cache(maxsize=1)
def get_signing_key() -> EllipticCurvePrivateKey:
    """Return the cached P-256 private key for workflow identity tokens."""
    return _derive_ec_private_key()


def _get_public_key() -> EllipticCurvePublicKey:
    return get_signing_key().public_key()


def _compute_kid(public_key: EllipticCurvePublicKey) -> str:
    """JWK thumbprint (RFC 7638) for EC P-256 key."""
    nums = public_key.public_numbers()
    x_b64 = _base64url_encode(nums.x.to_bytes(32, "big"))
    y_b64 = _base64url_encode(nums.y.to_bytes(32, "big"))
    canonical = f'{{"crv":"P-256","kty":"EC","x":"{x_b64}","y":"{y_b64}"}}'
    return _base64url_encode(hashlib.sha256(canonical.encode("ascii")).digest())


@lru_cache(maxsize=1)
def get_public_jwk() -> dict[str, str]:
    """Return the P-256 public key as a JWK dict suitable for a JWKS keys array."""
    public_key = _get_public_key()
    nums = public_key.public_numbers()
    return {
        "kty": "EC",
        "use": "sig",
        "alg": _ALGORITHM,
        "kid": _compute_kid(public_key),
        "crv": "P-256",
        "x": _base64url_encode(nums.x.to_bytes(32, "big")),
        "y": _base64url_encode(nums.y.to_bytes(32, "big")),
    }


def mint_jwt(claims: dict[str, Any]) -> str:
    """Sign a JWT with the workflow identity ES256 key."""
    private_key = get_signing_key()
    kid = get_public_jwk()["kid"]
    return jwt.encode(
        payload=claims,
        key=private_key,
        algorithm=_ALGORITHM,
        headers={"kid": kid},
    )


def verify_jwt(token: str, *, audience: str | None = None) -> dict[str, Any]:
    """Verify and decode a workflow identity JWT."""
    public_key = _get_public_key()
    options: dict[str, Any] = {}
    kwargs: dict[str, Any] = {"algorithms": [_ALGORITHM], "options": options}
    if audience is not None:
        kwargs["audience"] = audience
    else:
        options["verify_aud"] = False
    return jwt.decode(token, key=public_key, **kwargs)
