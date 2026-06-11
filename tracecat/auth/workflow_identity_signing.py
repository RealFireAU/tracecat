"""RS256 signing key derivation and JWT operations for workflow identity tokens.

Uses RS256 (RSASSA-PKCS1-v1_5 with SHA-256) because major cloud workload identity
federation providers (Azure Entra, AWS STS, GCP) all support it and some require it.

The RSA-2048 key pair is derived deterministically from ``USER_AUTH_SECRET`` via
HKDF so all replicas share one signing identity without key distribution.
The first call performs prime generation (typically <200 ms); subsequent calls
are free due to ``lru_cache``.
"""

from __future__ import annotations

import base64
import hashlib
import math
import random as stdlib_random
from functools import lru_cache
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPrivateNumbers,
    RSAPublicKey,
    RSAPublicNumbers,
    rsa_crt_dmp1,
    rsa_crt_dmq1,
    rsa_crt_iqmp,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from tracecat.auth.secrets import get_user_auth_secret

_HKDF_SALT = b"tracecat-workflow-identity-signing-v1"
_HKDF_INFO = b"rsa-2048-signing-key"
_ALGORITHM = "RS256"
_KEY_BITS = 2048
_E = 65537


# ---------------------------------------------------------------------------
# Deterministic RSA key derivation
# ---------------------------------------------------------------------------


def _miller_rabin(n: int, k: int, *, rng: stdlib_random.Random) -> bool:
    """Return True if n is probably prime (k rounds of Miller-Rabin)."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int, rng: stdlib_random.Random) -> int:
    """Generate a probable prime of exactly *bits* bits using *rng*."""
    while True:
        candidate = rng.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1  # set MSB and LSB
        if _miller_rabin(candidate, k=20, rng=rng):
            return candidate


def _derive_rsa_private_key() -> RSAPrivateKey:
    """Derive a deterministic RSA-2048 private key from USER_AUTH_SECRET.

    Uses HKDF-SHA256 to produce 64 bytes of seed material, then seeds a
    deterministic PRNG to generate the RSA primes.  The same secret always
    produces the same keypair.
    """
    secret = get_user_auth_secret()
    seed = HKDF(
        algorithm=SHA256(),
        length=64,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(secret.encode("utf-8"))

    rng = stdlib_random.Random(int.from_bytes(seed, "big"))
    half = _KEY_BITS // 2

    while True:
        p = _generate_prime(half, rng)
        q = _generate_prime(half, rng)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        phi = (p - 1) * (q - 1)
        if math.gcd(_E, phi) == 1:
            break

    d = pow(_E, -1, phi)
    pub = RSAPublicNumbers(e=_E, n=p * q)
    priv = RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=rsa_crt_dmp1(d, p),
        dmq1=rsa_crt_dmq1(d, q),
        iqmp=rsa_crt_iqmp(p, q),
        public_numbers=pub,
    )
    return priv.private_key()


@lru_cache(maxsize=1)
def get_signing_key() -> RSAPrivateKey:
    """Return the cached RSA-2048 private key for workflow identity tokens."""
    return _derive_rsa_private_key()


def _get_public_key() -> RSAPublicKey:
    return get_signing_key().public_key()


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _compute_kid(public_key: RSAPublicKey) -> str:
    """Compute a JWK thumbprint (RFC 7638) as the key ID.

    For RSA, the thumbprint is SHA-256 of the canonical JSON
    ``{"e":"...","kty":"RSA","n":"..."}``.
    """
    nums = public_key.public_numbers()
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    e_b64 = _base64url_encode(e_bytes)
    n_b64 = _base64url_encode(n_bytes)
    canonical = f'{{"e":"{e_b64}","kty":"RSA","n":"{n_b64}"}}'
    return _base64url_encode(hashlib.sha256(canonical.encode("ascii")).digest())


@lru_cache(maxsize=1)
def get_public_jwk() -> dict[str, str]:
    """Return the RSA public key as a JWK dict suitable for a JWKS ``keys`` array."""
    public_key = _get_public_key()
    nums = public_key.public_numbers()
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": _ALGORITHM,
        "kid": _compute_kid(public_key),
        "n": _base64url_encode(n_bytes),
        "e": _base64url_encode(e_bytes),
    }


def mint_jwt(claims: dict[str, Any]) -> str:
    """Sign a JWT with the workflow identity RS256 key."""
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
