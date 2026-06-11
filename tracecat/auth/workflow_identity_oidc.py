"""OIDC discovery endpoints for workflow identity tokens.

Exposes the public JWKS and discovery document so that external identity
providers (Azure Entra, AWS STS, GCP, etc.) can validate workflow identity
tokens issued by Tracecat.

Mounted at ``/oauth/workflow`` — the issuer URL for workflow identity tokens.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from tracecat.auth.workflow_identities import (
    WORKFLOW_IDENTITY_ISSUER_PATH,
    get_issuer_url,
)
from tracecat.auth.workflow_identity_signing import get_public_jwk

router = APIRouter(
    prefix=WORKFLOW_IDENTITY_ISSUER_PATH, tags=["Workflow Identity OIDC"]
)


@router.get("/.well-known/openid-configuration")
async def openid_configuration() -> dict[str, Any]:
    """OIDC discovery document for workflow identity tokens.

    External IDPs fetch this to learn the JWKS URI and issuer, then use
    the public key from JWKS to validate workflow identity tokens before
    issuing their own access tokens.
    """
    issuer = get_issuer_url()
    return {
        "issuer": issuer,
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"],
        "subject_types_supported": ["public"],
        "response_types_supported": ["token"],
        "claims_supported": [
            "iss",
            "sub",
            "aud",
            "iat",
            "exp",
            "workspace_id",
            "organization_id",
            "wf_id",
            "wf_exec_id",
            "wf_run_id",
        ],
    }


@router.get("/.well-known/jwks.json")
async def jwks() -> dict[str, list[dict[str, str]]]:
    """JSON Web Key Set containing the RS256 public key for workflow identity tokens."""
    return {"keys": [get_public_jwk()]}
