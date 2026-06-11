"""Workflow identity tokens for external IDP trust.

Allows Tracecat workflow executions to be trusted by external identity providers
(Azure Entra, AWS STS, GCP, etc.) for token exchange via RFC 8693 token exchange.

A workflow execution can mint a signed JWT that external IDPs validate using
Tracecat's public keys exposed at the OIDC discovery endpoint:

    {PUBLIC_API_URL}/oauth/workflow/.well-known/openid-configuration

Example flow:
1. Workflow starts, mints identity token if config.identity.enabled=true
2. Action receives token via ENV.workflow.identity_token
3. Action exchanges token with Azure/AWS/GCP for access token (RFC 8693)
4. Action uses access token with provider APIs (Graph, IAM, etc.)

Azure Entra example audience: ``api://AzureADTokenExchange``
AWS example audience: ``sts.amazonaws.com``
GCP example audience: ``//iam.googleapis.com/projects/{project}/locations/global/workloadIdentityPools/{pool}/providers/{provider}``
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from jwt import PyJWTError
from pydantic import BaseModel, Field, ValidationError

from tracecat import config
from tracecat.identifiers import OrganizationID, WorkspaceID
from tracecat.identifiers.workflow import WorkflowUUID
from tracecat.logger import logger

WORKFLOW_IDENTITY_DEFAULT_TTL_SECONDS = 600  # 10 minutes
WORKFLOW_IDENTITY_ISSUER_PATH = "/oauth/workflow"
REQUIRED_CLAIMS = (
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
)


def get_issuer_url() -> str:
    """Return the public issuer URL for workflow identity tokens.

    Must match the router prefix so that external IDPs can reach the
    OIDC discovery document at ``{issuer}/.well-known/openid-configuration``.
    """
    return (
        f"{config.TRACECAT__PUBLIC_API_URL.rstrip('/')}{WORKFLOW_IDENTITY_ISSUER_PATH}"
    )


class WorkflowIdentityPayload(BaseModel):
    """Payload extracted from a verified workflow identity token."""

    workspace_id: WorkspaceID
    organization_id: OrganizationID
    wf_id: WorkflowUUID
    wf_exec_id: str
    wf_run_id: str
    audiences: list[str]
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def issuer(self) -> str:
        """OIDC issuer URL."""
        return get_issuer_url()


def mint_workflow_identity_token(
    *,
    workspace_id: WorkspaceID,
    organization_id: OrganizationID,
    wf_id: WorkflowUUID,
    wf_exec_id: str,
    wf_run_id: str,
    trigger_type: str,
    execution_type: str,
    audiences: list[str] | None = None,
    workflow_timeout_seconds: float | None = None,
) -> str:
    """Mint an RS256-signed JWT for workflow execution identity.

    Creates a cryptographically signed token that external IDPs can validate
    using the public key served at the JWKS endpoint. The token can be
    exchanged for provider-specific access tokens using RFC 8693 token exchange.

    Token lifetime is gated to the workflow's own execution timeout so the
    identity token cannot outlive the workflow that issued it.  If no timeout
    is configured the default is 10 minutes.

    Subject format:
        ``urn:org:{org_id}:ws:{workspace_id}:wf:{wf_id}:{trigger_type}:{execution_type}:exec:{wf_exec_id}``

    Args:
        workspace_id: Workspace where workflow is running.
        organization_id: Organization that owns the workspace.
        wf_id: Workflow ID.
        wf_exec_id: Temporal workflow execution ID (unique per execution).
        wf_run_id: Temporal run ID.
        trigger_type: How the workflow was triggered (e.g. "webhook", "scheduled").
        execution_type: Draft or published execution.
        audiences: Token audiences for external IDPs.
                   Azure Entra: ``api://AzureADTokenExchange``
                   AWS STS: ``sts.amazonaws.com``
                   If None, empty list is used.
        workflow_timeout_seconds: Execution timeout — gates the token TTL.
                                  If 0 or None, defaults to 10 minutes.

    Returns:
        A compact JWS string (RS256) suitable for RFC 8693 token exchange.
    """
    # Import here to avoid circular imports at module load time
    from tracecat.auth.workflow_identity_signing import mint_jwt

    now = datetime.now(UTC)
    ttl = (
        int(workflow_timeout_seconds)
        if workflow_timeout_seconds and workflow_timeout_seconds > 0
        else WORKFLOW_IDENTITY_DEFAULT_TTL_SECONDS
    )
    audiences = audiences or []

    issuer = get_issuer_url()
    subject = (
        f"urn:org:{organization_id}"
        f":ws:{workspace_id}"
        f":wf:{wf_id}"
        f":{trigger_type}"
        f":{execution_type}"
        f":exec:{wf_exec_id}"
    )

    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audiences,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        "workspace_id": str(workspace_id),
        "organization_id": str(organization_id),
        "wf_id": str(wf_id),
        "wf_exec_id": wf_exec_id,
        "wf_run_id": wf_run_id,
    }

    logger.debug(
        "Minting workflow identity token",
        wf_id=wf_id,
        wf_exec_id=wf_exec_id,
        trigger_type=trigger_type,
        execution_type=execution_type,
        audiences=audiences,
        ttl_seconds=ttl,
    )

    return mint_jwt(payload)


def verify_workflow_identity_token(token: str) -> WorkflowIdentityPayload:
    """Verify and decode a workflow identity token.

    Args:
        token: The compact JWS token string.

    Returns:
        WorkflowIdentityPayload with verified claims.

    Raises:
        ValueError: If token is invalid, expired, or missing required claims.
    """
    from tracecat.auth.workflow_identity_signing import verify_jwt

    try:
        payload = verify_jwt(token)
    except PyJWTError as exc:
        logger.warning("Failed to verify workflow identity token", error=str(exc))
        raise ValueError("Invalid workflow identity token") from exc

    missing = [c for c in REQUIRED_CLAIMS if c not in payload]
    if missing:
        logger.warning("Workflow identity token missing claims", missing=missing)
        raise ValueError("Invalid workflow identity token")

    try:
        issued_at = datetime.fromtimestamp(payload["iat"], tz=UTC)
        expires_at = datetime.fromtimestamp(payload["exp"], tz=UTC)

        token_payload = WorkflowIdentityPayload(
            workspace_id=payload["workspace_id"],
            organization_id=payload["organization_id"],
            wf_id=payload["wf_id"],
            wf_exec_id=payload["wf_exec_id"],
            wf_run_id=payload["wf_run_id"],
            audiences=payload.get("aud", []),
            issued_at=issued_at,
            expires_at=expires_at,
        )
    except (KeyError, ValidationError, ValueError) as exc:
        logger.warning("Workflow identity token payload is invalid", error=str(exc))
        raise ValueError("Workflow identity token payload is invalid") from exc

    return token_payload
