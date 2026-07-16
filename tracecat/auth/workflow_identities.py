"""Workflow identity tokens for external IDP trust.

Allows Tracecat workflow executions to be trusted by external identity providers
(Azure Entra, AWS STS, GCP, etc.) for token exchange via RFC 8693 token exchange.

A workflow execution can mint a signed JWT that external IDPs validate using
Tracecat's public keys exposed at the OIDC discovery endpoint:

    {PUBLIC_API_URL}/oauth/workflow/.well-known/openid-configuration

Token minting happens on the executor (outside the Temporal workflow sandbox)
so that cryptographic operations are never subject to Temporal's determinism
restrictions. The token is injected into ``ENV.workflow.identity_token`` before
action argument templates are evaluated, and is automatically added to the
secrets masking set so it is redacted from action outputs and Temporal event
history using the same substitution mechanism as secret values.

Example flow:
1. Executor mints identity token at the start of each action if identity.enabled=true
2. Action receives token via ENV.workflow.identity_token
3. Action exchanges token with Azure/AWS/GCP for access token (RFC 8693)
4. Action uses access token with provider APIs (Graph, IAM, etc.)

Azure Entra example audience: ``api://AzureADTokenExchange``
AWS example audience: ``sts.amazonaws.com``
GCP example audience: ``//iam.googleapis.com/projects/{project}/locations/global/workloadIdentityPools/{pool}/providers/{provider}``
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from jwt import PyJWTError
from pydantic import BaseModel, Field, ValidationError

from tracecat import config
from tracecat.auth.workflow_identity_signing import mint_jwt, verify_jwt
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
    "tracecat",
)

# Well-known audience identifiers that trigger provider-specific claim injection.
_AWS_STS_AUDIENCE = "sts.amazonaws.com"


def _provider_claims(
    audiences: list[str],
    *,
    workspace_id: WorkspaceID,
    organization_id: OrganizationID,
    wf_id: WorkflowUUID,
    wf_exec_id: str,
) -> dict[str, Any]:
    """Return extra top-level claims required by specific identity providers.

    Each provider that requires non-standard claim namespaces gets its own
    branch here. Callers get back a dict that is merged into the JWT payload.

    AWS STS: AssumeRoleWithWebIdentity reads session tags from the
    ``https://aws.amazon.com/tags`` claim namespace, allowing IAM conditions
    to match on workflow-level attributes.
    """
    claims: dict[str, Any] = {}

    if _AWS_STS_AUDIENCE in audiences:
        claims["https://aws.amazon.com/tags"] = {
            "principal_tags": {
                "WorkspaceId": [str(workspace_id)],
                "OrganizationId": [str(organization_id)],
                "WorkflowId": [str(wf_id)],
                "ExecutionId": [wf_exec_id],
            },
            "transitive_tag_keys": [
                "WorkspaceId",
                "OrganizationId",
                "WorkflowId",
                "ExecutionId",
            ],
        }

    return claims


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
    """Mint an ES256-signed JWT for workflow execution identity.

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
        A compact JWS string (ES256) suitable for RFC 8693 token exchange.
    """
    now = datetime.now(UTC)
    ttl = (
        int(workflow_timeout_seconds)
        if workflow_timeout_seconds and workflow_timeout_seconds > 0
        else WORKFLOW_IDENTITY_DEFAULT_TTL_SECONDS
    )
    audiences = audiences or []

    issuer = get_issuer_url()
    # Subject is stable per workflow so it can be used as a fixed subject in
    # external IDP federated credentials (e.g. Entra). Execution-specific
    # context lives in the wf_exec_id / wf_run_id claims.
    subject = f"urn:org:{organization_id}:ws:{workspace_id}:wf:{wf_id}"

    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        # Single-audience tokens use a string; multi-audience use an array.
        "aud": audiences[0] if len(audiences) == 1 else audiences,
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        # Tracecat-specific context nested under a single key.
        "tracecat": {
            "workspace_id": str(workspace_id),
            "organization_id": str(organization_id),
            "wf_id": str(wf_id),
            "wf_exec_id": wf_exec_id,
            "wf_run_id": wf_run_id,
            "trigger_type": trigger_type,
            "execution_type": execution_type,
        },
        # Provider-specific claim namespaces injected by audience.
        **_provider_claims(
            audiences,
            workspace_id=workspace_id,
            organization_id=organization_id,
            wf_id=wf_id,
            wf_exec_id=wf_exec_id,
        ),
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
        tc = payload["tracecat"]

        token_payload = WorkflowIdentityPayload(
            workspace_id=tc["workspace_id"],
            organization_id=tc["organization_id"],
            wf_id=tc["wf_id"],
            wf_exec_id=tc["wf_exec_id"],
            wf_run_id=tc["wf_run_id"],
            audiences=(
                [aud] if isinstance(aud := payload.get("aud", []), str) else aud
            ),
            issued_at=issued_at,
            expires_at=expires_at,
        )
    except (KeyError, ValidationError, ValueError) as exc:
        logger.warning("Workflow identity token payload is invalid", error=str(exc))
        raise ValueError("Workflow identity token payload is invalid") from exc

    return token_payload
