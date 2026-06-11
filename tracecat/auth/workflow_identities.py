"""Workflow identity tokens for external IDP trust.

Allows Tracecat workflow executions to be trusted by external identity providers
(Azure Entra, AWS STS, GCP, etc.) for token exchange via RFC 8693 token exchange.

A workflow execution can mint a signed JWT that external IDPs validate using
Tracecat's public keys. This enables actions to exchange the workflow token for
provider-specific access tokens without storing long-lived credentials.

Example flow:
1. Workflow starts, mints identity token if config.identity.enabled=true
2. Action receives token via ENV.workflow.identity_token
3. Action exchanges token with Azure/AWS/GCP for access token
4. Action uses access token with provider APIs (Graph, IAM, etc.)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import jwt
from jwt import PyJWTError
from pydantic import BaseModel, Field, ValidationError

from tracecat import config
from tracecat.auth.secrets import get_service_key
from tracecat.identifiers import OrganizationID, WorkspaceID
from tracecat.identifiers.workflow import WorkflowUUID
from tracecat.logger import logger

WORKFLOW_IDENTITY_TOKEN_ISSUER = "tracecat-workflow"
WORKFLOW_IDENTITY_TOKEN_SUBJECT_PREFIX = "tracecat-workflow-execution"
WORKFLOW_IDENTITY_DEFAULT_TTL_SECONDS = 600  # 10 minutes
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
    def subject(self) -> str:
        """RFC 8693 compliant subject for OIDC federation.

        Format: {app_url}/workflows/{org_id}/{wf_id}/{wf_exec_id}
        """
        base = _app_base_url()
        return f"{base}/workflows/{self.organization_id}/{self.wf_id}/{self.wf_exec_id}"

    @property
    def issuer(self) -> str:
        """OIDC issuer URL."""
        return _app_base_url() + "/"


def _app_base_url() -> str:
    """Derive a clean base URL from TRACECAT__PUBLIC_APP_URL, stripping trailing slashes."""
    url = config.TRACECAT__PUBLIC_APP_URL.rstrip("/")
    parsed = urlparse(url)
    # Return scheme + netloc only (no path) as the canonical base
    return f"{parsed.scheme}://{parsed.netloc}"


def mint_workflow_identity_token(
    *,
    workspace_id: WorkspaceID,
    organization_id: OrganizationID,
    wf_id: WorkflowUUID,
    wf_exec_id: str,
    wf_run_id: str,
    audiences: list[str] | None = None,
    workflow_timeout_seconds: float | None = None,
) -> str:
    """Mint a JWT for workflow execution identity.

    Creates a cryptographically signed token that external IDPs can validate
    to trust this workflow execution. The token can be exchanged for provider-
    specific access tokens using RFC 8693 token exchange.

    Token lifetime is gated to the workflow's own execution timeout so the
    identity token cannot outlive the workflow that issued it.  If no timeout
    is configured the default is 10 minutes.

    Args:
        workspace_id: Workspace where workflow is running
        organization_id: Organization that owns the workspace
        wf_id: Workflow ID
        wf_exec_id: Temporal workflow execution ID (unique per execution)
        wf_run_id: Temporal run ID
        audiences: List of external IDP audiences (e.g., Azure tenant, AWS account).
                   If None, empty list is used (audiences can be validated on exchange).
        workflow_timeout_seconds: The workflow execution timeout in seconds.
                                  If 0 or None, falls back to the default TTL (10 min).

    Returns:
        A signed JWT (compact JWS format) suitable for token exchange with external IDPs.
    """
    now = datetime.now(UTC)
    ttl = (
        int(workflow_timeout_seconds)
        if workflow_timeout_seconds and workflow_timeout_seconds > 0
        else WORKFLOW_IDENTITY_DEFAULT_TTL_SECONDS
    )
    audiences = audiences or []

    base_url = _app_base_url()
    issuer = f"{base_url}/"
    subject = f"{base_url}/workflows/{organization_id}/{wf_id}/{wf_exec_id}"

    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audiences,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        # Custom claims for access control and audit
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
        audiences=audiences,
        ttl_seconds=ttl,
    )

    return jwt.encode(payload, get_service_key(), algorithm="HS256")


def verify_workflow_identity_token(token: str) -> WorkflowIdentityPayload:
    """Verify and decode a workflow identity token.

    Validates the token signature and required claims. Used by:
    - Tracecat internally for audit/revocation
    - External IDPs for token exchange validation

    Args:
        token: The compact JWS token string

    Returns:
        WorkflowIdentityPayload with verified claims

    Raises:
        ValueError: If token is invalid, expired, or missing required claims
    """
    try:
        payload = jwt.decode(
            token,
            get_service_key(),
            algorithms=["HS256"],
            options={"require": list(REQUIRED_CLAIMS)},
            # Don't validate audience here - external IDPs handle that
        )
    except PyJWTError as exc:
        logger.warning("Failed to verify workflow identity token", error=str(exc))
        raise ValueError("Invalid workflow identity token") from exc

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
