"""Unit tests for workflow identity token minting and verification."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from tracecat.auth.workflow_identities import (
    REQUIRED_CLAIMS,
    WORKFLOW_IDENTITY_DEFAULT_TTL_SECONDS,
    WorkflowIdentityPayload,
    get_issuer_url,
    mint_workflow_identity_token,
    verify_workflow_identity_token,
)

WORKSPACE_ID = uuid.uuid4()
ORGANIZATION_ID = uuid.uuid4()
WF_ID = uuid.uuid4()
WF_EXEC_ID = "test-workflow-execution-id"
WF_RUN_ID = "test-run-id"


@pytest.fixture(autouse=True)
def patch_public_api_url():
    with patch("tracecat.auth.workflow_identities.config") as mock_config:
        mock_config.TRACECAT__PUBLIC_API_URL = "https://api.tracecat.example.com"
        yield mock_config


@pytest.fixture(autouse=True)
def patch_signing(patch_public_api_url):
    """Patch MCP OIDC signing with a real ephemeral P-256 key for tests."""
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        generate_private_key,
    )

    private_key = generate_private_key(SECP256R1())
    public_key = private_key.public_key()

    import jwt as pyjwt

    def fake_mint_jwt(claims):
        return pyjwt.encode(claims, private_key, algorithm="ES256")

    mock_jwk = MagicMock()
    mock_jwk.__getitem__ = lambda self, k: "test-kid" if k == "kid" else None

    with (
        patch("tracecat.auth.workflow_identities.mint_jwt", side_effect=fake_mint_jwt),
        patch(
            "tracecat.auth.workflow_identities.get_signing_key",
            return_value=MagicMock(public_key=lambda: public_key),
        ),
    ):
        yield private_key, public_key


def _decode(token, public_key):
    import jwt as pyjwt

    return pyjwt.decode(
        token, public_key, algorithms=["ES256"], options={"verify_aud": False}
    )


def _mint(**kwargs) -> str:
    defaults: dict = {
        "workspace_id": WORKSPACE_ID,
        "organization_id": ORGANIZATION_ID,
        "wf_id": WF_ID,
        "wf_exec_id": WF_EXEC_ID,
        "wf_run_id": WF_RUN_ID,
    }
    defaults.update(kwargs)
    return mint_workflow_identity_token(**defaults)


class TestGetIssuerUrl:
    def test_uses_public_api_url(self, patch_public_api_url):
        patch_public_api_url.TRACECAT__PUBLIC_API_URL = "https://api.example.com"
        assert get_issuer_url() == "https://api.example.com/oauth/workflow"

    def test_strips_trailing_slash(self, patch_public_api_url):
        patch_public_api_url.TRACECAT__PUBLIC_API_URL = "https://api.example.com/"
        assert get_issuer_url() == "https://api.example.com/oauth/workflow"


class TestMintWorkflowIdentityToken:
    def test_returns_string(self, patch_signing):
        token = _mint()
        assert isinstance(token, str) and len(token) > 0

    def test_token_has_required_claims(self, patch_signing):
        _, public_key = patch_signing
        token = _mint(audiences=["https://login.microsoftonline.com"])
        payload = _decode(token, public_key)
        for claim in REQUIRED_CLAIMS:
            assert claim in payload, f"Missing claim: {claim}"

    def test_audiences_in_token(self, patch_signing):
        _, public_key = patch_signing
        audiences = ["https://login.microsoftonline.com", "https://sts.amazonaws.com"]
        payload = _decode(_mint(audiences=audiences), public_key)
        assert payload["aud"] == audiences

    def test_empty_audiences_default(self, patch_signing):
        _, public_key = patch_signing
        assert _decode(_mint(), public_key)["aud"] == []

    def test_ttl_from_workflow_timeout(self, patch_signing):
        _, public_key = patch_signing
        payload = _decode(_mint(workflow_timeout_seconds=300), public_key)
        assert payload["exp"] - payload["iat"] == 300

    def test_default_ttl_when_timeout_is_none(self, patch_signing):
        _, public_key = patch_signing
        payload = _decode(_mint(workflow_timeout_seconds=None), public_key)
        assert payload["exp"] - payload["iat"] == WORKFLOW_IDENTITY_DEFAULT_TTL_SECONDS

    def test_default_ttl_when_timeout_is_zero(self, patch_signing):
        _, public_key = patch_signing
        payload = _decode(_mint(workflow_timeout_seconds=0), public_key)
        assert payload["exp"] - payload["iat"] == WORKFLOW_IDENTITY_DEFAULT_TTL_SECONDS

    def test_custom_claims_present(self, patch_signing):
        _, public_key = patch_signing
        payload = _decode(_mint(), public_key)
        assert payload["workspace_id"] == str(WORKSPACE_ID)
        assert payload["organization_id"] == str(ORGANIZATION_ID)
        assert payload["wf_id"] == str(WF_ID)
        assert payload["wf_exec_id"] == WF_EXEC_ID
        assert payload["wf_run_id"] == WF_RUN_ID

    def test_issuer_is_oauth_workflow_url(self, patch_signing, patch_public_api_url):
        _, public_key = patch_signing
        patch_public_api_url.TRACECAT__PUBLIC_API_URL = "https://api.example.com"
        payload = _decode(_mint(), public_key)
        assert payload["iss"] == "https://api.example.com/oauth/workflow"

    def test_subject_contains_wf_info(self, patch_signing):
        _, public_key = patch_signing
        payload = _decode(_mint(), public_key)
        assert str(ORGANIZATION_ID) in payload["sub"]
        assert str(WF_ID) in payload["sub"]
        assert WF_EXEC_ID in payload["sub"]


class TestVerifyWorkflowIdentityToken:
    def test_verify_valid_token(self, patch_signing):
        token = _mint(audiences=["https://login.microsoftonline.com"])
        result = verify_workflow_identity_token(token)
        assert isinstance(result, WorkflowIdentityPayload)
        assert result.wf_exec_id == WF_EXEC_ID
        assert result.wf_run_id == WF_RUN_ID

    def test_verify_returns_correct_ids(self, patch_signing):
        result = verify_workflow_identity_token(_mint())
        assert str(result.workspace_id) == str(WORKSPACE_ID)
        assert str(result.organization_id) == str(ORGANIZATION_ID)
        assert str(result.wf_id) == str(WF_ID)

    def test_verify_wrong_key_raises(self, patch_signing):
        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1,
            generate_private_key,
        )

        wrong_key = generate_private_key(SECP256R1())
        # Sign with wrong key, but verification uses the patched public_key
        bad_token = pyjwt.encode({"iss": "x"}, wrong_key, algorithm="ES256")
        with pytest.raises(ValueError, match="Invalid workflow identity token"):
            verify_workflow_identity_token(bad_token)

    def test_verify_expired_token_raises(self, patch_signing):
        _, public_key = patch_signing
        import jwt as pyjwt

        private_key, _ = patch_signing
        bad_token = pyjwt.encode(
            {
                "iss": "x",
                "sub": "x",
                "aud": [],
                "iat": 1,
                "exp": 1,
                "workspace_id": str(WORKSPACE_ID),
                "organization_id": str(ORGANIZATION_ID),
                "wf_id": str(WF_ID),
                "wf_exec_id": WF_EXEC_ID,
                "wf_run_id": WF_RUN_ID,
            },
            private_key,
            algorithm="ES256",
        )
        with pytest.raises(ValueError, match="Invalid workflow identity token"):
            verify_workflow_identity_token(bad_token)

    def test_verify_missing_claim_raises(self, patch_signing):
        import jwt as pyjwt

        private_key, _ = patch_signing
        bad_token = pyjwt.encode(
            {
                "iss": "x",
                "sub": "x",
                "aud": [],
                "iat": 1,
                "exp": 9999999999,
                "workspace_id": str(WORKSPACE_ID),
                "organization_id": str(ORGANIZATION_ID),
                "wf_id": str(WF_ID),
                "wf_exec_id": WF_EXEC_ID,
                # wf_run_id intentionally omitted
            },
            private_key,
            algorithm="ES256",
        )
        with pytest.raises(ValueError, match="Invalid workflow identity token"):
            verify_workflow_identity_token(bad_token)

    def test_verify_audiences_preserved(self, patch_signing):
        audiences = ["https://login.microsoftonline.com", "https://sts.amazonaws.com"]
        result = verify_workflow_identity_token(_mint(audiences=audiences))
        assert result.audiences == audiences

    def test_verify_timestamps(self, patch_signing):
        before = datetime.now(UTC)
        token = _mint()
        after = datetime.now(UTC)
        result = verify_workflow_identity_token(token)
        assert before <= result.issued_at <= after
        assert result.expires_at > result.issued_at


class TestWorkflowIdentityPayload:
    def _make(self) -> WorkflowIdentityPayload:
        return WorkflowIdentityPayload(
            workspace_id=WORKSPACE_ID,
            organization_id=ORGANIZATION_ID,
            wf_id=WF_ID,
            wf_exec_id=WF_EXEC_ID,
            wf_run_id=WF_RUN_ID,
            audiences=[],
        )

    def test_issuer_is_oauth_workflow_url(self, patch_public_api_url):
        patch_public_api_url.TRACECAT__PUBLIC_API_URL = "https://api.example.com"
        assert self._make().issuer == "https://api.example.com/oauth/workflow"

    def test_subject_contains_wf_info(self, patch_public_api_url):
        patch_public_api_url.TRACECAT__PUBLIC_API_URL = "https://api.example.com"
        subject = self._make().subject
        assert "api.example.com/oauth/workflow/workflows/" in subject
        assert str(ORGANIZATION_ID) in subject
        assert str(WF_ID) in subject
