"""Unit tests for workflow identity token minting and verification."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import jwt
import pytest

from tracecat.auth.workflow_identities import (
    REQUIRED_CLAIMS,
    WorkflowIdentityPayload,
    mint_workflow_identity_token,
    verify_workflow_identity_token,
)

FAKE_SERVICE_KEY = "test-service-key-for-unit-tests"
WORKSPACE_ID = uuid.uuid4()
ORGANIZATION_ID = uuid.uuid4()
WF_ID = uuid.uuid4()
WF_EXEC_ID = "test-workflow-execution-id"
WF_RUN_ID = "test-run-id"


@pytest.fixture(autouse=True)
def patch_service_key():
    with patch(
        "tracecat.auth.workflow_identities.get_service_key",
        return_value=FAKE_SERVICE_KEY,
    ):
        yield


@pytest.fixture(autouse=True)
def patch_hostname():
    with patch("tracecat.auth.workflow_identities.config") as mock_config:
        mock_config.TRACECAT__HOSTNAME = "tracecat.example.com"
        mock_config.TRACECAT__WORKFLOW_IDENTITY_TOKEN_TTL_SECONDS = 900
        yield mock_config


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


class TestMintWorkflowIdentityToken:
    def test_returns_string(self):
        token = _mint()
        assert isinstance(token, str)
        assert len(token) > 0

    def test_token_has_required_claims(self):
        token = _mint(audiences=["https://login.microsoftonline.com"])
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        for claim in REQUIRED_CLAIMS:
            assert claim in payload, f"Missing claim: {claim}"

    def test_audiences_in_token(self):
        audiences = ["https://login.microsoftonline.com", "https://sts.amazonaws.com"]
        token = _mint(audiences=audiences)
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        assert payload["aud"] == audiences

    def test_empty_audiences_default(self):
        token = _mint()
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        assert payload["aud"] == []

    def test_custom_ttl(self):
        token = _mint(ttl_seconds=60)
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        assert payload["exp"] - payload["iat"] == 60

    def test_default_ttl_used_when_none(self, patch_hostname):
        patch_hostname.TRACECAT__WORKFLOW_IDENTITY_TOKEN_TTL_SECONDS = 300
        token = _mint(ttl_seconds=None)
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        assert payload["exp"] - payload["iat"] == 300

    def test_custom_claims_present(self):
        token = _mint()
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        assert payload["workspace_id"] == str(WORKSPACE_ID)
        assert payload["organization_id"] == str(ORGANIZATION_ID)
        assert payload["wf_id"] == str(WF_ID)
        assert payload["wf_exec_id"] == WF_EXEC_ID
        assert payload["wf_run_id"] == WF_RUN_ID

    def test_issuer_uses_hostname(self, patch_hostname):
        patch_hostname.TRACECAT__HOSTNAME = "myhost.example.com"
        token = _mint()
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        assert payload["iss"] == "https://myhost.example.com/"

    def test_subject_contains_wf_info(self, patch_hostname):
        patch_hostname.TRACECAT__HOSTNAME = "myhost.example.com"
        token = _mint()
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        assert str(ORGANIZATION_ID) in payload["sub"]
        assert str(WF_ID) in payload["sub"]
        assert WF_EXEC_ID in payload["sub"]


class TestVerifyWorkflowIdentityToken:
    def test_verify_valid_token(self):
        token = _mint(audiences=["https://login.microsoftonline.com"])
        result = verify_workflow_identity_token(token)
        assert isinstance(result, WorkflowIdentityPayload)
        assert result.wf_exec_id == WF_EXEC_ID
        assert result.wf_run_id == WF_RUN_ID

    def test_verify_returns_correct_ids(self):
        token = _mint()
        result = verify_workflow_identity_token(token)
        assert str(result.workspace_id) == str(WORKSPACE_ID)
        assert str(result.organization_id) == str(ORGANIZATION_ID)
        assert str(result.wf_id) == str(WF_ID)

    def test_verify_invalid_signature_raises(self):
        token = _mint()
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(ValueError, match="Invalid workflow identity token"):
            verify_workflow_identity_token(tampered)

    def test_verify_wrong_key_raises(self):
        token = jwt.encode(
            {"iss": "x", "sub": "x", "aud": [], "iat": 1, "exp": 9999999999,
             "workspace_id": str(WORKSPACE_ID), "organization_id": str(ORGANIZATION_ID),
             "wf_id": str(WF_ID), "wf_exec_id": WF_EXEC_ID, "wf_run_id": WF_RUN_ID},
            "wrong-key",
            algorithm="HS256",
        )
        with pytest.raises(ValueError, match="Invalid workflow identity token"):
            verify_workflow_identity_token(token)

    def test_verify_expired_token_raises(self):
        token = jwt.encode(
            {"iss": "x", "sub": "x", "aud": [], "iat": 1, "exp": 1,
             "workspace_id": str(WORKSPACE_ID), "organization_id": str(ORGANIZATION_ID),
             "wf_id": str(WF_ID), "wf_exec_id": WF_EXEC_ID, "wf_run_id": WF_RUN_ID},
            FAKE_SERVICE_KEY,
            algorithm="HS256",
        )
        with pytest.raises(ValueError, match="Invalid workflow identity token"):
            verify_workflow_identity_token(token)

    def test_verify_missing_claim_raises(self):
        # Missing wf_run_id
        token = jwt.encode(
            {"iss": "x", "sub": "x", "aud": [], "iat": 1, "exp": 9999999999,
             "workspace_id": str(WORKSPACE_ID), "organization_id": str(ORGANIZATION_ID),
             "wf_id": str(WF_ID), "wf_exec_id": WF_EXEC_ID},
            FAKE_SERVICE_KEY,
            algorithm="HS256",
        )
        with pytest.raises(ValueError, match="Invalid workflow identity token"):
            verify_workflow_identity_token(token)

    def test_verify_audiences_preserved(self):
        audiences = ["https://login.microsoftonline.com", "https://sts.amazonaws.com"]
        token = _mint(audiences=audiences)
        result = verify_workflow_identity_token(token)
        assert result.audiences == audiences

    def test_verify_timestamps(self):
        before = datetime.now(UTC)
        token = _mint()
        after = datetime.now(UTC)
        result = verify_workflow_identity_token(token)
        assert before <= result.issued_at <= after
        assert result.expires_at > result.issued_at


class TestWorkflowIdentityPayload:
    def test_subject_property(self):
        payload = WorkflowIdentityPayload(
            workspace_id=WORKSPACE_ID,
            organization_id=ORGANIZATION_ID,
            wf_id=WF_ID,
            wf_exec_id=WF_EXEC_ID,
            wf_run_id=WF_RUN_ID,
            audiences=[],
        )
        with patch("tracecat.auth.workflow_identities.config") as mock_cfg:
            mock_cfg.TRACECAT__HOSTNAME = "host.example.com"
            subject = payload.subject
        assert subject.startswith("https://host.example.com/workflows/")
        assert str(ORGANIZATION_ID) in subject
        assert str(WF_ID) in subject

    def test_issuer_property(self):
        payload = WorkflowIdentityPayload(
            workspace_id=WORKSPACE_ID,
            organization_id=ORGANIZATION_ID,
            wf_id=WF_ID,
            wf_exec_id=WF_EXEC_ID,
            wf_run_id=WF_RUN_ID,
            audiences=[],
        )
        with patch("tracecat.auth.workflow_identities.config") as mock_cfg:
            mock_cfg.TRACECAT__HOSTNAME = "host.example.com"
            issuer = payload.issuer
        assert issuer == "https://host.example.com/"

    def test_fallback_hostname_when_empty(self):
        payload = WorkflowIdentityPayload(
            workspace_id=WORKSPACE_ID,
            organization_id=ORGANIZATION_ID,
            wf_id=WF_ID,
            wf_exec_id=WF_EXEC_ID,
            wf_run_id=WF_RUN_ID,
            audiences=[],
        )
        with patch("tracecat.auth.workflow_identities.config") as mock_cfg:
            mock_cfg.TRACECAT__HOSTNAME = ""
            subject = payload.subject
            issuer = payload.issuer
        assert "tracecat.local" in subject
        assert "tracecat.local" in issuer
