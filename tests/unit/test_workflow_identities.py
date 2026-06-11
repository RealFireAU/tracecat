"""Unit tests for workflow identity token minting and verification."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import jwt
import pytest

from tracecat.auth.workflow_identities import (
    REQUIRED_CLAIMS,
    WORKFLOW_IDENTITY_DEFAULT_TTL_SECONDS,
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
def patch_app_url():
    with patch("tracecat.auth.workflow_identities.config") as mock_config:
        mock_config.TRACECAT__PUBLIC_APP_URL = "https://tracecat.example.com"
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

    def test_ttl_from_workflow_timeout(self):
        token = _mint(workflow_timeout_seconds=300)
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        assert payload["exp"] - payload["iat"] == 300

    def test_default_ttl_when_timeout_is_none(self):
        token = _mint(workflow_timeout_seconds=None)
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        assert payload["exp"] - payload["iat"] == WORKFLOW_IDENTITY_DEFAULT_TTL_SECONDS

    def test_default_ttl_when_timeout_is_zero(self):
        token = _mint(workflow_timeout_seconds=0)
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        assert payload["exp"] - payload["iat"] == WORKFLOW_IDENTITY_DEFAULT_TTL_SECONDS

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

    def test_issuer_derived_from_public_app_url(self, patch_app_url):
        patch_app_url.TRACECAT__PUBLIC_APP_URL = "https://myhost.example.com"
        token = _mint()
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        assert payload["iss"] == "https://myhost.example.com/"

    def test_subject_contains_wf_info(self):
        token = _mint()
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        assert str(ORGANIZATION_ID) in payload["sub"]
        assert str(WF_ID) in payload["sub"]
        assert WF_EXEC_ID in payload["sub"]

    def test_public_app_url_path_stripped_from_base(self, patch_app_url):
        # Paths in PUBLIC_APP_URL should not appear in issuer/subject
        patch_app_url.TRACECAT__PUBLIC_APP_URL = "https://myhost.example.com/some/path"
        token = _mint()
        payload = jwt.decode(
            token, FAKE_SERVICE_KEY, algorithms=["HS256"], options={"verify_aud": False}
        )
        assert payload["iss"] == "https://myhost.example.com/"
        assert "/some/path" not in payload["iss"]


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
                "wf_run_id": WF_RUN_ID,
            },
            "wrong-key",
            algorithm="HS256",
        )
        with pytest.raises(ValueError, match="Invalid workflow identity token"):
            verify_workflow_identity_token(token)

    def test_verify_expired_token_raises(self):
        token = jwt.encode(
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
            FAKE_SERVICE_KEY,
            algorithm="HS256",
        )
        with pytest.raises(ValueError, match="Invalid workflow identity token"):
            verify_workflow_identity_token(token)

    def test_verify_missing_claim_raises(self):
        token = jwt.encode(
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
    def _make_payload(self) -> WorkflowIdentityPayload:
        return WorkflowIdentityPayload(
            workspace_id=WORKSPACE_ID,
            organization_id=ORGANIZATION_ID,
            wf_id=WF_ID,
            wf_exec_id=WF_EXEC_ID,
            wf_run_id=WF_RUN_ID,
            audiences=[],
        )

    def test_subject_property(self, patch_app_url):
        patch_app_url.TRACECAT__PUBLIC_APP_URL = "https://host.example.com"
        subject = self._make_payload().subject
        assert subject.startswith("https://host.example.com/workflows/")
        assert str(ORGANIZATION_ID) in subject
        assert str(WF_ID) in subject

    def test_issuer_property(self, patch_app_url):
        patch_app_url.TRACECAT__PUBLIC_APP_URL = "https://host.example.com"
        assert self._make_payload().issuer == "https://host.example.com/"

    def test_trailing_slash_stripped(self, patch_app_url):
        patch_app_url.TRACECAT__PUBLIC_APP_URL = "https://host.example.com/"
        assert self._make_payload().issuer == "https://host.example.com/"
