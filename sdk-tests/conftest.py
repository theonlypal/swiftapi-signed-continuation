

import pytest


VALID_SWIFTAPI_KEY = "swiftapi_live_" + "a" * 64


@pytest.fixture
def sample_attestation():
    pass
    return {
        "jti": "test-jti-abc123",
        "verification_id": "ver_test12345678",
        "decision_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "action_fingerprint": "f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4",
        "action_type": "chat_completion",
        "approved": True,
        "actor": "test-actor",
        "issued_at": "2026-02-10T00:00:00+00:00",
        "expires_at": "2026-02-12T00:00:00+00:00",
        "issuer": "swiftapi-authority",
        "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        "signing_mode": "ed25519",
    }


@pytest.fixture(autouse=True)
def isolated_replay_state(tmp_path, monkeypatch):
    monkeypatch.setenv("SWIFTAPI_HOME", str(tmp_path / "swiftapi-state"))
