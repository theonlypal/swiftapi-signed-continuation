

import pytest
from swiftapi import verify_signature, is_valid, get_public_key
from swiftapi.exceptions import SignatureVerificationError


class TestPublicKey:
    def test_public_key_exists(self):
        key = get_public_key()
        assert key is not None
        assert len(key) > 0

    def test_public_key_is_base64(self):
        import base64
        key = get_public_key()
        decoded = base64.b64decode(key)
        assert len(decoded) == 32  


class TestVerifySignature:
    def test_rejects_missing_signature(self):
        with pytest.raises(SignatureVerificationError, match="Missing signature"):
            verify_signature({})

    def test_rejects_incomplete_attestation(self):
        with pytest.raises(SignatureVerificationError, match="missing required fields"):
            verify_signature({"signature": "AAAA"})

    def test_rejects_bad_signature(self, sample_attestation):
        with pytest.raises(SignatureVerificationError):
            verify_signature(sample_attestation)

    def test_rejects_empty_signature(self):
        with pytest.raises(SignatureVerificationError, match="Missing signature"):
            verify_signature({"signature": "", "jti": "x", "action_fingerprint": "y", "expires_at": "z"})


class TestIsValid:
    def test_returns_false_on_empty(self):
        assert is_valid({}) is False

    def test_returns_false_on_bad_attestation(self, sample_attestation):
        assert is_valid(sample_attestation) is False

    def test_returns_false_on_garbage(self):
        assert is_valid({"garbage": True}) is False
