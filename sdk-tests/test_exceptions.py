

from swiftapi.exceptions import (
    SwiftAPIError,
    AuthenticationError,
    PolicyViolation,
    SignatureVerificationError,
    AttestationExpiredError,
    AttestationRevokedError,
    RateLimitError,
    NetworkError,
)


class TestExceptionHierarchy:
    def test_all_inherit_from_base(self):
        exceptions = [
            AuthenticationError,
            PolicyViolation,
            SignatureVerificationError,
            AttestationExpiredError,
            AttestationRevokedError,
            RateLimitError,
            NetworkError,
        ]
        for exc_class in exceptions:
            assert issubclass(exc_class, SwiftAPIError)

    def test_base_has_status_code(self):
        err = SwiftAPIError("test", status_code=403)
        assert err.status_code == 403

    def test_base_has_response(self):
        err = SwiftAPIError("test", response={"error": "denied"})
        assert err.response == {"error": "denied"}


class TestPolicyViolation:
    def test_has_action_type(self):
        err = PolicyViolation("denied", action_type="file_delete")
        assert err.action_type == "file_delete"

    def test_has_denial_reason(self):
        err = PolicyViolation("denied", denial_reason="requires human approval")
        assert err.denial_reason == "requires human approval"


class TestRateLimitError:
    def test_has_retry_after(self):
        err = RateLimitError(retry_after=30)
        assert err.retry_after == 30

    def test_message_includes_retry(self):
        err = RateLimitError(retry_after=60)
        assert "60s" in str(err)

    def test_no_retry_after(self):
        err = RateLimitError()
        assert err.retry_after is None


class TestAttestationRevokedError:
    def test_has_jti(self):
        err = AttestationRevokedError(jti="abc-123")
        assert err.jti == "abc-123"

    def test_message_includes_jti(self):
        err = AttestationRevokedError(jti="abc-123")
        assert "abc-123" in str(err)
