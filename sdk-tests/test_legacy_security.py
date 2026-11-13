

import base64
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
import requests
from nacl.signing import SigningKey

from swiftapi import Anthropic, Enforcement, OpenAI, SwiftAPI
from swiftapi.exceptions import (
    AttestationExpiredError,
    AttestationRevokedError,
    NetworkError,
    PolicyViolation,
    SignatureVerificationError,
    SwiftAPIError,
)
from swiftapi import verifier


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def reject_request(*args, **kwargs):
        raise AssertionError("Legacy security tests must not access the network")

    monkeypatch.setattr(requests.Session, "request", reject_request)


def server_fingerprint(data, attest=False):
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return digest[:32] if attest else digest


@pytest.fixture
def sign_attestation(monkeypatch):
    key = SigningKey.generate()
    monkeypatch.setattr(verifier, "VERIFY_KEY", key.verify_key)

    def sign(data, action_type="chat_completion", approved=True, attest=True, **fields):
        now = datetime.now(timezone.utc)
        signed = {
            "jti": "jti-test",
            "verification_id": "ver-test",
            "decision_hash": "test-decision-hash",
            "action_fingerprint": server_fingerprint(data, attest=attest),
            "action_type": action_type,
            "approved": approved,
            "actor": "test-actor",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "issuer": "swiftapi",
        }
        signed.update(fields)
        payload = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
        signed["signature"] = base64.b64encode(key.sign(payload).signature).decode()
        signed["signing_mode"] = "ed25519"
        if attest:
            signed["action_data"] = copy.deepcopy(data)
            if approved is False:
                
                signed.update({
                    "denial_reason": "Denied by policy",
                    "violated_policies": [{"policy_id": "test"}],
                    "evaluated_policies": ["test"],
                    "evaluation_context": {"known_action_type": True},
                })
        return signed

    return sign


@pytest.fixture(params=["openai", "anthropic"])
def provider(request):
    if request.param == "openai":
        target = OpenAI(swiftapi_key="swiftapi_live_test", openai_key="test").chat.completions
        response_data = {"choices": [{"message": {"content": "allowed"}}]}
        expected_url = "https://api.openai.com/v1/chat/completions"
    else:
        target = Anthropic(swiftapi_key="swiftapi_live_test", anthropic_key="test").messages
        response_data = {"content": [{"text": "allowed"}], "stop_reason": "end_turn"}
        expected_url = "https://api.anthropic.com/v1/messages"
    return target, response_data, expected_url


def fake_provider_session(target, response_data, attest):
    calls = []

    def post(url, **kwargs):
        calls.append((url, copy.deepcopy(kwargs)))
        if len(calls) == 1:
            data = attest(kwargs["json"]["action_data"])
        else:
            data = response_data
        return Mock(status_code=200, json=lambda: data)

    target._session = Mock(post=post)
    return calls


def test_provider_rejects_unsigned_approval(provider):
    target, response, _ = provider
    calls = fake_provider_session(target, response, lambda data: {"approved": True})
    with pytest.raises(SignatureVerificationError, match="Missing signature"):
        target.create(model="test", messages=[{"role": "user", "content": "hello"}])
    assert len(calls) == 1


def test_provider_accepts_current_signed_approval_and_binds_kwargs(provider, sign_attestation):
    target, response, expected_url = provider
    calls = fake_provider_session(target, response, sign_attestation)
    result = target.create(
        model="test",
        messages=[{"role": "user", "content": "hello شَرْط"}],
        tools=[{"type": "function", "function": {"name": "test", "parameters": {}}}],
        stop=["STOP"],
    )
    assert len(calls) == 2
    assert calls[1][0] == expected_url
    assert calls[0][1]["json"]["action_type"] == "chat_completion"
    attested_payload = calls[0][1]["json"]["action_data"]
    assert attested_payload == calls[1][1]["json"]
    assert attested_payload["tools"][0]["function"]["name"] == "test"
    assert attested_payload["stop"] == ["STOP"]
    assert all(call[1]["allow_redirects"] is False for call in calls)
    assert result.attested is True
    assert result.jti == "jti-test"


def test_provider_signed_denial_preserves_empty_response(provider, sign_attestation):
    target, response, _ = provider
    calls = fake_provider_session(target, response, lambda data: sign_attestation(data, approved=False))
    result = target.create(model="test", messages=[])
    content = result.content if isinstance(result.content, str) else result.content[0].text
    assert content == ""
    assert result.attested is False
    assert len(calls) == 1


@pytest.mark.parametrize("field,value", [
    ("action_fingerprint", "0" * 32),
    ("action_type", "file_delete"),
    ("approved", "true"),
    ("approved", 1),
])
def test_provider_rejects_signed_wrong_binding(provider, sign_attestation, field, value):
    target, response, _ = provider
    calls = fake_provider_session(target, response, lambda data: sign_attestation(data, **{field: value}))
    with pytest.raises(SignatureVerificationError):
        target.create(model="test", messages=[])
    assert len(calls) == 1


def test_provider_rejects_forged_approved_field(provider, sign_attestation):
    target, response, _ = provider

    def tampered(data):
        attestation = sign_attestation(data, approved=False)
        attestation["approved"] = True
        return attestation

    calls = fake_provider_session(target, response, tampered)
    with pytest.raises(SignatureVerificationError):
        target.create(model="test", messages=[])
    assert len(calls) == 1


def test_provider_uses_detached_request_during_attestation(provider, sign_attestation):
    target, response, _ = provider
    messages = [{"role": "user", "content": "original"}]

    def attest(data):
        messages[0]["content"] = "changed while awaiting authority"
        return sign_attestation(data)

    calls = fake_provider_session(target, response, attest)
    target.create(model="test", messages=messages)
    assert calls[1][1]["json"]["messages"][0]["content"] == "original"
    assert calls[0][1]["json"]["action_data"] == calls[1][1]["json"]


def enforcement_client(sign_attestation, **fields):
    client = SwiftAPI("swiftapi_live_test")

    def verify(action_type, intent, params=None, actor="sdk"):
        data = {"action_type": action_type, "intent": intent, "params": params or {}}
        return {"approved": True, "execution_attestation": sign_attestation(
            data, action_type=action_type, attest=False, **fields
        )}

    client.verify = Mock(side_effect=verify)
    return client


def enter_guard(guard, path, execute):
    if path == "run":
        return guard.run(execute, "file_write", "Save", {"path": "/test"})
    if path == "decorator":
        @guard.protect("file_write", "Save", {"path": "/test"})
        def operation():
            return execute()

        return operation()
    with guard.guard("file_write", "Save", {"path": "/test"}):
        return execute()


@pytest.mark.parametrize("path", ["run", "decorator", "context"])
def test_enforcement_accepts_bound_current_signature(sign_attestation, path):
    client = enforcement_client(sign_attestation)
    execute = Mock(return_value="done")
    assert enter_guard(Enforcement(client, verbose=False), path, execute) == "done"
    execute.assert_called_once_with()


@pytest.mark.parametrize("path", ["run", "context"])
@pytest.mark.parametrize("fields,error", [
    ({"approved": False}, PolicyViolation),
    ({"approved": "true"}, SignatureVerificationError),
    ({"action_fingerprint": "0" * 64}, SignatureVerificationError),
    ({"expires_at": "2000-01-01T00:00:00+00:00"}, AttestationExpiredError),
])
def test_enforcement_rejects_signed_invalid_decisions(sign_attestation, path, fields, error):
    client = enforcement_client(sign_attestation, **fields)
    execute = Mock()
    with pytest.raises(error):
        enter_guard(Enforcement(client, verbose=False), path, execute)
    execute.assert_not_called()


@pytest.mark.parametrize("path", ["run", "context"])
def test_enforcement_rejects_forged_approval(path):
    client = SwiftAPI("swiftapi_live_test")
    client.verify = Mock(return_value={"approved": True, "execution_attestation": {"approved": True}})
    execute = Mock()
    with pytest.raises(SignatureVerificationError):
        enter_guard(Enforcement(client, verbose=False), path, execute)
    execute.assert_not_called()


@pytest.mark.parametrize("path", ["run", "context"])
def test_paranoid_enforcement_stops_on_revocation_network_error(sign_attestation, path):
    client = enforcement_client(sign_attestation)
    client._request = Mock(side_effect=NetworkError("unavailable"))
    execute = Mock()
    with pytest.raises(NetworkError, match="unavailable"):
        enter_guard(Enforcement(client, paranoid=True, verbose=False), path, execute)
    execute.assert_not_called()


@pytest.mark.parametrize("revoked", [True, False])
def test_revocation_requires_matching_boolean_response(revoked):
    client = SwiftAPI("swiftapi_live_test")
    client._request = Mock(return_value={"jti": "test", "revoked": revoked, "details": None})
    assert client.check_revocation("test") is revoked


@pytest.mark.parametrize("response", [
    {}, {"jti": "test"}, {"jti": "test", "revoked": "false"},
    {"jti": "test", "revoked": 0}, {"jti": "other", "revoked": False}, [],
])
def test_malformed_revocation_response_fails_closed(response):
    client = SwiftAPI("swiftapi_live_test")
    client._request = Mock(return_value=response)
    with pytest.raises(SwiftAPIError, match="Invalid revocation response"):
        client.check_revocation("test")


def test_paranoid_enforcement_stops_on_revoked_attestation(sign_attestation):
    client = enforcement_client(sign_attestation)
    client._request = Mock(return_value={"jti": "jti-test", "revoked": True})
    execute = Mock()
    with pytest.raises(AttestationRevokedError):
        enter_guard(Enforcement(client, paranoid=True, verbose=False), "run", execute)
    execute.assert_not_called()


def test_signature_verification_preserves_signed_denial_authenticity(sign_attestation):
    attestation = sign_attestation({}, approved=False)
    assert verifier.verify_signature(attestation) is True
    assert verifier.is_valid(attestation) is True


@pytest.mark.parametrize("signature", ["AAAA", "not-base64!!", 7])
def test_malformed_signature_raises_sdk_error(sign_attestation, signature):
    attestation = sign_attestation({})
    attestation["signature"] = signature
    with pytest.raises(SignatureVerificationError):
        verifier.verify_signature(attestation)


def test_signature_requires_timezone(sign_attestation):
    attestation = sign_attestation({}, expires_at="2099-01-01T00:00:00")
    with pytest.raises(SignatureVerificationError, match="timezone"):
        verifier.verify_signature(attestation)


def test_authority_client_never_follows_redirects():
    client = SwiftAPI("swiftapi_live_test")
    response = Mock(status_code=302, headers={"Location": "https://other.example/"})
    client._session.request = Mock(return_value=response)
    with pytest.raises(SwiftAPIError, match="redirect refused"):
        client.get_info()
    assert client._session.request.call_args.kwargs["allow_redirects"] is False


def test_provider_authority_redirect_stops_before_provider(provider):
    target, _, _ = provider
    target._session = Mock()
    target._session.post.return_value = Mock(status_code=307, text="redirect")
    with pytest.raises(SwiftAPIError, match="Attestation failed"):
        target.create(model="test", messages=[])
    assert target._session.post.call_count == 1
    assert target._session.post.call_args.kwargs["allow_redirects"] is False
