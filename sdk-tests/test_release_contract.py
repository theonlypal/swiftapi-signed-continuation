import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
from unittest.mock import Mock
import pytest
from swiftapi import SwiftAPI, Enforcement
from swiftapi.brake.core import AuthorizationDenied
from swiftapi.verifier import _action_fingerprint
from nacl.signing import SigningKey
import base64
import tarfile


def sdk_document(name):
    archive_path=Path(__file__).resolve().parents[1]/'packages/swiftapi_python-1.4.0.tar.gz'
    with tarfile.open(archive_path) as archive:
        return archive.extractfile('swiftapi_python-1.4.0/'+name).read().decode('utf-8')


def test_readme_local_example():
    source = sdk_document('README.md')
    snippet = re.search(r"```python\n(.*?)\n```", source, re.DOTALL).group(1)
    exec(compile(snippet, "README.md", "exec"), {})


def test_legacy_callback_replay_blocked(monkeypatch):
    import swiftapi.verifier as verifier

    signer = SigningKey.generate()
    monkeypatch.setattr(verifier, "VERIFY_KEY", signer.verify_key)
    attestation = {
        "jti": "same-jti",
        "action_type": "x",
        "action_fingerprint": _action_fingerprint(
            {"action_type": "x", "intent": "test", "params": {}}
        ),
        "approved": True,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    }
    attestation["signature"] = base64.b64encode(
        signer.sign(verifier._reconstruct_signed_payload(attestation)).signature
    ).decode()
    client = Mock()
    client.verify.return_value = {"approved": True, "execution_attestation": attestation}
    guard = Enforcement(client, verbose=False)
    calls = []
    guard.run(lambda: calls.append(1), action="x", intent="test")
    with pytest.raises(AuthorizationDenied):
        guard.run(lambda: calls.append(2), action="x", intent="test")
    assert calls == [1]


def test_all_historical_public_exports():
    import swiftapi

    expected = {
        "__version__",
        "SwiftAPI",
        "Enforcement",
        "enforce",
        "OpenAI",
        "Anthropic",
        "verify_signature",
        "is_valid",
        "get_public_key",
        "SwiftAPIError",
        "AuthenticationError",
        "PolicyViolation",
        "SignatureVerificationError",
        "AttestationExpiredError",
        "AttestationRevokedError",
        "RateLimitError",
        "NetworkError",
        "Colors",
        "Symbols",
        "print_approved",
        "print_denied",
        "print_verified",
        "print_error",
        "print_info",
    }
    assert expected <= set(swiftapi.__all__)


def test_all_document_snippets_compile():
    archive_path=Path(__file__).resolve().parents[1]/'packages/swiftapi_python-1.4.0.tar.gz'
    with tarfile.open(archive_path) as archive:
        names=[member.name.split('/',1)[1] for member in archive.getmembers()
               if member.isfile() and member.name.endswith('.md')
               and (member.name.endswith('/README.md') or '/docs/' in member.name)]
    for name in names:
        for snippet in re.findall(r"```python\n(.*?)\n```", sdk_document(name), re.DOTALL):
            ast.parse(snippet)


def test_revocation_unknown_stops_paranoid_callback():
    from swiftapi.exceptions import NetworkError

    api = SwiftAPI("swiftapi_live_test")
    api._request = Mock(side_effect=NetworkError("offline"))
    with pytest.raises(NetworkError):
        api.check_revocation("x")


def test_readme_document_links_resolve_outside_source_checkout():
    from urllib.parse import urlparse

    source = sdk_document('README.md')
    links = re.findall(r"\[[^\]]+\]\(([^)]+)\)", source)
    assert links
    for link in links:
        parsed = urlparse(link)
        assert parsed.scheme == "https" and parsed.netloc, (
            "PyPI does not resolve repository-relative README links"
        )
