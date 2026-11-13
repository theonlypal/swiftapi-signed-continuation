import asyncio
from unittest.mock import Mock, patch
import pytest
from swiftapi.brake.benchmarks import summarize
from swiftapi.brake.core import (
    ActionEnvelope,
    BindingCondition,
    LocalAuthority,
    InvalidEnvelope,
    canonical,
)
from swiftapi.brake.remote import RemoteAuthority
from swiftapi.exceptions import NetworkError


def row(case="one", **changes):
    return dict(
        case_id=case,
        framework="HarmBench",
        revision="a" * 40,
        corpus_sha256="b" * 64,
        classification="GATE_BLOCK",
        evidence_sha256="c" * 64,
        authorized=False,
        consequence_observed=False,
        **changes,
    )


def test_eval_error_cannot_be_hidden():
    escaped = row("two")
    escaped["consequence_observed"] = True
    report = summarize([row(), escaped], ["one", "two"])
    assert report["status"] == "FAIL" and report["unauthorized_consequential_escapes"] == 1
    assert len(report["results"]) == 2 and report["failures"] == [escaped]


def test_eval_denominator_cannot_change():
    with pytest.raises(InvalidEnvelope):
        summarize([row()], ["one", "two"])
    with pytest.raises(InvalidEnvelope):
        summarize([row(), row()], ["one", "two"])


def test_remote_authority_and_async_are_verified():
    signer = LocalAuthority()
    action = ActionEnvelope("x", {"value": 1})
    state = {"approved": True}
    condition = BindingCondition(action.action_hash, state)
    decision = signer.authorize(action=action, condition=condition, state=state)
    remote = RemoteAuthority("https://authority.example/authorize", signer.public_key, "test-token")
    with patch(
        "swiftapi.brake.remote.requests.post",
        return_value=Mock(status_code=200, content=canonical(decision.to_dict())),
    ) as post:
        assert remote.authorize(action=action, condition=condition, state=state).allowed
        assert asyncio.run(
            remote.authorize_async(action=action, condition=condition, state=state)
        ).allowed
        assert post.call_args.kwargs["allow_redirects"] is False
        assert post.call_args.kwargs["timeout"] == 10
        assert b"test-token" not in post.call_args.kwargs["data"]


def test_remote_redirect_no_retry():
    remote = RemoteAuthority(
        "https://authority.example/authorize", LocalAuthority().public_key, "test"
    )
    with patch("swiftapi.brake.remote.requests.post", return_value=Mock(status_code=302)) as post:
        with pytest.raises(NetworkError):
            remote.authorize(action=ActionEnvelope("x", {}), condition=None, state={})
        assert post.call_count == 1


def test_corpus_loader_preserves_rows_and_hashes(tmp_path):
    import hashlib
    from swiftapi.brake.benchmarks import load_cases

    path = tmp_path / "inert.csv"
    path.write_text(
        "Behavior,BehaviorID,SemanticCategory,ContextString\nInert one,a,test,context\nInert two,b,test,\n"
    )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    rows = load_cases("HarmBench", path, digest)
    assert len(rows) == 2 and rows[0]["context"] == "context"
    path.write_text(path.read_text() + "Changed,c,test,\n")
    with pytest.raises(InvalidEnvelope):
        load_cases("HarmBench", path, digest)
