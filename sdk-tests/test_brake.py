import json
import os
from pathlib import Path
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from hypothesis import given, strategies as st
from swiftapi import (
    ActionEnvelope,
    BindingCondition,
    LocalAuthority,
    LocalGuard,
    CapabilityBroker,
    AuthorizationDenied,
    ReplayError,
    verify_receipt,
)
from swiftapi.brake.core import canonical, loads, verify_decision, InvalidEnvelope, ReplayLedger
from swiftapi.brake.install import install, uninstall, doctor
from swiftapi.brake.observations import observe
from swiftapi.brake.qualification import qualify
from swiftapi.brake.mcp import call, tools


@pytest.fixture
def signed():
    authority = LocalAuthority()
    action = ActionEnvelope("service.write", {"target": "one", "bytes": "x"}, "write one")
    state = {"ticket": "approved", "revision": 7}
    condition = BindingCondition(action.action_hash, state)
    decision = authority.authorize(action=action, state=state, condition=condition)
    return authority, action, state, condition, decision


def test_qualification(tmp_path):
    report = qualify(tmp_path / "qualification")
    assert report["status"] == "PASS"
    assert report["passed"] == report["total"] == 11
    for path in report["receipts"]:
        assert verify_receipt(loads(Path(path).read_bytes()), report["public_key"])


def test_missing_condition_never_calls_function(tmp_path, signed):
    authority, action, state, _, _ = signed
    calls = []
    guard = LocalGuard(authority, tmp_path / "ledger")
    with pytest.raises(AuthorizationDenied):
        guard.run(
            lambda: calls.append(1),
            action=action.capability,
            params=action.params,
            intent=action.intent,
            condition=None,
            state=state,
        )
    assert calls == []


def test_guard_executes_after_verified_condition(tmp_path, signed):
    authority, action, state, condition, _ = signed
    calls = []
    guard = LocalGuard(authority, tmp_path / "ledger")
    assert (
        guard.run(
            lambda: calls.append(1),
            action=action.capability,
            params=action.params,
            intent=action.intent,
            condition=condition,
            state=state,
        )
        is None
    )
    assert calls == [1]


@pytest.mark.parametrize(
    "field,value",
    [
        ("action_hash", "0" * 64),
        ("state_hash", "0" * 64),
        ("condition_hash", "0" * 64),
        ("capability", "different"),
        ("allowed", "true"),
        ("allowed", False),
        ("expires_at", 0),
        ("expires_at", True),
        ("issued_at", True),
        ("issued_at", 9007199254740991),
        ("nonce", "../bad"),
        ("schema", "swiftapi.execution/v1"),
    ],
)
def test_even_signed_wrong_binding_denied(signed, field, value):
    authority, action, state, condition, decision = signed
    p = decision.to_dict()["payload"]
    p[field] = value
    with pytest.raises(AuthorizationDenied):
        verify_decision(authority.sign(p), authority.public_key, action, condition, state)


def test_no_self_asserted_trust(signed):
    authority, _, _, _, decision = signed
    with pytest.raises(AuthorizationDenied):
        verify_receipt(decision, LocalAuthority().public_key)
    assert verify_receipt(decision, authority.public_key)["allowed"]


def test_nested_snapshots_are_immutable(signed):
    authority, action, state, condition, decision = signed
    action.params["target"] = "changed"
    condition.required_state["ticket"] = "changed"
    decision.payload["allowed"] = False
    assert action.to_dict()["params"]["target"] == "one"
    assert condition.to_dict()["required_state"]["ticket"] == "approved"
    assert decision.allowed
    verify_decision(decision, authority.public_key, action, condition, state)


def test_type_sensitive_condition():
    action = ActionEnvelope("x", {})
    condition = BindingCondition(action.action_hash, {"x": True})
    assert not condition.evaluate(action, {"x": 1})


@pytest.mark.parametrize(
    "value", [float("nan"), float("inf"), 1.5, 2**53, {1: "bad"}, ("a",), {"x": object()}, "\ud800"]
)
def test_canonical_rejects_ambiguous_values(value):
    with pytest.raises(InvalidEnvelope):
        canonical(value)


@given(
    st.dictionaries(
        st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=10),
        st.integers(min_value=-(2**53 - 1), max_value=2**53 - 1),
        max_size=10,
    )
)
def test_canonical_property(mapping):
    assert canonical(mapping) == canonical(dict(reversed(list(mapping.items()))))
    assert loads(canonical(mapping)) == mapping


def test_duplicate_json_key_rejected():
    with pytest.raises(InvalidEnvelope):
        loads('{"allowed": false, "allowed": true}')


def test_replay_atomic_across_connections(tmp_path):
    def worker(_):
        ledger = ReplayLedger(tmp_path / "ledger")
        try:
            ledger.claim("trusted", "unique")
            return 1
        except ReplayError:
            return 0

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(worker, range(20))) == 1
    with pytest.raises(ReplayError):
        ReplayLedger(tmp_path / "ledger").claim("trusted", "unique")


def test_unauthorized_broker_never_changes_target(tmp_path):
    broker = CapabilityBroker(tmp_path / "broker")
    request = broker.propose("test.txt", "the exact bytes")
    result = broker.execute(request["request_id"])
    assert result["classification"] == "GATE_BLOCK"
    assert list(broker.sandbox.iterdir()) == []
    broker.authorize(request["request_id"])
    result = broker.execute(request["request_id"])
    assert result["classification"] == "AUTHORIZED_EXECUTION"
    assert broker.read_marker("test.txt")["content"] == "the exact bytes"
    assert broker.execute(request["request_id"])["classification"] == "GATE_BLOCK"


@pytest.mark.parametrize("name", ["../outside", "/absolute", ".hidden", "a/b", "x\x00y", ""])
def test_broker_path_traversal(tmp_path, name):
    broker = CapabilityBroker(tmp_path / "broker")
    with pytest.raises(InvalidEnvelope):
        broker.propose(name, "x")


def test_broker_no_overwrite_or_symlink(tmp_path):
    broker = CapabilityBroker(tmp_path / "broker")
    target = broker.sandbox / "target"
    outside = tmp_path / "outside"
    outside.write_text("original")
    target.symlink_to(outside)
    with pytest.raises(AuthorizationDenied):
        broker.propose("target", "changed")
    assert outside.read_text() == "original"


def test_swap_sandbox_after_authorization(tmp_path):
    broker = CapabilityBroker(tmp_path / "broker")
    rid = broker.propose("target", "x")["request_id"]
    broker.authorize(rid)
    broker.sandbox.rename(broker.root / "old-sandbox")
    broker.sandbox.mkdir(mode=0o700)
    assert broker.execute(rid)["classification"] == "GATE_BLOCK"
    assert not list(broker.sandbox.iterdir())


def test_forged_broker_grant(tmp_path):
    broker = CapabilityBroker(tmp_path / "broker")
    rid = broker.propose("target", "x")["request_id"]
    broker.authorize(rid)
    grant = broker.grants / (rid + ".json")
    data = loads(grant.read_bytes())
    data["payload"]["action_hash"] = "f" * 64
    grant.write_text(json.dumps(data))
    assert broker.execute(rid)["classification"] == "GATE_BLOCK"
    assert not list(broker.sandbox.iterdir())


def test_broker_execution_race(tmp_path):
    broker = CapabilityBroker(tmp_path / "broker")
    rid = broker.propose("target", "x")["request_id"]
    broker.authorize(rid)
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda _: broker.execute(rid), range(10)))
    assert sum(r["classification"] == "AUTHORIZED_EXECUTION" for r in results) == 1
    assert (broker.sandbox / "target").read_text() == "x"


def test_preexecution_receipt_error_blocks_side_effect(tmp_path, monkeypatch):
    broker = CapabilityBroker(tmp_path / "broker")
    rid = broker.propose("target", "x")["request_id"]
    broker.authorize(rid)

    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(broker, "_receipt", fail)
    with pytest.raises(OSError):
        broker.execute(rid)
    assert not list(broker.sandbox.iterdir())


def test_no_authorize_mcp_tool(tmp_path):
    broker = CapabilityBroker(tmp_path / "broker")
    assert "authorize" not in [t["name"] for t in tools()]
    with pytest.raises(Exception):
        call(broker, "authorize", {})


def test_mcp_stdio_handshake_and_gate(tmp_path):
    env = dict(os.environ, SWIFTAPI_HOME=str(tmp_path / "broker"))
    requests = [
        dict(jsonrpc="2.0", id=1, method="initialize", params={"protocolVersion": "2025-11-25"}),
        dict(jsonrpc="2.0", method="notifications/initialized"),
        dict(jsonrpc="2.0", id=2, method="tools/list"),
        dict(jsonrpc="2.0", id=3, method="tools/call", params={"name": "status", "arguments": {}}),
    ]
    r = subprocess.run(
        [sys.executable, "-m", "swiftapi", "mcp"],
        input="\n".join(json.dumps(x) for x in requests) + "\n",
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    answers = [json.loads(x) for x in r.stdout.splitlines()]
    assert len(answers) == 3
    assert answers[0]["result"]["protocolVersion"] == "2025-11-25"
    assert len(answers[1]["result"]["tools"]) == 4
    assert answers[2]["result"]["isError"] is False


@pytest.mark.parametrize("host", ["codex", "claude"])
def test_install_dry_run_idempotence_and_owned_uninstall(tmp_path, host):
    path = tmp_path / (".codex/config.toml" if host == "codex" else ".claude.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    original = (
        b'model = "existing"\n'
        if host == "codex"
        else b'{"mcpServers":{"existing":{"command":"safe"}},"theme":"dark"}\n'
    )
    path.write_bytes(original)
    plan = install(host, True, tmp_path)
    assert plan["dry_run"] and path.read_bytes() == original
    assert not (tmp_path / ".local").exists()
    install(host, False, tmp_path)
    first = path.read_bytes()
    assert install(host, False, tmp_path)["changes"][0]["status"] == "already installed"
    assert path.read_bytes() == first
    assert doctor(tmp_path)["hosts"][host]["installed"]
    if host == "codex":
        path.write_bytes(path.read_bytes() + "\n# unrelated change\n".encode())
    else:
        obj = json.loads(path.read_bytes())
        obj["theme"] = "new"
        path.write_text(json.dumps(obj))
    uninstall(host, False, tmp_path)
    if host == "codex":
        assert path.read_bytes() == original + b"\n# unrelated change\n"
    else:
        obj = json.loads(path.read_bytes())
        assert obj["theme"] == "new" and set(obj["mcpServers"]) == {"existing"}
    assert not doctor(tmp_path)["hosts"][host]["installed"]


def test_uninstall_preserves_modified_owned_configuration(tmp_path):
    install("codex", False, tmp_path)
    path = tmp_path / ".codex/config.toml"
    path.write_text(path.read_text().replace("swiftapi_brake", "modified"))
    old = path.read_bytes()
    with pytest.raises(InvalidEnvelope):
        uninstall("codex", False, tmp_path)
    assert path.read_bytes() == old


def test_provider_stop_is_not_native_eos():
    result = observe(successful=True, visible_text="", finish_reason="stop")
    assert result["classification"] == "PROVIDER_VOID"
    assert result["void_subtype"] == "V0" and not result["native_eos_verified"]
    assert (
        observe(
            successful=True,
            visible_text="",
            finish_reason="stop",
            native_token_ids=[151645],
            eos_token_id=151645,
        )["classification"]
        == "NATIVE_VOID"
    )
    assert (
        observe(successful=True, visible_text="", finish_reason="stop", tool_calls=True)[
            "classification"
        ]
        == "ERROR"
    )
    assert (
        observe(successful=False, visible_text="", finish_reason="stop")["classification"]
        == "ERROR"
    )
    assert observe(successful=True, visible_text=" ", finish_reason="stop")["void_subtype"] is None


def test_cli_verifies_denial_and_execution_receipts(tmp_path, capsys):
    from swiftapi.cli import main

    report = qualify(tmp_path / "qualify-cli")
    for receipt in report["receipts"]:
        assert (
            main(["verify", receipt, "--public-key", str(tmp_path / "qualify-cli/public-key.json")])
            == 0
        )
        assert json.loads(capsys.readouterr().out)["schema"] == "swiftapi.execution/v1"
    altered = json.loads(Path(report["receipts"][0]).read_text())
    altered["signature"] = "A" * 88
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(altered))
    assert (
        main(["verify", str(forged), "--public-key", str(tmp_path / "qualify-cli/public-key.json")])
        == 1
    )


def test_mcp_tool_annotations_describe_bounded_effects():
    from swiftapi.brake.mcp import tools

    descriptions = {tool["name"]: tool for tool in tools()}
    assert {name for name, tool in descriptions.items() if tool["annotations"]["readOnlyHint"]} == {
        "status",
        "read_marker",
    }
    assert all(
        not tool["annotations"]["destructiveHint"] and not tool["annotations"]["openWorldHint"]
        for tool in descriptions.values()
    )


def test_reinstall_preserves_claude_native_json_formatting(tmp_path):
    install("claude", False, tmp_path)
    config = tmp_path / ".claude.json"
    obj = json.loads(config.read_text())
    obj["unrelatedNativeState"] = {"counter": 2}
    native_bytes = json.dumps(obj, separators=(",", ":")).encode()
    config.write_bytes(native_bytes)
    result = install("claude", False, tmp_path)
    assert result["changes"][0]["status"] == "already installed"
    assert config.read_bytes() == native_bytes


def test_cli_execution_error_has_error_exit(monkeypatch, capsys):
    from unittest.mock import Mock
    import swiftapi.cli as cli

    broker = Mock()
    broker.execute.return_value = {"classification": "ERROR", "executed": False}
    monkeypatch.setattr(cli, "CapabilityBroker", lambda: broker)
    assert cli.main(["brake", "execute", "a" * 64]) == 1
    assert json.loads(capsys.readouterr().out)["classification"] == "ERROR"
