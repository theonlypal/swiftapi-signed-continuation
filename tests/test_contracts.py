
import base64
import copy
import hashlib
import json
import os
import shutil
import socket
import threading
import types
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import torch
from nacl.signing import SigningKey

from swiftapi import native_taxonomy, native_verify
from swiftapi.exceptions import PolicyViolation, SwiftAPIError
from swiftapi.native import NativeEOSClient
from swiftapi_native_service import backend as B
from swiftapi_native_service import core, service as S, verify as full_verify
from swiftapi_native_service.httpd import LocalServer
from swiftapi_native_service import experiment as X

WORKSPACE = Path(__file__).resolve().parents[1]
HARNESS = Path(os.environ.get("SWIFTAPI_NATIVE_HARNESS_DIR", WORKSPACE.parent / "swiftapi-native-eos-receipts"))
SOURCE = Path(os.environ.get("SWIFTAPI_NATIVE_SOURCE_DIR", HARNESS / ".cache" / "pccg2"))
FROZEN_TAXONOMY = Path(os.environ.get("SWIFTAPI_FROZEN_TAXONOMY", str(Path.home()/".cache/swiftapi-native/void_matrix.FROZEN.py")))
Q = "What is 2 + 2?"
KEY = "swiftapi_live_" + "5a" * 32          
OTHER_KEY = "swiftapi_live_" + "c3" * 32    
EOS = 151645
VERIFIED, NOT_VERIFIED = "PERMISSION_VERIFIED", "PERMISSION_NOT_VERIFIED"
REPLAY, FRESH = "RECORDED_LOGITS_REPLAY", "FRESH_MODEL_EXECUTION"
UNSIGNED_FIELDS = {"signature", "signing_mode", "action_data", "denial_reason", "violated_policies",
                   "evaluated_policies", "evaluation_context"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


class Clock:
    pass

    def __init__(self, start=1_800_000_000.0):
        self.now = start

    def time(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class LabelledTestAuthority:
    pass

    evidence_kind = "LABELLED_TEST_DOUBLE_AUTHORITY_NOT_PRODUCTION"

    def __init__(self, clock=None):
        self._key = SigningKey.generate()
        self.public_key = base64.b64encode(bytes(self._key.verify_key)).decode()
        self.clock = clock
        self.unknown, self.revoked, self.calls = set(), set(), []
        self.permission = "APPROVE"          
        self.unreachable = False             
        self.revocation_unreachable = False  
        self.on_recheck = None
        self.revocation_evidence = None      

    def now(self):
        import time
        return self.clock.time() if self.clock else time.time()

    def issue(self, action, approved=True, age=0.0, lifetime=300.0):
        issued = self.now() - age
        grant = {"jti": uuid.uuid4().hex, "action_type": action["scope"],
                 "action_fingerprint": sha(compact(action))[:32], "approved": approved,
                 "issued_at": iso(issued), "expires_at": iso(issued + lifetime),
                 "signing_mode": "ed25519", "action_data": action}
        if not approved:
            grant["denial_reason"] = "TEST DOUBLE denial"
        signed = {k: v for k, v in grant.items() if k not in UNSIGNED_FIELDS}
        grant["signature"] = base64.b64encode(self._key.sign(compact(signed)).signature).decode()
        return grant

    def _signature(self, grant, ignore_expiry=True):
        native_verify.signature({k: v for k, v in grant.items() if k not in UNSIGNED_FIELDS}, grant["signature"],
                                self.public_key)

    def validate(self, grant, action, now=None):
        core.check_grant(grant, action, now=self.now() if now is None else now, verifier=self._signature)

    def authorize(self, key, action):
        core.validate_key(key)
        self.calls.append(("attest", action["scope"]))
        if self.unreachable:
            raise core.ServiceError("AUTHORITY_UNAVAILABLE", 503)
        if key in self.unknown:
            raise core.ServiceError("AUTHENTICATION_REJECTED", 401)
        if action["scope"] == core.SCOPE and self.permission == "UNSIGNED_DENIAL":
            raise core.ServiceError("AUTHORITY_DENIED", 403)
        if action["scope"] == core.SCOPE and self.permission == "SIGNED_DENIAL":
            return self.issue(action, approved=False)
        return self.issue(action)

    def authenticate(self, key, instance):
        action = {"scope": "swiftapi.native_service.connection_check", "nonce": str(uuid.uuid4()),
                  "principal_sha256": core.validate_key(key), "instance_id": instance}
        grant = self.authorize(key, action)
        return {"action": action, "grant": grant, "observed_at": self.now(),
                "identity_basis": "TEST DOUBLE connection-check grant"}

    def recheck(self, key, grant, action):
        self.validate(grant, action)
        self.calls.append(("revocation", grant["jti"]))
        if self.on_recheck:
            self.on_recheck()
        if self.revocation_unreachable:
            raise core.ServiceError("REVOCATION_UNAVAILABLE", 503)
        if grant["jti"] in self.revoked:
            revoked = core.ServiceError("AUTHORITY_REVOKED", 403)
            if self.revocation_evidence is not None:
                revoked.revocation_evidence = self.revocation_evidence(grant["jti"])
            raise revoked

    def revocation_entry(self, jti, revoked_at=None, cursor=7, **changes):
        pass
        entry = {"cursor": cursor, "jti": jti, "revoked_at": iso(self.now() - 1 if revoked_at is None else revoked_at),
                 "revoked_by": "TEST DOUBLE", "reason": "TEST DOUBLE revocation"}
        entry.update(changes)
        entry["signature"] = base64.b64encode(self._key.sign(compact(entry)).signature).decode()
        return entry


@pytest.fixture(scope="module")
def replay_backend():
    if not (HARNESS / "SOURCE_MANIFEST.json").is_file():
        pytest.fail("Pinned harness and source are required")
    return B.PCCG2Backend(SOURCE, Path("/nonexistent-content"), HARNESS, B.REPLAY)


@pytest.fixture
def clock(monkeypatch):
    fake = Clock()
    for module in (core, S):
        monkeypatch.setattr(module, "time", fake)
    return fake


@pytest.fixture
def world(replay_backend, tmp_path):
    authority = LabelledTestAuthority()
    service = S.NativeService(replay_backend, tmp_path / "runtime", authority=authority)
    return types.SimpleNamespace(service=service, authority=authority, backend=replay_backend, tmp=tmp_path)


@pytest.fixture
def timed(replay_backend, tmp_path, clock):
    authority = LabelledTestAuthority(clock)
    service = S.NativeService(replay_backend, tmp_path / "runtime", authority=authority)
    return types.SimpleNamespace(service=service, authority=authority, backend=replay_backend, clock=clock,
                                 tmp=tmp_path)


def new_id():
    return str(uuid.uuid4())


def body(request_id, grant="OMIT", question=Q):
    data = {"request_id": request_id, "question": question}
    if grant != "OMIT":
        data["grant"] = grant
    return data


def generate(w, request_id=None, grant="OMIT", key=KEY, question=Q):
    data = body(request_id or new_id(), grant, question)
    return w.service.generate(key, data, raw_request=compact(data))


def permitted(w, key=KEY, question=Q):
    request_id = new_id()
    permission = w.service.authorize(key, {"request_id": request_id, "question": question})
    return request_id, permission


def folder(w, receipt):
    return w.service.signer.directory / "evidence" / receipt["payload"]["execution_id"]


def light(w, receipt, mode=REPLAY, directory=None):
    path = (directory or folder(w, receipt)) / "receipt.json"
    return native_verify.verify_receipt(path, w.service.signer.public, mode, authority_key=w.authority.public_key,
                                        expected_max_grant_age_seconds=60)


def full(w, receipt, mode=REPLAY, directory=None, backend=None):
    path = (directory or folder(w, receipt)) / "receipt.json"
    return full_verify.verify_receipt(path, w.service.signer.public, mode, backend or w.backend,
                                      authority_key=w.authority.public_key, expected_max_grant_age_seconds=60)


def both(w, receipt, mode=REPLAY):
    return light(w, receipt, mode), full(w, receipt, mode)


def assert_v0(row, reason):
    assert row["status"] == "COMPLETED", row.get("error_code")
    assert row["authority_decision"]["permission"] == NOT_VERIFIED
    assert row["authority_decision"]["reason"] == reason
    assert row["gate_condition"] == "EQ(485487,485489)"
    assert row["result"]["generated_token_ids"] == [EOS] and row["output"] == ""
    assert row["taxonomy"]["class"] == "V0" and row["decoder_executed"] is True
    assert row["stop_cause"] == "LEARNED_GATE"


def resigned_copy(w, receipt, mutate, name="forged"):
    pass
    target = w.tmp / name / uuid.uuid4().hex
    shutil.copytree(folder(w, receipt), target)
    payload = copy.deepcopy(receipt["payload"])
    mutate(payload, target)
    (target / "receipt.json").write_bytes(compact(w.service.signer.sign(payload)) + b"\n")
    return target


def test_verified_permission_selects_the_archived_token_and_the_receipt_binds_everything(world):
    request_id, permission = permitted(world)
    assert permission["grant"]["approved"] is True and permission["authority_refusal"] is None
    receipt = generate(world, request_id, permission["grant"])
    row = receipt["payload"]
    assert row["status"] == "COMPLETED" and row["schema"] == "swiftapi-native-service-receipt/2"
    assert row["authority_decision"]["permission"] == VERIFIED
    assert row["authority_decision"]["reason"] == "VERIFIED_EXACT_REQUEST"
    assert row["authority_decision"]["denial_authority_signed"] is False
    assert row["gate_condition"] == "EQ(485487,485487)" and row["stop_cause"] == "NONE"
    assert row["result"]["generated_token_ids"] == [19] and row["output"] == "4"
    
    assert row["mode"] == REPLAY and row["model_executed"] is False
    assert row["taxonomy"]["class"] == "R"
    assert row["taxonomy"]["response_scope"] == "FIRST_TOKEN_ONLY_NOT_A_COMPLETE_ANSWER"
    assert row["result"]["finish"] == "REPLAY_ONE_TOKEN_ONLY" and row["result"]["generation_complete"] is False
    assert row["authority_evidence_kind"] == "LABELLED_TEST_DOUBLE_AUTHORITY_NOT_PRODUCTION"
    
    files = folder(world, receipt)
    artifacts = world.backend.prompt_artifacts(Q)
    assert (files / "prompt.utf8.bin").read_bytes() == artifacts["rendered_prompt"]
    assert row["action"]["rendered_prompt_sha256"] == sha(artifacts["rendered_prompt"])
    assert json.loads((files / "input-token-ids.json").read_bytes()) == artifacts["input_ids"]
    assert row["action"]["input_ids_sha256"] == sha(compact(artifacts["input_ids"]))
    assert (files / "grant.json").read_bytes() == compact(permission["grant"])
    assert row["assets"]["grant.json"]["sha256"] == sha(compact(permission["grant"]))
    assert (files / "output.bin").read_bytes() == b"4" and row["assets"]["output.bin"]["sha256"] == sha(b"4")
    stock, selected = ((files / f"0-{kind}.bf16.bin").read_bytes() for kind in ("stock", "selected"))
    assert row["vector_files"] == {"0-stock.bf16.bin": sha(stock), "0-selected.bf16.bin": sha(selected)}
    cut = 2 * EOS
    assert stock[:cut] == selected[:cut] and stock[cut + 2:] == selected[cut + 2:]
    assert stock[cut:cut + 2] != selected[cut:cut + 2]
    assert row["action_sha256"] == sha(compact(row["action"]))
    assert permission["grant"]["action_fingerprint"] == row["action_sha256"][:32]
    summary_light, summary_full = both(world, receipt)
    assert summary_light["status"] == "PASS" and summary_full["numerical_replay"] == "PASS"
    assert summary_full["full_model_forward_pass_reproduced"] is False


def test_null_grant_is_not_verified_and_runs_the_decoder_to_a_signed_v0(world):
    receipt = generate(world, grant=None)
    assert_v0(receipt["payload"], "MISSING_PERMISSION")
    assert receipt["payload"]["authority_decision"]["denial_authority_signed"] is False
    both(world, receipt)


def test_omitted_grant_is_not_verified_and_its_receipt_verifies(world):
    pass
    receipt = generate(world, grant="OMIT")
    assert_v0(receipt["payload"], "MISSING_PERMISSION")
    both(world, receipt)


@pytest.mark.parametrize("key", [None, "", "swiftapi_live_short", KEY.upper(), KEY + "0", 7, OTHER_KEY])
def test_missing_malformed_or_unknown_key_is_operational_and_never_reaches_the_backend(world, monkeypatch, key):
    world.authority.unknown.add(OTHER_KEY)
    monkeypatch.setattr(world.backend, "run", lambda *a, **k: pytest.fail("backend reached"))
    monkeypatch.setattr(world.backend, "prompt_artifacts", lambda *a, **k: pytest.fail("prompt rendered"))
    data = body(new_id(), None)
    receipt = world.service.generate(key, data, raw_request=compact(data))
    row = receipt["payload"]
    assert row["status"] == "OPERATIONAL" and row["taxonomy"]["class"] == "operational"
    assert row["decoder_executed"] is False and row["model_executed"] is False
    assert row["authority_decision"] is None and row["authentication"] is None and row["output"] == ""
    assert "result" not in row and row["vector_files"] == {}
    assert light(world, receipt)["execution_outcome"] == "OPERATIONAL_NOT_A_VOID"


def test_signed_denial_is_kept_and_labelled_authority_signed(world):
    world.authority.permission = "SIGNED_DENIAL"
    request_id, permission = permitted(world)
    assert permission["grant"]["approved"] is False and permission["denial_authority_signed"] is True
    receipt = generate(world, request_id, permission["grant"])
    row = receipt["payload"]
    assert_v0(row, "AUTHORITY_DENIED")
    assert row["authority_decision"]["denial_authority_signed"] is True
    assert row["authority_decision"]["authority_reported_approved"] is False
    assert (folder(world, receipt) / "authority-denial.json").read_bytes() == compact(permission["grant"])
    both(world, receipt)


def test_unsigned_refusal_is_never_labelled_authority_signed(world):
    world.authority.permission = "UNSIGNED_DENIAL"
    request_id, permission = permitted(world)
    assert permission["grant"] is None and permission["denial_authority_signed"] is False
    receipt = generate(world, request_id, permission["grant"])
    row = receipt["payload"]
    assert_v0(row, "AUTHORITY_DENIED_UNSIGNED")
    assert row["authority_decision"]["denial_authority_signed"] is False
    assert "authority-denial.json" not in row["assets"]
    both(world, receipt)


def test_a_denial_whose_signature_does_not_verify_is_not_an_authority_signed_denial(world):
    world.authority.permission = "SIGNED_DENIAL"
    request_id, permission = permitted(world)
    forged = dict(permission["grant"], signature=base64.b64encode(bytes(64)).decode())
    receipt = generate(world, request_id, forged)
    row = receipt["payload"]
    assert_v0(row, "INVALID_AUTHORITY_SIGNATURE")
    assert row["authority_decision"]["denial_authority_signed"] is False
    both(world, receipt)


def test_expired_grant(timed):
    request_id = new_id()
    action, _ = timed.service.action(core.validate_key(KEY), {"request_id": request_id, "question": Q})
    grant = timed.authority.issue(action, age=61.0)
    receipt = generate(timed, request_id, grant)
    assert_v0(receipt["payload"], "GRANT_EXPIRED")
    both(timed, receipt)


def test_future_grant(timed):
    request_id = new_id()
    action, _ = timed.service.action(core.validate_key(KEY), {"request_id": request_id, "question": Q})
    receipt = generate(timed, request_id, timed.authority.issue(action, age=-30.0))
    assert_v0(receipt["payload"], "GRANT_FUTURE")
    both(timed, receipt)


def test_grant_bound_to_another_request_or_another_key(world):
    other_id, other = permitted(world)
    receipt = generate(world, new_id(), other["grant"])
    assert_v0(receipt["payload"], "GRANT_BINDING_MISMATCH")
    both(world, receipt)
    
    receipt = generate(world, other_id, other["grant"], key=OTHER_KEY)
    assert_v0(receipt["payload"], "GRANT_BINDING_MISMATCH")
    both(world, receipt)


def test_grant_for_another_question_in_the_bank(world):
    other_question = next(q for q in world.backend.allowed_questions if q != Q)
    request_id, permission = permitted(world, question=other_question)
    receipt = generate(world, request_id, permission["grant"], question=Q)
    assert_v0(receipt["payload"], "GRANT_BINDING_MISMATCH")


def test_zeroed_signature(world):
    request_id, permission = permitted(world)
    receipt = generate(world, request_id, dict(permission["grant"], signature=base64.b64encode(bytes(64)).decode()))
    assert_v0(receipt["payload"], "INVALID_AUTHORITY_SIGNATURE")
    both(world, receipt)


@pytest.mark.parametrize("junk", [False, 0, "", [], "grant", 1.5, {"approved": True}, {}])
def test_a_grant_that_is_not_a_grant(world, junk):
    receipt = generate(world, grant=junk)
    assert_v0(receipt["payload"], "INVALID_AUTHORITY_SIGNATURE")
    both(world, receipt)


def test_grant_signed_by_another_authority(world):
    request_id = new_id()
    action, _ = world.service.action(core.validate_key(KEY), {"request_id": request_id, "question": Q})
    receipt = generate(world, request_id, LabelledTestAuthority().issue(action))
    assert_v0(receipt["payload"], "INVALID_AUTHORITY_SIGNATURE")
    both(world, receipt)


def test_revoked_grant_in_the_test_double(world):
    pass
    request_id, permission = permitted(world)
    world.authority.revoked.add(permission["grant"]["jti"])
    receipt = generate(world, request_id, permission["grant"])
    assert_v0(receipt["payload"], "AUTHORITY_REVOKED")
    assert receipt["payload"]["authority_decision"]["grant_checks_passed"] is True
    both(world, receipt)


def test_used_request_and_used_grant(world):
    request_id, permission = permitted(world)
    first = generate(world, request_id, permission["grant"])
    assert first["payload"]["authority_decision"]["permission"] == VERIFIED
    second = generate(world, request_id, permission["grant"])
    assert_v0(second["payload"], "REPLAYED_REQUEST")
    assert second["payload"]["execution_id"] != first["payload"]["execution_id"]
    both(world, second)
    
    both(world, first)


def test_a_replayed_request_that_carries_a_signed_denial_still_verifies(world):
    world.authority.permission = "SIGNED_DENIAL"
    request_id, permission = permitted(world)
    generate(world, request_id, permission["grant"])
    second = generate(world, request_id, permission["grant"])
    assert_v0(second["payload"], "REPLAYED_REQUEST")
    both(world, second)


def test_key_rejected_at_the_boundary(world, monkeypatch):
    request_id, permission = permitted(world)
    real = world.backend.run

    def run(question, *, decide):
        def at_boundary():
            world.authority.unknown.add(KEY)
            return decide()
        return real(question, decide=at_boundary)

    monkeypatch.setattr(world.backend, "run", run)
    receipt = generate(world, request_id, permission["grant"])
    row = receipt["payload"]
    assert_v0(row, "KEY_REJECTED_AT_BOUNDARY")
    assert row["boundary_authentication"] is None
    both(world, receipt)


def test_replayed_request_with_the_key_rejected_at_the_boundary_still_verifies(world, monkeypatch):
    request_id, permission = permitted(world)
    generate(world, request_id, permission["grant"])
    real = world.backend.run

    def run(question, *, decide):
        def at_boundary():
            world.authority.unknown.add(KEY)
            return decide()
        return real(question, decide=at_boundary)

    monkeypatch.setattr(world.backend, "run", run)
    second = generate(world, request_id, permission["grant"])
    assert second["payload"]["authority_decision"]["permission"] == NOT_VERIFIED
    both(world, second)


def test_unreachable_authority_before_the_request_is_operational(world, monkeypatch):
    monkeypatch.setattr(world.backend, "run", lambda *a, **k: pytest.fail("backend reached"))
    world.authority.unreachable = True
    receipt = generate(world, grant=None)
    row = receipt["payload"]
    assert row["status"] == "OPERATIONAL" and row["error_code"] == "AUTHORITY_UNAVAILABLE"
    assert row["taxonomy"]["class"] == "operational" and row["authority_decision"] is None
    light(world, receipt)


def test_unreachable_authority_at_the_boundary_selects_nothing_and_keeps_the_scored_vector(world, monkeypatch):
    request_id, permission = permitted(world)
    real = world.backend.run

    def run(question, *, decide):
        def at_boundary():
            world.authority.unreachable = True
            return decide()
        return real(question, decide=at_boundary)

    monkeypatch.setattr(world.backend, "run", run)
    receipt = generate(world, request_id, permission["grant"])
    row = receipt["payload"]
    assert row["status"] == "OPERATIONAL" and row["error_code"] == "AUTHORITY_UNAVAILABLE"
    assert row["taxonomy"]["class"] == "operational" and row["output"] == "" and "result" not in row
    assert row["authority_decision"] is None and row["vector_files"] == {}
    files = folder(world, receipt)
    assert (files / "output.bin").read_bytes() == b""
    archived = world.backend._logits[world.backend._index[Q]]
    assert (files / "partial-0-stock.bf16.bin").read_bytes() == B._vector_bytes(archived)
    trace = json.loads((files / "partial-trace.json").read_bytes())
    assert trace["selected_token_ids"] == [] and trace["output_released"] is False
    assert light(world, receipt)["execution_outcome"] == "OPERATIONAL_NOT_A_VOID"
    assert full(world, receipt)["execution_outcome"] == "OPERATIONAL_NOT_A_VOID"


def test_unreachable_revocation_lookup_is_operational_not_a_denial(world):
    request_id, permission = permitted(world)
    world.authority.revocation_unreachable = True
    receipt = generate(world, request_id, permission["grant"])
    row = receipt["payload"]
    assert row["status"] == "OPERATIONAL" and row["error_code"] == "REVOCATION_UNAVAILABLE"
    assert row["taxonomy"]["class"] == "operational" and row["authority_decision"] is None
    
    assert world.service.ledger.connection().execute(
        "SELECT COUNT(*) FROM used_grants WHERE jti=?", (permission["grant"]["jti"],)).fetchone()[0] == 0
    light(world, receipt)


def test_an_operational_receipt_issued_after_authentication_still_verifies(world, monkeypatch):
    pass
    monkeypatch.setattr(world.service, "readiness", lambda: {"ready": False, "status": "BACKEND_NOT_WARM"})
    receipt = generate(world, grant=None)
    row = receipt["payload"]
    assert row["status"] == "OPERATIONAL" and row["error_code"] == "BACKEND_NOT_WARM" and row["http_status"] == 503
    assert row["decoder_executed"] is False
    assert light(world, receipt)["execution_outcome"] == "OPERATIONAL_NOT_A_VOID"


@pytest.mark.parametrize("change", [
    lambda b: b.update(extra=1),
    lambda b: b.update(condition="EQ(485487,485487)"),
    lambda b: b.update(authorization_status="VALID_ALLOW"),
    lambda b: b.update(permission="PERMISSION_VERIFIED"),
    lambda b: b.update(question="What is 2 + 3000?"),
    lambda b: b.update(request_id="not-a-uuid"),
    lambda b: b.pop("question"),
])
def test_a_caller_cannot_type_a_condition_or_a_permission(world, monkeypatch, change):
    monkeypatch.setattr(world.backend, "run", lambda *a, **k: pytest.fail("backend reached"))
    data = body(new_id(), None)
    change(data)
    receipt = world.service.generate(KEY, data, raw_request=compact(data))
    assert receipt["payload"]["status"] == "OPERATIONAL" and receipt["payload"]["decoder_executed"] is False
    with pytest.raises(core.ServiceError):
        world.service.authorize(KEY, data)


def test_the_key_never_reaches_a_file(world):
    request_id, permission = permitted(world)
    generate(world, request_id, permission["grant"])
    generate(world, grant=None)
    leaked = dict(body(new_id(), None), grant={"note": KEY})
    receipt = world.service.generate(KEY, leaked, raw_request=compact(leaked))
    assert receipt["payload"]["error_code"] == "CREDENTIAL_IN_PAYLOAD"
    for path in world.service.signer.directory.rglob("*"):
        if path.is_file():
            assert KEY.encode() not in path.read_bytes(), path


def test_the_decision_time_in_the_receipt_is_the_time_the_grant_was_checked(timed):
    pass
    request_id = new_id()
    action, _ = timed.service.action(core.validate_key(KEY), {"request_id": request_id, "question": Q})
    grant = timed.authority.issue(action, age=59.5)
    timed.authority.on_recheck = lambda: timed.clock.advance(1.0)
    receipt = generate(timed, request_id, grant)
    row = receipt["payload"]
    assert row["status"] == "COMPLETED"
    if row["authority_decision"]["permission"] == VERIFIED:
        both(timed, receipt)
    else:
        assert_v0(row, "GRANT_EXPIRED")
        both(timed, receipt)


def test_receipt_times_are_ordered_and_bound(timed):
    request_id, permission = permitted(timed)
    timed.clock.advance(2.0)
    receipt = generate(timed, request_id, permission["grant"])
    row = receipt["payload"]
    times = row["times"]
    assert times["request_arrival_at"] == row["started_at"] <= times["scores_ready_at"] <= times["decision_at"]
    assert times["decision_at"] == row["authority_decision"]["evaluated_at"] <= row["finished_at"]
    assert times["grant_issued_at"] == permission["grant"]["issued_at"]
    
    assert row["result"]["scores_ready_at"] is not None and row["result"]["timing"]["decision_outcome"] == "RETURNED"


class StubContent:
    def __init__(self, first, later_token, before=None):
        self.first, self.later_token, self.calls, self.before = first, later_token, 0, before

    def __call__(self, input_ids, past_key_values, use_cache, logits_to_keep):
        self.calls += 1
        if self.before:
            self.before(self.calls)
        if past_key_values is None:
            vector = self.first
        else:
            vector = torch.zeros(B.VOCABULARY, dtype=torch.bfloat16)
            vector[self.later_token] = 10
        return types.SimpleNamespace(logits=vector[None, None, :], past_key_values=self.calls)


def stub_fresh_world(replay_backend, tmp_path, monkeypatch, stub, clock=None, cap=4):
    import transformers
    monkeypatch.setattr(transformers.AutoModelForCausalLM, "from_pretrained",
                        lambda *a, **k: pytest.fail("content model loader reached"))
    backend = B.PCCG2Backend(SOURCE, tmp_path / "no-content", HARNESS, B.FRESH, full_model=True, max_new_tokens=cap)
    monkeypatch.setattr(backend, "_load_content", lambda: stub)
    monkeypatch.setattr(backend, "preflight", lambda: {"ready": True, "model_loaded": True,
                                                       "status": "TEST_DOUBLE_READY", "inference_executed": False})
    authority = LabelledTestAuthority(clock)
    service = S.NativeService(backend, tmp_path / "fresh-runtime", authority=authority)
    return types.SimpleNamespace(service=service, authority=authority, backend=replay_backend, clock=clock,
                                 tmp=tmp_path, fresh_backend=backend)


def witness(replay_backend):
    return replay_backend._logits[replay_backend._index[Q]].clone()


def test_stubbed_fresh_verified_trace_is_complete_and_verifies(replay_backend, tmp_path, monkeypatch):
    w = stub_fresh_world(replay_backend, tmp_path, monkeypatch, StubContent(witness(replay_backend), EOS))
    request_id, permission = permitted(w)
    receipt = generate(w, request_id, permission["grant"])
    row = receipt["payload"]
    assert row["status"] == "COMPLETED" and row["mode"] == FRESH and row["model_executed"] is True
    assert row["result"]["generated_token_ids"] == [19, EOS] and row["output"] == "4"
    assert row["taxonomy"]["class"] == "R" and row["taxonomy"]["response_scope"] == "COMPLETE_TO_NATIVE_EOS"
    assert len(row["vector_files"]) == 4
    assert light(w, receipt, FRESH)["status"] == "PASS"
    summary = full(w, receipt, FRESH)
    assert summary["numerical_replay"] == "PASS" and summary["full_model_forward_pass_reproduced"] is False


def test_stubbed_fresh_missing_permission_is_v0_after_one_forward_pass(replay_backend, tmp_path, monkeypatch):
    stub = StubContent(witness(replay_backend), 19)
    w = stub_fresh_world(replay_backend, tmp_path, monkeypatch, stub)
    receipt = generate(w, grant=None)
    assert_v0(receipt["payload"], "MISSING_PERMISSION")
    assert stub.calls == 1 and receipt["payload"]["model_executed"] is True
    light(w, receipt, FRESH)
    full(w, receipt, FRESH)


def test_stubbed_fresh_slow_forward_pass_expires_the_grant_and_stops(replay_backend, tmp_path, monkeypatch, clock):
    pass
    stub = StubContent(witness(replay_backend), EOS, before=lambda call: clock.advance(61.0) if call == 1 else None)
    w = stub_fresh_world(replay_backend, tmp_path, monkeypatch, stub, clock)
    request_id, permission = permitted(w)
    receipt = generate(w, request_id, permission["grant"])
    row = receipt["payload"]
    assert_v0(row, "GRANT_EXPIRED")
    assert stub.calls == 1 and row["times"]["scores_ready_at"] - row["times"]["request_arrival_at"] == 61.0
    assert row["authority_decision"]["denial_authority_signed"] is False
    light(w, receipt, FRESH)
    full(w, receipt, FRESH)


@pytest.mark.parametrize("cap", [1, 2, 8])
def test_stubbed_fresh_receipts_verify_for_any_configured_token_cap(replay_backend, tmp_path, monkeypatch, cap):
    pass
    w = stub_fresh_world(replay_backend, tmp_path, monkeypatch, StubContent(witness(replay_backend), 19), cap=cap)
    request_id, permission = permitted(w)
    receipt = generate(w, request_id, permission["grant"])
    row = receipt["payload"]
    assert row["status"] == "COMPLETED" and row["result"]["generated_token_ids"] == [19] * cap
    assert row["action"]["profile"]["max_new_tokens"] == cap == row["result"]["max_new_tokens"]
    assert row["taxonomy"]["response_scope"] == "TRUNCATED_AT_TOKEN_CAP"
    light(w, receipt, FRESH)
    full(w, receipt, FRESH)


def test_stubbed_fresh_failed_load_does_not_claim_the_model_ran(replay_backend, tmp_path, monkeypatch):
    w = stub_fresh_world(replay_backend, tmp_path, monkeypatch, None)

    def unavailable():
        raise B.RuntimeUnavailable("UNAVAILABLE_HARDWARE: TEST DOUBLE load error")

    monkeypatch.setattr(w.fresh_backend, "_load_content", unavailable)
    receipt = generate(w, grant=None)
    row = receipt["payload"]
    assert row["status"] == "OPERATIONAL" and "result" not in row
    assert row["model_executed"] is False, "no forward pass happened"


def test_stubbed_fresh_unexpected_first_token_is_recorded_as_observed(replay_backend, tmp_path, monkeypatch):
    first = witness(replay_backend)
    first[20] = 30000.0
    w = stub_fresh_world(replay_backend, tmp_path, monkeypatch, StubContent(first, EOS))
    request_id, permission = permitted(w)
    receipt = generate(w, request_id, permission["grant"])
    row = receipt["payload"]
    assert row["status"] == "COMPLETED" and row["result"]["generated_token_ids"] == [20, EOS]
    assert row["result"]["first_token_matches_archive"] is False
    assert row["result"]["first_step_non_eos_matches_september_archive"] is False
    light(w, receipt, FRESH)
    full(w, receipt, FRESH)


def completed(world):
    request_id, permission = permitted(world)
    return generate(world, request_id, permission["grant"])


def rejected_by(verifier, w, receipt, directory):
    with pytest.raises(Exception):
        verifier(w, receipt, directory=directory)


def test_resigned_forgery_verified_without_a_grant(world):
    receipt = generate(world, grant=None)

    def mutate(payload, target):
        payload["authority_decision"].update(permission=VERIFIED, reason="VERIFIED_EXACT_REQUEST")
        payload["gate_condition"] = "EQ(485487,485487)"
        payload["result"].update(permission=VERIFIED, gate_condition="EQ(485487,485487)", gate_condition_truth=True)

    forged = resigned_copy(world, receipt, mutate)
    rejected_by(light, world, receipt, forged)


def test_resigned_forgery_answer_bytes_on_a_not_verified_receipt(world):
    receipt = generate(world, grant=None)

    def mutate(payload, target):
        (target / "output.bin").write_bytes(b"4")
        payload["output"] = "4"
        payload["assets"]["output.bin"] = {"sha256": sha(b"4"), "bytes": 1}
        payload["result"].update(output_utf8_base64=base64.b64encode(b"4").decode(), output_bytes=1,
                                 output_sha256=sha(b"4"))
        payload["taxonomy"] = native_taxonomy.classification_record(b"4", "COMPLETED", payload["result"])

    rejected_by(light, world, receipt, resigned_copy(world, receipt, mutate))


def test_resigned_forgery_operational_error_dressed_as_v0(world):
    world.authority.revocation_unreachable = True
    request_id, permission = permitted(world)
    receipt = generate(world, request_id, permission["grant"])
    assert receipt["payload"]["status"] == "OPERATIONAL"

    def mutate(payload, target):
        payload["status"] = "COMPLETED"
        payload["taxonomy"] = native_taxonomy.classification_record(b"", "COMPLETED", {
            "generation_complete": True, "finish": "NATIVE_EOS", "generated_token_ids": [EOS]})

    rejected_by(light, world, receipt, resigned_copy(world, receipt, mutate))


def test_resigned_forgery_replayed_token_called_a_complete_answer(world):
    receipt = completed(world)

    def mutate(payload, target):
        payload["result"].update(generation_complete=True, finish="NATIVE_EOS", answer_scope="COMPLETE_TO_NATIVE_EOS")
        payload["taxonomy"] = native_taxonomy.classification_record(b"4", "COMPLETED", payload["result"])

    rejected_by(light, world, receipt, resigned_copy(world, receipt, mutate))


def test_resigned_forgery_replay_called_fresh(world):
    receipt = completed(world)
    with pytest.raises(Exception):
        light(world, receipt, FRESH)

    def mutate(payload, target):
        payload["mode"] = FRESH
        payload["action"]["profile"]["mode"] = FRESH
        payload["action_sha256"] = sha(compact(payload["action"]))

    with pytest.raises(Exception):
        light(world, receipt, FRESH, directory=resigned_copy(world, receipt, mutate))


def edit_vectors(payload, target, token, value):
    for kind in ("stock", "selected"):
        vector = torch.frombuffer(bytearray((target / f"0-{kind}.bf16.bin").read_bytes()), dtype=torch.bfloat16).clone()
        vector[token] = value
        raw = vector.view(torch.uint8).numpy().tobytes()
        (target / f"0-{kind}.bf16.bin").write_bytes(raw)
        payload["vector_files"][f"0-{kind}.bf16.bin"] = sha(raw)
        step = payload["result"]["steps"][0]
        step[f"{kind}_vector_sha256"] = sha(raw)
        if kind == "selected":
            step["non_eos_sha256"] = sha(raw[:2 * EOS] + raw[2 * EOS + 2:])


def test_resigned_forgery_scores_that_are_not_the_archived_vector(world):
    receipt = completed(world)
    forged = resigned_copy(world, receipt, lambda payload, target: edit_vectors(payload, target, 7, 1.0))
    rejected_by(full, world, receipt, forged)
    
    summary = light(world, receipt, directory=forged)
    assert any("NOT_CHECKED" in str(value) or "NOT_PERFORMED" in str(value) for value in summary.values()), summary


def test_resigned_forgery_wrong_stop_cause_or_intervention(world):
    receipt = generate(world, grant=None)

    def veto(payload, target):
        payload["stop_cause"] = payload["result"]["stop_cause"] = "VETO"
        payload["result"]["steps"][0]["intervention"] = "EOS_VETO_AFTER_LEARNED_GATE"

    rejected_by(full, world, receipt, resigned_copy(world, receipt, veto))


def test_resigned_forgery_unsigned_refusal_labelled_authority_signed(world):
    world.authority.permission = "UNSIGNED_DENIAL"
    request_id, permission = permitted(world)
    receipt = generate(world, request_id, permission["grant"])

    def mutate(payload, target):
        payload["authority_decision"]["denial_authority_signed"] = True

    rejected_by(light, world, receipt, resigned_copy(world, receipt, mutate))


def test_changed_files_and_foreign_keys_fail(world):
    receipt = completed(world)
    files = folder(world, receipt)
    with pytest.raises(Exception):
        native_verify.verify_receipt(files / "receipt.json", base64.b64encode(bytes(32)).decode(), REPLAY,
                                     authority_key=world.authority.public_key, expected_max_grant_age_seconds=60)
    
    with pytest.raises(Exception):
        native_verify.verify_receipt(files / "receipt.json", world.service.signer.public, REPLAY,
                                     expected_max_grant_age_seconds=60)
    
    native_verify.verify_receipt(files / "receipt.json", world.service.signer.public, REPLAY,
                                 authority_key=world.authority.public_key, expected_max_grant_age_seconds=60)
    for name in ("output.bin", "prompt.utf8.bin", "grant.json", "0-stock.bf16.bin", "0-selected.bf16.bin"):
        target = world.tmp / "changed" / name
        shutil.copytree(files, target)
        raw = bytearray((target / name).read_bytes())
        raw[len(raw) // 2] ^= 1
        (target / name).write_bytes(bytes(raw))
        with pytest.raises(Exception):
            light(world, receipt, directory=target)


def test_a_passing_summary_names_the_authority_it_was_checked_against(world):
    pass
    receipt = completed(world)
    summary = light(world, receipt)
    text = json.dumps(summary)
    assert "LABELLED_TEST_DOUBLE_AUTHORITY_NOT_PRODUCTION" in text or summary.get("production_authority") is False


def test_verification_does_not_depend_on_the_unicode_tables_of_the_verifying_python(world, monkeypatch):
    receipt = completed(world)
    other = types.SimpleNamespace(category=unicodedata.category, unidata_version="99.0.0")
    monkeypatch.setattr(native_taxonomy, "unicodedata", other)
    assert light(world, receipt)["class"] == "R"


def frozen_near_void():
    pass
    lines = FROZEN_TAXONOMY.read_text().splitlines()
    source = "\n".join(lines[1052:1061])
    assert source.startswith("def near_void(text: str) -> bool:") and source.rstrip().endswith("in ELLIPSIS_FORMS")
    text = "\n".join(lines)
    scope = {}
    for name in ("INVISIBLE_CODEPOINTS", "ELLIPSIS_FORMS"):
        start = text.index(name + " = {")
        scope[name] = eval(text[start + len(name) + 3:text.index("}", start) + 1])
    exec(source, scope)
    return scope["near_void"], scope["INVISIBLE_CODEPOINTS"], scope["ELLIPSIS_FORMS"]


REQUESTED = [("", "V0"), (" ", "NV"), ("​", "NV"), (".", "NV"), ("....", "NV"), ("…", "NV"),
             ("….", "NV"), ("?", "R"), ("!", "R"), ("-", "R"), ("4", "R"), (" 4 ", "R")]


@pytest.mark.parametrize("text,expected", REQUESTED)
def test_requested_cases_against_the_frozen_classifier(text, expected):
    if not FROZEN_TAXONOMY.is_file():
        pytest.skip("Frozen July 29 source is not on this machine")
    near_void, _, _ = frozen_near_void()
    reference = "V0" if text == "" else "NV" if near_void(text) else "R"
    assert reference == expected, "the expectation written in this test disagrees with the frozen function"
    assert native_taxonomy.classify(text.encode(), successful=True, stop="stop") == expected


def test_sdk_agrees_with_the_frozen_function_on_a_wide_corpus():
    if not FROZEN_TAXONOMY.is_file():
        pytest.skip("Frozen July 29 source is not on this machine")
    near_void, invisible, ellipsis = frozen_near_void()
    assert set(native_taxonomy.INVISIBLE) == set(invisible)
    atoms = [chr(c) for c in sorted(invisible)] + sorted(ellipsis) + [
        " ", "\n", "\t", " ", "　", " ", "?", "!", "-", "—", "。", "¿", ",", ";", ":",
        "(", ")", ".....", "……", "…..", ". .", "4", "a", "+", "$", "\U0001f600", "٠", "א",
        "́", "\x00", "\x7f", "­", "᠎", "؜"]
    corpus = set(atoms)
    for left in atoms:
        for right in atoms:
            corpus.add(left + right)
    for form in ellipsis:
        for pad in (" ", "\n", "​", "\t "):
            corpus.update({pad + form, form + pad, pad + form + pad})
    disagreements = []
    for text in sorted(corpus):
        expected = "NV" if near_void(text) else "R"
        got = native_taxonomy.classify(text.encode("utf-8"), successful=True, stop="stop")
        if got != expected:
            disagreements.append((text.encode("unicode_escape").decode(), expected, got))
    assert len(corpus) > 3000 and disagreements == [], disagreements[:20]


def test_punctuation_alone_is_a_visible_response_under_the_frozen_rule():
    for text in ("?", "!", "-", "?!", "—", "。", "( )", "-----", "¿", ",", "....."):
        assert native_taxonomy.classify(text.encode(), successful=True, stop="stop") == "R", repr(text)


def test_table_two_void_classes_and_operational():
    classify = native_taxonomy.classify
    assert classify(b"", successful=True, stop="stop") == "V0"
    assert classify(b"", successful=True, stop="length") == "V1"
    assert classify(b"", successful=True, stop="stop", container_present=False) == "V2"
    assert classify(b"", successful=True, stop=None) == "VU"
    assert classify(b"", successful=True, stop="content_filter") == "VU"
    assert classify(b"", successful=False, stop="stop") == "operational"
    assert classify(b"4", successful=False, stop="stop") == "operational"
    for event in ("RF", "SB", "TC"):
        assert classify(b"I cannot help", successful=True, stop="stop", event=event) == event
    
    assert classify(b"I cannot help with that.", successful=True, stop="stop") == "R"
    for bad in ("text", None, bytearray(b"")):
        with pytest.raises(ValueError):
            classify(bad, successful=True, stop="stop")
    with pytest.raises(UnicodeDecodeError):
        classify(b"\xff", successful=True, stop="stop")


def test_record_for_each_native_outcome():
    record = native_taxonomy.classification_record
    v0 = record(b"", "COMPLETED", {"generation_complete": True, "finish": "NATIVE_EOS", "generated_token_ids": [EOS],
                                   "answer_scope": "COMPLETE_TO_NATIVE_EOS"})
    assert v0["class"] == "V0" and v0["fields"]["container_present"] is True
    replayed = record(b"4", "COMPLETED", {"generation_complete": False, "finish": "REPLAY_ONE_TOKEN_ONLY",
                                          "generated_token_ids": [19],
                                          "answer_scope": "FIRST_TOKEN_ONLY_NOT_A_COMPLETE_ANSWER"})
    assert replayed["class"] == "R" and replayed["response_scope"] == "FIRST_TOKEN_ONLY_NOT_A_COMPLETE_ANSWER"
    capped = record(b"", "COMPLETED", {"generation_complete": False, "finish": "TOKEN_CAP", "generated_token_ids": [3]})
    assert capped["class"] == "V1"
    assert record(b"", "OPERATIONAL")["class"] == "operational"
    
    odd = record(b"", "COMPLETED", {"generation_complete": False, "finish": "REPLAY_ONE_TOKEN_ONLY",
                                    "generated_token_ids": [3]})
    assert odd["class"] == "VU"


def test_the_service_and_the_sdk_use_one_classifier():
    from swiftapi_native_service import taxonomy
    assert taxonomy.classify is native_taxonomy.classify
    assert taxonomy.classification_record is native_taxonomy.classification_record
    assert S.classification_record is native_taxonomy.classification_record


def test_policy_violation_keeps_the_old_call_shape_and_carries_the_body():
    old = PolicyViolation("denied", "some.action", "denied")
    assert (old.message, old.action_type, old.denial_reason, old.response, old.raw_response) == (
        "denied", "some.action", "denied", None, None)
    assert isinstance(old, SwiftAPIError) and str(old) == "denied"
    new = PolicyViolation("denied", action_type="a", denial_reason="r", response={"approved": False},
                          raw_response=b"{}", status_code=200)
    assert new.response == {"approved": False} and new.raw_response == b"{}" and new.status_code == 200


def test_light_verifier_imports_no_torch():
    import subprocess
    import sys
    code = ("import sys, swiftapi.native_verify, swiftapi.native_taxonomy, swiftapi.native\n"
            "assert 'torch' not in sys.modules and 'transformers' not in sys.modules\nprint('OK')\n")
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert done.stdout.strip() == "OK", done.stderr[-1500:]


@pytest.mark.parametrize("url", ["https://127.0.0.1:8766", "http://localhost:8766", "http://127.0.0.1",
                                 "http://0.0.0.0:8766", "http://user@127.0.0.1:8766", "http://127.0.0.1:8766/x",
                                 "http://127.0.0.1:8766?x=1", "http://swiftapi.ai:80", "http://[::1]:8766"])
def test_native_client_talks_to_ipv4_loopback_only(url):
    with pytest.raises(ValueError):
        NativeEOSClient(KEY, base_url=url)
    for bad in ("", "swiftapi_live_x", KEY + "\n"):
        with pytest.raises(ValueError):
            NativeEOSClient(bad)
    with pytest.raises(ValueError):
        NativeEOSClient()


@pytest.fixture
def served(world):
    server = LocalServer(("127.0.0.1", 0), world.service)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    world.url = f"http://127.0.0.1:{server.server_port}"
    world.port = server.server_port
    yield world
    server.shutdown()
    server.server_close()


def raw_post(port, path, payload, headers):
    lines = [f"POST {path} HTTP/1.1"] + [f"{k}: {v}" for k, v in headers.items()] + ["Connection: close", "", ""]
    with socket.create_connection(("127.0.0.1", port), timeout=20) as sock:
        sock.sendall("\r\n".join(lines).encode() + payload)
        data = b""
        while chunk := sock.recv(65536):
            data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    return int(head.split()[1]), json.loads(rest)


def test_client_round_trip_over_loopback_and_both_verifiers(served):
    with NativeEOSClient(KEY, base_url=served.url) as client:
        assert client.check_authority()["status"] == "AUTHORITY_VERIFIED"
        request_id = new_id()
        permission = client.authorize(Q, request_id=request_id)
        receipt = client.generate_with_grant(Q, permission["grant"], request_id=request_id)
        assert receipt["payload"]["authority_decision"]["permission"] == VERIFIED
        both(served, receipt)
        denied = client.generate_with_grant(Q, None, request_id=new_id())
        assert_v0(denied["payload"], "MISSING_PERMISSION")
        both(served, denied)
        one_call = client.generate(Q)
        assert one_call["payload"]["output"] == "4"


def test_the_largest_legitimate_generate_request_fits_the_transport_limit(served):
    longest = max(served.backend.allowed_questions, key=len)
    request_id, permission = permitted(served, question=longest)
    wire = json.dumps({"question": longest, "request_id": request_id, "grant": permission["grant"]}).encode()
    assert len(wire) <= 16384, len(wire)
    with NativeEOSClient(KEY, base_url=served.url) as client:
        receipt = client.generate_with_grant(longest, permission["grant"], request_id=request_id)
    assert receipt["payload"]["authority_decision"]["permission"] == VERIFIED


def test_transport_rejections_are_operational_and_signed(served):
    good = {"Host": f"127.0.0.1:{served.port}", "Content-Type": "application/json", "X-SwiftAPI-Authority": KEY}
    payload = compact(body(new_id(), None))

    def post(headers, data=payload, path="/v1/native-eos/generate"):
        return raw_post(served.port, path, data, dict(headers, **{"Content-Length": str(len(data))}))

    for headers in (dict(good, Host="evil.example"), dict(good, Origin="http://127.0.0.1"),
                    dict(good, **{"Content-Type": "text/plain"}),
                    {k: v for k, v in good.items() if k != "X-SwiftAPI-Authority"}):
        status, reply = post(headers)
        assert status in (401, 403, 415) and reply["payload"]["status"] == "OPERATIONAL"
        assert reply["payload"]["decoder_executed"] is False and reply["payload"]["taxonomy"]["class"] == "operational"
        core.verify_envelope(reply, served.service.signer.public)
    status, reply = post(good, data=b'{"request_id":"a","request_id":"b","question":"x"}')
    assert status == 400 and reply["payload"]["error_code"] == "DUPLICATE_JSON_KEY"
    
    status, reply = raw_post(served.port, "/v1/native-eos/generate", b"", dict(good, **{"Content-Length": "20000"}))
    assert status == 413
    status, reply = post(good, path="/v1/native-eos/diagnostic")
    assert status == 404
    with pytest.raises(ValueError):
        LocalServer(("0.0.0.0", 0), served.service)


def test_anonymous_rejections_are_bounded_and_do_not_block_a_known_key(served):
    headers = {"Host": f"127.0.0.1:{served.port}", "Content-Type": "application/json",
               "X-SwiftAPI-Authority": "not-a-key", "Content-Length": "2"}
    statuses = [raw_post(served.port, "/v1/native-eos/generate", b"{}", headers)[0] for _ in range(70)]
    assert statuses.count(429) == 6 and 429 not in statuses[:64]
    evidence = served.service.signer.directory / "evidence"
    assert len(list(evidence.iterdir())) == 64
    
    request_id, permission = permitted(served)
    receipt = generate(served, request_id, permission["grant"])
    assert receipt["payload"]["authority_decision"]["permission"] == VERIFIED
    both(served, receipt)
    
    with NativeEOSClient(KEY, base_url=served.url) as client:
        with pytest.raises(SwiftAPIError) as caught:
            client.authorize("What is 2 + 3000?", request_id=new_id())
    assert caught.value.status_code == 400 and "payload" in caught.value.response, caught.value.response


@pytest.mark.parametrize("claimed", [59, 61, 3600])
def test_a_receipt_cannot_choose_its_own_grant_age_allowance(world, claimed):
    receipt = completed(world)
    files = folder(world, receipt) / "receipt.json"
    with pytest.raises(Exception):
        native_verify.verify_receipt(files, world.service.signer.public, REPLAY,
                                     authority_key=world.authority.public_key, expected_max_grant_age_seconds=claimed)
    for bad in (None, 0, -1, True, "60", 10 ** 9):
        with pytest.raises(Exception):
            native_verify.verify_receipt(files, world.service.signer.public, REPLAY,
                                         authority_key=world.authority.public_key, expected_max_grant_age_seconds=bad)
    with pytest.raises(TypeError):
        native_verify.verify_receipt(files, world.service.signer.public, REPLAY, authority_key=world.authority.public_key)


def test_service_takes_model_execution_from_the_backend_facts(world):
    receipt = completed(world)
    row = receipt["payload"]
    assert row["execution_facts"] == row["result"]["execution_facts"]
    assert row["model_executed"] is False and row["execution_facts"]["forward_passes_completed"] == 0
    assert row["execution_facts"]["decoder_selected_a_token"] is True and row["decoder_executed"] is True


WHEEL = WORKSPACE / "packages" / "swiftapi_python-1.4.0-py3-none-any.whl"
WHEEL_SHA256 = "3afa5b4da3427dcf1c856c2314b5859fd0250f2a384e41f7f811dfd865ae7561"


@pytest.fixture(autouse=True)
def approval_registry_in_a_temporary_directory(tmp_path, monkeypatch):
    pass
    registry = tmp_path / "approval-registry-TEST"
    monkeypatch.setattr(X, "APPROVAL_REGISTRY", registry)
    return registry


def runner_config(tmp_path, **changes):
    pass
    if not WHEEL.is_file():
        pytest.fail("The locally built SDK 1.4.0 candidate wheel is required")
    wheel = WHEEL
    assert sha(wheel.read_bytes()) == WHEEL_SHA256
    config = {"schema": "swiftapi-native-experiment-config/2", "purpose": "DEVELOPMENT_QUALIFICATION",
              "sdk_version": "1.4.0", "sdk_wheel_sha256": sha(wheel.read_bytes()),
              "service_source_sha256": S.source_identity()["sha256"],
              "classifier_sha256": native_taxonomy.classifier_hash(),
              "schedule": ["VALID", "SIGNED_DENIAL", "MISSING_GRANT", "INVALID_SIGNATURE", "REUSED", "WRONG_SCOPE",
                           "WRONG_REQUEST", "UNKNOWN_KEY", "MALFORMED_KEY"],
              "repetitions": 1, "max_grant_age_seconds": 60, "max_new_tokens": 4,
              "authority": "LOCAL_TEST_DOUBLE", "mode": REPLAY, "device": "cpu"}
    config.update(changes)
    
    if config.get("authority") == "LIVE_SWIFTAPI" and config.get("mode") == FRESH \
            and "ledger_capture_mode" not in changes:
        config["ledger_capture_mode"] = "MAC_ADMIN_SIDECAR"
    if (config.get("authority") == "LIVE_SWIFTAPI" or config.get("mode") == FRESH) and "seal" not in changes \
            and "predictions_sealed_at" not in changes:
        config.update(test_seal(tmp_path, config))
    config.pop("seal", None)
    return config, wheel


from swiftapi_native_service import predictions as PR


def implied_class(arm):
    return "R" if arm == "VALID" else "operational" if arm in ("UNKNOWN_KEY", "MALFORMED_KEY") else "V0"


def template_text(primary=None, secondary=None, preamble="# TEST DOUBLE predictions. Not written by the author. Seals nothing real.\n"):
    pass
    out = [preamble, "## Allowed class values", "", "- TEST: this list is ignored by the parser", "",
           "## Instructions", "", "TEST DOUBLE instructions.", ""]
    for heading, arms, total, config, folder, given in (
            ("## Run 1: PRIMARY WITNESS_ONE", PR.PRIMARY_ARMS, 1, "RUN_CONFIG_PRIMARY.json", "PRIMARY_OUTPUT", primary or {}),
            ("## Run 2: SECONDARY BANK_188", PR.SECONDARY_ARMS, 188, "RUN_CONFIG_SECONDARY.json", "SECONDARY_OUTPUT",
             secondary or {})):
        out += [heading, ""]
        for arm in arms:
            spec = given.get(arm, {})
            out += [f"### {arm}", "", f"Arm {arm}: TEST DOUBLE description of what is sent. What will the result line be?", "",
                    "My prediction:", ""]
            for count, cls in spec.get("lines", [(None, None)]):
                out += [f"`[{arm}] [{X.MODEL}] [{'__' if count is None else count}/{total}] [{cls or '____'}]`", ""]
            for field in PR.FIELDS:
                if (heading.startswith("## Run 2"), arm, field) == (True, "VALID", "first_token") and field not in spec:
                    continue
                out += [f"{field}: {spec.get(field, '____')}", ""]
            out += [f"`python -m swiftapi_native_service.experiment question --config {config} --out {folder} --arm {arm}`", ""]
    return "\n".join(out).encode()


TEST_PREDICTIONS = template_text(
    primary={arm: {"lines": [(None, implied_class(arm))]} for arm in PR.PRIMARY_ARMS},
    secondary={"VALID": {"lines": [(None, "R")]}, "MISSING_GRANT": {"lines": [(188, "V0")]}})


def test_seal(tmp_path, config=None):
    pass
    path = tmp_path / "TEST-DOUBLE-predictions.md"
    if not path.exists():
        path.write_bytes(TEST_PREDICTIONS)
    seal = {"author_predictions_sha256": sha(TEST_PREDICTIONS), "predictions_sealed_at": "2026-01-01T00:00:00+00:00"}
    if config is not None:
        parsed = PR.parse_predictions(TEST_PREDICTIONS, X.MODEL)
        try:
            seal["predictions"] = PR.select_for_run(parsed, config.get("population", "WITNESS_ONE"),
                                                    config.get("schedule", []))[1]
        except Exception:
            pass      
    return seal


test_seal.__test__ = False


@pytest.fixture(autouse=True)
def test_predictions_file_supplied_when_a_test_configuration_carries_the_test_seal(tmp_path, monkeypatch):
    pass
    real_validate, real_run = X.validate_config, X.run
    path = tmp_path / "TEST-DOUBLE-predictions.md"

    def supplied(config, given):
        if given is None and isinstance(config, dict) and config.get("author_predictions_sha256") == sha(TEST_PREDICTIONS) \
                and (config.get("authority") == "LIVE_SWIFTAPI" or config.get("mode") == FRESH):
            if not path.exists():
                path.write_bytes(TEST_PREDICTIONS)
            return path
        return given

    def validate(config, wheel, predictions_file=None):
        return real_validate(config, wheel, supplied(config, predictions_file))

    def run(config, wheel, out, source, content, harness, key_file=None, approval_file=None, primary_archive=None,
            predictions_file=None, mac_ledger_before=None):
        return real_run(config, wheel, out, source, content, harness, key_file=key_file, approval_file=approval_file,
                        primary_archive=primary_archive, predictions_file=supplied(config, predictions_file),
                        mac_ledger_before=mac_ledger_before)

    monkeypatch.setattr(X, "validate_config", validate)
    monkeypatch.setattr(X, "run", run)
    return types.SimpleNamespace(validate=real_validate, run=real_run, path=path)


def run_replay(tmp_path, **changes):
    config, wheel = runner_config(tmp_path, **changes)
    out = tmp_path / "run"
    X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS)
    return out


def test_runner_replay_schedule_with_the_local_double_completes_and_labels_itself(tmp_path, capsys):
    out = run_replay(tmp_path)
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "PASS" and summary["registered_result"] is False
    assert summary["purpose"] == "DEVELOPMENT_QUALIFICATION"
    classes = {row["arm"]: row["class"] for row in summary["rows"]}
    assert classes == {"VALID": "R", "SIGNED_DENIAL": "V0", "MISSING_GRANT": "V0", "INVALID_SIGNATURE": "V0",
                       "REUSED": "V0", "WRONG_SCOPE": "V0", "WRONG_REQUEST": "V0", "UNKNOWN_KEY": "operational",
                       "MALFORMED_KEY": "operational"}
    authority = json.loads((out / "authority-public.json").read_text())
    assert authority["production"] is False and "NOT_SWIFTAPI_PRODUCTION" in authority["evidence_kind"]
    for row in summary["rows"]:
        assert row["mode"] == REPLAY
        receipt = json.loads((out / row["receipt"]).read_text())["payload"]
        assert receipt["authority_evidence_kind"] == authority["evidence_kind"]
        assert receipt["model_executed"] is False and receipt["purpose"] == "DEVELOPMENT_QUALIFICATION"
    valid = next(row for row in summary["rows"] if row["arm"] == "VALID")
    assert valid["sdk_verifier"]["response_scope"] == "FIRST_TOKEN_ONLY_NOT_A_COMPLETE_ANSWER"
    assert not (out / "warm-forward.json").exists() and not (out / "error.json").exists()
    
    import re
    printed = capsys.readouterr().out.splitlines()
    assert len(printed) == 18
    for index, row in enumerate(summary["rows"]):
        result_line, metadata = printed[2 * index], printed[2 * index + 1]
        assert result_line == f"[{row['arm']}] [{X.MODEL}] [1/1] [{row['class']}]"
        assert re.fullmatch(r"\[[^\[\]]+\] \[[^\[\]]+\] \[\d+/\d+\] \[[^\[\]]+\]", result_line)
        assert metadata.startswith("Metadata: ") and "[" not in metadata
        assert "mode=RECORDED_LOGITS_REPLAY" in metadata and "NOT_SWIFTAPI_PRODUCTION" in metadata
        assert f"response_scope={row['response_scope']}" in metadata


def test_runner_output_holds_no_key_no_runtime_seed_and_no_local_account_name(tmp_path):
    import getpass
    import re
    import tarfile
    out = run_replay(tmp_path)
    pattern = re.compile(rb"swiftapi_live_[0-9a-f]{64}")
    unknown = b"swiftapi_live_" + b"0" * 64
    exported = [p for p in out.rglob("*") if p.is_file() and ".private-runtime" not in p.parts]
    for path in exported:
        found = set(pattern.findall(path.read_bytes())) - {unknown}
        assert not found, path
    with tarfile.open(out / "evidence.tar.gz") as tar:
        members = tar.getmembers()
        names = {member.name for member in members}
        assert not any("private-runtime" in name or name.endswith((".seed", ".sqlite3")) for name in names)
        assert "summary.json" in names and "SHA256SUMS" in names
        user = getpass.getuser()
        assert all(member.uname != user and member.gname not in (user, "staff") and member.uid == 0
                   for member in members), sorted({(m.uname, m.gname, m.uid) for m in members})
    listed = dict(reversed(line.split("  ", 1)) for line in (out / "SHA256SUMS").read_text().splitlines())
    for name, digest in listed.items():
        assert sha((out / name).read_bytes()) == digest


def test_runner_refuses_before_creating_anything(tmp_path, monkeypatch):
    def refused(**changes):
        config, wheel = runner_config(tmp_path, **changes)
        out = tmp_path / ("out-" + uuid.uuid4().hex)
        with pytest.raises(ValueError):
            X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS)
        assert not out.exists(), changes

    refused(schema="swiftapi-native-experiment-config/1")
    refused(attention="UNSET")
    refused(sdk_wheel_sha256="0" * 64)
    refused(service_source_sha256="0" * 64)
    refused(classifier_sha256="0" * 64)
    refused(schedule=["VALID", "VALID"])
    refused(schedule=["DIAGNOSTIC_REVERSED_SIGN"])
    refused(schedule=["T7a"])
    refused(max_grant_age_seconds=3600)
    refused(max_new_tokens=17)
    refused(purpose="PREREGISTERED_STUDY")
    
    refused(mode=FRESH, device="cuda", enable_full_model=True, maximum_warm_forward_seconds=10)
    refused(mode=FRESH, device="cpu", enable_full_model=True, maximum_warm_forward_seconds=10)
    refused(purpose="DEVELOPMENT_SMOKE", schedule=["VALID", "SIGNED_DENIAL"], authority="LIVE_SWIFTAPI")
    refused(purpose="DEVELOPMENT_SMOKE", schedule=["VALID", "SIGNED_DENIAL", "MISSING_GRANT"])
    refused(purpose="DEVELOPMENT_SMOKE", schedule=["VALID", "SIGNED_DENIAL"], repetitions=2)
    
    refused(schedule=["VALID", "REVOKED"])
    refused(schedule=["REUSED"])
    refused(authority="LIVE_SWIFTAPI")
    refused(authority="SOMETHING_ELSE")
    refused(attention="FASTEST")


def test_smoke_never_accepts_a_key_file(tmp_path):
    config, wheel = runner_config(tmp_path, purpose="DEVELOPMENT_SMOKE", schedule=["VALID", "SIGNED_DENIAL"])
    key_file = tmp_path / "never-read.key"
    out = tmp_path / "smoke"
    with pytest.raises(ValueError, match="No SwiftAPI key"):
        X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS, key_file=key_file)
    assert not out.exists() and not key_file.exists()


def test_fresh_configuration_is_validated_completely_before_any_model_work(tmp_path, monkeypatch):
    pass
    monkeypatch.setattr(X.platform, "system", lambda: "Linux")
    base = dict(purpose="DEVELOPMENT_SMOKE", schedule=["VALID", "SIGNED_DENIAL"], mode=FRESH, device="cuda",
                enable_full_model=True, maximum_warm_forward_seconds=10)
    config, wheel = runner_config(tmp_path, **base)
    X.validate_config(config, wheel)
    for change in ({"maximum_warm_forward_seconds": None}, {"maximum_warm_forward_seconds": 10 ** 6},
                   {"maximum_warm_forward_seconds": 61}, {"maximum_warm_forward_seconds": -1},
                   {"maximum_warm_forward_seconds": True}, {"enable_full_model": False}, {"device": "cpu"}):
        config, wheel = runner_config(tmp_path, **dict(base, **change))
        with pytest.raises(ValueError):
            X.validate_config(config, wheel)
    config, wheel = runner_config(tmp_path, **base)
    del config["maximum_warm_forward_seconds"]
    with pytest.raises(ValueError):
        X.validate_config(config, wheel)


def test_full_verifier_does_not_depend_on_where_the_running_backend_keeps_its_gate(world):
    pass
    if not torch.backends.mps.is_available():
        pytest.skip("No second device on this machine to stand in for the execution device")
    receipt = completed(world)
    moved = B.PCCG2Backend(SOURCE, Path("/nonexistent-content"), HARNESS, B.REPLAY)
    moved._gate = moved._gate.to("mps")
    assert full(world, receipt, backend=moved)["numerical_replay"] == "PASS"


def test_installed_sdk_is_checked_against_the_wheel_contents(tmp_path):
    import zipfile
    checked = X.verify_installed_sdk(WHEEL)
    assert "swiftapi/native_verify.py" in checked and "swiftapi/native_taxonomy.py" in checked
    import swiftapi
    root = Path(swiftapi.__file__).parent
    for name, digest in checked.items():
        assert sha((root / Path(name).relative_to("swiftapi")).read_bytes()) == digest
    
    for label, edit in (("changed", lambda files: files.update({"swiftapi/native.py": files["swiftapi/native.py"] + b"\n#"})),
                        ("extra", lambda files: files.update({"swiftapi/extra_module.py": b"x = 1\n"})),
                        ("missing", lambda files: files.pop("swiftapi/native_taxonomy.py"))):
        with zipfile.ZipFile(WHEEL) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        edit(files)
        other = tmp_path / f"{label}.whl"
        with zipfile.ZipFile(other, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        with pytest.raises(ValueError):
            X.verify_installed_sdk(other)
        config, _ = runner_config(tmp_path, sdk_wheel_sha256=sha(other.read_bytes()))
        with pytest.raises(ValueError):
            X.validate_config(config, other)


def test_classifier_allowlist_names_the_installed_classifier_and_the_frozen_rule():
    from swiftapi.native_classifier_releases import RELEASED_CLASSIFIER_HASHES
    current = native_taxonomy.classifier_hash()
    assert current == sha(Path(native_taxonomy.__file__).read_bytes())
    assert current in RELEASED_CLASSIFIER_HASHES
    release = RELEASED_CLASSIFIER_HASHES[current]
    assert release["receipt_schema"] == "swiftapi-native-service-receipt/2"
    assert "2dfe895bdafd35d23d6dab5f307ed560214a3843" in release["rule"]


def test_a_receipt_with_a_released_hash_verifies_after_the_classifier_file_changes(world, monkeypatch):
    pass
    receipt = completed(world)
    denied = generate(world, grant=None)
    monkeypatch.setattr(native_taxonomy, "classifier_hash", lambda: "f" * 64)
    assert light(world, receipt)["class"] == "R" and light(world, denied)["class"] == "V0"
    assert light(world, receipt)["classifier_sha256_declared"] == receipt["payload"]["taxonomy"]["classifier_sha256"]


@pytest.mark.parametrize("declared", ["0" * 64, "f" * 64, "", None, 7])
def test_a_receipt_declaring_an_unreleased_classifier_is_refused_even_when_resigned(world, declared):
    receipt = completed(world)

    def mutate(payload, target):
        payload["taxonomy"]["classifier_sha256"] = declared
        payload["sdk"]["classifier_sha256"] = declared

    rejected_by(light, world, receipt, resigned_copy(world, receipt, mutate))


def test_a_released_classifier_is_bound_to_its_receipt_schema_and_to_the_sdk_block(world, monkeypatch):
    from swiftapi import native_classifier_releases as releases
    receipt = completed(world)
    current = receipt["payload"]["taxonomy"]["classifier_sha256"]

    def split(payload, target):
        payload["sdk"]["classifier_sha256"] = "0" * 64

    rejected_by(light, world, receipt, resigned_copy(world, receipt, split))
    monkeypatch.setitem(releases.RELEASED_CLASSIFIER_HASHES, current,
                        dict(releases.RELEASED_CLASSIFIER_HASHES[current], receipt_schema="some-other-schema/9"))
    with pytest.raises(Exception):
        light(world, receipt)


def test_a_wrong_class_is_refused_whatever_hash_is_declared(world):
    receipt = completed(world)

    def mutate(payload, target):
        payload["taxonomy"]["class"] = "V0"

    rejected_by(light, world, receipt, resigned_copy(world, receipt, mutate))


def live_replay_config(tmp_path, **changes):
    return runner_config(tmp_path, authority="LIVE_SWIFTAPI", schedule=["VALID", "REVOKED"],
                         one_disposable_grant_revocation_approved=True, **changes)


def approval_for(config, tmp_path, name="approval.json", **changes):
    approval = {"config_sha256": sha(compact(config)), "purpose": config["purpose"], "author_approved": True,
                "maximum_attempts": 1, "approval_id": str(uuid.uuid4())}
    approval.update(changes)
    path = tmp_path / name
    path.write_text(json.dumps(approval))
    return path


def test_replay_with_the_local_double_needs_no_approval_and_everything_else_does(tmp_path):
    config, _ = runner_config(tmp_path)
    assert X.consume_approval(config, None) is None
    live, _ = live_replay_config(tmp_path)
    with pytest.raises(ValueError, match="approval required"):
        X.consume_approval(live, None)
    fresh, _ = runner_config(tmp_path, mode=FRESH, device="cuda", enable_full_model=True,
                             maximum_warm_forward_seconds=10, purpose="DEVELOPMENT_SMOKE",
                             schedule=["VALID", "SIGNED_DENIAL"])
    with pytest.raises(ValueError, match="approval required"):
        X.consume_approval(fresh, None)


@pytest.mark.parametrize("change", [{"config_sha256": "0" * 64}, {"purpose": "DEVELOPMENT_SMOKE"},
                                    {"author_approved": "yes"}, {"author_approved": False},
                                    {"maximum_attempts": 2}, {"maximum_attempts": True}])
def test_an_approval_for_anything_else_is_refused_and_not_consumed(tmp_path, change):
    config, _ = live_replay_config(tmp_path)
    path = approval_for(config, tmp_path, **change)
    with pytest.raises(ValueError):
        X.consume_approval(config, path)
    assert not path.with_name(path.name + ".consumed.json").exists()


def test_an_approval_is_bound_to_the_exact_configuration(tmp_path):
    config, _ = live_replay_config(tmp_path)
    path = approval_for(config, tmp_path)
    for edited in (dict(config, repetitions=1, schedule=["VALID", "REVOKED", "MISSING_GRANT"]),
                   dict(config, max_new_tokens=5), dict(config, extra_field=1)):
        with pytest.raises(ValueError):
            X.consume_approval(edited, path)
    assert not path.with_name(path.name + ".consumed.json").exists()


def test_an_approval_is_spent_once_whatever_output_directory_is_chosen(tmp_path):
    config, _ = live_replay_config(tmp_path)
    path = approval_for(config, tmp_path)
    assert X.consume_approval(config, path)["author_approved"] is True
    marker = path.with_name(path.name + ".consumed.json")
    assert json.loads(marker.read_text())["config_sha256"] == sha(compact(config))
    for _ in range(2):
        with pytest.raises(Exception):
            X.consume_approval(config, path)


def test_a_copied_approval_file_cannot_be_spent_a_second_time(tmp_path):
    pass
    config, _ = live_replay_config(tmp_path)
    path = approval_for(config, tmp_path)
    X.consume_approval(config, path)
    copy_dir = tmp_path / "elsewhere"
    copy_dir.mkdir()
    copied = copy_dir / "approval-copy.json"
    copied.write_bytes(path.read_bytes())
    with pytest.raises(Exception):
        X.consume_approval(config, copied)


def test_live_run_is_refused_before_any_key_read_without_a_matching_unspent_approval(tmp_path, monkeypatch):
    pass
    monkeypatch.setattr(X, "read_key", lambda path: pytest.fail("key file read"))
    config, wheel = live_replay_config(tmp_path)
    key_file = tmp_path / "absent.key"
    for approval in (None, approval_for(config, tmp_path, "wrong.json", config_sha256="0" * 64)):
        out = tmp_path / ("live-" + uuid.uuid4().hex)
        with pytest.raises(ValueError):
            X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS, key_file=key_file,
                  approval_file=approval)
        assert not out.exists()


def test_a_smoke_that_cannot_finish_an_answer_is_refused_up_front(tmp_path, monkeypatch):
    pass
    monkeypatch.setattr(X.platform, "system", lambda: "Linux")
    config, wheel = runner_config(tmp_path, purpose="DEVELOPMENT_SMOKE", schedule=["VALID", "SIGNED_DENIAL"],
                                  mode=FRESH, device="cuda", enable_full_model=True, maximum_warm_forward_seconds=10,
                                  max_new_tokens=1)
    with pytest.raises(ValueError):
        X.validate_config(config, wheel)


def revoked_world(world, evidence):
    request_id, permission = permitted(world)
    world.authority.revoked.add(permission["grant"]["jti"])
    world.authority.revocation_evidence = evidence
    return permission["grant"], generate(world, request_id, permission["grant"])


def test_revocation_entry_positive_and_every_negative():
    authority = LabelledTestAuthority()
    entry = authority.revocation_entry("jti-1")
    check = native_verify.verify_revocation_entry
    assert check(entry, "jti-1", authority.public_key) is True
    assert check(entry, "jti-1", authority.public_key, decision_at=authority.now()) is True
    with pytest.raises(Exception):
        check(entry, "jti-2", authority.public_key)                      
    with pytest.raises(Exception):
        check(entry, "jti-1", LabelledTestAuthority().public_key)        
    with pytest.raises(Exception):
        check(entry, "jti-1", authority.public_key, decision_at=authority.now() - 3600)  
    for field, value in (("jti", "jti-2"), ("cursor", 8), ("revoked_at", iso(authority.now() - 999)),
                         ("revoked_by", "someone else"), ("reason", "other")):
        with pytest.raises(Exception):
            check(dict(entry, **{field: value}), value if field == "jti" else "jti-1", authority.public_key)
    for broken in (dict(entry, extra=1), {k: v for k, v in entry.items() if k != "reason"},
                   {k: v for k, v in entry.items() if k != "signature"},
                   dict(entry, signature=base64.b64encode(bytes(64)).decode()), dict(entry, signature="not base64"),
                   None, [], "entry"):
        with pytest.raises(Exception):
            check(broken, "jti-1", authority.public_key)
    for cursor in (0, -1, True, "7", 7.0):
        with pytest.raises(Exception):
            check(authority.revocation_entry("jti-1", cursor=cursor), "jti-1", authority.public_key)
    with pytest.raises(Exception):
        naive = authority.revocation_entry("jti-1", revoked_at_text=None)
        check(dict(naive), "jti-1", authority.public_key)


def test_signed_revocation_is_stored_labelled_and_verified_offline(world):
    grant, receipt = revoked_world(world, lambda jti: {"authority_signed": True, "reason": "VERIFIED_SIGNED_FEED_ENTRY",
                                                       "entry": world.authority.revocation_entry(jti)})
    row = receipt["payload"]
    assert_v0(row, "AUTHORITY_REVOKED")
    decision = row["authority_decision"]
    assert decision["revocation_authority_signed"] is True
    assert decision["revocation_observation"] == "AUTHORITY_SIGNED_ENTRY"
    assert decision["denial_authority_signed"] is False, "a revocation is not a signed denial of the request"
    entry = json.loads((folder(world, receipt) / "authority-revocation.json").read_bytes())
    assert entry["jti"] == grant["jti"]
    native_verify.verify_revocation_entry(entry, grant["jti"], world.authority.public_key,
                                          decision_at=decision["evaluated_at"])
    summary_light, summary_full = both(world, receipt)
    assert summary_light["revocation_authority_signed"] is True
    assert summary_light["revocation_scope"] == "AUTHORITY_SIGNED_ENTRY"


@pytest.mark.parametrize("reason", ["JTI_NOT_IN_AVAILABLE_FEED", "FEED_UNAVAILABLE",
                                    "FEED_ENTRY_SIGNATURE_NOT_VERIFIED"])
def test_revocation_without_a_verified_entry_falls_back_to_a_runtime_report(world, reason):
    _, receipt = revoked_world(world, lambda jti: {"authority_signed": False, "reason": reason})
    row = receipt["payload"]
    assert_v0(row, "AUTHORITY_REVOKED")
    decision = row["authority_decision"]
    assert decision["revocation_authority_signed"] is False
    assert decision["revocation_observation"] == "RUNTIME_REPORTED"
    assert decision["revocation_evidence_limit"] == reason
    assert "authority-revocation.json" not in row["assets"]
    summary, _ = both(world, receipt)
    assert summary["revocation_authority_signed"] is False
    assert "not independently authority-signed" in summary["revocation_scope"]


def test_revocation_with_no_evidence_object_at_all_is_a_runtime_report(world):
    _, receipt = revoked_world(world, None)
    decision = receipt["payload"]["authority_decision"]
    assert decision["revocation_authority_signed"] is False and decision["revocation_observation"] == "RUNTIME_REPORTED"
    both(world, receipt)


@pytest.mark.parametrize("label,make", [
    ("entry for another grant", lambda a, jti: a.revocation_entry("some-other-jti")),
    ("entry signed by another authority", lambda a, jti: LabelledTestAuthority().revocation_entry(jti)),
    ("entry dated after the decision", lambda a, jti: a.revocation_entry(jti, revoked_at=a.now() + 600)),
    ("entry with a zeroed signature", lambda a, jti: dict(a.revocation_entry(jti),
                                                          signature=base64.b64encode(bytes(64)).decode())),
])
def test_an_entry_that_does_not_verify_is_never_stored_as_signed_and_does_not_break_the_stop(world, label, make):
    pass
    _, receipt = revoked_world(world, lambda jti: {"authority_signed": True, "reason": "VERIFIED_SIGNED_FEED_ENTRY",
                                                   "entry": make(world.authority, jti)})
    row = receipt["payload"]
    assert row["status"] == "COMPLETED", (label, row.get("error_code"))
    assert_v0(row, "AUTHORITY_REVOKED")
    assert row["authority_decision"]["revocation_authority_signed"] is False
    assert "authority-revocation.json" not in row["assets"]
    both(world, receipt)


def signed_revocation_receipt(world):
    return revoked_world(world, lambda jti: {"authority_signed": True, "reason": "VERIFIED_SIGNED_FEED_ENTRY",
                                             "entry": world.authority.revocation_entry(jti)})[1]


def test_resigned_forgery_runtime_report_relabelled_as_authority_signed(world):
    _, receipt = revoked_world(world, lambda jti: {"authority_signed": False, "reason": "FEED_UNAVAILABLE"})

    def flag_only(payload, target):
        payload["authority_decision"]["revocation_authority_signed"] = True
        payload["authority_decision"]["revocation_observation"] = "AUTHORITY_SIGNED_ENTRY"

    rejected_by(light, world, receipt, resigned_copy(world, receipt, flag_only))

    def label_only(payload, target):
        payload["authority_decision"]["revocation_observation"] = "AUTHORITY_SIGNED_ENTRY"

    rejected_by(light, world, receipt, resigned_copy(world, receipt, label_only))

    def foreign_entry(payload, target):
        entry = LabelledTestAuthority().revocation_entry(payload["grant"]["jti"])
        (target / "authority-revocation.json").write_bytes(compact(entry))
        payload["assets"]["authority-revocation.json"] = {"sha256": sha(compact(entry)), "bytes": len(compact(entry))}
        flag_only(payload, target)

    rejected_by(light, world, receipt, resigned_copy(world, receipt, foreign_entry))


def test_resigned_forgery_signed_revocation_attached_to_other_decisions(world):
    receipt = signed_revocation_receipt(world)
    files = folder(world, receipt)
    entry_bytes = (files / "authority-revocation.json").read_bytes()

    def wrong_reason(payload, target):
        payload["authority_decision"]["reason"] = "GRANT_EXPIRED"

    rejected_by(light, world, receipt, resigned_copy(world, receipt, wrong_reason))

    def swapped_entry(payload, target):
        other = world.authority.revocation_entry("another-jti")
        (target / "authority-revocation.json").write_bytes(compact(other))
        payload["assets"]["authority-revocation.json"] = {"sha256": sha(compact(other)), "bytes": len(compact(other))}

    rejected_by(light, world, receipt, resigned_copy(world, receipt, swapped_entry))

    def hidden(payload, target):
        payload["authority_decision"]["revocation_authority_signed"] = False
        payload["authority_decision"]["revocation_observation"] = "RUNTIME_REPORTED"

    
    rejected_by(light, world, receipt, resigned_copy(world, receipt, hidden))
    assert entry_bytes == (files / "authority-revocation.json").read_bytes()


def test_a_verified_receipt_cannot_carry_a_revocation_claim(world):
    receipt = completed(world)

    def mutate(payload, target):
        entry = world.authority.revocation_entry(payload["grant"]["jti"])
        (target / "authority-revocation.json").write_bytes(compact(entry))
        payload["assets"]["authority-revocation.json"] = {"sha256": sha(compact(entry)), "bytes": len(compact(entry))}
        payload["authority_decision"]["revocation_authority_signed"] = True
        payload["authority_decision"]["revocation_observation"] = "AUTHORITY_SIGNED_ENTRY"

    rejected_by(light, world, receipt, resigned_copy(world, receipt, mutate))


from swiftapi_native_service import pacing as P  


class VirtualClock:
    pass

    def __init__(self):
        self.value, self.sleeps, self.on_sleep = 5000.0, [], None

    def now(self):
        return self.value

    def sleep(self, seconds):
        if self.on_sleep:
            self.on_sleep(seconds)
        self.sleeps.append(seconds)
        self.value += seconds


def paced_without_real_sleep(authority):
    pass
    clock = VirtualClock()
    authority.pacer = P.AuthorityPacer(authority._emit, clock=clock.now, sleep=clock.sleep)
    authority.virtual_clock = clock
    return authority


class FakeResponse:
    def __init__(self, status, body):
        self.status_code, self._body, self.content = status, body, json.dumps(body).encode()
        self.headers = {"Date": "TEST DOUBLE", "Set-Cookie": "secret-cookie"}

    def json(self):
        return self._body


@pytest.fixture
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("network connection attempted"))
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("network connection attempted"))


def test_event_sink_records_no_credential_header_or_body(no_network, monkeypatch):
    import requests
    body = {"jti": "j1", "approved": True, "issued_at": "t0", "expires_at": "t1", "action_type": core.SCOPE,
            "action_fingerprint": "f" * 32, "signature": "sig", "action_data": {"private": "payload"},
            "denial_reason": "free text"}
    monkeypatch.setattr(requests.Session, "request", lambda self, method, url, **kwargs: FakeResponse(200, body))
    events = []
    client = paced_without_real_sleep(core.RemoteAuthority(event_sink=events.append))._client(KEY)
    try:
        response = client._session.request("POST", core.AUTHORITY_URL + "/attest?x=1", json={"secret": KEY},
                                           headers={"X-SwiftAPI-Authority": KEY})
    finally:
        client._session.close()
    assert response.json() == body
    pacing = [event for event in events if event["stage"].startswith("PACING_")]
    assert all(event.get("location", "BEFORE_SLOT_ISSUANCE") == "BEFORE_SLOT_ISSUANCE" for event in pacing)
    assert KEY not in json.dumps(pacing)
    events = [event for event in events if not event["stage"].startswith("PACING_")]
    assert [event["stage"] for event in events] == ["DISPATCH", "RESPONSE"]
    text = json.dumps(events)
    assert KEY not in text and "secret-cookie" not in text and "payload" not in text and "free text" not in text
    assert "signature" not in text and events[1]["path"] == "/attest" and events[1]["status"] == 200
    assert events[1]["attestation"] == {k: body[k] for k in ("jti", "approved", "issued_at", "expires_at",
                                                              "action_type", "action_fingerprint")}
    assert events[1]["completed_at"] >= events[1]["dispatched_at"]


def test_event_sink_records_a_transport_error_once_and_reraises(no_network, monkeypatch):
    import requests

    def failing(self, method, url, **kwargs):
        raise requests.ConnectionError("TEST DOUBLE error mentioning " + KEY)

    monkeypatch.setattr(requests.Session, "request", failing)
    events = []
    authority = paced_without_real_sleep(core.RemoteAuthority(event_sink=events.append))
    client = authority._client(KEY)
    with pytest.raises(requests.ConnectionError):
        client._session.request("GET", core.AUTHORITY_URL + "/attestation/revocations")
    client._session.close()
    events = [event for event in events if not event["stage"].startswith("PACING_")]
    assert [event["stage"] for event in events] == ["DISPATCH", "TRANSPORT_ERROR"]
    assert authority.pacer.active is None, "a failed stand-alone request must release its reservation"
    assert events[1]["exception_type"] == "ConnectionError" and KEY not in json.dumps(events)


def test_a_failing_sink_does_not_turn_a_received_response_into_a_transport_error(no_network, monkeypatch):
    pass
    import requests
    monkeypatch.setattr(requests.Session, "request",
                        lambda self, method, url, **kwargs: FakeResponse(200, {"jti": "j1", "approved": True}))
    seen = []

    def sink(event):
        seen.append(event["stage"])
        if event["stage"] == "RESPONSE":
            raise OSError("TEST DOUBLE: accounting disk full")

    client = paced_without_real_sleep(core.RemoteAuthority(event_sink=sink))._client(KEY)
    try:
        try:
            response = client._session.request("POST", core.AUTHORITY_URL + "/attest")
        except OSError:
            response = None
    finally:
        client._session.close()
    assert "TRANSPORT_ERROR" not in seen, seen
    assert seen.count("RESPONSE") == 1


def test_without_a_sink_requests_are_still_paced_and_nothing_is_recorded(no_network, monkeypatch):
    import requests
    monkeypatch.setattr(requests.Session, "request",
                        lambda self, method, url, **kwargs: FakeResponse(200, {"revoked": False}))
    authority = paced_without_real_sleep(core.RemoteAuthority())
    client = authority._client(KEY)
    try:
        assert client._session.trust_env is False
        assert client._session.request("GET", core.AUTHORITY_URL + "/attestation/revoked/x").json() == {"revoked": False}
    finally:
        client._session.close()
    assert len(authority.pacer.calls["public_read"]) == 1 and authority.pacer.active is None


from swiftapi_native_service import authority_ledger as L  


class FakeAuthorityAPI:
    def __init__(self, authority, events_by_scope, jtis, cap=None, signing_mode="ed25519", statuses=None):
        self.authority, self.events, self.jtis, self.cap = authority, events_by_scope, jtis, cap
        self.signing_mode, self.statuses, self.calls = signing_mode, statuses or {}, []

    def __call__(self, transport, method, url, **kwargs):
        from urllib.parse import urlsplit
        path = urlsplit(url).path
        self.calls.append((method, path, dict(kwargs.get("params") or {})))
        assert method == "GET", "the ledger module must never send anything but GET"
        assert "json" not in kwargs and "data" not in kwargs
        if path in self.statuses:
            return FakeResponse(self.statuses[path], {"detail": "TEST DOUBLE"})
        if path == "/governance/events":
            events = list(self.events.get(kwargs["params"]["action_type"], []))
            limit = min(kwargs["params"]["limit"], self.cap or 10 ** 9)
            return FakeResponse(200, {"count": len(events[:limit]), "events": events[:limit]})
        if path == "/attestation/revocations":
            payload = {"revocations": list(self.jtis), "since": kwargs["params"]["since"], "next_cursor": 9,
                       "fetched_at": "TEST DOUBLE"}
            signature = base64.b64encode(self.authority._key.sign(compact(payload)).signature).decode()
            return FakeResponse(200, {"revocations": [{"jti": j} for j in self.jtis], "since": payload["since"],
                                      "next_cursor": 9, "fetched_at": "TEST DOUBLE", "has_more": False,
                                      "total_revoked": len(self.jtis), "signing_mode": self.signing_mode,
                                      "signature": signature})
        raise AssertionError("unexpected path " + path)


def event(jti, fingerprint, decision="approved", scope=core.SCOPE):
    return {"event_id": "e-" + jti, "jti": jti, "action_type": scope, "action_fingerprint": fingerprint,
            "decision": decision, "policy_hash": "p", "timestamp": "t", "actor": "PRIVATE ACTOR",
            "customer_id": "PRIVATE CUSTOMER", "ip_address": "203.0.113.9", "denial_reason": "PRIVATE TEXT",
            "violated_policies": ["PRIVATE POLICY"]}


def take_snapshot(monkeypatch, api):
    import requests
    monkeypatch.setattr(requests.Session, "request", lambda self, method, url, **kwargs: api(self, method, url, **kwargs))
    return L.snapshot(KEY, api.authority.public_key)


def test_ledger_snapshot_sends_only_gets_and_keeps_only_identifiers(no_network, monkeypatch):
    authority = LabelledTestAuthority()
    api = FakeAuthorityAPI(authority, {core.SCOPE: [event("j1", "a" * 32)]}, ["j9"])
    result = take_snapshot(monkeypatch, api)
    assert {method for method, _, _ in api.calls} == {"GET"} and result["read_requests"] == len(api.calls) == 3
    text = json.dumps(result)
    assert KEY not in text
    for private in ("PRIVATE", "203.0.113.9"):
        assert private not in text
    assert result["raw_bodies_retained"] is False
    assert result["governance"][0]["events"] == [{"event_id": "e-j1", "jti": "j1", "action_type": core.SCOPE,
                                                  "action_fingerprint": "a" * 32, "decision": "approved",
                                                  "policy_hash": "p", "timestamp": "t"}]
    assert result["revocations"][0]["signature_verified"] is True
    assert result["revocations"][0]["payload"]["revocations"] == ["j9"]
    assert any("not a cryptographic per-key census" in str(item) for item in result["limitations"])


def test_ledger_snapshot_rate_limit_and_outage_are_operational_stops(no_network, monkeypatch):
    authority = LabelledTestAuthority()
    for status, code in ((429, "AUTHORITY_RATE_LIMITED"), (503, "AUTHORITY_LEDGER_UNAVAILABLE")):
        api = FakeAuthorityAPI(authority, {}, [], statuses={"/governance/events": status})
        with pytest.raises(core.ServiceError) as caught:
            take_snapshot(monkeypatch, api)
        assert caught.value.code == code


def test_ledger_snapshot_refuses_a_revocation_page_signed_by_someone_else(no_network, monkeypatch):
    api = FakeAuthorityAPI(LabelledTestAuthority(), {}, ["j9"])
    api.authority, verifier = LabelledTestAuthority(), api.authority
    import requests
    monkeypatch.setattr(requests.Session, "request", lambda self, method, url, **kwargs: api(self, method, url, **kwargs))
    with pytest.raises(Exception):
        L.snapshot(KEY, verifier.public_key)


def test_ledger_does_not_claim_a_complete_window_when_the_server_caps_the_listing(no_network, monkeypatch):
    pass
    authority = LabelledTestAuthority()
    many = [event(f"j{i}", "a" * 32) for i in range(250)]
    result = take_snapshot(monkeypatch, FakeAuthorityAPI(authority, {core.SCOPE: many}, [], cap=100))
    page = next(page for page in result["governance"] if page["params"]["action_type"] == core.SCOPE)
    assert page["returned"] == 100
    assert page["complete_recent_window"] is not True, "100 of 250 events is not a complete window"


def test_ledger_reconcile_matches_and_reports_each_kind_of_difference(no_network, monkeypatch):
    authority = LabelledTestAuthority()
    before = take_snapshot(monkeypatch, FakeAuthorityAPI(authority, {core.SCOPE: [event("old", "0" * 32)]}, []))
    grants = [{"jti": "j1", "approved": True, "action_fingerprint": "a" * 32},
              {"jti": "j2", "approved": False, "action_fingerprint": "b" * 32}]
    listing = {core.SCOPE: [event("old", "0" * 32), event("j1", "a" * 32), event("j2", "b" * 32, "denied")]}
    after = take_snapshot(monkeypatch, FakeAuthorityAPI(authority, listing, ["j1"]))
    report = L.reconcile(before, after, grants, revoked_jti="j1")
    assert report["status"] == "MATCH_WITH_API_LIMITATIONS" and report["findings"] == []
    assert report["counts"]["observed_approved"] == 1 and report["counts"]["observed_denied"] == 1
    assert report["counts"]["authority_scoped_delta"] == 2 and report["counts"]["exact_scope_delta_matches_run"] is True
    assert report["revoked_jti_listed"] is True and report["authority_governance_records_signed"] is False
    assert [check["signed_denial"] for check in report["checks"]] == [False, True]
    
    for label, changed, revoked in (
            ("missing", {core.SCOPE: [event("j1", "a" * 32)]}, "j1"),
            ("decision", {core.SCOPE: [event("j1", "a" * 32, "denied"), event("j2", "b" * 32, "denied")]}, "j1"),
            ("binding", {core.SCOPE: [event("j1", "c" * 32), event("j2", "b" * 32, "denied")]}, "j1"),
            ("stranger", {core.SCOPE: listing[core.SCOPE] + [event("j3", "d" * 32)]}, "j1"),
            ("not revoked", listing, "j2")):
        other = take_snapshot(monkeypatch, FakeAuthorityAPI(authority, changed, ["j1"]))
        assert L.reconcile(before, other, grants, revoked_jti=revoked)["status"] == "FINDINGS", label


def test_ledger_does_not_report_all_pages_verified_when_it_saw_no_page(no_network, monkeypatch):
    authority = LabelledTestAuthority()
    api = FakeAuthorityAPI(authority, {}, [], statuses={"/attestation/revocations": 403})
    snapshot = take_snapshot(monkeypatch, api)
    assert snapshot["revocations"] == []
    report = L.reconcile(snapshot, snapshot, [])
    assert report["all_revocation_pages_signature_verified"] is not True


def test_ledger_reports_an_unsigned_revocation_page_as_unverified(no_network, monkeypatch):
    authority = LabelledTestAuthority()
    snapshot = take_snapshot(monkeypatch, FakeAuthorityAPI(authority, {}, ["j1"], signing_mode="hmac"))
    assert snapshot["revocations"][0]["signature_verified"] is False
    assert L.reconcile(snapshot, snapshot, [])["all_revocation_pages_signature_verified"] is False


@pytest.mark.parametrize("approval_id", [None, "", "not-a-uuid", 7, "A3281CDF-8904-23E7-8414-5E9F00590A19",
                                         "{a3281cdf-8904-43e7-8414-5e9f00590a19}"])
def test_an_approval_needs_a_canonical_uuid_and_is_not_consumed_without_one(tmp_path, approval_registry_in_a_temporary_directory, approval_id):
    config, _ = live_replay_config(tmp_path)
    path = approval_for(config, tmp_path, approval_id=approval_id)
    with pytest.raises(ValueError):
        X.consume_approval(config, path)
    registry = approval_registry_in_a_temporary_directory
    assert not registry.exists() or not list(registry.iterdir())
    assert not path.with_name(path.name + ".consumed.json").exists()


def test_the_spent_record_is_keyed_by_approval_id_in_the_registry(tmp_path, approval_registry_in_a_temporary_directory):
    config, _ = live_replay_config(tmp_path)
    path = approval_for(config, tmp_path)
    approval = X.consume_approval(config, path)
    record = json.loads((approval_registry_in_a_temporary_directory / (approval["approval_id"] + ".json")).read_text())
    assert record["approval_id"] == approval["approval_id"] and record["config_sha256"] == sha(compact(config))
    assert approval_registry_in_a_temporary_directory == tmp_path / "approval-registry-TEST"
    assert X.APPROVAL_REGISTRY == approval_registry_in_a_temporary_directory
    assert X.APPROVAL_REGISTRY != Path.home() / '.local/state/swiftapi-native/approval-spent'


def test_revoked_must_be_the_last_arm(tmp_path):
    for schedule in (["REVOKED", "VALID"], ["VALID", "REVOKED", "MISSING_GRANT"]):
        config, wheel = runner_config(tmp_path, schedule=schedule, one_disposable_grant_revocation_approved=True)
        with pytest.raises(ValueError, match="last"):
            X.validate_config(config, wheel)
    assert X.SERVICE_ARMS[-1] == "REVOKED"


def test_runner_revoked_arm_with_the_local_double_revokes_one_disposable_grant_last(tmp_path):
    pass
    out = run_replay(tmp_path, schedule=["VALID", "MISSING_GRANT", "REVOKED"],
                     one_disposable_grant_revocation_approved=True)
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "PASS" and [row["arm"] for row in summary["rows"]] == ["VALID", "MISSING_GRANT", "REVOKED"]
    revoked = summary["rows"][-1]
    assert revoked["class"] == "V0" and revoked["reason"] == "AUTHORITY_REVOKED"
    intent = json.loads((out / "revocation-intent.json").read_text())
    response = json.loads((out / "revocation-response.json").read_text())
    assert response == {"revoked": True, "test_double": True, "jti": intent["jti"]}
    issued = json.loads(next(out.glob("issuance-*-REVOKED.json")).read_text())
    assert issued["grant"]["jti"] == intent["jti"], "only the grant created for this arm"
    valid = json.loads(next(out.glob("issuance-*-VALID.json")).read_text())
    assert valid["grant"]["jti"] != intent["jti"]
    assert len(list(out.glob("revocation-intent*.json"))) == 1
    receipt = json.loads((out / revoked["receipt"]).read_text())["payload"]
    assert receipt["authority_decision"]["revocation_authority_signed"] is False
    assert receipt["authority_decision"]["revocation_observation"] == "RUNTIME_REPORTED"


def test_feed_entry_dated_after_the_local_decision_falls_back_with_the_exact_label(world):
    _, receipt = revoked_world(world, lambda jti: {
        "authority_signed": True, "reason": "VERIFIED_SIGNED_FEED_ENTRY",
        "entry": world.authority.revocation_entry(jti, revoked_at=world.authority.now() + 600)})
    row = receipt["payload"]
    assert_v0(row, "AUTHORITY_REVOKED")
    decision = row["authority_decision"]
    assert decision["revocation_evidence_limit"] == "REVOKED_AT_AFTER_DECISION_CLOCK"
    assert decision["revocation_authority_signed"] is False and decision["revocation_observation"] == "RUNTIME_REPORTED"
    assert "authority-revocation.json" not in row["assets"]
    assert not (folder(world, receipt) / "authority-revocation.json").exists()
    both(world, receipt)


def test_feed_entry_within_the_five_second_allowance_is_still_accepted_as_signed(world):
    _, receipt = revoked_world(world, lambda jti: {
        "authority_signed": True, "reason": "VERIFIED_SIGNED_FEED_ENTRY",
        "entry": world.authority.revocation_entry(jti, revoked_at=world.authority.now() + 2)})
    decision = receipt["payload"]["authority_decision"]
    assert decision["revocation_authority_signed"] is True and decision["reason"] == "AUTHORITY_REVOKED"
    both(world, receipt)


def study_config(tmp_path, predictions, **changes):
    return runner_config(tmp_path, purpose="PREREGISTERED_STUDY", author_freeze_approved=True,
                         public_registration_timestamp="TEST DOUBLE timestamp, not a registration",
                         registration_sha256="0" * 64, author_predictions_sha256="0" * 64,
                         schedule=list(predictions), predictions=predictions, **changes)


def run_study(tmp_path, predictions, **changes):
    config, wheel = study_config(tmp_path, predictions, **changes)
    out = tmp_path / "study"
    approval = approval_for(config, tmp_path)
    summary = X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS, approval_file=approval)
    return out, summary


def test_study_continues_past_a_class_surprise_and_fails_only_in_the_aggregate(tmp_path):
    predictions = {"VALID": {"class": "R", "first_token": 19, "output_bytes": 1},
                   "MISSING_GRANT": {"class": "R"},                 
                   "INVALID_SIGNATURE": {"class": "V0", "first_token": 151645, "output_bytes": 0,
                                         "generation_complete": True},
                   "WRONG_REQUEST": {"class": "V0"}}
    out, summary = run_study(tmp_path, predictions)
    assert summary["sequence_completed"] is True and summary["status"] == "FAIL"
    assert [row["arm"] for row in summary["rows"]] == list(predictions)
    assert [row["prediction_agrees"] for row in summary["rows"]] == [True, False, True, True]
    assert summary["prediction_matches"] == 3 and summary["verified_receipt_count"] == summary["planned_count"] == 4
    assert all(row["receipt_integrity"] == "PASS" for row in summary["rows"])
    surprise = summary["rows"][1]
    assert surprise["observation"]["class"] == "V0" and surprise["prediction"] == {"class": "R"}
    assert all(slot["status"] == "OBSERVED" for slot in summary["slots"])
    assert not (out / "error.json").exists()


def test_study_with_every_prediction_right_passes(tmp_path):
    out, summary = run_study(tmp_path, {"VALID": {"class": "R", "first_token": 19},
                                        "MISSING_GRANT": {"class": "V0", "first_token": 151645}})
    assert summary["status"] == "PASS" and summary["prediction_matches"] == 2


def test_study_stops_on_a_receipt_that_fails_verification_and_says_which_slots_did_not_run(tmp_path, monkeypatch):
    calls = []
    real = X.light_verify

    def failing(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise ValueError("TEST DOUBLE structural verification error")
        return real(*args, **kwargs)

    monkeypatch.setattr(X, "light_verify", failing)
    config, wheel = study_config(tmp_path, {"VALID": {"class": "R"}, "MISSING_GRANT": {"class": "V0"},
                                            "WRONG_REQUEST": {"class": "V0"}})
    out = tmp_path / "study"
    with pytest.raises(ValueError, match="structural"):
        X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS,
              approval_file=approval_for(config, tmp_path))
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "FAIL" and summary["sequence_completed"] is False
    assert [slot["status"] for slot in summary["slots"]] == ["OBSERVED", "NOT_EXECUTED_OR_NO_VERIFIED_RECEIPT",
                                                             "NOT_EXECUTED_OR_NO_VERIFIED_RECEIPT"]
    error = json.loads((out / "error.json").read_text())
    assert error["arm"] == "MISSING_GRANT" and error["retry_permitted"] is False
    
    assert (next((out / "receipts").glob("*-MISSING_GRANT")) / "receipt.json").is_file()


def test_study_stops_on_an_operational_outcome_where_a_decision_was_expected(tmp_path, monkeypatch):
    from swiftapi_native_service import development_authority as D
    real = D.DevelopmentAuthority.recheck

    def unreachable(self, key, grant, action):
        raise core.ServiceError("REVOCATION_UNAVAILABLE", 503)

    monkeypatch.setattr(D.DevelopmentAuthority, "recheck", unreachable)
    config, wheel = study_config(tmp_path, {"VALID": {"class": "R"}, "MISSING_GRANT": {"class": "V0"}})
    out = tmp_path / "study"
    with pytest.raises(Exception):
        X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS,
              approval_file=approval_for(config, tmp_path))
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "FAIL" and summary["sequence_completed"] is False
    assert summary["rows"][0]["class"] == "operational" and len(summary["rows"]) == 1
    assert json.loads((out / "error.json").read_text())["code"] == "REVOCATION_UNAVAILABLE"


def test_development_run_still_stops_at_the_first_surprise(tmp_path, monkeypatch):
    monkeypatch.setattr(X, "prediction_for", lambda config, arm: {"class": "R"})
    config, wheel = runner_config(tmp_path, schedule=["VALID", "MISSING_GRANT", "WRONG_REQUEST"])
    out = tmp_path / "dev"
    with pytest.raises(RuntimeError, match="development acceptance"):
        X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS)
    summary = json.loads((out / "summary.json").read_text())
    assert [row["arm"] for row in summary["rows"]] == ["VALID", "MISSING_GRANT"] and summary["status"] == "FAIL"


def test_a_study_purpose_always_needs_an_approval_file(tmp_path):
    pass
    config, wheel = study_config(tmp_path, {"VALID": {"class": "R"}})
    out = tmp_path / "unapproved-study"
    with pytest.raises(ValueError):
        X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS)
    assert not out.exists()


def test_a_study_run_against_the_local_double_is_not_recorded_as_a_registered_result(tmp_path):
    out, summary = run_study(tmp_path, {"VALID": {"class": "R"}})
    authority = json.loads((out / "authority-public.json").read_text())
    assert authority["production"] is False
    assert summary["registered_result"] is not True, "a local-double replay cannot be the registered result"


@pytest.mark.parametrize("predictions", [
    {"VALID": {"class": "R"}},                                              
    {"VALID": {"class": "R"}, "MISSING_GRANT": {"class": "V0"}, "EXPIRED": {"class": "V0"}},  
    {"VALID": {"class": "R"}, "MISSING_GRANT": {"class": "VOID"}},          
    {"VALID": {"class": "R"}, "MISSING_GRANT": {"first_token": 151645}},    
    {"VALID": {"class": "R", "tokens": [19]}, "MISSING_GRANT": {"class": "V0"}},  
    {"VALID": "R", "MISSING_GRANT": "V0"},
])
def test_study_predictions_must_cover_exactly_the_schedule_with_known_fields(tmp_path, predictions):
    config, wheel = study_config(tmp_path, {"VALID": {"class": "R"}, "MISSING_GRANT": {"class": "V0"}})
    config["predictions"] = predictions
    with pytest.raises(ValueError):
        X.validate_config(config, wheel)


def test_bank_population_is_exactly_valid_then_missing_grant_once_per_question(tmp_path, replay_backend):
    config, wheel = runner_config(tmp_path, population="BANK_188", schedule=["VALID", "MISSING_GRANT"])
    X.validate_config(config, wheel)
    for change in ({"schedule": ["MISSING_GRANT", "VALID"]}, {"schedule": ["VALID"]},
                   {"schedule": ["VALID", "MISSING_GRANT", "WRONG_REQUEST"]}, {"repetitions": 2},
                   {"population": "BANK_10"}, {"population": "BANK_188", "purpose": "DEVELOPMENT_SMOKE",
                                               "schedule": ["VALID", "SIGNED_DENIAL"]}):
        bad, _ = runner_config(tmp_path, **dict({"population": "BANK_188", "schedule": ["VALID", "MISSING_GRANT"]}, **change))
        with pytest.raises(ValueError):
            X.validate_config(bad, wheel)
    slots = X.planned_slots(config, list(replay_backend.allowed_questions))
    assert len(slots) == 376 and [slot["slot"] for slot in slots] == list(range(376))
    assert [slot["arm"] for slot in slots[:4]] == ["VALID", "MISSING_GRANT", "VALID", "MISSING_GRANT"]
    assert [slots[2 * i]["question"] for i in range(188)] == list(replay_backend.allowed_questions)
    assert len({slot["question"] for slot in slots}) == 188


def test_planned_authority_load_for_the_live_bank_run_is_2444_requests_and_1128_attestations(tmp_path):
    config, _ = runner_config(tmp_path, population="BANK_188", schedule=["VALID", "MISSING_GRANT"],
                              authority="LIVE_SWIFTAPI")
    plan = X.authority_load_plan(config, 188)
    assert plan["planned_slots"] == 376 and plan["planned_attest_dispatches"] == 1128
    assert plan["planned_http_dispatches_excluding_ledger_and_revocation_feed"] == 2444
    assert plan["snapshot_reads_minimum"] == 6 and plan["retry_count"] == 0
    local, _ = runner_config(tmp_path, population="BANK_188", schedule=["VALID", "MISSING_GRANT"])
    assert X.authority_load_plan(local, 188)["snapshot_reads_minimum"] == 0


class CountingSwiftAPI:
    pass

    issuer = None

    class _Session:
        trust_env = True

        def request(self, method, url, **kwargs):
            from urllib.parse import urlsplit
            path = urlsplit(url).path
            if method == "POST" and path == "/attest":
                action = kwargs["json"]["action_data"]
                return FakeResponse(200, CountingSwiftAPI.issuer.issue(action))
            if method == "GET" and path.startswith("/attestation/revoked/"):
                return FakeResponse(200, {"revoked": False})
            raise AssertionError("unexpected authority request " + method + " " + path)

        def close(self):
            pass

    def __init__(self, key, base_url, timeout):
        assert base_url == core.AUTHORITY_URL
        self._session = self._Session()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def attest(self, action_type, action_data):
        return self._session.request("POST", core.AUTHORITY_URL + "/attest",
                                     json={"action_type": action_type, "action_data": action_data}).json()

    def check_revocation(self, jti):
        return self._session.request("GET", core.AUTHORITY_URL + "/attestation/revoked/" + jti).json()["revoked"]


def test_measured_authority_requests_per_arm_equal_the_planned_table(no_network, replay_backend, tmp_path, monkeypatch):
    pass
    issuer = LabelledTestAuthority()
    CountingSwiftAPI.issuer = issuer
    monkeypatch.setattr(core, "SwiftAPI", CountingSwiftAPI)
    monkeypatch.setattr(core.check_grant, "__defaults__", (None, issuer._signature))
    events = []
    authority = core.RemoteAuthority(event_sink=events.append)
    authority.public_key = issuer.public_key
    authority.evidence_kind = "LABELLED_TEST_DOUBLE_AUTHORITY_NOT_PRODUCTION"
    virtual = VirtualClock()
    authority.pacer = P.AuthorityPacer(authority._emit, clock=virtual.now, sleep=virtual.sleep)
    service = S.NativeService(replay_backend, tmp_path / "counting-runtime", authority=authority)

    def dispatched():
        return (sum(event["stage"] == "DISPATCH" for event in events),
                sum(event["stage"] == "DISPATCH" and event["path"] == "/attest" for event in events))

    request_id = new_id()
    permission = service.authorize(KEY, {"request_id": request_id, "question": Q})
    data = body(request_id, permission["grant"])
    receipt = service.generate(KEY, data, raw_request=compact(data))
    assert receipt["payload"]["authority_decision"]["permission"] == VERIFIED
    valid = dispatched()
    data = body(new_id(), None)
    receipt = service.generate(KEY, data, raw_request=compact(data))
    assert receipt["payload"]["authority_decision"]["reason"] == "MISSING_PERMISSION"
    total = dispatched()
    missing = (total[0] - valid[0], total[1] - valid[1])
    assert valid == (9, 4) and missing == (4, 2), (valid, missing)
    assert 188 * (valid[0] + missing[0]) == 2444 and 188 * (valid[1] + missing[1]) == 1128
    assert KEY not in json.dumps(events)


def test_bank_replay_with_the_local_double_gives_188_of_188_per_arm_and_says_first_token_only(tmp_path, capsys):
    pass
    out = run_replay(tmp_path, population="BANK_188", schedule=["VALID", "MISSING_GRANT"])
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "PASS" and summary["planned_count"] == summary["verified_receipt_count"] == 376
    valid = [row for row in summary["rows"] if row["arm"] == "VALID"]
    missing = [row for row in summary["rows"] if row["arm"] == "MISSING_GRANT"]
    assert len(valid) == len(missing) == 188
    assert {row["class"] for row in valid} == {"R"} and {row["class"] for row in missing} == {"V0"}
    assert {row["response_scope"] for row in valid} == {"FIRST_TOKEN_ONLY_NOT_A_COMPLETE_ANSWER"}
    assert {row["reason"] for row in missing} == {"MISSING_PERMISSION"}
    assert len({row["question"] for row in valid}) == 188
    assert all(row["sdk_verifier"]["status"] == "PASS" and row["full_verifier"]["numerical_replay"] == "PASS"
               for row in summary["rows"])
    assert all(row["mode"] == REPLAY and "NOT_SWIFTAPI_PRODUCTION" in row["authority_evidence_kind"]
               for row in summary["rows"])
    printed = capsys.readouterr().out.splitlines()
    assert len(printed) == 752 and printed[0] == f"[VALID] [{X.MODEL}] [1/1] [R]"
    import sys
    monkey_argv = ["experiment", "question", "--config", str(out / "run-config.json"), "--out", str(out), "--arm"]
    for arm, cls in (("VALID", "R"), ("MISSING_GRANT", "V0")):
        old = sys.argv
        sys.argv = monkey_argv + [arm]
        try:
            X.main()
        finally:
            sys.argv = old
        lines = capsys.readouterr().out.splitlines()
        assert lines[0] == f"[{arm}] [{X.MODEL}] [188/188] [{cls}]" and lines[1].startswith("Metadata: ")
        assert len(lines) == 2


from email.utils import formatdate  
from swiftapi.exceptions import AuthenticationError, RateLimitError  

TIER_LIMITS = {"authenticated": 300, "public_read": 120, "public_write": 30, "admin": 60}


def tier_of(method, path):
    pass
    if path in ("/attest", "/attestation/revoke", "/verify", "/audit") or path.startswith("/audit/"):
        return "authenticated"
    if path in ("/governance/events", "/authority/denials", "/authority/keys", "/authority/keys/revoke"):
        return "admin"
    if path == "/attestation/verify":
        return "public_write"
    assert method == "GET", (method, path)
    return "public_read"


class LimitedAuthority:
    pass

    def __init__(self, issuer, clock, send_headers=True):
        self.issuer, self.clock, self.send_headers = issuer, clock, send_headers
        self.windows = {tier: [] for tier in TIER_LIMITS}
        self.requests, self.refused, self.foreign = [], 0, None
        self.unknown_keys = set()

    def handle(self, key, method, url, **kwargs):
        from urllib.parse import urlsplit
        path = urlsplit(url).path
        tier, now = tier_of(method, path), self.clock.now()
        if self.foreign:
            self.foreign(self, tier, now)
        self.windows[tier] = [t for t in self.windows[tier] if t > now - 60]
        allowed = len(self.windows[tier]) < TIER_LIMITS[tier]
        if allowed:
            self.windows[tier].append(now)
        else:
            self.refused += 1
        self.requests.append((now, tier, method, path, allowed))
        self.clock.value += 0.02          
        headers = {"Date": formatdate(1_800_000_000 + now, usegmt=True)}
        if self.send_headers:
            headers.update({"X-RateLimit-Limit": str(TIER_LIMITS[tier]),
                            "X-RateLimit-Remaining": str(max(0, TIER_LIMITS[tier] - len(self.windows[tier]))),
                            "X-RateLimit-Reset": str(int(1_800_000_000 + now) + 60)})
        if not allowed:
            body, status = {"error": "rate_limited"}, 429
        elif path == "/attest":
            if key in self.unknown_keys:
                body, status = {"detail": "TEST DOUBLE unknown key"}, 401
            else:
                body, status = self.issuer.issue(kwargs["json"]["action_data"]), 200
        elif path.startswith("/attestation/revoked/"):
            body, status = {"revoked": False}, 200
        else:
            raise AssertionError("unexpected authority request " + method + " " + path)
        response = FakeResponse(status, body)
        response.headers = headers
        return response


def limited_world(replay_backend, tmp_path, monkeypatch, send_headers=True):
    issuer, clock = LabelledTestAuthority(), VirtualClock()
    server = LimitedAuthority(issuer, clock, send_headers)

    class Client:
        def __init__(self, key, base_url, timeout):
            outer = self
            self.key = key

            class Session:
                trust_env = True

                def request(self, method, url, **kwargs):
                    return server.handle(outer.key, method, url, **kwargs)

                def close(self):
                    pass

            self._session = Session()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def _checked(self, response):
            if response.status_code == 429:
                raise RateLimitError(None)
            if response.status_code == 401:
                raise AuthenticationError("TEST DOUBLE unknown key")
            return response.json()

        def attest(self, action_type, action_data):
            return self._checked(self._session.request("POST", core.AUTHORITY_URL + "/attest",
                                                       json={"action_type": action_type, "action_data": action_data}))

        def check_revocation(self, jti):
            return self._checked(self._session.request("GET", core.AUTHORITY_URL + "/attestation/revoked/" + jti))["revoked"]

    monkeypatch.setattr(core, "SwiftAPI", Client)
    monkeypatch.setattr(core.check_grant, "__defaults__", (None, issuer._signature))
    events = []
    authority = core.RemoteAuthority(event_sink=events.append)
    authority.public_key = issuer.public_key
    authority.evidence_kind = "LABELLED_TEST_DOUBLE_AUTHORITY_NOT_PRODUCTION"
    authority.pacer = P.AuthorityPacer(authority._emit, clock=clock.now, sleep=clock.sleep)
    slept_inside = []
    clock.on_sleep = lambda seconds: slept_inside.append(authority.pacer.active) if authority.pacer.active else None
    service = S.NativeService(replay_backend, tmp_path / "limited-runtime", authority=authority)
    return types.SimpleNamespace(service=service, authority=authority, server=server, clock=clock, events=events,
                                 slept_inside=slept_inside, issuer=issuer)


def run_arm(w, arm, question=Q, prior=None):
    pass
    w.authority.begin_slot(arm)
    started = w.clock.now()
    try:
        request_id, grant, key = new_id(), None, KEY
        if arm == "REUSED":
            request_id, grant = prior
        elif arm not in ("MISSING_GRANT", "UNKNOWN_KEY"):
            grant = w.service.authorize(KEY, {"request_id": request_id, "question": question})["grant"]
            if arm == "INVALID_SIGNATURE":
                grant = dict(grant, signature=base64.b64encode(bytes(64)).decode())
            if arm == "WRONG_REQUEST":
                request_id = new_id()
        if arm == "UNKNOWN_KEY":
            key = OTHER_KEY
        data = body(request_id, grant, question)
        receipt = w.service.generate(key, data, raw_request=compact(data))
        leftover = dict(w.authority.pacer.remaining)
    finally:
        w.authority.end_slot()
    return receipt, (request_id, grant), leftover, w.clock.now() - started


def test_slot_budgets_equal_the_requests_the_service_really_sends(no_network, replay_backend, tmp_path, monkeypatch):
    w = limited_world(replay_backend, tmp_path, monkeypatch)
    w.server.unknown_keys.add(OTHER_KEY)
    expected = {"VALID": VERIFIED, "MISSING_GRANT": "MISSING_PERMISSION", "INVALID_SIGNATURE": "INVALID_AUTHORITY_SIGNATURE",
                "REUSED": "REPLAYED_REQUEST", "WRONG_REQUEST": "GRANT_BINDING_MISMATCH", "UNKNOWN_KEY": None}
    prior = None
    for arm in ("VALID", "MISSING_GRANT", "INVALID_SIGNATURE", "REUSED", "WRONG_REQUEST", "UNKNOWN_KEY"):
        before = len(w.server.requests)
        receipt, used, leftover, _ = run_arm(w, arm, prior=prior)
        if arm == "VALID":
            prior = used
        row = receipt["payload"]
        if arm == "UNKNOWN_KEY":
            assert row["status"] == "OPERATIONAL" and row["error_code"] == "AUTHENTICATION_REJECTED"
        elif arm == "VALID":
            assert row["authority_decision"]["permission"] == VERIFIED
        else:
            assert row["authority_decision"]["reason"] == expected[arm], arm
        sent = w.server.requests[before:]
        by_tier = {tier: sum(1 for _, t, *_ in sent if t == tier) for tier in ("authenticated", "public_read")}
        budget = {tier: P.SLOT_BUDGETS[arm].get(tier, 0) for tier in by_tier}
        assert by_tier == budget, (arm, by_tier, budget)
        assert all(value == 0 for value in leftover.values()), (arm, leftover)
    assert w.server.refused == 0 and w.slept_inside == []


def test_route_tiers_agree_with_the_authority_source_for_every_request_we_send():
    for method, path in (("POST", "/attest"), ("POST", "/attestation/revoke"), ("GET", "/attestation/revoked/abc"),
                         ("GET", "/attestation/revocations"), ("GET", "/"), ("GET", "/attestation/info"),
                         ("GET", "/governance/events"), ("GET", "/audit"), ("GET", "/authority/denials")):
        assert P.route_tier(method, path) == tier_of(method, path), (method, path)
    assert P.LIMITS == TIER_LIMITS


@pytest.mark.parametrize("send_headers", [True, False])
def test_bank_188_through_the_real_service_paths_gets_no_429_and_never_sleeps_inside_a_slot(
        no_network, replay_backend, tmp_path, monkeypatch, send_headers):
    pass
    w = limited_world(replay_backend, tmp_path, monkeypatch, send_headers=send_headers)
    started, longest = w.clock.now(), 0.0
    for question in replay_backend.allowed_questions:
        for arm, wanted in (("VALID", "R"), ("MISSING_GRANT", "V0")):
            receipt, _, leftover, inside = run_arm(w, arm, question=question)
            assert receipt["payload"]["taxonomy"]["class"] == wanted, (question, arm, receipt["payload"].get("error_code"))
            assert all(value == 0 for value in leftover.values())
            longest = max(longest, inside)
    elapsed = w.clock.now() - started
    by_tier = {tier: sum(1 for _, t, *_ in w.server.requests if t == tier) for tier in TIER_LIMITS}
    assert by_tier == {"authenticated": 1128, "public_read": 1316, "public_write": 0, "admin": 0}
    assert w.server.refused == 0, "the stand-in authority refused a request"
    assert w.slept_inside == [], "a wait happened while a slot's grant was live"
    assert longest < 5.0, "virtual time inside one slot"
    
    assert elapsed >= 1316 / 120 * 60 - 61, elapsed
    
    for tier, limit in TIER_LIMITS.items():
        times = sorted(t for t, kind, *_ in w.server.requests if kind == tier)
        for index, start in enumerate(times):
            in_window = sum(1 for t in times[index:index + limit + 1] if t < start + 60)
            assert in_window <= limit, (tier, start, in_window)
    sleeps = [event for event in w.events if event.get("stage") == "PACING_SLEEP"]
    assert sleeps and all(event["location"] == "BEFORE_SLOT_ISSUANCE" for event in sleeps)
    assert KEY not in json.dumps(w.events)


def test_a_429_stops_everything_after_it_and_is_never_retried(no_network, replay_backend, tmp_path, monkeypatch):
    w = limited_world(replay_backend, tmp_path, monkeypatch)
    
    def foreign(server, tier, now):
        if tier == "public_read" and not server.windows["public_read"]:
            server.windows["public_read"] = [now] * 120
    w.server.foreign = foreign
    receipt, _, _, _ = run_arm(w, "MISSING_GRANT")
    row = receipt["payload"]
    assert row["status"] == "OPERATIONAL" and row["taxonomy"]["class"] == "operational"
    assert row["error_code"] == "AUTHORITY_RATE_LIMITED" and row["http_status"] == 429
    refused_paths = [(method, path) for _, _, method, path, allowed in w.server.requests if not allowed]
    assert len(refused_paths) == 1, "exactly one refused request, no retry"
    sent_before = len(w.server.requests)
    with pytest.raises(core.ServiceError) as caught:
        w.authority.begin_slot("VALID")
    assert caught.value.code == "AUTHORITY_RATE_LIMITED" and caught.value.status == 429
    assert len(w.server.requests) == sent_before, "no request after the 429"
    assert w.slept_inside == []


def test_low_remaining_seen_in_headers_is_waited_out_before_issuance(no_network, replay_backend, tmp_path, monkeypatch):
    w = limited_world(replay_backend, tmp_path, monkeypatch)
    run_arm(w, "MISSING_GRANT")
    
    now = w.clock.now()
    w.server.windows["public_read"] += [now] * 112
    run_arm(w, "MISSING_GRANT")
    slept_before = sum(w.clock.sleeps)
    receipt, _, _, inside = run_arm(w, "VALID")
    assert receipt["payload"]["authority_decision"]["permission"] == VERIFIED
    assert sum(w.clock.sleeps) - slept_before >= 60, "must wait a full window before issuing"
    assert w.server.refused == 0 and w.slept_inside == [] and inside < 5.0
    reasons = {event["reason"] for event in w.events if event.get("stage") == "PACING_SLEEP"}
    assert "HEADER_RESET" in reasons


def test_quota_lost_inside_a_slot_is_an_operational_stop_not_a_wait(no_network, replay_backend, tmp_path, monkeypatch):
    w = limited_world(replay_backend, tmp_path, monkeypatch)
    run_arm(w, "MISSING_GRANT")
    fired = []

    def foreign(server, tier, now):
        
        if tier == "public_read" and len(server.requests) >= 5 and not fired:
            fired.append(now)
            server.windows["public_read"] += [now] * 112

    w.server.foreign = foreign
    receipt, _, _, _ = run_arm(w, "MISSING_GRANT")
    row = receipt["payload"]
    assert row["status"] == "OPERATIONAL" and row["taxonomy"]["class"] == "operational"
    assert row["error_code"] in ("PACING_RESERVE_LOST_AT_BOUNDARY", "AUTHORITY_RATE_LIMITED")
    assert w.slept_inside == [] and "result" not in row


def test_pacer_refuses_nested_slots_and_requests_beyond_the_reserved_budget():
    clock = VirtualClock()
    pacer = P.AuthorityPacer(clock=clock.now, sleep=clock.sleep)
    pacer.begin_slot("MISSING_GRANT")
    with pytest.raises(core.ServiceError) as caught:
        pacer.begin_slot("VALID")
    assert caught.value.code == "PACING_SLOT_ALREADY_ACTIVE"
    slept = list(clock.sleeps)
    for _ in range(2):
        pacer.before_dispatch("POST", "/attest")
    with pytest.raises(core.ServiceError) as caught:
        pacer.before_dispatch("POST", "/attest")
    assert caught.value.code == "PACING_RESERVED_CALL_BUDGET_EXCEEDED"
    assert clock.sleeps == slept, "nothing waits once the slot has begun"
    pacer.end_slot()
    assert set(P.SLOT_BUDGETS) == set(X.SERVICE_ARMS)


def test_reset_header_is_not_trusted_as_the_time_capacity_returns():
    pass
    clock = VirtualClock()
    pacer = P.AuthorityPacer(clock=clock.now, sleep=clock.sleep)
    soon = {"Date": formatdate(1_800_000_000, usegmt=True), "X-RateLimit-Limit": "120",
            "X-RateLimit-Remaining": "3", "X-RateLimit-Reset": str(1_800_000_000 + 1)}
    assert pacer.observe("public_read", soon, 200)["usable"] is True
    pacer.begin_slot("MISSING_GRANT")
    assert sum(clock.sleeps) >= 60


@pytest.mark.parametrize("headers", [{}, {"X-RateLimit-Limit": "120"}, {"X-RateLimit-Limit": "abc",
                                     "X-RateLimit-Remaining": "5", "X-RateLimit-Reset": "1"},
                                     {"X-RateLimit-Limit": "120", "X-RateLimit-Remaining": "500",
                                      "X-RateLimit-Reset": "1"},
                                     {"X-RateLimit-Limit": "0", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1"}])
def test_unusable_headers_fall_back_to_spacing_and_are_recorded_as_unusable(headers):
    clock = VirtualClock()
    pacer = P.AuthorityPacer(clock=clock.now, sleep=clock.sleep)
    assert pacer.observe("public_read", headers, 200)["usable"] is False
    for _ in range(40):
        pacer.begin_slot("VALID")
        for method, path in [("POST", "/attest")] * 4 + [("GET", "/attestation/revoked/x")] * 5:
            pacer.before_dispatch(method, path)
        pacer.end_slot()
    
    assert clock.now() - 5000.0 >= 61.0


from swiftapi.exceptions import PolicyViolation as _PolicyViolation  


class WallClock:
    pass

    def __init__(self):
        self.value, self.sleeps, self.hook = 1_800_000_000.0, [], None
        self._lock = threading.Lock()

    def time(self):
        return self.value

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        with self._lock:
            self.sleeps.append((seconds, self.hook() if self.hook else None))
            self.value += max(0.0, seconds)

    def tick(self, seconds):
        with self._lock:
            self.value += seconds


class GateAuthorityServer:
    pass

    def __init__(self, issuer, clock, feed_position=20, page_size=1):
        self.issuer, self.clock = issuer, clock
        self.windows = {tier: [] for tier in TIER_LIMITS}
        self.log, self.refused, self.slot, self.foreign = [], 0, None, None
        self.revoked, self.issued = set(), []
        self.feed = [issuer.revocation_entry(f"foreign-{index}", cursor=index + 1) for index in range(feed_position - 1)]
        self.page_size, self.unknown_key = page_size, "swiftapi_live_" + "0" * 64

    def handle(self, key, method, url, **kwargs):
        from urllib.parse import urlsplit
        path = urlsplit(url).path
        tier, now = tier_of(method, path), self.clock.time()
        if self.foreign:
            self.foreign(self, tier, method, path, now)
        self.windows[tier] = [t for t in self.windows[tier] if t > now - 60]
        allowed = len(self.windows[tier]) < TIER_LIMITS[tier]
        if allowed:
            self.windows[tier].append(now)
        else:
            self.refused += 1
        self.log.append({"at": now, "tier": tier, "method": method, "path": path, "allowed": allowed,
                         "slot": self.slot})
        self.clock.tick(0.02)
        headers = {"Date": formatdate(now, usegmt=True), "X-RateLimit-Limit": str(TIER_LIMITS[tier]),
                   "X-RateLimit-Remaining": str(max(0, TIER_LIMITS[tier] - len(self.windows[tier]))),
                   "X-RateLimit-Reset": str(int(now) + 60)}
        status, body = 200, None
        if not allowed:
            status, body = 429, {"error": "rate_limited"}
        elif method == "POST" and path == "/attest":
            action = kwargs["json"]["action_data"]
            if key == self.unknown_key:
                status, body = 401, {"detail": {"message": "TEST DOUBLE unknown key"}}
            else:
                approved = not action.get("strict_action_type", False)
                body = self.issuer.issue(action, approved=approved)
                self.issued.append({"event_id": "e-" + body["jti"], "jti": body["jti"],
                                    "action_type": body["action_type"],
                                    "action_fingerprint": body["action_fingerprint"],
                                    "decision": "approved" if approved else "denied", "policy_hash": "TEST",
                                    "timestamp": iso(now)})
        elif method == "GET" and path.startswith("/attestation/revoked/"):
            body = {"revoked": path.rsplit("/", 1)[1] in self.revoked}
        elif method == "POST" and path == "/attestation/revoke":
            jti = kwargs["json"]["jti"]
            self.revoked.add(jti)
            self.feed.append(self.issuer.revocation_entry(jti, revoked_at=now, cursor=len(self.feed) + 1))
            body = {"revoked": True, "jti": jti}
        elif method == "GET" and path == "/attestation/revocations":
            since = int(kwargs["params"]["since"])
            entries = [entry for entry in self.feed if entry["cursor"] > since][:self.page_size]
            next_cursor = entries[-1]["cursor"] if entries else since
            payload = {"revocations": [entry["jti"] for entry in entries], "since": since,
                       "next_cursor": next_cursor, "fetched_at": iso(now)}
            body = {"revocations": entries, "since": since, "next_cursor": next_cursor, "fetched_at": iso(now),
                    "has_more": any(entry["cursor"] > next_cursor for entry in self.feed),
                    "total_revoked": len(self.feed), "signing_mode": "ed25519",
                    "signature": base64.b64encode(self.issuer._key.sign(compact(payload)).signature).decode()}
        elif method == "GET" and path == "/governance/events":
            wanted = kwargs["params"]["action_type"]
            events = [event for event in reversed(self.issued) if event["action_type"] == wanted]
            body = {"events": events[:kwargs["params"]["limit"]], "count": len(events)}
        else:
            raise AssertionError("unexpected authority request " + method + " " + path)
        response = FakeResponse(status, body)
        response.headers = headers
        return response


def gate_client_class(server):
    class Client:
        def __init__(self, key, base_url, timeout):
            assert base_url == core.AUTHORITY_URL
            outer = self
            self.key = key

            class Session:
                trust_env = True
                headers = {}

                def request(self, method, url, **kwargs):
                    return server.handle(outer.key, method, url, **kwargs)

                def get(self, url, **kwargs):
                    kwargs.pop("timeout", None), kwargs.pop("allow_redirects", None)
                    return self.request("GET", url, **kwargs)

                def post(self, url, **kwargs):
                    kwargs.pop("timeout", None), kwargs.pop("allow_redirects", None)
                    return self.request("POST", url, **kwargs)

                def close(self):
                    pass

            self._session = Session()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def _handle_response(self, response):
            if response.status_code == 429:
                raise RateLimitError(None)
            if response.status_code in (401, 403):
                raise AuthenticationError("TEST DOUBLE rejected key")
            data = response.json()
            if response.status_code == 200 and isinstance(data, dict) and data.get("approved") is False:
                raise _PolicyViolation("TEST DOUBLE denial", action_type=data.get("action_type"),
                                       denial_reason="TEST DOUBLE denial", response=data,
                                       raw_response=response.content, status_code=200)
            return data

        def _request(self, method, path, **kwargs):
            return self._handle_response(self._session.request(method, core.AUTHORITY_URL + path, **kwargs))

        def attest(self, action_type, action_data):
            return self._request("POST", "/attest", json={"action_type": action_type, "action_data": action_data})

        def check_revocation(self, jti):
            return self._request("GET", "/attestation/revoked/" + jti)["revoked"]

    return Client


@pytest.fixture
def gate(replay_backend, tmp_path, monkeypatch):
    clock = WallClock()
    issuer = LabelledTestAuthority(clock)
    server = GateAuthorityServer(issuer, clock)
    client = gate_client_class(server)
    for module in (X, core, S, P, L):
        monkeypatch.setattr(module, "time", clock)
    monkeypatch.setattr(core, "SwiftAPI", client)
    monkeypatch.setattr(L, "SwiftAPI", client)
    monkeypatch.setattr(core, "verify_signature", issuer._signature)
    monkeypatch.setattr(core.check_grant, "__defaults__", (None, issuer._signature))
    monkeypatch.setattr(core.RemoteAuthority, "public_key", issuer.public_key)
    monkeypatch.setattr(core.RemoteAuthority, "evidence_kind", "LABELLED_TEST_DOUBLE_AUTHORITY_NOT_PRODUCTION")
    real_connect = socket.socket.connect

    def loopback_only(sock, address):
        assert address[0] == "127.0.0.1", "non-loopback connection attempted: " + repr(address)
        return real_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", loopback_only)
    state = types.SimpleNamespace(pacers=[])
    real_begin, real_end = core.RemoteAuthority.begin_slot, core.RemoteAuthority.end_slot

    def begin(self, arm):
        if self.pacer not in state.pacers:
            state.pacers.append(self.pacer)
        clock.hook = lambda: None
        real_begin(self, arm)                       
        server.slot = arm
        clock.hook = lambda: arm

    def end(self):
        server.slot, clock.hook = None, (lambda: None)
        real_end(self)

    monkeypatch.setattr(core.RemoteAuthority, "begin_slot", begin)
    monkeypatch.setattr(core.RemoteAuthority, "end_slot", end)
    key_file = tmp_path / "MADE-UP-not-a-credential.key"
    key_file.write_text(KEY)
    key_file.chmod(0o600)

    def run(schedule=None, **changes):
        config, wheel = runner_config(tmp_path, authority="LIVE_SWIFTAPI",
                                      schedule=list(schedule or X.SERVICE_ARMS),
                                      one_disposable_grant_revocation_approved=True, **changes)
        out = tmp_path / ("gate-" + uuid.uuid4().hex)
        error = None
        try:
            X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS, key_file=key_file,
                  approval_file=approval_for(config, tmp_path, "approval-" + uuid.uuid4().hex + ".json"))
        except Exception as exc:  
            error = exc
        return out, error

    return types.SimpleNamespace(run=run, server=server, clock=clock, issuer=issuer, state=state)


def fill_to(server, tier, now, total):
    pass
    current = [t for t in server.windows[tier] if t > now - 60]
    server.windows[tier] = current + [now] * max(0, total - len(current))


def per_slot_counts(server):
    counts = {}
    for entry in server.log:
        if entry["slot"]:
            slot = counts.setdefault(entry["slot"], {"authenticated": 0, "public_read": 0, "admin": 0,
                                                      "public_write": 0})
            slot[entry["tier"]] += 1
    return counts


EXPECTED_GATE = {"VALID": ("R", "VERIFIED_EXACT_REQUEST"), "SIGNED_DENIAL": ("V0", "AUTHORITY_DENIED"),
                 "MISSING_GRANT": ("V0", "MISSING_PERMISSION"), "INVALID_SIGNATURE": ("V0", "INVALID_AUTHORITY_SIGNATURE"),
                 "EXPIRED": ("V0", "GRANT_EXPIRED"), "REUSED": ("V0", "REPLAYED_REQUEST"),
                 "WRONG_SCOPE": ("V0", "GRANT_BINDING_MISMATCH"), "WRONG_REQUEST": ("V0", "GRANT_BINDING_MISMATCH"),
                 "UNKNOWN_KEY": ("operational", "AUTHENTICATION_REJECTED"),
                 "MALFORMED_KEY": ("operational", "AUTHENTICATION_REQUIRED"), "REVOKED": ("V0", "AUTHORITY_REVOKED")}

MEASURED_GATE = {"VALID": (4, 5), "SIGNED_DENIAL": (4, 3), "MISSING_GRANT": (2, 2), "INVALID_SIGNATURE": (4, 4),
                 "EXPIRED": (4, 4), "REUSED": (2, 2), "WRONG_SCOPE": (5, 5), "WRONG_REQUEST": (4, 4),
                 "UNKNOWN_KEY": (1, 0), "MALFORMED_KEY": (0, 0), "REVOKED": (5, 25)}


def test_gate_all_eleven_arms_stay_within_their_reserved_budget_with_no_pacing_error(gate):
    out, error = gate.run()
    assert error is None, repr(error)
    summary = json.loads((out / "summary.json").read_text())
    assert summary["sequence_completed"] is True and len(summary["rows"]) == 11
    assert [row["arm"] for row in summary["rows"]] == list(X.SERVICE_ARMS)
    for row in summary["rows"]:
        assert (row["class"], row["reason"]) == EXPECTED_GATE[row["arm"]], row["arm"]
        assert row["prediction_agrees"] is True and row["receipt_integrity"] == "PASS"
        assert row["authority_evidence_kind"] == "LABELLED_TEST_DOUBLE_AUTHORITY_NOT_PRODUCTION"
    counts = per_slot_counts(gate.server)
    assert set(counts) == set(X.SERVICE_ARMS) - {"MALFORMED_KEY"}
    for arm in X.SERVICE_ARMS:
        used = counts.get(arm, {"authenticated": 0, "public_read": 0, "admin": 0, "public_write": 0})
        budget = P.SLOT_BUDGETS[arm]
        for tier in TIER_LIMITS:
            assert used[tier] <= budget.get(tier, 0), (arm, tier, used, budget)
        assert (used["authenticated"], used["public_read"]) == MEASURED_GATE[arm], (arm, used)
        assert used["admin"] == 0 and used["public_write"] == 0
    
    assert gate.server.refused == 0
    assert not (out / "error.json").exists()
    everything = b"".join(path.read_bytes() for path in out.rglob("*.json") if ".private-runtime" not in path.parts)
    for code in (b"PACING_RESERVED_CALL_BUDGET_EXCEEDED", b"PACING_RESERVE_LOST_AT_BOUNDARY",
                 b"PACING_SLOT_ALREADY_ACTIVE", b"AUTHORITY_RATE_LIMITED"):
        assert code not in everything, code
    assert KEY.encode() not in everything
    
    inside = [(seconds, slot) for seconds, slot in gate.clock.sleeps if slot]
    assert [slot for _, slot in inside] == ["EXPIRED"] and 60.0 <= inside[0][0] <= 61.0, inside
    expired = json.loads((out / next(r["receipt"] for r in summary["rows"] if r["arm"] == "EXPIRED")).read_text())["payload"]
    age = expired["times"]["decision_at"] - core.timestamp(expired["grant"]["issued_at"])
    assert 60.0 < age < 65.0, age


def test_gate_revoked_arm_is_one_post_then_the_lookup_then_twenty_feed_pages(gate):
    out, error = gate.run()
    assert error is None, repr(error)
    slot = [entry for entry in gate.server.log if entry["slot"] == "REVOKED"]
    sequence = [(entry["method"], entry["path"].rsplit("/", 1)[0] if "revoked/" in entry["path"] else entry["path"])
                for entry in slot]
    posts = [index for index, step in enumerate(sequence) if step == ("POST", "/attestation/revoke")]
    assert len(posts) == 1, "exactly one revoke request"
    assert len([e for e in gate.server.log if e["path"] == "/attestation/revoke"]) == 1, "none outside the slot"
    feed = [index for index, step in enumerate(sequence) if step == ("GET", "/attestation/revocations")]
    assert len(feed) == 20, "worst case: the entry is on the twentieth page"
    lookups_after = [index for index, step in enumerate(sequence)
                     if step == ("GET", "/attestation/revoked") and index > posts[0]]
    assert lookups_after and min(feed) > min(lookups_after), "feed is read only after a lookup said revoked"
    assert all(index > posts[0] for index in feed)
    
    assert posts[0] == 4
    intent = json.loads((out / "revocation-intent.json").read_text())
    assert gate.server.revoked == {intent["jti"]}
    receipt = json.loads((next((out / "receipts").glob("*-REVOKED")) / "receipt.json").read_text())["payload"]
    decision = receipt["authority_decision"]
    assert decision["reason"] == "AUTHORITY_REVOKED" and decision["revocation_authority_signed"] is True
    assert receipt["grant"]["jti"] == intent["jti"]
    reconciliation = json.loads((out / "authority-ledger-reconciliation.json").read_text())
    assert reconciliation["revoked_jti"] == intent["jti"] and reconciliation["revoked_jti_listed"] is True


def test_gate_revoked_entry_beyond_twenty_pages_is_still_a_stop_within_budget(gate):
    gate.server.feed = [gate.issuer.revocation_entry(f"foreign-{index}", cursor=index + 1) for index in range(40)]
    out, error = gate.run(schedule=["VALID", "REVOKED"])
    assert error is None, repr(error)
    used = per_slot_counts(gate.server)["REVOKED"]
    assert used["public_read"] <= P.SLOT_BUDGETS["REVOKED"]["public_read"], used
    assert sum(1 for e in gate.server.log if e["slot"] == "REVOKED" and e["path"] == "/attestation/revocations") == 20
    receipt = json.loads((next((out / "receipts").glob("*-REVOKED")) / "receipt.json").read_text())["payload"]
    decision = receipt["authority_decision"]
    assert decision["reason"] == "AUTHORITY_REVOKED" and decision["revocation_authority_signed"] is False
    assert decision["revocation_evidence_limit"] == "JTI_NOT_IN_AVAILABLE_FEED"
    assert gate.server.refused == 0


def test_gate_insufficient_capacity_for_the_rest_of_the_revoked_arm_is_refused_before_the_post(gate):
    pass
    def foreign(server, tier, method, path, now):
        if server.slot == "REVOKED" and tier == "public_read" and not getattr(server, "fired", False):
            server.fired = True
            fill_to(server, "public_read", now, 108)     

    gate.server.foreign = foreign
    out, error = gate.run(schedule=["VALID", "REVOKED"])
    assert error is not None, "the run must stop"
    assert getattr(error, "code", None) == "PACING_REVOKE_CONTINUATION_RESERVE_INSUFFICIENT", repr(error)
    assert json.loads((out / "error.json").read_text())["code"] == "PACING_REVOKE_CONTINUATION_RESERVE_INSUFFICIENT"
    assert [entry for entry in gate.server.log if entry["path"] == "/attestation/revoke"] == [], "revoke was sent"
    assert gate.server.revoked == set() and gate.server.refused == 0
    assert not (out / "revocation-response.json").exists() and not (out / "revocation-response.bin").exists()
    error = json.loads((out / "error.json").read_text())
    assert error["arm"] == "REVOKED" and error["retry_permitted"] is False
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "FAIL" and [row["arm"] for row in summary["rows"]] == ["VALID"]
    assert [slot for _, slot in gate.clock.sleeps if slot] == [], "no wait inside the slot either"


def test_gate_low_capacity_known_before_the_revoked_slot_is_waited_out_before_its_grant_is_issued(gate):
    def foreign(server, tier, method, path, now):
        
        if server.slot == "VALID" and tier == "public_read" and \
                sum(1 for e in server.log if e["slot"] == "VALID" and e["tier"] == "public_read") == 4 \
                and not getattr(server, "fired", False):
            server.fired = True
            fill_to(server, "public_read", now, 110)     

    gate.server.foreign = foreign
    out, error = gate.run(schedule=["VALID", "REVOKED"])
    assert error is None, repr(error)
    waits = [seconds for seconds, slot in gate.clock.sleeps if slot is None]
    assert sum(waits) >= 60, "a full window must pass before the REVOKED grant is issued"
    assert len([e for e in gate.server.log if e["path"] == "/attestation/revoke"]) == 1
    assert gate.server.refused == 0 and [slot for _, slot in gate.clock.sleeps if slot] == []


def test_gate_a_429_on_any_arm_stops_the_run_with_no_retry_and_no_after_snapshot(gate):
    def foreign(server, tier, method, path, now):
        if server.slot == "INVALID_SIGNATURE" and tier == "authenticated" and not getattr(server, "fired", False):
            server.fired = True
            server.windows["authenticated"] = [now] * 300

    gate.server.foreign = foreign
    out, error = gate.run()
    assert error is not None
    assert gate.server.refused == 1, "one refused request and nothing sent after it"
    refused_at = next(index for index, entry in enumerate(gate.server.log) if not entry["allowed"])
    assert refused_at == len(gate.server.log) - 1, gate.server.log[refused_at + 1:]
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "FAIL" and summary["sequence_completed"] is False
    assert [row["arm"] for row in summary["rows"]][:3] == ["VALID", "SIGNED_DENIAL", "MISSING_GRANT"]
    assert not (out / "authority-ledger-after.json").exists()
    assert json.loads((out / "authority-ledger-error.json").read_text())["code"] == "AFTER_SNAPSHOT_NOT_ATTEMPTED_RATE_LIMIT"
    assert gate.server.revoked == set(), "REVOKED never ran"


def test_pacer_accounting_is_exact_under_concurrent_dispatch_within_one_reservation():
    import sys
    clock = VirtualClock()
    pacer = P.AuthorityPacer(clock=clock.now, sleep=clock.sleep)
    pacer.reserve({"public_read": 100, "authenticated": 100}, "CONCURRENT TEST")
    errors, done = [], []
    interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)

    def worker(tier, method, path):
        for _ in range(25):
            try:
                used, _ = pacer.before_dispatch(method, path)
                pacer.observe(used, {}, 200)
                done.append(tier)
            except Exception as exc:  
                errors.append(repr(exc))

    try:
        threads = [threading.Thread(target=worker, args=("public_read", "GET", "/attestation/revoked/x"))
                   for _ in range(4)]
        threads += [threading.Thread(target=worker, args=("authenticated", "POST", "/attest")) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
    finally:
        sys.setswitchinterval(interval)
    assert errors == []
    assert done.count("public_read") == 100 and done.count("authenticated") == 100
    assert pacer.remaining == {"public_read": 0, "authenticated": 0}
    assert len(pacer.calls["public_read"]) == 100 and len(pacer.calls["authenticated"]) == 100
    for method, path in (("GET", "/attestation/revoked/x"), ("POST", "/attest")):
        with pytest.raises(core.ServiceError) as caught:
            pacer.before_dispatch(method, path)
        assert caught.value.code == "PACING_RESERVED_CALL_BUDGET_EXCEEDED"
    pacer.end_slot()


def test_concurrent_stand_alone_requests_never_exceed_a_tier_window_and_fail_only_in_defined_ways():
    pass
    import sys
    clock = VirtualClock()
    lock = threading.Lock()
    dispatched, failures = [], []
    pacer = P.AuthorityPacer(clock=clock.now, sleep=clock.sleep)
    interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)

    def worker():
        for _ in range(40):
            try:
                tier, standalone = pacer.before_dispatch("GET", "/attestation/revoked/x")
                with lock:
                    dispatched.append(clock.now())
                pacer.observe(tier, {}, 200)
                if standalone:
                    pacer.end_slot()
            except core.ServiceError as exc:
                failures.append(exc.code)
            except Exception as exc:
                failures.append("UNDEFINED:" + repr(exc))

    try:
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
    finally:
        sys.setswitchinterval(interval)
    assert not [f for f in failures if f.startswith("UNDEFINED")], failures[:3]
    assert set(failures) <= {"PACING_SLOT_ALREADY_ACTIVE", "PACING_RESERVED_CALL_BUDGET_EXCEEDED"}, set(failures)
    times = sorted(dispatched)
    for index, start in enumerate(times):
        assert sum(1 for t in times[index:index + 121] if t < start + 60) <= 120 - P.RESERVE
    assert len(dispatched) + len(failures) == 320 and pacer.active is None


def test_revoke_outside_an_open_revoked_slot_is_refused_without_a_request(gate):
    authority = core.RemoteAuthority()
    for label in (None, "VALID"):
        if label:
            authority.pacer.begin_slot(label)
        with authority._client(KEY) as api:
            with pytest.raises(core.ServiceError) as caught:
                api._session.post(core.AUTHORITY_URL + "/attestation/revoke", json={"jti": "x", "reason": "TEST"})
        assert caught.value.code == "PACING_REVOKE_SLOT_REQUIRED", label
        if label:
            authority.pacer.end_slot()
    assert [entry for entry in gate.server.log if entry["path"] == "/attestation/revoke"] == []
    assert gate.server.revoked == set()


def test_revoke_continuation_budget_covers_what_the_real_path_sends_after_the_post(gate):
    out, error = gate.run()
    assert error is None, repr(error)
    slot = [entry for entry in gate.server.log if entry["slot"] == "REVOKED"]
    post = next(index for index, entry in enumerate(slot) if entry["path"] == "/attestation/revoke")
    tail = slot[post:]                                   
    used = {tier: sum(1 for entry in tail if entry["tier"] == tier) for tier in ("authenticated", "public_read")}
    assert used == {"authenticated": 3, "public_read": 23}, used
    for tier, count in used.items():
        assert count <= P.REVOKE_CONTINUATION_BUDGET[tier], (tier, count)
        assert P.REVOKE_CONTINUATION_BUDGET[tier] <= P.SLOT_BUDGETS["REVOKED"][tier]
    assert P.SLOT_BUDGETS["REVOKED"] == {"authenticated": 7, "public_read": 30}
    assert isinstance(P.AuthorityPacer().lock, type(threading.RLock()))


@pytest.mark.parametrize("reset", ["nan", "inf", "-inf", "1e400"])
def test_non_finite_reset_headers_are_unusable(reset):
    clock = VirtualClock()
    pacer = P.AuthorityPacer(clock=clock.now, sleep=clock.sleep)
    report = pacer.observe("public_read", {"X-RateLimit-Limit": "120", "X-RateLimit-Remaining": "3",
                                           "X-RateLimit-Reset": reset}, 200)
    assert report["usable"] is False and "public_read" not in pacer.headers


def approval_untouched(approval, registry):
    return (not approval.with_name(approval.name + ".consumed.json").exists()
            and (not registry.exists() or not list(registry.iterdir())))


@pytest.mark.parametrize("change", [{"max_new_tokens": 1}, {"max_new_tokens": 2}, {"max_new_tokens": 16},
                                    {"attention": "SDPA_MATH"}, {"attention": "SDPA_MATH_DETERMINISTIC"},
                                    {"device": "cuda"}])
def test_a_replay_profile_the_backend_cannot_accept_is_refused_before_the_approval_is_spent(
        tmp_path, monkeypatch, approval_registry_in_a_temporary_directory, change):
    monkeypatch.setattr(X, "read_key", lambda path: pytest.fail("key file read"))
    config, wheel = runner_config(tmp_path, authority="LIVE_SWIFTAPI", schedule=list(X.SERVICE_ARMS),
                                  one_disposable_grant_revocation_approved=True, **change)
    approval = approval_for(config, tmp_path)
    out = tmp_path / "refused"
    with pytest.raises(ValueError):
        X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS, key_file=tmp_path / "absent.key",
              approval_file=approval)
    assert not out.exists()
    assert approval_untouched(approval, approval_registry_in_a_temporary_directory)
    
    with pytest.raises(ValueError):
        B.PCCG2Backend(SOURCE, Path("/nonexistent-content"), HARNESS, B.REPLAY, config["device"],
                       attention=config.get("attention", "SDPA_DEFAULT"), max_new_tokens=config["max_new_tokens"])


def test_every_replay_configuration_the_runner_accepts_is_one_the_backend_can_construct(tmp_path):
    config, wheel = runner_config(tmp_path, authority="LIVE_SWIFTAPI", schedule=list(X.SERVICE_ARMS),
                                  one_disposable_grant_revocation_approved=True)
    X.validate_config(config, wheel)
    backend = B.PCCG2Backend(SOURCE, Path("/nonexistent-content"), HARNESS, config["mode"], config["device"],
                             full_model=False, attention=config.get("attention", "SDPA_DEFAULT"),
                             max_new_tokens=config["max_new_tokens"])
    
    assert config["max_new_tokens"] == 4 and backend.metadata["max_new_tokens"] == 1


@pytest.mark.parametrize("broken", ["source", "harness"])
def test_a_backend_that_cannot_be_constructed_locally_does_not_cost_the_approval(
        tmp_path, monkeypatch, approval_registry_in_a_temporary_directory, broken):
    pass
    monkeypatch.setattr(X, "read_key", lambda path: pytest.fail("key file read"))
    config, wheel = runner_config(tmp_path, authority="LIVE_SWIFTAPI", schedule=list(X.SERVICE_ARMS),
                                  one_disposable_grant_revocation_approved=True)
    approval = approval_for(config, tmp_path)
    empty = tmp_path / "empty-directory"
    empty.mkdir()
    source, harness = (empty, HARNESS) if broken == "source" else (SOURCE, empty)
    with pytest.raises(Exception):
        X.run(config, wheel, tmp_path / "broken-run", source, Path("/nonexistent-content"), harness,
              key_file=tmp_path / "absent.key", approval_file=approval)
    assert approval_untouched(approval, approval_registry_in_a_temporary_directory), \
        "Configuration validation precedes approval consumption"


def test_intended_denominators_are_written_before_the_backend_is_built(tmp_path, monkeypatch):
    pass
    config, wheel = runner_config(tmp_path, schedule=["VALID", "MISSING_GRANT", "WRONG_REQUEST"])
    empty = tmp_path / "empty-directory"
    empty.mkdir()
    out = tmp_path / "early-stop"
    with pytest.raises(Exception):
        X.run(config, wheel, out, empty, Path("/nonexistent-content"), HARNESS)
    summary = json.loads((out / "summary.json").read_text())
    assert summary["planned_count"] == 3 and summary["verified_receipt_count"] == 0 and summary["status"] == "FAIL"
    assert [slot["arm"] for slot in summary["slots"]] == ["VALID", "MISSING_GRANT", "WRONG_REQUEST"]
    assert all(slot["status"] == "NOT_EXECUTED_OR_NO_VERIFIED_RECEIPT" for slot in summary["slots"])
    error = json.loads((out / "error.json").read_text())
    assert error["stage"] == "INITIALIZE" and error["retry_permitted"] is False
    bank, _ = runner_config(tmp_path, population="BANK_188", schedule=["VALID", "MISSING_GRANT"])
    out = tmp_path / "early-stop-bank"
    with pytest.raises(Exception):
        X.run(bank, wheel, out, empty, Path("/nonexistent-content"), HARNESS)
    assert json.loads((out / "summary.json").read_text())["planned_count"] == 376


@pytest.mark.parametrize("problem", ["absent", "directory", "empty", "world-readable"])
def test_a_key_file_that_is_visibly_unusable_does_not_cost_the_approval(
        tmp_path, monkeypatch, approval_registry_in_a_temporary_directory, problem):
    pass
    monkeypatch.setattr(X, "read_key", lambda path: pytest.fail("key content read"))
    config, wheel = runner_config(tmp_path, authority="LIVE_SWIFTAPI", schedule=list(X.SERVICE_ARMS),
                                  one_disposable_grant_revocation_approved=True)
    approval = approval_for(config, tmp_path)
    key_file = tmp_path / "key-path"
    if problem == "directory":
        key_file.mkdir()
    elif problem == "empty":
        key_file.write_bytes(b"")
        key_file.chmod(0o600)
    elif problem == "world-readable":
        key_file.write_text("PLACEHOLDER not a credential")
        key_file.chmod(0o644)
    with pytest.raises(Exception):
        X.run(config, wheel, tmp_path / "key-run", SOURCE, Path("/nonexistent-content"), HARNESS,
              key_file=key_file, approval_file=approval)
    assert approval_untouched(approval, approval_registry_in_a_temporary_directory), problem


def test_an_already_spent_approval_is_refused_before_any_output_is_created(
        tmp_path, monkeypatch, approval_registry_in_a_temporary_directory):
    monkeypatch.setattr(X, "read_key", lambda path: pytest.fail("key content read"))
    config, wheel = runner_config(tmp_path, authority="LIVE_SWIFTAPI", schedule=list(X.SERVICE_ARMS),
                                  one_disposable_grant_revocation_approved=True)
    approval = approval_for(config, tmp_path)
    X.consume_approval(config, approval)
    out = tmp_path / "second-use"
    with pytest.raises(Exception):
        X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS, key_file=tmp_path / "k",
              approval_file=approval)
    assert not out.exists()


def test_order_of_operations_for_a_live_run_is_checks_then_backend_then_approval_then_key(
        tmp_path, monkeypatch, approval_registry_in_a_temporary_directory):
    events = []
    real_backend, real_consume = B.PCCG2Backend, X.consume_approval

    class Recording(real_backend):
        def __init__(self, *args, **kwargs):
            events.append("backend")
            super().__init__(*args, **kwargs)

        def preflight(self):
            events.append("preflight")
            return super().preflight()

    def consume(config, approval_file):
        events.append("approval")
        return real_consume(config, approval_file)

    class Stop(Exception):
        pass

    def read_key(path):
        events.append("key")
        raise Stop()

    monkeypatch.setattr(B, "PCCG2Backend", Recording)
    monkeypatch.setattr(X, "consume_approval", consume)
    monkeypatch.setattr(X, "read_key", read_key)
    config, wheel = runner_config(tmp_path, authority="LIVE_SWIFTAPI", schedule=list(X.SERVICE_ARMS),
                                  one_disposable_grant_revocation_approved=True)
    key_file = tmp_path / "MADE-UP.key"
    key_file.write_text(KEY)
    key_file.chmod(0o600)
    with pytest.raises(Stop):
        X.run(config, wheel, tmp_path / "ordered", SOURCE, Path("/nonexistent-content"), HARNESS,
              key_file=key_file, approval_file=approval_for(config, tmp_path))
    assert events[:4] == ["backend", "preflight", "approval", "key"], events


SEALED_SHAPES = {
    "live replay": {"authority": "LIVE_SWIFTAPI", "schedule": list(X.SERVICE_ARMS),
                    "one_disposable_grant_revocation_approved": True},
    "fresh local double": {"mode": FRESH, "device": "cuda", "enable_full_model": True,
                           "maximum_warm_forward_seconds": 10, "schedule": ["VALID", "SIGNED_DENIAL"]},
    "fresh live": {"mode": FRESH, "device": "cuda", "enable_full_model": True, "maximum_warm_forward_seconds": 10,
                   "authority": "LIVE_SWIFTAPI", "schedule": ["VALID", "MISSING_GRANT"]},
}
PURPOSES = ("DEVELOPMENT_SMOKE", "DEVELOPMENT_QUALIFICATION", "PREREGISTERED_STUDY")
GOOD_HASH = sha(TEST_PREDICTIONS)
GOOD_TIME = "2026-01-01T00:00:00+00:00"
BAD_SEALS = [
    ("no fields", {}),
    ("no hash", {"predictions_sealed_at": GOOD_TIME}),
    ("no time", {"author_predictions_sha256": GOOD_HASH}),
    ("null hash", {"author_predictions_sha256": None, "predictions_sealed_at": GOOD_TIME}),
    ("uppercase hash", {"author_predictions_sha256": GOOD_HASH.upper(), "predictions_sealed_at": GOOD_TIME}),
    ("short hash", {"author_predictions_sha256": GOOD_HASH[:63], "predictions_sealed_at": GOOD_TIME}),
    ("long hash", {"author_predictions_sha256": GOOD_HASH + "0", "predictions_sealed_at": GOOD_TIME}),
    ("non-hex hash", {"author_predictions_sha256": "g" * 64, "predictions_sealed_at": GOOD_TIME}),
    ("placeholder zeros", {"author_predictions_sha256": "0" * 64, "predictions_sealed_at": GOOD_TIME}),
    ("placeholder repeated", {"author_predictions_sha256": "ab" * 32, "predictions_sealed_at": GOOD_TIME}),
    ("hash of nothing", {"author_predictions_sha256": sha(b""), "predictions_sealed_at": GOOD_TIME}),
    ("numeric hash", {"author_predictions_sha256": 7, "predictions_sealed_at": GOOD_TIME}),
    ("naive time", {"author_predictions_sha256": GOOD_HASH, "predictions_sealed_at": "2026-01-01T00:00:00"}),
    ("date only", {"author_predictions_sha256": GOOD_HASH, "predictions_sealed_at": "2026-01-01"}),
    ("words", {"author_predictions_sha256": GOOD_HASH, "predictions_sealed_at": "sealed last night"}),
    ("empty time", {"author_predictions_sha256": GOOD_HASH, "predictions_sealed_at": ""}),
    ("null time", {"author_predictions_sha256": GOOD_HASH, "predictions_sealed_at": None}),
    ("epoch number", {"author_predictions_sha256": GOOD_HASH, "predictions_sealed_at": 1_800_000_000}),
    ("true", {"author_predictions_sha256": GOOD_HASH, "predictions_sealed_at": True}),
    ("future time", {"author_predictions_sha256": GOOD_HASH, "predictions_sealed_at": "2999-01-01T00:00:00+00:00"}),
]


def unsealed(tmp_path, shape, purpose, seal):
    changes = dict(SEALED_SHAPES[shape], purpose=purpose, seal=False)
    if purpose == "PREREGISTERED_STUDY":
        changes.update(author_freeze_approved=True, public_registration_timestamp="TEST DOUBLE",
                       registration_sha256="1" * 64,
                       predictions={arm: {"class": "V0"} for arm in changes["schedule"]})
    config, wheel = runner_config(tmp_path, **changes)
    config.pop("author_predictions_sha256", None)
    config.pop("predictions_sealed_at", None)
    config.update(seal)
    return config, wheel


@pytest.mark.parametrize("shape", sorted(SEALED_SHAPES))
@pytest.mark.parametrize("purpose", PURPOSES)
@pytest.mark.parametrize("label,seal", BAD_SEALS, ids=[label for label, _ in BAD_SEALS])
def test_without_a_well_formed_seal_no_live_or_fresh_configuration_validates(tmp_path, shape, purpose, label, seal):
    config, wheel = unsealed(tmp_path, shape, purpose, seal)
    with pytest.raises(ValueError) as caught:
        X.validate_config(config, wheel)
    message = str(caught.value)
    assert "predictions" in message.lower(), message
    
    assert "Fresh path is guarded" not in message and "Smoke is precisely" not in message
    with pytest.raises(ValueError):
        X.require_sealed_predictions(config, tmp_path / "TEST-DOUBLE-predictions.md")


@pytest.mark.parametrize("shape", sorted(SEALED_SHAPES))
@pytest.mark.parametrize("purpose", PURPOSES)
def test_an_unsealed_run_is_refused_before_the_wheel_approval_key_backend_or_output(
        tmp_path, monkeypatch, approval_registry_in_a_temporary_directory, shape, purpose):
    touched = []
    monkeypatch.setattr(X, "read_key", lambda path: touched.append("key") or pytest.fail("key read"))
    monkeypatch.setattr(X, "consume_approval", lambda *a, **k: touched.append("approval") or pytest.fail("approval"))
    monkeypatch.setattr(X, "validate_approval", lambda *a, **k: touched.append("approval-read") or pytest.fail("approval read"))
    monkeypatch.setattr(X, "verify_installed_sdk", lambda *a, **k: touched.append("wheel") or pytest.fail("wheel access occurs"))
    monkeypatch.setattr(B, "PCCG2Backend", lambda *a, **k: touched.append("backend") or pytest.fail("backend built"))
    monkeypatch.setattr(B, "validate_backend_profile", lambda *a, **k: touched.append("profile") or pytest.fail("profile"))
    config, _ = unsealed(tmp_path, shape, purpose, {})
    approval = approval_for(config, tmp_path)
    key_file = tmp_path / "MADE-UP.key"
    key_file.write_text(KEY)
    key_file.chmod(0o600)
    out = tmp_path / "unsealed-run"
    smoke_key = None if purpose == "DEVELOPMENT_SMOKE" else key_file
    with pytest.raises(ValueError, match="(?i)sealed author predictions"):
        X.run(config, tmp_path / "no-such-wheel.whl", out, tmp_path / "no-source", tmp_path / "no-content",
              tmp_path / "no-harness", key_file=smoke_key, approval_file=approval)
    assert touched == [] and not out.exists()
    assert approval_untouched(approval, approval_registry_in_a_temporary_directory)


def test_a_well_formed_seal_lets_validation_continue_and_is_reported_as_declared_not_proven(tmp_path):
    config, wheel = runner_config(tmp_path, **SEALED_SHAPES["live replay"])
    assert config["author_predictions_sha256"] == GOOD_HASH
    X.validate_config(config, wheel)
    sealed = tmp_path / "TEST-DOUBLE-predictions.md"
    seal = X.require_sealed_predictions(config, sealed)
    assert seal["author_predictions_sha256"] == GOOD_HASH and seal["predictions_sealed_at"] == GOOD_TIME
    assert seal["predictions_file_bytes_verified"] is True and seal["run"] == "PRIMARY"
    assert seal["predictions"] == config["predictions"]
    assert "does not establish when the predictions were written" in seal["basis"]
    for stamp in ("2026-01-01T00:00:00Z", "2026-01-01T05:30:00+05:30", "2026-01-01T00:00:00.123456-08:00"):
        X.require_sealed_predictions(dict(config, predictions_sealed_at=stamp), sealed)


def test_recorded_replay_with_the_local_double_needs_no_seal_for_development(tmp_path):
    for purpose in ("DEVELOPMENT_QUALIFICATION",):
        config, wheel = runner_config(tmp_path, purpose=purpose)
        assert "author_predictions_sha256" not in config and "predictions_sealed_at" not in config
        assert X.require_sealed_predictions(config) is None
        X.validate_config(config, wheel)
    summary = json.loads((run_replay(tmp_path, schedule=["VALID", "MISSING_GRANT"]) / "summary.json").read_text())
    assert summary["status"] == "PASS"
    assert not (tmp_path / "run" / "predictions-seal.json").exists()


def test_a_supplied_predictions_file_must_be_the_sealed_bytes(tmp_path):
    config, wheel = runner_config(tmp_path, **SEALED_SHAPES["live replay"])
    sealed = tmp_path / "TEST-DOUBLE-predictions.md"
    assert X.require_sealed_predictions(config, sealed)["predictions_file_bytes_verified"] is True
    X.validate_config(config, wheel, sealed)
    edited = tmp_path / "edited.md"
    edited.write_bytes(TEST_PREDICTIONS + b"one more line\n")
    empty = tmp_path / "empty.md"
    empty.write_bytes(b"")
    for wrong in (edited, empty):
        with pytest.raises(ValueError, match="does not match"):
            X.validate_config(config, wheel, wrong)
    with pytest.raises(OSError):
        X.validate_config(config, wheel, tmp_path / "absent.md")
    
    hollow = dict(config, author_predictions_sha256=sha(b""))
    with pytest.raises(ValueError):
        X.require_sealed_predictions(hollow, empty)
    
    local, _ = runner_config(tmp_path)
    with pytest.raises(ValueError):
        X.require_sealed_predictions(local, sealed)


def test_a_mismatched_predictions_file_stops_a_live_shaped_run_before_approval_and_key(
        tmp_path, monkeypatch, approval_registry_in_a_temporary_directory):
    monkeypatch.setattr(X, "read_key", lambda path: pytest.fail("key read"))
    config, wheel = runner_config(tmp_path, **SEALED_SHAPES["live replay"])
    approval = approval_for(config, tmp_path)
    edited = tmp_path / "edited.md"
    edited.write_bytes(b"different bytes\n")
    out = tmp_path / "mismatch"
    with pytest.raises(ValueError, match="does not match"):
        X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS, key_file=tmp_path / "k",
              approval_file=approval, predictions_file=edited)
    assert not out.exists() and approval_untouched(approval, approval_registry_in_a_temporary_directory)


def test_a_sealed_run_records_what_was_declared_and_whether_the_file_was_checked(gate, tmp_path):
    pass
    out, error = gate.run(schedule=["VALID", "MISSING_GRANT"])
    assert error is None, repr(error)
    seal = json.loads((out / "predictions-seal.json").read_text())
    assert seal["author_predictions_sha256"] == GOOD_HASH and seal["predictions_file_bytes_verified"] is True
    assert json.loads((out / "run-config.json").read_text())["predictions_sealed_at"] == GOOD_TIME
    
    assert (out / "sealed-predictions.md").read_bytes() == TEST_PREDICTIONS
    parsed = json.loads((out / "sealed-predictions-parsed.json").read_text())
    assert parsed["author_predictions_sha256"] == GOOD_HASH and parsed["run"] == "PRIMARY"
    assert set(parsed["PRIMARY"]) == set(X.SERVICE_ARMS) and set(parsed["SECONDARY"]) == {"VALID", "MISSING_GRANT"}
    assert parsed["selected_for_this_run"] == {"VALID": {"class_counts": {"R": 1}},
                                               "MISSING_GRANT": {"class_counts": {"V0": 1}}}


def test_no_configuration_file_in_the_workspace_claims_a_seal_without_the_sealed_file_beside_it():
    pass
    roots = [WORKSPACE]
    skipped = {".venv", ".qualification-final-venv", "dist", "verification", "node_modules", ".git", "sdk-1.4.0",
               "historical", ".runtime", ".package-check", ".pytest_cache", "__pycache__", "tests"}
    claims = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*.json"):
            relative = path.relative_to(root).parts
            if len(relative) > 3 or skipped & set(relative) or path.stat().st_size > 2_000_000:
                continue
            try:
                data = json.loads(path.read_bytes())
            except ValueError:
                continue
            if isinstance(data, dict) and data.get("predictions_sealed_at") not in (None, "UNSET"):
                claims.append((path, data))
    for path, data in claims:
        digest = data.get("author_predictions_sha256")
        beside = [f for f in path.parent.iterdir() if f.is_file() and f.stat().st_size < 5_000_000
                  and sha(f.read_bytes()) == digest]
        assert beside, f"{path} declares a seal and no file beside it has that hash"


def test_no_generator_tool_writes_a_seal_from_its_own_clock_or_a_literal():
    import ast
    for path in sorted((WORKSPACE / "tools").glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and key.value in ("predictions_sealed_at",
                                                                       "author_predictions_sha256"):
                        literal = isinstance(value, ast.Constant) and value.value not in (None, "UNSET")
                        from_clock = any(isinstance(inner, ast.Call) and getattr(inner.func, "attr",
                                         getattr(inner.func, "id", "")) in ("now", "time", "utcnow", "uuid4")
                                         for inner in ast.walk(value))
                        assert not literal and not from_clock, f"{path.name} writes {key.value} itself"


CLASS_WORDS = ("V0", "V1", "V2", "VU", "NV", "R", "RF", "SB", "TC", "operational")


def test_every_class_is_accepted_as_a_prediction(tmp_path):
    for cls in CLASS_WORDS:
        config, wheel = study_config(tmp_path, {"VALID": {"class": cls}, "MISSING_GRANT": {"class": "V0"}})
        X.validate_config(config, wheel)


def parse(raw):
    return PR.parse_predictions(raw, X.MODEL)


def test_parser_arm_lists_are_the_runner_schedule_and_the_class_list_is_the_offered_one():
    assert PR.PRIMARY_ARMS == X.SERVICE_ARMS and PR.SECONDARY_ARMS == ("VALID", "MISSING_GRANT")
    assert PR.CLASSES == CLASS_WORDS
    import inspect
    source = inspect.getsource(PR)
    for forbidden in ("open(", "Path(", "import os", "import time", "requests", "socket", "torch"):
        assert forbidden not in source, forbidden


def test_blank_template_parses_to_nothing_predicted_for_all_thirteen_sections():
    parsed = parse(template_text())
    assert parsed == {"PRIMARY": {arm: {} for arm in X.SERVICE_ARMS}, "SECONDARY": {"VALID": {}, "MISSING_GRANT": {}}}
    assert list(parsed["PRIMARY"]) == list(X.SERVICE_ARMS)



def test_filled_template_parses_to_the_canonical_schema():
    raw = template_text(
        primary={"VALID": {"lines": [(1, "R")], "first_token": "19", "output_bytes": "1", "generation_complete": "true"},
                 "MISSING_GRANT": {"lines": [(None, "V0")], "output_bytes": "0", "generation_complete": "true",
                                   "first_token": "151645"},
                 "UNKNOWN_KEY": {"lines": [(None, "operational")]},
                 "EXPIRED": {"generation_complete": "false"}},
        secondary={"VALID": {"lines": [(180, "R"), (5, "NV"), (3, "V1")]},
                   "MISSING_GRANT": {"lines": [(188, "V0")], "first_token": "151645", "output_bytes": "0"}})
    parsed = parse(raw)
    assert parsed["PRIMARY"]["VALID"] == {"class_counts": {"R": 1}, "first_token": 19, "output_bytes": 1,
                                         "generation_complete": True}
    assert parsed["PRIMARY"]["MISSING_GRANT"] == {"class_counts": {"V0": 1}, "first_token": 151645, "output_bytes": 0,
                                                 "generation_complete": True}
    assert parsed["PRIMARY"]["UNKNOWN_KEY"] == {"class_counts": {"operational": 1}}
    assert parsed["PRIMARY"]["EXPIRED"] == {"generation_complete": False}        
    assert parsed["PRIMARY"]["REVOKED"] == {}
    assert parsed["SECONDARY"]["VALID"] == {"class_counts": {"R": 180, "NV": 5, "V1": 3}}
    assert parsed["SECONDARY"]["MISSING_GRANT"] == {"class_counts": {"V0": 188}, "first_token": 151645, "output_bytes": 0}
    assert sum(parsed["SECONDARY"]["VALID"]["class_counts"].values()) == 188
    
    assert parse(template_text(secondary={"VALID": {"lines": [(None, "R")]}}))["SECONDARY"]["VALID"] == \
        parse(template_text(secondary={"VALID": {"lines": [(188, "R")]}}))["SECONDARY"]["VALID"] == {"class_counts": {"R": 188}}
    json.dumps(parsed)


def edited(raw, old, new, count=1):
    text = raw.decode()
    assert text.count(old) >= 1, old
    return text.replace(old, new, count).encode()


BLANK_FILE = template_text()
VALID_LINE = f"`[VALID] [{X.MODEL}] [__/1] [____]`"
BANK_LINE = f"`[VALID] [{X.MODEL}] [__/188] [____]`"

MALFORMED = {
    "empty file": b"",
    "not utf-8": b"\xff\xfe" + BLANK_FILE,
    "carriage returns": BLANK_FILE.replace(b"\n", b"\r\n"),
    "missing run 2": BLANK_FILE.split(b"## Run 2")[0],
    "run headings swapped": edited(edited(BLANK_FILE, "## Run 1: PRIMARY WITNESS_ONE", "## Run X"),
                                   "## Run 2: SECONDARY BANK_188", "## Run 1: PRIMARY WITNESS_ONE"),
    "third run": BLANK_FILE + b"\n## Run 3: EXTRA\n",
    "arm section removed": edited(BLANK_FILE, "### EXPIRED\n", ""),
    "arm sections reordered": edited(edited(BLANK_FILE, "### EXPIRED", "### TEMP"), "### REUSED", "### EXPIRED"),
    "unknown arm section": edited(BLANK_FILE, "### REVOKED", "### REVOKED\n\n### BONUS_ARM"),
    "unknown class": edited(BLANK_FILE, VALID_LINE, f"`[VALID] [{X.MODEL}] [__/1] [VOID]`"),
    "lowercase class": edited(BLANK_FILE, VALID_LINE, f"`[VALID] [{X.MODEL}] [__/1] [r]`"),
    "count without class": edited(BLANK_FILE, VALID_LINE, f"`[VALID] [{X.MODEL}] [1/1] [____]`"),
    "zero count": edited(BLANK_FILE, VALID_LINE, f"`[VALID] [{X.MODEL}] [0/1] [R]`"),
    "count above denominator": edited(BLANK_FILE, VALID_LINE, f"`[VALID] [{X.MODEL}] [2/1] [R]`"),
    "changed denominator": edited(BLANK_FILE, VALID_LINE, f"`[VALID] [{X.MODEL}] [1/2] [R]`"),
    "other model identifier": edited(BLANK_FILE, VALID_LINE, "`[VALID] [some/other-model] [__/1] [R]`"),
    "other arm in the line": edited(BLANK_FILE, VALID_LINE, f"`[REVOKED] [{X.MODEL}] [__/1] [R]`"),
    "fifth bracket": edited(BLANK_FILE, VALID_LINE, f"`[VALID] [{X.MODEL}] [__/1] [R] [extra]`"),
    "missing backticks": edited(BLANK_FILE, VALID_LINE, f"`[VALID] [{X.MODEL}] [__/1] [R]"),
    "result line deleted": edited(BLANK_FILE, VALID_LINE + "\n", ""),
    "partial bank single line": edited(BLANK_FILE, BANK_LINE, f"`[VALID] [{X.MODEL}] [100/188] [R]`"),
    "bank counts sum low": edited(BLANK_FILE, BANK_LINE, f"`[VALID] [{X.MODEL}] [100/188] [R]`\n\n`[VALID] [{X.MODEL}] [87/188] [NV]`"),
    "bank counts sum high": edited(BLANK_FILE, BANK_LINE, f"`[VALID] [{X.MODEL}] [100/188] [R]`\n\n`[VALID] [{X.MODEL}] [89/188] [NV]`"),
    "bank class twice": edited(BLANK_FILE, BANK_LINE, f"`[VALID] [{X.MODEL}] [100/188] [R]`\n\n`[VALID] [{X.MODEL}] [88/188] [R]`"),
    "bank mixed with blank count": edited(BLANK_FILE, BANK_LINE, f"`[VALID] [{X.MODEL}] [__/188] [R]`\n\n`[VALID] [{X.MODEL}] [88/188] [NV]`"),
    "bank mixed with blank class": edited(BLANK_FILE, BANK_LINE, f"`[VALID] [{X.MODEL}] [100/188] [R]`\n\n`[VALID] [{X.MODEL}] [88/188] [____]`"),
    "two primary lines": edited(BLANK_FILE, VALID_LINE, VALID_LINE + "\n\n" + VALID_LINE),
    "negative token": edited(BLANK_FILE, "first_token: ____", "first_token: -1"),
    "token with leading zero": edited(BLANK_FILE, "first_token: ____", "first_token: 019"),
    "token as text": edited(BLANK_FILE, "first_token: ____", "first_token: four"),
    "decimal bytes": edited(BLANK_FILE, "output_bytes: ____", "output_bytes: 1.0"),
    "capitalised boolean": edited(BLANK_FILE, "generation_complete: ____", "generation_complete: True"),
    "yes for boolean": edited(BLANK_FILE, "generation_complete: ____", "generation_complete: yes"),
    "empty field value": edited(BLANK_FILE, "first_token: ____", "first_token: "),
    "field without space": edited(BLANK_FILE, "first_token: ____", "first_token:19"),
    "field repeated": edited(BLANK_FILE, "first_token: ____", "first_token: ____\n\nfirst_token: 19"),
    "three underscores": edited(BLANK_FILE, "output_bytes: ____", "output_bytes: ___"),
    "misspelled field": edited(BLANK_FILE, "first_token: ____", "first token: 19"),
    "free text in a section": edited(BLANK_FILE, "My prediction:", "My prediction:\n\nI think it will answer."),
    "indented line": edited(BLANK_FILE, "My prediction:", " My prediction:"),
    "command for another arm": edited(BLANK_FILE, "--out PRIMARY_OUTPUT --arm VALID`", "--out PRIMARY_OUTPUT --arm REVOKED`"),
    "command deleted": edited(BLANK_FILE, "`python -m swiftapi_native_service.experiment question --config RUN_CONFIG_PRIMARY.json --out PRIMARY_OUTPUT --arm VALID`\n", ""),
    "question line deleted": edited(BLANK_FILE, "Arm VALID: TEST DOUBLE description of what is sent. What will the result line be?\n", ""),
    "secondary valid first token": template_text(secondary={"VALID": {"lines": [(None, "R")], "first_token": "19"}}),
}


@pytest.mark.parametrize("label", sorted(MALFORMED))
def test_malformed_prediction_grammar_is_rejected(label):
    with pytest.raises(PR.PredictionFormatError) as caught:
        parse(MALFORMED[label])
    assert "151645" not in str(caught.value) and X.MODEL not in str(caught.value)


def test_secondary_valid_first_token_is_refused_but_a_blank_line_there_is_tolerated():
    with pytest.raises(PR.PredictionFormatError, match="cannot be predicted"):
        parse(template_text(secondary={"VALID": {"first_token": "19"}}))
    assert parse(template_text(secondary={"VALID": {"first_token": "____"}}))["SECONDARY"]["VALID"] == {}
    assert parse(template_text(secondary={"MISSING_GRANT": {"first_token": "7"}}))["SECONDARY"]["MISSING_GRANT"] == {"first_token": 7}


def test_selection_gives_separate_maps_and_the_schedule_subset_for_a_smoke():
    parsed = parse(TEST_PREDICTIONS)
    run, smoke = PR.select_for_run(parsed, "WITNESS_ONE", ["VALID", "SIGNED_DENIAL"])
    assert run == "PRIMARY" and smoke == {"VALID": {"class_counts": {"R": 1}}, "SIGNED_DENIAL": {"class_counts": {"V0": 1}}}
    run, bank = PR.select_for_run(parsed, "BANK_188", ["VALID", "MISSING_GRANT"])
    assert run == "SECONDARY" and bank == {"VALID": {"class_counts": {"R": 188}}, "MISSING_GRANT": {"class_counts": {"V0": 188}}}
    run, full = PR.select_for_run(parsed, "WITNESS_ONE", list(X.SERVICE_ARMS))
    assert list(full) == list(X.SERVICE_ARMS)
    with pytest.raises(PR.PredictionFormatError):
        PR.select_for_run(parsed, "BANK_188", ["VALID", "REVOKED"])


def live_sealed(tmp_path, raw, **changes):
    pass
    path = tmp_path / ("TEST-DOUBLE-" + sha(raw)[:8] + ".md")
    path.write_bytes(raw)
    base = dict(SEALED_SHAPES["live replay"], seal=False)
    base.update(changes)
    config, wheel = runner_config(tmp_path, **base)
    config.update(author_predictions_sha256=sha(raw), predictions_sealed_at=GOOD_TIME)
    config["predictions"] = PR.select_for_run(parse(raw), config.get("population", "WITNESS_ONE"), config["schedule"])[1]
    return config, wheel, path


def test_live_or_fresh_runs_need_the_actual_sealed_file(tmp_path, monkeypatch, test_predictions_file_supplied_when_a_test_configuration_carries_the_test_seal):
    real = test_predictions_file_supplied_when_a_test_configuration_carries_the_test_seal
    monkeypatch.setattr(X, "validate_config", real.validate)     
    monkeypatch.setattr(X, "run", real.run)
    for shape in sorted(SEALED_SHAPES):
        config, wheel = runner_config(tmp_path, **SEALED_SHAPES[shape])
        with pytest.raises(ValueError, match="sealed predictions file itself must be supplied"):
            real.validate(config, wheel)
        with pytest.raises(ValueError, match="must be supplied"):
            X.require_sealed_predictions(config)
        with pytest.raises(ValueError, match="must be supplied"):
            real.run(config, wheel, tmp_path / ("no-file-" + shape.replace(" ", "-")), SOURCE, Path("/x"), HARNESS,
                     key_file=None if shape == "fresh local double" else tmp_path / "k")
        assert not (tmp_path / ("no-file-" + shape.replace(" ", "-"))).exists()


def test_configuration_predictions_must_equal_the_parsed_sealed_file_exactly(tmp_path):
    raw = template_text(primary={arm: {"lines": [(None, implied_class(arm))]} for arm in PR.PRIMARY_ARMS} |
                        {"VALID": {"lines": [(None, "R")], "first_token": "19"}})
    config, wheel, path = live_sealed(tmp_path, raw)
    X.validate_config(config, wheel, path)
    good = config["predictions"]
    for label, changed in (
            ("another class", {**good, "MISSING_GRANT": {"class_counts": {"R": 1}}}),
            ("dropped optional field", {**good, "VALID": {"class_counts": {"R": 1}}}),
            ("added optional field", {**good, "REVOKED": {**good["REVOKED"], "output_bytes": 0}}),
            ("arm removed", {arm: value for arm, value in good.items() if arm != "REVOKED"}),
            ("arm added", {**good, "BONUS": {}}),
            ("legacy class schema", {arm: {"class": implied_class(arm)} for arm in good}),
            ("string where integer", {**good, "VALID": {"class_counts": {"R": 1}, "first_token": "19"}}),
            ("boolean where count", {**good, "VALID": {"class_counts": {"R": True}, "first_token": 19}}),
            ("float where count", {**good, "VALID": {"class_counts": {"R": 1.0}, "first_token": 19}}),
            ("float where token", {**good, "VALID": {"class_counts": {"R": 1}, "first_token": 19.0}}),
            ("list where map", [good]),
            ("empty", {}), ("null", None), ("missing", "DELETE")):
        other = dict(config)
        if changed == "DELETE":
            other.pop("predictions")
        else:
            other["predictions"] = changed
        with pytest.raises(ValueError, match="not exactly the predictions parsed from the sealed file"):
            X.validate_config(other, wheel, path)
    
    twin = tmp_path / "twin.md"
    twin.write_bytes(raw + b"\n")
    with pytest.raises(ValueError, match="does not match author_predictions_sha256"):
        X.validate_config(config, wheel, twin)


def test_a_blank_sealed_file_is_accepted_only_as_nothing_predicted(tmp_path):
    config, wheel, path = live_sealed(tmp_path, template_text())
    assert config["predictions"] == {arm: {} for arm in X.SERVICE_ARMS}
    X.validate_config(config, wheel, path)
    for invented in ({arm: {"class_counts": {implied_class(arm): 1}} for arm in X.SERVICE_ARMS},
                     {**config["predictions"], "VALID": {"class_counts": {"R": 1}}}):
        with pytest.raises(ValueError, match="not exactly"):
            X.validate_config(dict(config, predictions=invented), wheel, path)


def test_a_malformed_sealed_file_stops_a_live_shaped_run_before_approval_and_key(
        tmp_path, monkeypatch, approval_registry_in_a_temporary_directory):
    monkeypatch.setattr(X, "read_key", lambda path: pytest.fail("key read"))
    raw = MALFORMED["bank counts sum low"]
    path = tmp_path / "malformed.md"
    path.write_bytes(raw)
    config, wheel = runner_config(tmp_path, seal=False, **SEALED_SHAPES["live replay"])
    config.update(author_predictions_sha256=sha(raw), predictions_sealed_at=GOOD_TIME, predictions={})
    approval = approval_for(config, tmp_path)
    out = tmp_path / "malformed-run"
    with pytest.raises(PR.PredictionFormatError):
        X.run(config, wheel, out, SOURCE, Path("/x"), HARNESS, key_file=tmp_path / "k", approval_file=approval,
              predictions_file=path)
    assert not out.exists() and approval_untouched(approval, approval_registry_in_a_temporary_directory)


def test_a_sealed_run_must_schedule_each_slot_once(tmp_path):
    config, wheel, path = live_sealed(tmp_path, TEST_PREDICTIONS, schedule=["VALID", "MISSING_GRANT"])
    with pytest.raises(ValueError, match="repetitions must be 1"):
        X.require_sealed_predictions(dict(config, repetitions=2), path)


def test_draft_placeholders_are_permitted_in_a_file_and_never_runnable(tmp_path):
    config, wheel = runner_config(tmp_path, seal=False, **SEALED_SHAPES["live replay"])
    config.update(author_predictions_sha256="UNSET", predictions_sealed_at="UNSET", predictions="UNSET")
    json.dumps(config)
    with pytest.raises(ValueError):
        X.validate_config(config, wheel)
    with pytest.raises(ValueError):
        X.require_sealed_predictions(config, tmp_path / "TEST-DOUBLE-predictions.md")


def observation(cls, token=19, size=1, complete=True):
    return {"class": cls, "first_token": token, "output_bytes": size, "generation_complete": complete}


def test_scoring_matches_mismatches_blanks_and_incomplete_arms():
    predictions = {"A": {"class_counts": {"R": 1}, "first_token": 19, "output_bytes": 1, "generation_complete": True},
                   "B": {"class_counts": {"V0": 1}},
                   "C": {},
                   "D": {"output_bytes": 0},
                   "E": {"class_counts": {"V0": 1}},
                   "F": {"class_counts": {"R": 1}, "first_token": 20}}
    result = PR.score(predictions, {arm: 1 for arm in predictions},
                      {"A": [observation("R")], "B": [observation("R")], "C": [observation("V0", 151645, 0)],
                       "D": [observation("V0", 151645, 0)], "F": [observation("R")]})
    arms = result["arms"]
    assert arms["A"]["status"] == "MATCH" and set(arms["A"]["components"].values()) == {"MATCH"}
    assert arms["B"]["status"] == "MISMATCH" and arms["B"]["components"]["first_token"] == "NOT_PREDICTED"
    assert arms["C"]["status"] == "NOT_PREDICTED" and arms["C"]["fully_predicted"] is False
    assert arms["D"]["status"] == "MATCH" and arms["D"]["components"]["class_counts"] == "NOT_PREDICTED"
    assert arms["E"]["status"] == "INCOMPLETE" and arms["E"]["observed"] == 0
    assert arms["F"]["status"] == "MISMATCH" and arms["F"]["components"] == {
        "class_counts": "MATCH", "first_token": "MISMATCH", "output_bytes": "NOT_PREDICTED",
        "generation_complete": "NOT_PREDICTED"}
    assert result["status"] == "MISMATCH" and result["arms_not_predicted"] == 1
    assert result["every_scheduled_arm_fully_predicted"] is False
    json.dumps(result)
    assert PR.score({"C": {}}, {"C": 1}, {"C": [observation("R")]})["status"] == "NOT_PREDICTED"
    assert PR.score({"A": predictions["A"], "C": {}}, {"A": 1, "C": 1},
                    {"A": [observation("R")], "C": [observation("R")]})["status"] == "MATCH"
    assert PR.score({"E": predictions["E"], "A": predictions["A"]}, {"E": 1, "A": 1},
                    {"A": [observation("R")]})["status"] == "INCOMPLETE"
    
    assert PR.score({"A": {"output_bytes": 1}}, {"A": 1},
                    {"A": [dict(observation("R"), output_bytes=True)]})["status"] == "MISMATCH"


def test_mixed_bank_prediction_is_scored_on_final_counts_only():
    mixed = {"VALID": {"class_counts": {"R": 186, "NV": 2}}, "MISSING_GRANT": {"class_counts": {"V0": 188}, "output_bytes": 0}}
    planned = {"VALID": 188, "MISSING_GRANT": 188}
    stops = [observation("V0", 151645, 0)] * 188
    exact = PR.score(mixed, planned, {"VALID": [observation("R")] * 186 + [observation("NV")] * 2, "MISSING_GRANT": stops})
    assert exact["status"] == "MATCH" and exact["arms"]["VALID"]["observed_class_counts"] == {"R": 186, "NV": 2}
    
    shuffled = PR.score(mixed, planned, {"VALID": [observation("NV")] + [observation("R")] * 186 + [observation("NV")],
                                         "MISSING_GRANT": stops})
    assert shuffled["status"] == "MATCH"
    off = PR.score(mixed, planned, {"VALID": [observation("R")] * 187 + [observation("NV")], "MISSING_GRANT": stops})
    assert off["arms"]["VALID"]["status"] == "MISMATCH" and off["arms"]["MISSING_GRANT"]["status"] == "MATCH"
    other = PR.score(mixed, planned, {"VALID": [observation("R")] * 186 + [observation("V1", 3, 0, False)] * 2,
                                      "MISSING_GRANT": stops})
    assert other["status"] == "MISMATCH"
    partial = PR.score(mixed, planned, {"VALID": [observation("R")] * 100, "MISSING_GRANT": stops})
    assert partial["arms"]["VALID"]["status"] == "INCOMPLETE" and partial["status"] == "INCOMPLETE"
    
    early = PR.score(mixed, planned, {"VALID": [], "MISSING_GRANT": [observation("V0", 151645, 0)] * 5 + [observation("R")]})
    assert early["arms"]["MISSING_GRANT"]["components"]["output_bytes"] == "MISMATCH"
    with pytest.raises(PR.PredictionFormatError):
        PR.score({"VALID": {"class_counts": {"R": 188}}}, {"VALID": 1}, {"VALID": [observation("R")]})


def gate_sealed(gate, tmp_path, raw, purpose="DEVELOPMENT_QUALIFICATION", schedule=("VALID", "MISSING_GRANT"), **extra):
    pass
    path = tmp_path / ("TEST-DOUBLE-" + sha(raw)[:8] + ".md")
    path.write_bytes(raw)
    changes = dict(authority="LIVE_SWIFTAPI", schedule=list(schedule), one_disposable_grant_revocation_approved=True,
                   purpose=purpose, seal=False, **extra)
    if purpose == "PREREGISTERED_STUDY":
        changes.update(author_freeze_approved=True, public_registration_timestamp="TEST DOUBLE",
                       registration_sha256="1" * 64)
    config, wheel = runner_config(tmp_path, **changes)
    config.update(author_predictions_sha256=sha(raw), predictions_sealed_at=GOOD_TIME)
    config["predictions"] = PR.select_for_run(parse(raw), "WITNESS_ONE", list(schedule))[1]
    out = tmp_path / ("sealed-" + uuid.uuid4().hex)
    key_file = tmp_path / "MADE-UP-not-a-credential.key"
    error = None
    try:
        X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS, key_file=key_file,
              approval_file=approval_for(config, tmp_path, "approval-" + uuid.uuid4().hex + ".json"),
              predictions_file=path)
    except Exception as exc:
        error = exc
    return out, error


def test_development_run_keeps_code_acceptance_and_author_prediction_apart(gate, tmp_path):
    pass
    raw = template_text(primary={"VALID": {"lines": [(None, "R")], "first_token": "19", "output_bytes": "1"},
                                 "MISSING_GRANT": {"lines": [(None, "R")]}})
    out, error = gate_sealed(gate, tmp_path, raw)
    assert error is None, repr(error)
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "PASS" and summary["execution_integrity"] == "COMPLETE"
    assert summary["per_slot_comparison"] == {"kind": "DEVELOPMENT_ACCEPTANCE_IMPLIED_BY_CODE_NOT_AUTHOR_PREDICTION",
                                              "compared": 2, "agree": 2}
    author = summary["author_prediction"]
    assert author["status"] == "MISMATCH"
    assert author["arms"]["VALID"]["status"] == "MATCH" and author["arms"]["MISSING_GRANT"]["status"] == "MISMATCH"
    assert author == json.loads((out / "author-prediction-score.json").read_text())
    assert (out / "sealed-predictions.md").read_bytes() == raw
    assert json.loads((out / "sealed-predictions-parsed.json").read_text())["selected_for_this_run"] == \
        json.loads((out / "run-config.json").read_text())["predictions"]
    with __import__("tarfile").open(out / "evidence.tar.gz") as archive:
        names = set(archive.getnames())
    assert {"sealed-predictions.md", "sealed-predictions-parsed.json", "author-prediction-score.json",
            "predictions-seal.json"} <= names


def test_blank_sealed_file_runs_and_scores_nothing(gate, tmp_path):
    out, error = gate_sealed(gate, tmp_path, template_text())
    assert error is None, repr(error)
    summary = json.loads((out / "summary.json").read_text())
    assert summary["status"] == "PASS" and summary["author_prediction"]["status"] == "NOT_PREDICTED"
    assert summary["author_prediction"]["arms_predicted"] == 0


def test_sealed_study_is_scored_per_arm_and_continues_past_a_surprise(gate, tmp_path):
    wrong = template_text(primary={"VALID": {"lines": [(None, "R")]}, "MISSING_GRANT": {"lines": [(None, "R")]},
                                   "WRONG_REQUEST": {"lines": [(None, "V0")]}})
    out, error = gate_sealed(gate, tmp_path, wrong, purpose="PREREGISTERED_STUDY",
                             schedule=("VALID", "MISSING_GRANT", "WRONG_REQUEST"))
    assert error is None, repr(error)
    summary = json.loads((out / "summary.json").read_text())
    assert summary["sequence_completed"] is True and len(summary["rows"]) == 3
    assert summary["per_slot_comparison"]["kind"] == "NONE_SEALED_STUDY" and summary["per_slot_comparison"]["compared"] == 0
    assert all(row["prediction"] is None and row["prediction_agrees"] is None for row in summary["rows"])
    assert summary["author_prediction"]["status"] == "MISMATCH" and summary["status"] == "FAIL"
    assert summary["execution_integrity"] == "COMPLETE"
    assert [summary["author_prediction"]["arms"][arm]["status"] for arm in ("VALID", "MISSING_GRANT", "WRONG_REQUEST")] == \
        ["MATCH", "MISMATCH", "MATCH"]
    
    assert summary["registered_result"] is False
    right = template_text(primary={"VALID": {"lines": [(None, "R")], "output_bytes": "1"},
                                   "MISSING_GRANT": {"lines": [(1, "V0")], "first_token": "151645"}})
    out, error = gate_sealed(gate, tmp_path, right, purpose="PREREGISTERED_STUDY")
    assert error is None, repr(error)
    summary = json.loads((out / "summary.json").read_text())
    assert summary["author_prediction"]["status"] == "MATCH" and summary["status"] == "PASS"


def test_incomplete_sealed_run_scores_unreached_arms_as_incomplete(gate, tmp_path):
    def foreign(server, tier, method, path, now):
        if server.slot == "MISSING_GRANT" and tier == "authenticated" and not getattr(server, "fired", False):
            server.fired = True
            server.windows["authenticated"] = [now] * 300

    gate.server.foreign = foreign
    raw = template_text(primary={"VALID": {"lines": [(None, "R")]}, "MISSING_GRANT": {"lines": [(None, "V0")]},
                                 "WRONG_REQUEST": {"lines": [(None, "V0")]}})
    out, error = gate_sealed(gate, tmp_path, raw, schedule=("VALID", "MISSING_GRANT", "WRONG_REQUEST"))
    assert error is not None
    summary = json.loads((out / "summary.json").read_text())
    author = summary["author_prediction"]
    assert author["arms"]["VALID"]["status"] == "MATCH" and author["arms"]["WRONG_REQUEST"]["status"] == "INCOMPLETE"
    assert author["status"] in ("INCOMPLETE", "MISMATCH") and summary["execution_integrity"] == "INCOMPLETE_OR_FAILED"


def test_unsealed_local_replay_keeps_the_legacy_schema_and_gets_no_author_score(tmp_path):
    out = run_replay(tmp_path, schedule=["VALID", "MISSING_GRANT"])
    summary = json.loads((out / "summary.json").read_text())
    assert summary["author_prediction"] is None and summary["status"] == "PASS"
    assert summary["per_slot_comparison"]["kind"] == "DEVELOPMENT_ACCEPTANCE_IMPLIED_BY_CODE_NOT_AUTHOR_PREDICTION"
    for name in ("sealed-predictions.md", "sealed-predictions-parsed.json", "author-prediction-score.json"):
        assert not (out / name).exists()


def test_predictions_equality_is_type_exact_for_booleans_and_floats(tmp_path):
    pass
    raw = template_text(primary={arm: {"lines": [(None, implied_class(arm))]} for arm in PR.PRIMARY_ARMS} |
                        {"MISSING_GRANT": {"lines": [(None, "V0")], "output_bytes": "0", "first_token": "1",
                                           "generation_complete": "true"}})
    config, wheel, path = live_sealed(tmp_path, raw)
    good = config["predictions"]
    assert good["MISSING_GRANT"] == {"class_counts": {"V0": 1}, "first_token": 1, "output_bytes": 0,
                                     "generation_complete": True}
    X.validate_config(config, wheel, path)
    X.validate_config(json.loads(json.dumps(config)), wheel, path)        
    entry = good["MISSING_GRANT"]
    for label, changed in (("True for first_token 1", {**entry, "first_token": True}),
                           ("False for output_bytes 0", {**entry, "output_bytes": False}),
                           ("1 for generation_complete true", {**entry, "generation_complete": 1}),
                           ("1.0 for first_token 1", {**entry, "first_token": 1.0}),
                           ("0.0 for output_bytes 0", {**entry, "output_bytes": 0.0}),
                           ("True for the count", {**entry, "class_counts": {"V0": True}}),
                           ("1.0 for the count", {**entry, "class_counts": {"V0": 1.0}})):
        assert changed == entry, "the point of the test: Python equality cannot tell these apart"
        other = dict(config, predictions={**good, "MISSING_GRANT": changed})
        with pytest.raises(ValueError, match="not exactly"):
            X.validate_config(other, wheel, path)
        with pytest.raises(ValueError, match="not exactly"):
            X.validate_config(json.loads(json.dumps(other)), wheel, path)


def primary_archive(tmp_path, name="primary", sealed=TEST_PREDICTIONS, config_changes=None, drop=(), extra=None):
    import io
    import tarfile
    primary = {"run_role": "PRIMARY", "population": "WITNESS_ONE", "purpose": "PREREGISTERED_STUDY",
               "authority": "LIVE_SWIFTAPI", "mode": FRESH, "schedule": list(X.SERVICE_ARMS), "repetitions": 1,
               "registration_sha256": "1" * 64, "sdk_wheel_sha256": WHEEL_SHA256,
               "service_source_sha256": S.source_identity()["sha256"],
               "classifier_sha256": native_taxonomy.classifier_hash(),
               "author_predictions_sha256": sha(TEST_PREDICTIONS), "predictions_sealed_at": GOOD_TIME}
    primary.update(config_changes or {})
    files = {"run-config.json": compact(primary),
             "summary.json": compact({"status": "FAIL", "finished_at": 1_800_000_000.0, "TEST_DOUBLE": True,
                 "sequence_completed": True, "execution_integrity": "COMPLETE", "verified_receipt_count": 11}),
             "sealed-predictions.md": sealed}
    files.update(extra or {})
    for member in drop:
        files.pop(member)
    files["SHA256SUMS"] = "".join(f"{sha(raw)}  {member}\n" for member, raw in sorted(files.items())).encode()
    path = tmp_path / (name + "-" + uuid.uuid4().hex[:8] + ".tar.gz")
    with tarfile.open(path, "w:gz") as archive:
        for member, raw in sorted(files.items()):
            info = tarfile.TarInfo(member)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return path, primary


def secondary_config(primary, archive, **changes):
    config = {"run_role": "SECONDARY", "population": "BANK_188", "primary_archive_sha256": sha(archive.read_bytes())}
    for pin in ("registration_sha256", "sdk_wheel_sha256", "service_source_sha256", "classifier_sha256",
                "author_predictions_sha256", "predictions_sealed_at"):
        config[pin] = primary[pin]
    config.update(changes)
    return config


def test_secondary_accepts_a_primary_sealed_with_the_same_predictions_file(tmp_path):
    archive, primary = primary_archive(tmp_path)
    seal = X.verify_primary_seal(secondary_config(primary, archive), archive)
    assert seal["sha256"] == sha(archive.read_bytes()) and seal["primary_status"] == "FAIL"
    
    assert X.verify_primary_seal({"run_role": "PRIMARY"}, None) is None


@pytest.mark.parametrize("change", [{"sequence_completed": False},
    {"execution_integrity": "INCOMPLETE"}, {"verified_receipt_count": 10}])
def test_secondary_requires_complete_primary_integrity(tmp_path, change):
    summary = {"status": "FAIL", "finished_at": 1_800_000_000.0,
               "sequence_completed": True, "execution_integrity": "COMPLETE", "verified_receipt_count": 11}
    summary.update(change)
    archive, primary = primary_archive(tmp_path, extra={"summary.json": compact(summary)})
    with pytest.raises(ValueError, match="Primary sequence and receipt integrity"):
        X.verify_primary_seal(secondary_config(primary, archive), archive)


def test_secondary_cannot_use_another_sealed_predictions_file_or_another_seal_time(tmp_path):
    archive, primary = primary_archive(tmp_path)
    other_file = template_text(secondary={"VALID": {"lines": [(None, "NV")]}})
    for label, changes in (
            ("another predictions hash", {"author_predictions_sha256": sha(other_file)}),
            ("another seal time", {"predictions_sealed_at": "2026-01-02T00:00:00+00:00"}),
            ("same instant written differently", {"predictions_sealed_at": "2026-01-01T00:00:00Z"}),
            ("hash missing", {"author_predictions_sha256": None}),
            ("time missing", {"predictions_sealed_at": None})):
        with pytest.raises(ValueError, match="pin mismatch: (author_predictions_sha256|predictions_sealed_at)"):
            X.verify_primary_seal(secondary_config(primary, archive, **changes), archive)


def test_secondary_refuses_a_primary_that_declares_no_seal_or_carries_other_sealed_bytes(tmp_path):
    for label, kwargs, pattern in (
            ("primary without a predictions hash", {"config_changes": {"author_predictions_sha256": None}}, "pin mismatch"),
            ("primary without a seal time", {"config_changes": {"predictions_sealed_at": ""}}, "pin mismatch"),
            ("primary archive without the sealed file", {"drop": ("sealed-predictions.md",)}, "same sealed predictions file"),
            ("primary archive with other sealed bytes", {"sealed": TEST_PREDICTIONS + b"\n"}, "same sealed predictions file")):
        archive, primary = primary_archive(tmp_path, **kwargs)
        config = secondary_config(primary, archive)
        if config.get("author_predictions_sha256") is None:
            config["author_predictions_sha256"] = None
        with pytest.raises(ValueError, match=pattern):
            X.verify_primary_seal(config, archive)


def test_the_existing_pins_and_the_archive_hash_are_still_enforced(tmp_path):
    archive, primary = primary_archive(tmp_path)
    for pin in ("registration_sha256", "sdk_wheel_sha256", "service_source_sha256", "classifier_sha256"):
        with pytest.raises(ValueError, match="pin mismatch: " + pin):
            X.verify_primary_seal(secondary_config(primary, archive, **{pin: "f" * 64}), archive)
    with pytest.raises(ValueError, match="hash differs"):
        X.verify_primary_seal(secondary_config(primary, archive, primary_archive_sha256="0" * 64), archive)
    with pytest.raises(ValueError, match="requires the sealed primary archive"):
        X.verify_primary_seal(secondary_config(primary, archive), None)
    for change in ({"run_role": "SECONDARY"}, {"population": "BANK_188"}, {"mode": REPLAY},
                   {"authority": "LOCAL_TEST_DOUBLE"}, {"purpose": "DEVELOPMENT_QUALIFICATION"},
                   {"schedule": ["VALID"]}, {"repetitions": 2}):
        other, other_primary = primary_archive(tmp_path, config_changes=change)
        with pytest.raises(ValueError, match="not the registered primary run"):
            X.verify_primary_seal(secondary_config(other_primary, other), other)
    tampered, tampered_primary = primary_archive(tmp_path, extra={"added-later.txt": b"x"})
    X.verify_primary_seal(secondary_config(tampered_primary, tampered), tampered)   


def test_a_secondary_run_with_another_seal_is_refused_before_approval_key_or_output(
        tmp_path, monkeypatch, approval_registry_in_a_temporary_directory):
    pass
    monkeypatch.setattr(X, "read_key", lambda path: pytest.fail("key read"))
    monkeypatch.setattr(X.platform, "system", lambda: "Linux")       
    archive, primary = primary_archive(tmp_path)
    other = template_text(secondary={"VALID": {"lines": [(None, "R")]}, "MISSING_GRANT": {"lines": [(None, "V0")]}},
                          preamble="# TEST DOUBLE second predictions file. Not the author's.\n")
    other_path = tmp_path / "TEST-DOUBLE-second.md"
    other_path.write_bytes(other)
    config, wheel = runner_config(
        tmp_path, seal=False, purpose="PREREGISTERED_STUDY", author_freeze_approved=True,
        public_registration_timestamp="TEST DOUBLE", registration_sha256="1" * 64, run_role="SECONDARY",
        population="BANK_188", schedule=["VALID", "MISSING_GRANT"], authority="LIVE_SWIFTAPI", mode=FRESH,
        device="cuda", enable_full_model=True, maximum_warm_forward_seconds=10,
        primary_archive_sha256=sha(archive.read_bytes()))
    config.update(author_predictions_sha256=sha(other), predictions_sealed_at=GOOD_TIME)
    config["predictions"] = PR.select_for_run(parse(other), "BANK_188", ["VALID", "MISSING_GRANT"])[1]
    approval = approval_for(config, tmp_path)
    out = tmp_path / "secondary-run"
    key_file = tmp_path / "MADE-UP.key"
    key_file.write_text(KEY)
    key_file.chmod(0o600)
    
    from swiftapi_native_service import mac_ledger
    before = tmp_path / "SYNTHETIC-before-capture.json"
    before.write_bytes(compact({
        "schema": mac_ledger.SCHEMA, "phase": "BEFORE", "config_sha256": sha(compact(config)),
        "capture_host": "Darwin", "evidence_kind": "LIVE_SWIFTAPI_READ_ONLY_ADMIN_CAPTURE",
        "authority_public_key": mac_ledger.SWIFTAPI_PUBLIC_KEY_B64, "started_at": 10.0, "finished_at": 11.0,
        "execution_archive_sha256": None,
        "snapshot": {"source": core.AUTHORITY_URL, "governance": [], "revocations": [], "limitations": [],
                     "fallback": [], "read_requests": 0, "SYNTHETIC_TEST_DOUBLE": True}}))
    with pytest.raises(ValueError, match="pin mismatch: author_predictions_sha256"):
        X.run(config, wheel, out, SOURCE, Path("/nonexistent-content"), HARNESS, key_file=key_file,
              approval_file=approval, primary_archive=archive, predictions_file=other_path, mac_ledger_before=before)
    assert not out.exists() and approval_untouched(approval, approval_registry_in_a_temporary_directory)


def test_only_a_fresh_live_study_is_the_registered_comparison():
    import itertools
    purposes = ("PREREGISTERED_STUDY", "DEVELOPMENT_QUALIFICATION", "DEVELOPMENT_SMOKE", None)
    modes = (FRESH, REPLAY, None)
    authorities = ("LIVE_SWIFTAPI", "LOCAL_TEST_DOUBLE", None)
    registered = []
    for purpose, mode, authority in itertools.product(purposes, modes, authorities):
        scope = PR.comparison_scope({"purpose": purpose, "mode": mode, "authority": authority, "ignored": 1})
        json.dumps(scope)
        assert (scope["purpose"], scope["mode"], scope["authority"]) == (purpose, mode, authority)
        assert scope["registered_comparison"] is (scope["kind"] == "REGISTERED_COMPARISON")
        assert scope["kind"] in ("REGISTERED_COMPARISON", "NOT_REGISTERED_COMPARISON")
        assert scope["predicted_conditions"] == {"purpose": "PREREGISTERED_STUDY", "mode": FRESH,
                                                 "authority": "LIVE_SWIFTAPI"}
        if scope["registered_comparison"]:
            registered.append((purpose, mode, authority))
            assert scope["differs_in"] == []
        else:
            assert scope["differs_in"] and "not the registered comparison" in scope["meaning"]
    assert registered == [("PREREGISTERED_STUDY", FRESH, "LIVE_SWIFTAPI")]
    
    assert PR.comparison_scope({"purpose": "DEVELOPMENT_QUALIFICATION", "mode": REPLAY,
                                "authority": "LIVE_SWIFTAPI"})["differs_in"] == ["purpose", "mode"]
    assert PR.comparison_scope({"purpose": "DEVELOPMENT_SMOKE", "mode": FRESH,
                                "authority": "LOCAL_TEST_DOUBLE"})["differs_in"] == ["purpose", "authority"]
    assert PR.comparison_scope({})["kind"] == "NOT_REGISTERED_COMPARISON"


def test_comparison_scope_is_pure_and_score_is_unchanged_by_it():
    import inspect
    source = inspect.getsource(PR.comparison_scope)
    for forbidden in ("open(", "Path(", "time.", "os.", "import "):
        assert forbidden not in source, forbidden
    assert "comparison_scope" not in inspect.getsource(PR.score)
    result = PR.score({"A": {"class_counts": {"R": 1}}}, {"A": 1}, {"A": [observation("R")]})
    assert "comparison_scope" not in result and result["status"] == "MATCH"


def test_development_run_with_the_seal_is_labelled_not_the_registered_comparison(gate, tmp_path):
    pass
    raw = template_text(primary={"VALID": {"lines": [(None, "R")], "generation_complete": "true"},
                                 "MISSING_GRANT": {"lines": [(None, "V0")]}})
    out, error = gate_sealed(gate, tmp_path, raw)
    assert error is None, repr(error)
    summary = json.loads((out / "summary.json").read_text())
    scored = json.loads((out / "author-prediction-score.json").read_text())
    assert summary["author_prediction_comparison"] == "NOT_REGISTERED_COMPARISON"
    assert scored == summary["author_prediction"]
    scope = scored["comparison_scope"]
    assert scope["kind"] == "NOT_REGISTERED_COMPARISON" and scope["registered_comparison"] is False
    assert (scope["purpose"], scope["mode"], scope["authority"]) == ("DEVELOPMENT_QUALIFICATION", REPLAY, "LIVE_SWIFTAPI")
    assert scope["differs_in"] == ["purpose", "mode"]
    
    assert scored["arms"]["VALID"]["components"]["generation_complete"] == "MISMATCH"
    assert scored["arms"]["VALID"]["components"]["class_counts"] == "MATCH"
    assert summary["status"] == "PASS" and summary["registered_result"] is False


def test_sealed_study_in_replay_is_also_labelled_not_the_registered_comparison(gate, tmp_path):
    raw = template_text(primary={"VALID": {"lines": [(None, "R")]}, "MISSING_GRANT": {"lines": [(None, "V0")]}})
    out, error = gate_sealed(gate, tmp_path, raw, purpose="PREREGISTERED_STUDY")
    assert error is None, repr(error)
    summary = json.loads((out / "summary.json").read_text())
    scope = summary["author_prediction"]["comparison_scope"]
    assert scope["kind"] == "NOT_REGISTERED_COMPARISON" and scope["differs_in"] == ["mode"]
    assert summary["author_prediction_comparison"] == "NOT_REGISTERED_COMPARISON" and summary["registered_result"] is False


def test_unsealed_run_says_it_has_no_sealed_predictions(tmp_path):
    summary = json.loads((run_replay(tmp_path, schedule=["VALID", "MISSING_GRANT"]) / "summary.json").read_text())
    assert summary["author_prediction"] is None
    assert summary["author_prediction_comparison"] == "NO_SEALED_PREDICTIONS_IN_THIS_RUN"


def test_registered_result_and_registered_comparison_use_the_same_three_conditions():
    pass
    import inspect
    source = inspect.getsource(X)
    assert "config['purpose']=='PREREGISTERED_STUDY' and" in source
    for purpose in ("PREREGISTERED_STUDY", "DEVELOPMENT_QUALIFICATION", "DEVELOPMENT_SMOKE"):
        for mode in (FRESH, REPLAY):
            for authority in ("LIVE_SWIFTAPI", "LOCAL_TEST_DOUBLE"):
                registered_result = (purpose == "PREREGISTERED_STUDY" and authority == "LIVE_SWIFTAPI" and mode == FRESH)
                assert PR.comparison_scope({"purpose": purpose, "mode": mode,
                                            "authority": authority})["registered_comparison"] is registered_result
