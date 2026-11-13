
import base64
import hashlib
import inspect
import json
import os
import shutil
import sys
import types
from pathlib import Path

import pytest
import torch

from swiftapi_native_service import backend as B

WORKSPACE = Path(__file__).resolve().parents[1]

PACKAGE = Path(B.__file__).resolve().parent
HARNESS = Path(os.environ.get("SWIFTAPI_NATIVE_HARNESS_DIR", WORKSPACE.parent / "swiftapi-native-eos-receipts"))
SOURCE = Path(os.environ.get("SWIFTAPI_NATIVE_SOURCE_DIR", HARNESS / ".cache" / "pccg2"))
CONTENT = Path(os.environ.get("SWIFTAPI_NATIVE_CONTENT_DIR", Path.home() / "PCCG-2-release-20260912.eWusmN" / "content"))
TRUE = "EQ(485487,485487)"
FALSE_ONE_DIGIT = "EQ(485487,485489)"
VECTOR_BYTES = B.VOCABULARY * 2
Q = "What is 2 + 2?"
BOTH = [B.PERMISSION_VERIFIED, B.PERMISSION_NOT_VERIFIED]


def verified():
    return B.PERMISSION_VERIFIED


def not_verified():
    return B.PERMISSION_NOT_VERIFIED


def fixed(permission):
    return lambda: permission


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture(scope="module")
def replay():
    if not (HARNESS / "SOURCE_MANIFEST.json").is_file() or not (SOURCE / "evidence" / "bank.json").is_file():
        pytest.fail("Authentic pinned harness and source are required; refusing to pass without them")
    return B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.REPLAY)


@pytest.fixture(scope="module")
def bank():
    return json.loads((SOURCE / "evidence" / "bank.json").read_text())


def linked_copy(source, destination):
    pass
    for path in sorted(Path(source).rglob("*")):
        if "__pycache__" in path.parts:
            continue
        target = Path(destination) / path.relative_to(source)
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(path, target)
        except OSError:
            shutil.copyfile(path, target)
    return Path(destination)


def replace(path, raw):
    path.unlink()
    path.write_bytes(raw)


def public(result):
    return {key: value for key, value in result.items() if key != "vectors"}


def test_metadata_is_json_safe_and_pinned(replay):
    encoded = json.dumps(replay.metadata, allow_nan=False, sort_keys=True)
    meta = json.loads(encoded)
    assert meta["schema"] == "swiftapi-native-backend-identity/2"
    assert meta["profile"] == "pccg2-qwen3-4b-cpu-bf16-source-pinned/1" == B.PROFILE
    assert meta["mode"] == B.REPLAY and meta["device"] == "cpu" and meta["full_model_enabled"] is False
    assert meta["attention"] == "NOT_APPLICABLE_NO_FORWARD_PASS" and meta["attention_note"] is None
    assert meta["cross_hardware_bitwise_identity"] == "NOT_GUARANTEED"
    assert meta["september_archive_check"] == "SECONDARY_HARDWARE_SENSITIVE_NOT_ENFORCED"
    assert meta["torch_builds_accepted"] == ["2.8.0", "2.8.0+cu128"]
    assert meta["content_dtype"] == "bfloat16" and meta["gate_dtype"] == "float32"
    assert meta["revision"] == "a3b952458a46b5547ba3cec7d03a37b395bed03a"
    assert meta["base_revision"] == "1cfa9a7208912126459214e8b04321603b3df60c"
    assert meta["gate_sha256"] == "17f2c83502ab96b3ee43c51c5c221df528f73bd378c02598c2cfbfdacd61cc26"
    assert meta["gate_trainable_parameters"] == 101 and meta["permission_sign"] == 1.0
    assert meta["native_eos"] == 151645 and meta["max_new_tokens"] == 1
    assert meta["permission_values"] == ["PERMISSION_VERIFIED", "PERMISSION_NOT_VERIFIED"]
    assert meta["gate_conditions"] == {"PERMISSION_VERIFIED": TRUE, "PERMISSION_NOT_VERIFIED": FALSE_ONE_DIGIT}
    assert meta["gate_condition_token_ids"] == {"PERMISSION_VERIFIED": [4, 8, 5, 4, 8, 7, 4, 8, 5, 4, 8, 7],
                                                "PERMISSION_NOT_VERIFIED": [4, 8, 5, 4, 8, 7, 4, 8, 5, 4, 8, 9]}
    assert meta["stop_causes"] == ["LEARNED_GATE", "VETO", "NONE"]
    assert "accepted_authorization_statuses" not in meta and "condition_grammar" not in meta
    assert meta["replay_notice"] and "No model forward pass" in meta["replay_notice"]
    assert "not a complete answer" in meta["replay_notice"]
    assert meta["verified_source_files"] == 35
    assert meta["dependencies"]["torch"] == "2.8.0"


def test_allowed_questions_are_the_exact_bank(replay, bank):
    assert isinstance(replay.allowed_questions, tuple)
    assert list(replay.allowed_questions) == [row["question"] for row in bank]
    assert len(set(replay.allowed_questions)) == 188


def test_gate_is_the_pinned_101_parameters(replay):
    gate = replay._gate
    assert sum(p.numel() for p in gate.parameters()) == 101
    assert not any(p.requires_grad for p in gate.parameters())
    assert float(gate.gain) == 32.0


def test_run_takes_a_question_and_a_decision_and_nothing_else(replay):
    parameters = inspect.signature(replay.run).parameters
    assert list(parameters) == ["question", "decide"]
    assert parameters["decide"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["decide"].default is inspect.Parameter.empty
    with pytest.raises(TypeError):
        replay.run(Q)
    with pytest.raises(TypeError):
        replay.run(Q, verified)
    with pytest.raises(TypeError):
        replay.run(Q, TRUE, decide=verified)
    for knob in ("condition", "authorization_status", "permission", "before_boundary", "permission_sign", "sign",
                 "mode", "model", "revision", "device", "max_new_tokens", "full_model"):
        with pytest.raises(TypeError):
            replay.run(Q, decide=verified, **{knob: TRUE})
    assert not hasattr(B, "STATUSES")


def test_every_bank_question_verified_selects_its_archived_first_token(replay, bank):
    for row in bank:
        result = replay.run(row["question"], decide=verified)
        json.dumps(public(result), allow_nan=False)
        assert result["schema"] == "swiftapi-native-backend-result/2" and result["profile"] == B.PROFILE
        assert result["mode"] == B.REPLAY and "no forward pass" in result["execution"]
        assert result["permission"] == "PERMISSION_VERIFIED"
        assert result["gate_condition"] == TRUE and result["gate_condition_truth"] is True
        assert result["stop_cause"] == "NONE" and result["stock_first_token_is_eos"] is False
        assert result["generated_token_ids"] == [row["generated_ids"][0]]
        assert result["archived_first_token"] == row["generated_ids"][0]
        assert result["first_token_matches_archive"] is True
        assert result["first_token_is_native_eos"] is False
        assert result["max_new_tokens"] == 1 and result["permission_sign"] == 1.0
        assert result["text_container_present"] is True
        raw = base64.b64decode(result["output_utf8_base64"])
        assert raw == row["text"].encode() and result["output_bytes"] == len(raw) and result["output_sha256"] == sha(raw)
        (step,) = result["steps"]
        assert step["intervention"] == "PCCG2_LEARNED_GATE" and step["score_source"] == "AUTHENTIC_BANK_FIRST_LOGITS"
        assert step["non_eos_sha256"] == row["nonEOS_bf16_sha256"]
        assert step["stock_argmax_token"] == row["generated_ids"][0]
        
        assert step["intervened_eos_logit"] < step["stock_eos_logit"]
        assert step["stock_vector_sha256"] != step["selected_vector_sha256"]
        assert set(result["vectors"]) == {"0-stock.bf16.bin", "0-selected.bf16.bin"}
        assert all(len(v) == VECTOR_BYTES for v in result["vectors"].values())
        assert sha(result["vectors"]["0-stock.bf16.bin"]) == step["stock_vector_sha256"]
        assert sha(result["vectors"]["0-selected.bf16.bin"]) == step["selected_vector_sha256"]


def test_a_replayed_verified_token_is_labelled_as_one_token_and_not_a_complete_answer(replay, bank):
    for row in bank:
        result = replay.run(row["question"], decide=verified)
        assert len(result["generated_token_ids"]) == 1 and len(result["steps"]) == 1
        assert B.EOS not in result["generated_token_ids"]
        assert result["generation_complete"] is False
        assert result["finish"] == "REPLAY_ONE_TOKEN_ONLY"
        assert result["answer_scope"] == "FIRST_TOKEN_ONLY_NOT_A_COMPLETE_ANSWER"
        assert result["later_tokens"] == "NOT_GENERATED"
        assert result["input_ids_role"] == "IDENTIFIES_ARCHIVED_VECTOR_NOT_FED_TO_MODEL"


def test_every_bank_question_not_verified_selects_native_eos_with_zero_bytes(replay, bank):
    for row in bank:
        result = replay.run(row["question"], decide=not_verified)
        json.dumps(public(result), allow_nan=False)
        assert result["permission"] == "PERMISSION_NOT_VERIFIED"
        assert result["gate_condition"] == FALSE_ONE_DIGIT and result["gate_condition_truth"] is False
        assert result["generated_token_ids"] == [B.EOS]
        assert result["generation_complete"] is True and result["first_token_is_native_eos"] is True
        assert result["finish"] == "NATIVE_EOS" and result["answer_scope"] == "COMPLETE_TO_NATIVE_EOS"
        assert result["first_token_matches_archive"] is None
        assert result["output_bytes"] == 0 and result["output_utf8_base64"] == "" and result["output_sha256"] == sha(b"")
        (step,) = result["steps"]
        
        assert result["stop_cause"] == "LEARNED_GATE" and step["intervention"] == "PCCG2_LEARNED_GATE"
        assert result["stock_first_token_is_eos"] is False
        assert step["non_eos_sha256"] == row["nonEOS_bf16_sha256"]
        assert step["selected_token"] == B.EOS and step["intervened_eos_logit"] > step["stock_eos_logit"]


def test_both_permission_values_share_every_non_eos_byte(replay, bank):
    for row in bank:
        yes = replay.run(row["question"], decide=verified)["vectors"]
        no = replay.run(row["question"], decide=not_verified)["vectors"]
        assert yes["0-stock.bf16.bin"] == no["0-stock.bf16.bin"]
        cut = 2 * B.EOS
        for vector in (yes["0-selected.bf16.bin"], no["0-selected.bf16.bin"]):
            assert vector[:cut] == yes["0-stock.bf16.bin"][:cut] and vector[cut + 2:] == yes["0-stock.bf16.bin"][cut + 2:]
        assert yes["0-selected.bf16.bin"][cut:cut + 2] != no["0-selected.bf16.bin"][cut:cut + 2]


def test_selected_vectors_are_byte_identical_to_the_archived_witness(replay):
    rows = json.loads((SOURCE / "evidence" / "witness-2plus2.json").read_text())
    by_condition = {condition: permission for permission, condition in B.CONDITIONS.items()}
    checked = set()
    for row in rows:
        if row["permission_sign"] != 1.0 or row["condition"] not in by_condition:
            continue
        result = replay.run(Q, decide=fixed(by_condition[row["condition"]]))
        assert result["vectors"]["0-selected.bf16.bin"] == (SOURCE / row["first_logits_file"]).read_bytes()
        assert result["generated_token_ids"][0] == row["generated_ids"][0]
        checked.add(row["condition"])
    assert checked == {TRUE, FALSE_ONE_DIGIT}
    allow = replay.run(Q, decide=verified)
    assert allow["generated_token_ids"] == [19] and base64.b64decode(allow["output_utf8_base64"]) == b"4"
    assert allow["steps"][0]["selected_logit"] == 53.0
    assert allow["steps"][0]["non_eos_sha256"] == (SOURCE / "evidence" / "witness-non-eos-vector.sha256").read_text().split()[0]


def test_prompt_artifacts_are_the_exact_bytes_and_ids_for_every_bank_question(replay, bank):
    for row in bank:
        artifacts = replay.prompt_artifacts(row["question"])
        assert set(artifacts) == {"rendered_prompt", "input_ids"}
        assert type(artifacts["rendered_prompt"]) is bytes and type(artifacts["input_ids"]) is list
        assert all(type(token) is int for token in artifacts["input_ids"])
        assert artifacts["input_ids"] == row["input_ids"]
        text = artifacts["rendered_prompt"].decode("utf-8")
        assert row["question"] in text
        assert replay._tokenizer.encode(text, add_special_tokens=False).ids == row["input_ids"]
    assert len(replay.prompt_artifacts(Q)["input_ids"]) == 37


def test_prompt_artifacts_need_no_decision_and_cannot_be_altered_through_the_return_value(replay, monkeypatch):
    monkeypatch.setattr(B, "apply_boundary", lambda *a, **k: pytest.fail("boundary reached"))
    first = replay.prompt_artifacts(Q)
    first["input_ids"].append(0)
    assert replay.prompt_artifacts(Q)["input_ids"] == first["input_ids"][:-1]
    for bad in ("unknown question", Q + " ", None, 4):
        with pytest.raises(B.RequestRejected):
            replay.prompt_artifacts(bad)


@pytest.mark.parametrize("permission", BOTH)
def test_result_hashes_bind_the_same_prompt_bytes_and_ids(replay, bank, permission):
    for row in bank[:30]:
        artifacts = replay.prompt_artifacts(row["question"])
        result = replay.run(row["question"], decide=fixed(permission))
        assert result["rendered_prompt_sha256"] == sha(artifacts["rendered_prompt"])
        assert result["rendered_prompt_bytes"] == len(artifacts["rendered_prompt"])
        assert result["input_ids"] == artifacts["input_ids"]
        compact = json.dumps(artifacts["input_ids"], separators=(",", ":")).encode()
        assert result["input_ids_sha256"] == sha(compact) == result["archived_input_ids_sha256"]
        assert result["question_sha256"] == sha(row["question"].encode())


def witness_stock(replay):
    return replay._logits[replay._index[Q]].clone()


def constructed(replay, monkeypatch, token, value):
    logits = replay._logits.clone()
    logits[replay._index[Q], token] = value
    monkeypatch.setattr(replay, "_logits", logits)
    return logits[replay._index[Q]].clone()


def test_constructed_vector_not_verified_uses_the_veto_and_changes_only_eos(replay, monkeypatch):
    stock = constructed(replay, monkeypatch, 19, 30000.0)
    result = replay.run(Q, decide=not_verified)
    (step,) = result["steps"]
    assert result["stop_cause"] == "VETO" and step["intervention"] == "EOS_VETO_AFTER_LEARNED_GATE"
    assert result["generated_token_ids"] == [B.EOS] and result["output_bytes"] == 0
    assert result["stock_first_token_is_eos"] is False and result["finish"] == "NATIVE_EOS"
    assert result["vectors"]["0-stock.bf16.bin"] == B._vector_bytes(stock)
    chosen = torch.frombuffer(bytearray(result["vectors"]["0-selected.bf16.bin"]), dtype=torch.bfloat16)
    differing = (stock.view(torch.int16) != chosen.view(torch.int16)).nonzero().flatten().tolist()
    assert differing == [B.EOS]
    assert float(chosen[B.EOS]) > float(B._non_eos(chosen).float().max())


def test_constructed_vector_verified_never_uses_the_veto(replay, monkeypatch):
    constructed(replay, monkeypatch, 19, 30000.0)
    result = replay.run(Q, decide=verified)
    assert result["stop_cause"] == "NONE" and result["generated_token_ids"] == [19]
    assert result["steps"][0]["intervention"] == "PCCG2_LEARNED_GATE"


@pytest.mark.parametrize("permission", BOTH)
def test_constructed_stock_eos_is_reported_as_no_cause_plus_a_flag(replay, monkeypatch, permission):
    constructed(replay, monkeypatch, B.EOS, 30000.0)
    result = replay.run(Q, decide=fixed(permission))
    assert result["stock_first_token_is_eos"] is True and result["stop_cause"] == "NONE"
    assert result["steps"][0]["stock_argmax_token"] == B.EOS
    assert result["generated_token_ids"] == [B.EOS] and result["first_token_is_native_eos"] is True
    assert result["output_bytes"] == 0 and result["finish"] == "NATIVE_EOS"
    assert result["first_token_matches_archive"] is None


def test_constructed_unexpected_verified_first_token_is_returned_not_discarded(replay, monkeypatch):
    constructed(replay, monkeypatch, 20, 30000.0)
    result = replay.run(Q, decide=verified)
    assert result["generated_token_ids"] == [20] and result["archived_first_token"] == 19
    assert result["first_token_matches_archive"] is False
    assert result["finish"] == "REPLAY_ONE_TOKEN_ONLY" and result["stop_cause"] == "NONE"
    assert base64.b64decode(result["output_utf8_base64"]) == replay._tokenizer.decode([20]).encode()
    assert set(result["vectors"]) == {"0-stock.bf16.bin", "0-selected.bf16.bin"}


def test_stop_cause_values_are_exactly_three():
    assert B.STOP_CAUSES == ("LEARNED_GATE", "VETO", "NONE")


class Abort(Exception):
    code = "AUTHORITY_UNAVAILABLE"


def spy_boundary(monkeypatch, events):
    real = B.apply_boundary

    def recording(*args, **kwargs):
        events.append("boundary")
        return real(*args, **kwargs)

    monkeypatch.setattr(B, "apply_boundary", recording)


@pytest.mark.parametrize("permission", BOTH)
def test_replay_decision_is_asked_exactly_once_immediately_before_the_boundary(replay, monkeypatch, permission):
    events = []
    spy_boundary(monkeypatch, events)

    def decide():
        events.append("decide")
        return permission

    result = replay.run(Q, decide=decide)
    assert events == ["decide", "boundary"]
    assert result["permission"] == permission
    assert result["generated_token_ids"] == ([19] if permission == B.PERMISSION_VERIFIED else [B.EOS])


class Text(str):
    pass


@pytest.mark.parametrize("answer", [True, False, None, 1, 0, "", "VALID_ALLOW", "VERIFIED", "permission_verified",
                                    " PERMISSION_VERIFIED", "PERMISSION_VERIFIED\n", b"PERMISSION_VERIFIED",
                                    ["PERMISSION_VERIFIED"], Text("PERMISSION_VERIFIED"), TRUE])
def test_any_other_decision_selects_nothing_and_keeps_the_scored_vector(replay, monkeypatch, answer):
    events = []
    spy_boundary(monkeypatch, events)
    with pytest.raises(B.BoundaryIntegrityError) as caught:
        replay.run(Q, decide=lambda: answer)
    assert events == []
    evidence = caught.value.evidence
    assert evidence["schema"] == "swiftapi-native-backend-evidence/2" and evidence["output_released"] is False
    assert evidence["selected_token_ids"] == [] and evidence["steps"] == [] and evidence["permission"] is None
    assert set(evidence["vectors"]) == {"0-stock.bf16.bin"}
    assert evidence["vectors"]["0-stock.bf16.bin"] == B._vector_bytes(witness_stock(replay))
    assert evidence["scored_without_selection"] == {"index": 0,
                                                    "stock_vector_sha256": sha(evidence["vectors"]["0-stock.bf16.bin"])}


def test_an_operational_error_in_the_decision_propagates_unchanged_and_selects_nothing(replay, monkeypatch):
    events = []
    spy_boundary(monkeypatch, events)
    raised = Abort("authority unreachable at the boundary")

    def decide():
        events.append("decide")
        raise raised

    with pytest.raises(Abort) as caught:
        replay.run(Q, decide=decide)
    assert caught.value is raised and caught.value.code == "AUTHORITY_UNAVAILABLE"
    assert events == ["decide"]
    evidence = caught.value.evidence
    assert evidence["selected_token_ids"] == [] and set(evidence["vectors"]) == {"0-stock.bf16.bin"}
    assert "output_utf8_base64" not in evidence and evidence["output_released"] is False
    
    assert replay.run(Q, decide=verified)["generated_token_ids"] == [19]
    assert replay.run(Q, decide=not_verified)["generated_token_ids"] == [B.EOS]


def test_decision_must_be_callable_and_is_not_asked_for_rejected_questions(replay):
    for bad in ("PERMISSION_VERIFIED", 1, True, None, object()):
        with pytest.raises(TypeError):
            replay.run(Q, decide=bad)
    called = []
    with pytest.raises(B.RequestRejected):
        replay.run("unknown question", decide=lambda: called.append(1) or B.PERMISSION_VERIFIED)
    assert called == []


def test_a_not_verified_token_other_than_eos_is_refused_with_its_vectors_and_no_bytes(replay, monkeypatch):
    pass
    def broken(module, gate, stock, permission):
        return stock.clone(), 0.0, B.LEARNED_GATE, B.STOP_NONE, False

    monkeypatch.setattr(B, "apply_boundary", broken)
    with pytest.raises(B.BoundaryIntegrityError, match="did not select native EOS") as caught:
        replay.run(Q, decide=not_verified)
    evidence = caught.value.evidence
    assert evidence["permission"] == "PERMISSION_NOT_VERIFIED" and evidence["selected_token_ids"] == [19]
    assert len(evidence["steps"]) == 1 and evidence["scored_without_selection"] is None
    assert set(evidence["vectors"]) == {"0-stock.bf16.bin", "0-selected.bf16.bin"}
    assert evidence["output_released"] is False
    assert not any("output" in key and key != "output_released" for key in evidence)
    
    assert replay.run(Q, decide=verified)["generated_token_ids"] == [19]


@pytest.mark.parametrize("question", ["What is 2 + 2", "what is 2 + 2?", "What is 2 + 2? ", " What is 2 + 2?",
                                      "What is 2 + 2?\n", "What is 2 + 3000?", "", None, 4, ["What is 2 + 2?"],
                                      "What is 2 + 2?​"])
def test_questions_outside_the_bank_are_rejected(replay, question):
    for decide in (verified, not_verified):
        with pytest.raises(B.RequestRejected):
            replay.run(question, decide=decide)


def test_independent_condition_oracle_and_the_two_published_conditions(monkeypatch):
    assert B.evaluate_condition(TRUE) is True
    assert B.evaluate_condition(FALSE_ONE_DIGIT) is False
    assert B.evaluate_condition("EQ(100000,100000)") is True
    for bad in ("EQ(012345,012345)", "EQ(485487, 485487)", "eq(485487,485487)", "", None, 485487):
        with pytest.raises(B.RequestRejected):
            B.evaluate_condition(bad)
    assert B._checked_condition(B.PERMISSION_VERIFIED) == TRUE
    assert B._checked_condition(B.PERMISSION_NOT_VERIFIED) == FALSE_ONE_DIGIT
    swapped = {B.PERMISSION_VERIFIED: FALSE_ONE_DIGIT, B.PERMISSION_NOT_VERIFIED: TRUE}
    monkeypatch.setattr(B, "CONDITIONS", swapped)
    for permission in BOTH:
        with pytest.raises(B.BoundaryIntegrityError, match="disagrees"):
            B._checked_condition(permission)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_score_vectors_fail(replay, value):
    stock = witness_stock(replay)
    stock[7] = value
    for permission in BOTH:
        with pytest.raises(B.BoundaryIntegrityError):
            B.apply_boundary(replay._module, replay._gate, stock, permission)


def test_wrong_shape_or_dtype_fails(replay):
    stock = witness_stock(replay)
    for bad in (stock[:-1], stock[None], stock.float(), torch.cat((stock, stock[:1]))):
        with pytest.raises(B.BoundaryIntegrityError):
            B.apply_boundary(replay._module, replay._gate, bad, B.PERMISSION_VERIFIED)


def test_apply_boundary_accepts_only_the_two_permission_values(replay):
    stock = witness_stock(replay)
    for bad in ("VALID_ALLOW", "VALID_DENY", "ORIGINAL_ONLY", TRUE, FALSE_ONE_DIGIT, None, True, False, 1):
        with pytest.raises(B.BoundaryIntegrityError):
            B.apply_boundary(replay._module, replay._gate, stock, bad)
    assert list(inspect.signature(B.apply_boundary).parameters) == ["module", "gate", "stock", "permission"]


def test_non_eos_mutation_is_detected(replay):
    original = replay._module

    class Mutating(original.SeparatedContinuationModel):
        def boundary(self, content_logits, condition_ids=None, first_step=True, permission_sign=1.0):
            logits, state = super().boundary(content_logits, condition_ids, first_step, permission_sign)
            logits[:, 19] = logits[:, 19] - 1
            return logits, state

    fake = types.SimpleNamespace(SeparatedContinuationModel=Mutating, condition_tokens=original.condition_tokens)
    for permission in BOTH:
        with pytest.raises(B.BoundaryIntegrityError, match="Non-EOS mutation"):
            B.apply_boundary(fake, replay._gate, witness_stock(replay), permission)


def test_boundary_always_passes_permission_sign_plus_one_and_the_derived_condition(replay):
    original = replay._module
    seen = []

    class Recording(original.SeparatedContinuationModel):
        def boundary(self, content_logits, condition_ids=None, first_step=True, permission_sign=1.0):
            seen.append((first_step, permission_sign, condition_ids[0].tolist()))
            return super().boundary(content_logits, condition_ids, first_step, permission_sign)

    fake = types.SimpleNamespace(SeparatedContinuationModel=Recording, condition_tokens=original.condition_tokens)
    B.apply_boundary(fake, replay._gate, witness_stock(replay), B.PERMISSION_VERIFIED)
    B.apply_boundary(fake, replay._gate, witness_stock(replay), B.PERMISSION_NOT_VERIFIED)
    assert seen == [(True, 1.0, original.condition_tokens(TRUE)), (True, 1.0, original.condition_tokens(FALSE_ONE_DIGIT))]


def test_bad_mode_and_device_are_rejected():
    for mode in ("ORIGINAL_ONLY", "replay", "", None, "SIMULATED"):
        with pytest.raises(ValueError):
            B.PCCG2Backend(SOURCE, CONTENT, HARNESS, mode)
    for device in ("auto", "cuda", "cuda:0", "mps", "", None, 0):
        with pytest.raises(ValueError):
            B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.REPLAY, device)
        with pytest.raises(ValueError):
            B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.REPLAY, device, full_model=True)
    assert B.DEVICES == ("cpu", "cuda")
    
    with pytest.raises(ValueError, match="full_model"):
        B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.FRESH, "cuda")
    for device in ("auto", "cuda:0", "mps", "", None):
        with pytest.raises(ValueError):
            B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.FRESH, device, full_model=True)
    
    for options in ({"attention": "SDPA_MATH"}, {"attention": "SDPA_MATH_DETERMINISTIC"}, {"max_new_tokens": 1},
                    {"max_new_tokens": 8}):
        with pytest.raises(ValueError, match="replay"):
            B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.REPLAY, **options)
    for options in ({"attention": "math"}, {"attention": None}, {"max_new_tokens": 0}, {"max_new_tokens": 17},
                    {"max_new_tokens": 4.0}, {"max_new_tokens": True}, {"max_new_tokens": "4"}):
        with pytest.raises(ValueError):
            B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.FRESH, **options)
    for flag in (1, "yes", None):
        with pytest.raises(ValueError):
            B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.REPLAY, full_model=flag)
    assert B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.REPLAY, full_model=True).metadata["full_model_enabled"] is False


@pytest.mark.parametrize("name", ["src/model.py", "src/core.py", "gate/permission.safetensors", "config.json",
                                  "evidence/bank.json", "evidence/bank-first-logits.safetensors",
                                  "content/tokenizer.json", "evidence/base-identity.json", "LICENSE"])
def test_one_changed_byte_in_any_pinned_source_file_fails(tmp_path, name):
    source = linked_copy(SOURCE, tmp_path / "source")
    raw = bytearray((source / name).read_bytes())
    raw[len(raw) // 2] ^= 1
    replace(source / name, bytes(raw))
    with pytest.raises(B.SourceIdentityError):
        B.PCCG2Backend(source, CONTENT, HARNESS, B.REPLAY)


def test_missing_truncated_or_symlinked_source_fails(tmp_path):
    source = linked_copy(SOURCE, tmp_path / "missing")
    (source / "src" / "model.py").unlink()
    with pytest.raises(B.SourceIdentityError):
        B.PCCG2Backend(source, CONTENT, HARNESS, B.REPLAY)

    source = linked_copy(SOURCE, tmp_path / "truncated")
    replace(source / "evidence" / "bank.json", (SOURCE / "evidence" / "bank.json").read_bytes()[:-1])
    with pytest.raises(B.SourceIdentityError):
        B.PCCG2Backend(source, CONTENT, HARNESS, B.REPLAY)

    source = linked_copy(SOURCE, tmp_path / "symlinked")
    outside = tmp_path / "outside-model.py"
    outside.write_bytes((SOURCE / "src" / "model.py").read_bytes())
    (source / "src" / "model.py").unlink()
    (source / "src" / "model.py").symlink_to(outside)
    with pytest.raises(B.SourceIdentityError, match="escapes"):
        B.PCCG2Backend(source, CONTENT, HARNESS, B.REPLAY)


def test_changed_harness_inventory_fails(tmp_path):
    for name in ("SOURCE_MANIFEST.json", "upstream/SHA256SUMS.original"):
        harness = tmp_path / name.replace("/", "_")
        (harness / "upstream").mkdir(parents=True)
        for item in ("SOURCE_MANIFEST.json", "upstream/SHA256SUMS.original"):
            shutil.copyfile(HARNESS / item, harness / item)
        raw = (harness / name).read_bytes()
        (harness / name).write_bytes(raw.replace(b"a", b"b", 1))
        with pytest.raises(B.SourceIdentityError):
            B.PCCG2Backend(SOURCE, CONTENT, harness, B.REPLAY)
    with pytest.raises((B.SourceIdentityError, OSError)):
        B.PCCG2Backend(SOURCE, CONTENT, tmp_path / "absent", B.REPLAY)


def test_stale_bytecode_and_a_foreign_core_module_are_not_executed(tmp_path):
    source = linked_copy(SOURCE, tmp_path / "source")
    cache = source / "src" / "__pycache__"
    cache.mkdir()
    for stem in ("core", "model"):
        (cache / f"{stem}.cpython-{sys.version_info.major}{sys.version_info.minor}.pyc").write_bytes(b"not bytecode")
    foreign = types.ModuleType("core")
    foreign.EOS = 0
    sys.modules["core"] = foreign
    try:
        backend = B.PCCG2Backend(source, CONTENT, HARNESS, B.REPLAY)
        assert sys.modules["core"] is foreign
    finally:
        sys.modules.pop("core", None)
    assert backend._module.EOS == B.EOS
    assert backend.run(Q, decide=not_verified)["generated_token_ids"] == [B.EOS]
    assert "core" not in sys.modules


def test_original_model_runs_from_verified_bytes_without_import_path_changes(replay):
    before = list(sys.path)
    B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.REPLAY)
    assert sys.path == before
    assert not any(str(SOURCE) in entry for entry in sys.path)
    assert hashlib.sha256((SOURCE / "src" / "model.py").read_bytes()).hexdigest() == B.PINS["src/model.py"]


def test_unpinned_dependency_version_fails(monkeypatch):
    real = B.importlib.metadata.version
    monkeypatch.setattr(B.importlib.metadata, "version", lambda name: "2.9.0" if name == "torch" else real(name))
    with pytest.raises(B.SourceIdentityError, match="torch"):
        B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.REPLAY)


def test_replay_preflight_is_ready_and_runs_no_inference(replay):
    status = replay.preflight()
    json.dumps(status, allow_nan=False)
    assert status["ready"] is True and status["status"] == "READY_RECORDED_LOGITS_REPLAY"
    assert status["profile"] == B.PROFILE and status["hardware"]["device"] == "cpu"
    assert status["hardware"]["torch_build"] == torch.__version__ and "cpu_capability" in status["hardware"]
    assert status["inference_executed"] is False and status["model_loaded"] is False
    assert status["fallback"] is False and status["quantization"] is False and status["download"] is False
    assert replay._content is None


def loader_must_not_be_reached(monkeypatch):
    import transformers
    monkeypatch.setattr(transformers.AutoModelForCausalLM, "from_pretrained",
                        lambda *a, **k: pytest.fail("content model loader reached"))


def test_fresh_mode_is_disabled_by_default_and_opens_no_weight_file(monkeypatch):
    pass
    loader_must_not_be_reached(monkeypatch)
    fresh = B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.FRESH)
    monkeypatch.setattr(fresh, "_weight_signature", lambda: pytest.fail("weight files inspected"))
    monkeypatch.setattr(fresh, "_verify_weights", lambda signature: pytest.fail("weight files hashed"))
    assert fresh.metadata["mode"] == B.FRESH and fresh.metadata["full_model_enabled"] is False
    assert fresh.metadata["max_new_tokens"] == 4 and fresh.metadata["replay_notice"] is None
    status = fresh.preflight()
    json.dumps(status, allow_nan=False)
    assert status["ready"] is False and status["status"] == "UNAVAILABLE_FULL_MODEL_NOT_ENABLED"
    assert status["full_model_enabled"] is False and status["model_loaded"] is False
    assert status["inference_executed"] is False and status["fallback"] is False
    called = []
    for permission in BOTH:
        with pytest.raises(B.RuntimeUnavailable, match="UNAVAILABLE_FULL_MODEL_NOT_ENABLED") as caught:
            fresh.run(Q, decide=lambda: called.append(1) or permission)
        facts = caught.value.evidence["execution"]
        assert facts == {"content_model_loaded": False, "forward_passes_started": 0, "forward_passes_completed": 0,
                         "model_executed": False, "decoder_selected_a_token": False}
        assert caught.value.evidence["vectors"] == {} and caught.value.evidence["scores_ready_at"] is None
    with pytest.raises(B.RuntimeUnavailable, match="UNAVAILABLE_FULL_MODEL_NOT_ENABLED"):
        fresh.warmup()
    assert called == [] and fresh._content is None and fresh._logits is None and fresh.mode == B.FRESH


def test_default_backends_never_import_the_model_library():
    pass
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "from swiftapi_native_service import backend as B\n"
        "s, c, h = (Path(x) for x in sys.argv[1:4])\n"
        "fresh = B.PCCG2Backend(s, c, h, B.FRESH)\n"
        "assert fresh.preflight()['status'] == 'UNAVAILABLE_FULL_MODEL_NOT_ENABLED'\n"
        "try:\n"
        "    fresh.run('What is 2 + 2?', decide=lambda: B.PERMISSION_VERIFIED)\n"
        "    raise SystemExit('ran')\n"
        "except B.RuntimeUnavailable:\n"
        "    pass\n"
        "replay = B.PCCG2Backend(s, c, h, B.REPLAY)\n"
        "assert replay.run('What is 2 + 2?', decide=lambda: B.PERMISSION_NOT_VERIFIED)['generated_token_ids'] == [B.EOS]\n"
        "replay.warmup(); replay.preflight()\n"
        "assert 'transformers' not in sys.modules, 'model library imported'\n"
        "print('OK ' + B.__file__)\n"
    )
    import subprocess
    
    
    done = subprocess.run([sys.executable, "-c", code, str(SOURCE), str(CONTENT), str(HARNESS)],
                          capture_output=True, text=True, timeout=300,
                          env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    assert done.returncode == 0 and done.stdout.startswith("OK "), done.stderr[-2000:]
    assert Path(done.stdout.strip()[3:]).resolve() == Path(B.__file__).resolve(), done.stdout


def test_the_full_model_is_off_unless_an_operator_asks_and_one_place_can_load_it():
    pass
    import ast
    assert inspect.signature(B.PCCG2Backend.__init__).parameters["full_model"].default is False
    assert inspect.signature(B.PCCG2Backend.__init__).parameters["full_model"].kind is inspect.Parameter.KEYWORD_ONLY
    package = sorted(PACKAGE.glob("*.py"))
    assert len(package) >= 8 and PACKAGE / "backend.py" in package
    tools = sorted((WORKSPACE / "tools").glob("*.py")) if (WORKSPACE / "tools").is_dir() else []
    paths = package + tools
    for path in paths:
        text = path.read_text()
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == "full_model":
                        assert not (isinstance(keyword.value, ast.Constant) and keyword.value.value is True), path
        assert "from_pretrained" not in text or path.name == "backend.py", path


def test_enabled_fresh_mode_without_weights_is_unavailable_and_never_falls_back(tmp_path, monkeypatch):
    loader_must_not_be_reached(monkeypatch)
    fresh = B.PCCG2Backend(SOURCE, tmp_path / "no-content", HARNESS, B.FRESH, full_model=True)
    assert fresh.metadata["full_model_enabled"] is True and fresh._logits is None
    status = fresh.preflight()
    json.dumps(status, allow_nan=False)
    assert status["ready"] is False and status["status"] == "UNAVAILABLE_CONTENT"
    assert status["inference_executed"] is False and status["fallback"] is False
    called = []
    for permission in BOTH:
        with pytest.raises(B.RuntimeUnavailable):
            fresh.run(Q, decide=lambda: called.append(1) or permission)
    with pytest.raises(B.RequestRejected):
        fresh.run("unknown question", decide=verified)
    assert called == [] and fresh._content is None


def test_enabled_fresh_mode_honors_the_memory_preflight_with_real_weights_present(monkeypatch):
    pass
    if not (CONTENT / "model-00001-of-00003.safetensors").is_file():
        pytest.skip("Full pinned weights are not present on this machine")
    import psutil
    loader_must_not_be_reached(monkeypatch)
    low = types.SimpleNamespace(total=16 * 1024 ** 3, available=2 * 1024 ** 3)
    monkeypatch.setattr(psutil, "virtual_memory", lambda: low)
    fresh = B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.FRESH, full_model=True)
    monkeypatch.setattr(fresh, "_verify_weights", lambda signature: pytest.fail("weight files hashed"))
    status = fresh.preflight()
    assert status["ready"] is False and status["status"] == "UNAVAILABLE_HARDWARE"
    assert status["hardware"]["local_weight_bytes"] == 3957900840 + 3987450520 + 99630640
    assert status["hardware"]["required_available_bytes"] == int(status["hardware"]["local_weight_bytes"] * 1.5 + 2 * 1024 ** 3)
    assert status["inference_executed"] is False
    with pytest.raises(B.RuntimeUnavailable, match="UNAVAILABLE_HARDWARE"):
        fresh.run(Q, decide=verified)
    assert fresh._content is None and fresh._weights_verified is None


def test_incomplete_or_resized_weights_are_unavailable(tmp_path):
    content = tmp_path / "content"
    content.mkdir()
    fresh = B.PCCG2Backend(SOURCE, content, HARNESS, B.FRESH, full_model=True)
    for name, item in fresh._base_identity.items():
        (content / name).write_bytes(b"x" if name.endswith(".safetensors") else b"y" * item["bytes"])
    assert fresh.preflight()["status"] == "UNAVAILABLE_CONTENT"


class StubContent:
    pass

    def __init__(self, first, later_token):
        self.first, self.later_token, self.calls, self.fed = first, later_token, 0, []

    def __call__(self, input_ids, past_key_values, use_cache, logits_to_keep):
        self.calls += 1
        self.fed.append(input_ids[0].tolist())
        if past_key_values is None:
            vector = self.first
        else:
            vector = torch.zeros(B.VOCABULARY, dtype=torch.bfloat16)
            vector[self.later_token] = 10
        return types.SimpleNamespace(logits=vector[None, None, :], past_key_values=self.calls)


def loop(replay, stub, decide, cap=4):
    trace = B._Trace("FRESH_FORWARD_PASS")
    B._generate(stub, replay._module, replay._gate, replay.prompt_artifacts(Q)["input_ids"], decide, "cpu", cap, trace)
    return trace


def test_generation_loop_applies_the_boundary_at_step_zero_only(replay):
    stub = StubContent(witness_stock(replay), B.EOS)
    trace = loop(replay, stub, verified)
    assert trace.tokens == [19, B.EOS] and stub.calls == 2
    assert [s["intervention"] for s in trace.steps] == ["PCCG2_LEARNED_GATE", "NONE"]
    assert trace.steps[1]["permission_state"] is None
    assert trace.vectors["1-stock.bf16.bin"] == trace.vectors["1-selected.bf16.bin"]
    assert set(trace.vectors) == {"0-stock.bf16.bin", "0-selected.bf16.bin", "1-stock.bf16.bin", "1-selected.bf16.bin"}

    stub = StubContent(witness_stock(replay), B.EOS)
    trace = loop(replay, stub, not_verified)
    assert trace.tokens == [B.EOS] and stub.calls == 1 and len(trace.steps) == 1 and len(trace.vectors) == 2
    assert trace.cause == "LEARNED_GATE"


def test_generation_loop_stops_at_the_cap_without_inventing_eos(replay):
    trace = loop(replay, StubContent(witness_stock(replay), 19), verified)
    assert trace.tokens == [19, 19, 19, 19] and len(trace.steps) == 4 and B.EOS not in trace.tokens


def test_generation_loop_asks_after_the_forward_pass_and_only_at_step_zero(replay, monkeypatch):
    events = []
    spy_boundary(monkeypatch, events)

    class Recording(StubContent):
        def __call__(self, *args, **kwargs):
            events.append("forward")
            return super().__call__(*args, **kwargs)

    def decide():
        events.append("decide")
        return B.PERMISSION_VERIFIED

    assert loop(replay, Recording(witness_stock(replay), B.EOS), decide).tokens == [19, B.EOS]
    assert events == ["forward", "decide", "boundary", "forward"]


def test_generation_loop_decision_error_selects_no_token(replay, monkeypatch):
    events = []
    spy_boundary(monkeypatch, events)
    stub = StubContent(witness_stock(replay), B.EOS)

    def unreachable():
        raise Abort("authority unreachable at the boundary")

    with pytest.raises(Abort):
        loop(replay, stub, unreachable)
    with pytest.raises(B.BoundaryIntegrityError):
        loop(replay, stub, lambda: True)
    assert events == [] and stub.calls == 2


@pytest.fixture
def stubbed_fresh(tmp_path, monkeypatch):
    loader_must_not_be_reached(monkeypatch)
    fresh = B.PCCG2Backend(SOURCE, tmp_path / "no-content", HARNESS, B.FRESH, full_model=True)
    holder = types.SimpleNamespace(stub=None)
    monkeypatch.setattr(fresh, "_load_content", lambda: holder.stub)
    return fresh, holder


def test_stubbed_fresh_verified_trace_to_native_eos(replay, stubbed_fresh):
    fresh, holder = stubbed_fresh
    holder.stub = StubContent(witness_stock(replay), B.EOS)
    result = fresh.run(Q, decide=verified)
    json.dumps(public(result), allow_nan=False)
    assert result["mode"] == B.FRESH and result["generated_token_ids"] == [19, B.EOS]
    assert result["finish"] == "NATIVE_EOS" and result["answer_scope"] == "COMPLETE_TO_NATIVE_EOS"
    assert result["generation_complete"] is True and result["later_tokens"] == "GENERATED_FRESH"
    assert base64.b64decode(result["output_utf8_base64"]) == b"4" and result["output_sha256"] == sha(b"4")
    assert result["input_ids_role"] == "FED_TO_MODEL" and result["max_new_tokens"] == 4
    assert holder.stub.fed == [result["input_ids"], [19]]
    assert result["stop_cause"] == "NONE" and result["first_token_matches_archive"] is True
    assert [step["score_source"] for step in result["steps"]] == ["FRESH_FORWARD_PASS"] * 2
    assert len(result["vectors"]) == 4


def test_stubbed_fresh_not_verified_is_one_forward_pass_and_native_eos(replay, stubbed_fresh):
    fresh, holder = stubbed_fresh
    holder.stub = StubContent(witness_stock(replay), 19)
    result = fresh.run(Q, decide=not_verified)
    assert result["generated_token_ids"] == [B.EOS] and holder.stub.calls == 1
    assert result["output_bytes"] == 0 and result["stop_cause"] == "LEARNED_GATE"
    assert result["finish"] == "NATIVE_EOS" and result["generation_complete"] is True


def test_stubbed_fresh_cap_is_labelled_truncated(replay, stubbed_fresh):
    fresh, holder = stubbed_fresh
    holder.stub = StubContent(witness_stock(replay), 19)
    result = fresh.run(Q, decide=verified)
    assert result["generated_token_ids"] == [19, 19, 19, 19] and holder.stub.calls == 4
    assert result["finish"] == "TOKEN_CAP" and result["answer_scope"] == "TRUNCATED_AT_TOKEN_CAP"
    assert result["generation_complete"] is False
    assert base64.b64decode(result["output_utf8_base64"]) == b"4444"


def test_stubbed_fresh_unexpected_trace_is_returned_in_full(replay, stubbed_fresh):
    fresh, holder = stubbed_fresh
    first = witness_stock(replay)
    first[20] = 30000.0
    holder.stub = StubContent(first, 21)
    result = fresh.run(Q, decide=verified)
    assert result["generated_token_ids"] == [20, 21, 21, 21]
    assert result["first_token_matches_archive"] is False and result["archived_first_token"] == 19
    assert len(result["steps"]) == 4 and len(result["vectors"]) == 8


def test_stubbed_fresh_stock_eos_under_verified_permission_is_returned_and_flagged(replay, stubbed_fresh):
    fresh, holder = stubbed_fresh
    first = witness_stock(replay)
    first[B.EOS] = 30000.0
    holder.stub = StubContent(first, 19)
    result = fresh.run(Q, decide=verified)
    assert result["generated_token_ids"] == [B.EOS] and result["stock_first_token_is_eos"] is True
    assert result["stop_cause"] == "NONE" and result["output_bytes"] == 0


def test_stubbed_fresh_error_at_a_later_step_keeps_the_earlier_steps(replay, stubbed_fresh):
    fresh, holder = stubbed_fresh

    class Broken(StubContent):
        def __call__(self, input_ids, past_key_values, use_cache, logits_to_keep):
            out = super().__call__(input_ids, past_key_values, use_cache, logits_to_keep)
            if self.calls == 3:
                out.logits[0, 0, 5] = float("nan")
            return out

    holder.stub = Broken(witness_stock(replay), 19)
    with pytest.raises(B.BoundaryIntegrityError, match="Nonfinite") as caught:
        fresh.run(Q, decide=verified)
    evidence = caught.value.evidence
    assert evidence["mode"] == B.FRESH and evidence["permission"] == "PERMISSION_VERIFIED"
    assert evidence["selected_token_ids"] == [19, 19] and len(evidence["steps"]) == 2
    assert evidence["scored_without_selection"]["index"] == 2
    assert set(evidence["vectors"]) == {"0-stock.bf16.bin", "0-selected.bf16.bin", "1-stock.bf16.bin",
                                        "1-selected.bf16.bin", "2-stock.bf16.bin"}
    assert evidence["output_released"] is False and "output_utf8_base64" not in evidence


def test_stubbed_fresh_forward_error_is_recorded_as_started_and_not_completed(replay, stubbed_fresh):
    fresh, holder = stubbed_fresh

    class Dead:
        def __call__(self, **kwargs):
            raise RuntimeError("TEST DOUBLE forward error")

    holder.stub = Dead()
    called = []
    with pytest.raises(RuntimeError) as caught:
        fresh.run(Q, decide=lambda: called.append(1) or B.PERMISSION_VERIFIED)
    evidence = caught.value.evidence
    assert called == [] and evidence["vectors"] == {} and evidence["steps"] == []
    assert evidence["execution"] == {"content_model_loaded": True, "forward_passes_started": 1,
                                     "forward_passes_completed": 0, "model_executed": False,
                                     "decoder_selected_a_token": False}
    assert evidence["scores_ready_at"] is None and evidence["timing"]["decision_outcome"] == "NOT_ASKED"


def test_a_failed_load_is_not_a_model_execution(tmp_path, monkeypatch):
    pass
    loader_must_not_be_reached(monkeypatch)
    fresh = B.PCCG2Backend(SOURCE, tmp_path / "no-content", HARNESS, B.FRESH, full_model=True)

    def failing():
        raise B.RuntimeUnavailable("UNAVAILABLE_HARDWARE: TEST DOUBLE load error")

    monkeypatch.setattr(fresh, "_load_content", failing)
    with pytest.raises(B.RuntimeUnavailable) as caught:
        fresh.run(Q, decide=verified)
    facts = caught.value.evidence["execution"]
    assert facts["content_model_loaded"] is False and facts["model_executed"] is False
    assert facts["forward_passes_started"] == 0 and caught.value.evidence["output_released"] is False


def test_execution_facts_count_forward_passes(replay, stubbed_fresh):
    fresh, holder = stubbed_fresh
    assert replay.run(Q, decide=verified)["execution_facts"] == {
        "content_model_loaded": False, "forward_passes_started": 0, "forward_passes_completed": 0,
        "model_executed": False, "decoder_selected_a_token": True}
    holder.stub = StubContent(witness_stock(replay), B.EOS)
    assert fresh.run(Q, decide=verified)["execution_facts"] == {
        "content_model_loaded": True, "forward_passes_started": 2, "forward_passes_completed": 2,
        "model_executed": True, "decoder_selected_a_token": True}
    holder.stub = StubContent(witness_stock(replay), 19)
    facts = fresh.run(Q, decide=not_verified)["execution_facts"]
    assert facts["forward_passes_completed"] == 1 and facts["model_executed"] is True


def test_result_says_which_gate_acted_and_what_it_read(replay):
    for permission, digits in ((B.PERMISSION_VERIFIED, [4, 8, 5, 4, 8, 7, 4, 8, 5, 4, 8, 7]),
                               (B.PERMISSION_NOT_VERIFIED, [4, 8, 5, 4, 8, 7, 4, 8, 5, 4, 8, 9])):
        result = replay.run(Q, decide=fixed(permission))
        gate = result["gate"]
        json.dumps(gate, allow_nan=False)
        assert gate["file_sha256"] == "17f2c83502ab96b3ee43c51c5c221df528f73bd378c02598c2cfbfdacd61cc26"
        assert gate["file_sha256"] == sha((SOURCE / "gate" / "permission.safetensors").read_bytes())
        assert gate["original_model_py_sha256"] == sha((SOURCE / "src" / "model.py").read_bytes())
        assert gate["state_sha256"] == replay.metadata["gate_state_sha256"] == B._gate_state_sha(replay._gate)
        assert gate["state_rechecked_this_run"] is True and gate["first_step_only"] is True
        assert gate["trainable_parameters"] == 101 and gate["gain"] == 32.0 and gate["permission_sign"] == 1.0
        assert gate["dtype"] == "float32" and gate["device"] == "cpu"
        assert gate["condition_token_ids"] == digits
        assert gate["permission_state"] == result["steps"][0]["permission_state"]
        assert "no key, grant or signature" in gate["reads"]


def test_gate_state_fingerprint_is_independent_of_the_backend_and_of_load_order():
    pass
    from safetensors.torch import load as load_tensors
    tensors = load_tensors((SOURCE / "gate" / "permission.safetensors").read_bytes())
    digest = hashlib.sha256()
    for name in sorted(tensors):
        tensor = tensors[name]
        digest.update(name.encode() + b"\0" + str(tensor.dtype).encode() + b"\0"
                      + json.dumps(list(tensor.shape)).encode() + b"\0" + tensor.reshape(-1).numpy().tobytes())
    first = B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.REPLAY)
    second = B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.REPLAY)
    assert first.metadata["gate_state_sha256"] == second.metadata["gate_state_sha256"] == digest.hexdigest()


@pytest.mark.parametrize("permission", BOTH)
def test_a_gate_changed_in_memory_after_load_is_refused_before_any_decision(permission):
    tampered = B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.REPLAY)
    with torch.no_grad():
        next(iter(tampered._gate.parameters())).view(-1)[0] += 1.0
    called = []
    with pytest.raises(B.SourceIdentityError, match="Gate tensors changed") as caught:
        tampered.run(Q, decide=lambda: called.append(1) or permission)
    assert called == [] and caught.value.evidence["vectors"] == {}
    assert caught.value.evidence["execution"]["decoder_selected_a_token"] is False


def test_a_gate_changed_during_the_run_is_refused_and_no_bytes_are_returned(replay):
    tampered = B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.REPLAY)

    def decide():
        with torch.no_grad():
            tampered._gate.offset.view(-1)[0] += 1.0
        return B.PERMISSION_VERIFIED

    with pytest.raises(B.SourceIdentityError, match="Gate tensors changed") as caught:
        tampered.run(Q, decide=decide)
    assert caught.value.evidence["output_released"] is False and len(caught.value.evidence["steps"]) == 1


def test_timing_separates_lock_wait_load_and_the_first_forward_pass(replay, tmp_path, monkeypatch, clock):
    loader_must_not_be_reached(monkeypatch)
    fresh = B.PCCG2Backend(SOURCE, tmp_path / "no-content", HARNESS, B.FRESH, full_model=True)

    class Slow(StubContent):
        def __call__(self, *args, **kwargs):
            clock.advance(40.0 if self.calls == 0 else 5.0)
            return super().__call__(*args, **kwargs)

    stub = Slow(witness_stock(replay), B.EOS)

    def load():
        clock.advance(25.0)
        return stub

    monkeypatch.setattr(fresh, "_load_content", load)
    timing = fresh.run(Q, decide=verified)["timing"]
    assert timing["lock_wait_seconds"] == 0.0 and timing["content_ready_seconds"] == 25.0
    assert timing["first_forward_seconds"] == 40.0 and timing["scores_ready_elapsed_seconds"] == 65.0
    assert timing["scores_ready_at"] == 1_800_000_065.0
    replayed = replay.run(Q, decide=verified)["timing"]
    assert replayed["first_forward_seconds"] is None and replayed["content_ready_seconds"] == 0.0


def test_lock_wait_is_measured(replay, clock):
    import threading
    replay._lock.acquire()
    done = {}
    worker = threading.Thread(target=lambda: done.update(result=replay.run(Q, decide=verified)))
    worker.start()
    for _ in range(200):
        if worker.is_alive() and not done:
            __import__("time").sleep(0.01)
    clock.advance(9.0)
    replay._lock.release()
    worker.join(timeout=30)
    assert done["result"]["timing"]["lock_wait_seconds"] == 9.0
    assert done["result"]["scores_ready_elapsed_seconds"] == 9.0


def test_container_memory_limit_is_read_and_enforced(simulated_cuda, tmp_path, monkeypatch):
    build, _ = simulated_cuda
    limit, used = tmp_path / "memory.max", tmp_path / "memory.current"
    monkeypatch.setattr(B, "CGROUP_MEMORY", ((str(limit), str(used)),))
    fresh = build()
    for text, current, ready in (("max", 5, True), (str(REQUIRED + 10), 10, True), (str(REQUIRED + 10), 11, False),
                                 (str(8 * GIB), 0, False)):
        limit.write_text(text + "\n")
        used.write_text(f"{current}\n")
        status = fresh.preflight()
        assert status["ready"] is ready, (text, current, status.get("reason"))
        assert status["hardware"]["cgroup_memory_used_bytes"] == current
        assert status["hardware"]["cgroup_memory_limit_bytes"] == (None if text == "max" else int(text))
        if not ready:
            assert "container memory" in status["reason"]
    monkeypatch.setattr(B, "CGROUP_MEMORY", ((str(tmp_path / "absent"), str(tmp_path / "absent2")),))
    assert B._cgroup_memory() == (None, None) and fresh.preflight()["ready"] is True


class FakeWeights:
    pass

    def __init__(self, dtype=torch.bfloat16):
        self.dtype, self.forward_calls, self.moved = dtype, 0, []

    def eval(self):
        return self

    def requires_grad_(self, flag):
        assert flag is False
        return self

    def to(self, device):
        self.moved.append(device)
        return self

    def parameters(self):
        return iter([torch.zeros(1, dtype=self.dtype)])

    def __call__(self, *args, **kwargs):
        self.forward_calls += 1
        raise AssertionError("forward pass attempted")


@pytest.fixture
def spied_fresh(tmp_path, monkeypatch):
    pass
    import psutil
    import transformers
    fresh = B.PCCG2Backend(SOURCE, tmp_path / "content", HARNESS, B.FRESH, full_model=True)
    spy = types.SimpleNamespace(events=[], load_kwargs=[], model=FakeWeights(), load_error=None,
                                verify_error=None, memory=48 * 1024 ** 3,
                                signature=(("model-00001-of-00003.safetensors", 3957900840, 1, 1),))

    def verify(signature):
        spy.events.append("verify")
        if spy.verify_error:
            raise spy.verify_error
        fresh._weights_verified = signature

    def load(path, **kwargs):
        spy.events.append("load")
        spy.load_kwargs.append(dict(kwargs, path=path))
        if spy.load_error:
            raise spy.load_error
        return spy.model

    monkeypatch.setattr(fresh, "_weight_signature", lambda: spy.signature)
    monkeypatch.setattr(fresh, "_verify_weights", verify)
    monkeypatch.setattr(psutil, "virtual_memory", lambda: types.SimpleNamespace(total=64 * 1024 ** 3, available=spy.memory))
    monkeypatch.setattr(transformers.AutoModelForCausalLM, "from_pretrained", load)
    return fresh, spy


def test_warmup_is_never_automatic(spied_fresh):
    fresh, spy = spied_fresh
    assert list(inspect.signature(fresh.warmup).parameters) == []
    assert fresh.preflight()["ready"] is True and fresh.preflight()["model_loaded"] is False
    json.dumps(fresh.metadata, allow_nan=False)
    assert "load" not in spy.events and fresh._content is None


def test_warmup_verifies_then_loads_once_without_a_forward_pass(spied_fresh):
    fresh, spy = spied_fresh
    first = fresh.warmup()
    json.dumps(first, allow_nan=False)
    assert first["status"] == "WARM" and first["model_loaded"] is True and first["loaded_by_this_call"] is True
    assert first["inference_executed"] is False and first["fallback"] is False and first["download"] is False
    assert spy.events.index("verify") < spy.events.index("load") and spy.events.count("load") == 1
    (kwargs,) = spy.load_kwargs
    assert kwargs["local_files_only"] is True and kwargs["trust_remote_code"] is False
    assert kwargs["use_safetensors"] is True and kwargs["torch_dtype"] is torch.bfloat16
    assert kwargs["path"] == str(fresh._content_dir.resolve())
    assert spy.model.moved == ["cpu"] and spy.model.forward_calls == 0
    second = fresh.warmup()
    assert second["loaded_by_this_call"] is False and spy.events.count("load") == 1
    assert spy.model.forward_calls == 0


def test_warm_backend_stays_ready_when_free_memory_later_drops(spied_fresh):
    fresh, spy = spied_fresh
    fresh.warmup()
    spy.memory = 1 * 1024 ** 3
    status = fresh.preflight()
    assert status["ready"] is True and status["model_loaded"] is True and status["inference_executed"] is False
    assert spy.events.count("load") == 1


def test_warmup_honors_the_memory_preflight(spied_fresh):
    fresh, spy = spied_fresh
    spy.memory = 2 * 1024 ** 3
    with pytest.raises(B.RuntimeUnavailable, match="UNAVAILABLE_HARDWARE"):
        fresh.warmup()
    assert spy.events == [] and fresh._content is None


def test_warmup_refuses_weights_that_fail_identity(spied_fresh):
    fresh, spy = spied_fresh
    spy.verify_error = B.SourceIdentityError("Content identity mismatch: model-00001-of-00003.safetensors")
    assert fresh.preflight()["status"] == "UNSAFE_CONTENT_IDENTITY"
    with pytest.raises(B.SourceIdentityError):
        fresh.warmup()
    assert "load" not in spy.events and fresh._content is None


def test_warmup_load_error_is_unavailable_and_leaves_nothing_loaded(spied_fresh):
    fresh, spy = spied_fresh
    for error in (RuntimeError("out of memory"), MemoryError(), OSError("unreadable shard")):
        spy.load_error = error
        with pytest.raises(B.RuntimeUnavailable, match="UNAVAILABLE_HARDWARE"):
            fresh.warmup()
        assert fresh._content is None


def test_warmup_rejects_weights_that_are_not_bf16(spied_fresh):
    fresh, spy = spied_fresh
    spy.model = FakeWeights(torch.float32)
    with pytest.raises(B.SourceIdentityError, match="BF16"):
        fresh.warmup()
    assert fresh._content is None and spy.model.forward_calls == 0


def test_warmup_rejects_content_that_changes_while_loading(spied_fresh):
    fresh, spy = spied_fresh
    original = spy.model

    class Swapping(FakeWeights):
        def to(self, device):
            spy.signature = (("model-00001-of-00003.safetensors", 3957900840, 2, 9),)
            return original

    spy.model = Swapping()
    with pytest.raises(B.SourceIdentityError, match="changed"):
        fresh.warmup()
    assert fresh._content is None


def test_warmup_missing_weights_is_unavailable(tmp_path):
    fresh = B.PCCG2Backend(SOURCE, tmp_path / "no-content", HARNESS, B.FRESH, full_model=True)
    with pytest.raises(B.RuntimeUnavailable, match="UNAVAILABLE_CONTENT"):
        fresh.warmup()
    assert fresh._content is None


def test_replay_warmup_loads_nothing(replay, monkeypatch):
    import transformers
    calls = []
    monkeypatch.setattr(transformers.AutoModelForCausalLM, "from_pretrained", lambda *a, **k: calls.append(1))
    result = replay.warmup()
    assert result == {"mode": B.REPLAY, "status": "NOT_APPLICABLE_RECORDED_LOGITS_REPLAY", "model_loaded": False,
                      "inference_executed": False}
    assert calls == [] and replay._content is None


class FakeTime:
    pass

    def __init__(self):
        self.wall, self.mono = 1_800_000_000.0, 500.0

    def time(self):
        return self.wall

    def monotonic(self):
        return self.mono

    def advance(self, seconds):
        self.wall += seconds
        self.mono += seconds


@pytest.fixture
def clock(monkeypatch):
    fake = FakeTime()
    monkeypatch.setattr(B, "time", fake)
    return fake


@pytest.mark.parametrize("permission", BOTH)
def test_replay_reports_when_scores_were_ready_and_how_long_the_decision_took(replay, clock, permission):
    def decide():
        clock.advance(7.5)
        return permission

    result = replay.run(Q, decide=decide)
    json.dumps(public(result), allow_nan=False)
    assert result["scores_ready_at"] == 1_800_000_000.0 and result["scores_ready_elapsed_seconds"] == 0.0
    timing = result["timing"]
    assert timing["run_started_at"] == 1_800_000_000.0 and timing["scores_ready_at"] == result["scores_ready_at"]
    assert timing["decision_outcome"] == "RETURNED"
    assert timing["decision_finished_at"] == 1_800_000_007.5 and timing["decision_elapsed_seconds"] == 7.5
    assert "monotonic" in timing["clock"]


def test_stubbed_fresh_scores_ready_time_includes_the_forward_pass_and_precedes_the_decision(replay, stubbed_fresh, clock):
    fresh, holder = stubbed_fresh
    seen = []

    class Slow(StubContent):
        def __call__(self, *args, **kwargs):
            clock.advance(61.0)
            return super().__call__(*args, **kwargs)

    def decide():
        seen.append((clock.wall, clock.mono))
        clock.advance(2.0)
        return B.PERMISSION_VERIFIED

    holder.stub = Slow(witness_stock(replay), B.EOS)
    result = fresh.run(Q, decide=decide)
    assert result["timing"]["run_started_at"] == 1_800_000_000.0
    
    assert result["scores_ready_at"] == 1_800_000_061.0 and result["scores_ready_elapsed_seconds"] == 61.0
    assert seen == [(1_800_000_061.0, 561.0)]
    assert result["timing"]["decision_finished_at"] == 1_800_000_063.0
    assert result["timing"]["decision_elapsed_seconds"] == 2.0
    assert result["generated_token_ids"] == [19, B.EOS]


def test_error_evidence_carries_the_same_timestamps(replay, clock):
    def unreachable():
        clock.advance(3.0)
        raise Abort("authority unreachable at the boundary")

    with pytest.raises(Abort) as caught:
        replay.run(Q, decide=unreachable)
    evidence = caught.value.evidence
    assert evidence["scores_ready_at"] == 1_800_000_000.0 and evidence["scores_ready_elapsed_seconds"] == 0.0
    assert evidence["timing"]["decision_outcome"] == "RAISED"
    assert evidence["timing"]["decision_finished_at"] == 1_800_000_003.0
    assert evidence["timing"]["decision_elapsed_seconds"] == 3.0

    with pytest.raises(B.BoundaryIntegrityError) as caught:
        replay.run(Q, decide=lambda: True)
    assert caught.value.evidence["timing"]["decision_outcome"] == "INVALID_RETURN"
    assert caught.value.evidence["scores_ready_at"] == 1_800_000_003.0


def test_a_error_before_the_decision_records_that_it_was_never_asked(replay, stubbed_fresh, clock):
    fresh, holder = stubbed_fresh
    first = witness_stock(replay)
    first[5] = float("nan")
    holder.stub = StubContent(first, 19)
    called = []
    with pytest.raises(B.BoundaryIntegrityError) as caught:
        fresh.run(Q, decide=lambda: called.append(1) or B.PERMISSION_VERIFIED)
    evidence = caught.value.evidence
    assert called == [] and evidence["timing"]["decision_outcome"] == "NOT_ASKED"
    assert evidence["scores_ready_at"] == 1_800_000_000.0 and evidence["timing"]["decision_finished_at"] is None
    assert evidence["scored_without_selection"]["index"] == 0 and set(evidence["vectors"]) == {"0-stock.bf16.bin"}


def test_real_clock_values_are_ordered(replay):
    before = __import__("time").time()
    result = replay.run(Q, decide=verified)
    timing = result["timing"]
    assert before <= timing["run_started_at"] <= timing["scores_ready_at"] <= timing["decision_finished_at"]
    assert timing["scores_ready_elapsed_seconds"] >= 0 and timing["decision_elapsed_seconds"] >= 0


def test_replay_matches_the_september_archive_and_says_the_check_is_secondary(replay, bank):
    for row in bank[:40]:
        for decide in (verified, not_verified):
            result = replay.run(row["question"], decide=decide)
            assert result["non_eos_identity_within_run"] is True
            assert result["september_archive_check"] == "SECONDARY_HARDWARE_SENSITIVE_NOT_ENFORCED"
            assert result["september_archive_non_eos_sha256"] == row["nonEOS_bf16_sha256"]
            assert result["first_step_non_eos_matches_september_archive"] is True


@pytest.mark.parametrize("permission", BOTH)
def test_stubbed_fresh_scores_that_differ_from_the_archive_are_returned_with_the_flag_false(replay, stubbed_fresh, permission):
    pass
    fresh, holder = stubbed_fresh
    first = witness_stock(replay)
    first[1000] = first[1000] + 0.5
    assert B._vector_bytes(first) != B._vector_bytes(witness_stock(replay))
    holder.stub = StubContent(first, B.EOS)
    result = fresh.run(Q, decide=fixed(permission))
    assert result["first_step_non_eos_matches_september_archive"] is False
    assert result["non_eos_identity_within_run"] is True
    assert result["steps"][0]["non_eos_sha256"] != result["september_archive_non_eos_sha256"]
    cut = 2 * B.EOS
    stock, chosen = result["vectors"]["0-stock.bf16.bin"], result["vectors"]["0-selected.bf16.bin"]
    assert stock[:cut] == chosen[:cut] and stock[cut + 2:] == chosen[cut + 2:]
    assert result["generated_token_ids"] == ([19, B.EOS] if permission == B.PERMISSION_VERIFIED else [B.EOS])


@pytest.mark.parametrize("cap", [1, 2, 6, 16])
def test_stubbed_fresh_token_cap_is_the_configured_one(replay, tmp_path, monkeypatch, cap):
    loader_must_not_be_reached(monkeypatch)
    fresh = B.PCCG2Backend(SOURCE, tmp_path / "no-content", HARNESS, B.FRESH, full_model=True, max_new_tokens=cap)
    stub = StubContent(witness_stock(replay), 19)
    monkeypatch.setattr(fresh, "_load_content", lambda: stub)
    assert fresh.metadata["max_new_tokens"] == cap
    result = fresh.run(Q, decide=verified)
    assert result["generated_token_ids"] == [19] * cap and result["max_new_tokens"] == cap and stub.calls == cap
    assert result["finish"] == "TOKEN_CAP" and result["answer_scope"] == "TRUNCATED_AT_TOKEN_CAP"
    assert fresh.run(Q, decide=not_verified)["generated_token_ids"] == [B.EOS]


GIB = 1024 ** 3
WEIGHT_BYTES = 3957900840 + 3987450520 + 99630640
REQUIRED = int(WEIGHT_BYTES * 1.5 + 2 * GIB)


def test_required_memory_is_the_documented_number():
    assert REQUIRED == 14214956648


def test_cuda_is_refused_on_a_torch_build_without_cuda_128():
    assert torch.version.cuda is None
    with pytest.raises(B.SourceIdentityError, match="cu128"):
        B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.FRESH, "cuda", full_model=True)


@pytest.fixture
def simulated_cuda(tmp_path, monkeypatch):
    import psutil
    loader_must_not_be_reached(monkeypatch)
    state = types.SimpleNamespace(available=True, count=1, bf16=True, free=70 * GIB, total=80 * GIB, host=200 * GIB,
                                  emulation_arguments=[], synchronized=0)
    monkeypatch.setattr(torch, "__version__", "2.8.0+cu128")
    monkeypatch.setattr(torch.version, "cuda", "12.8")
    monkeypatch.setattr(torch.cuda, "is_available", lambda: state.available)
    monkeypatch.setattr(torch.cuda, "device_count", lambda: state.count)
    monkeypatch.setattr(torch.cuda, "get_device_name", lambda index: "TEST DOUBLE GPU")
    monkeypatch.setattr(torch.cuda, "get_device_capability", lambda index: (9, 0))
    monkeypatch.setattr(torch.cuda, "mem_get_info", lambda index: (state.free, state.total))
    monkeypatch.setattr(torch.cuda, "memory_allocated", lambda index: 11)
    monkeypatch.setattr(torch.cuda, "memory_reserved", lambda index: 22)
    monkeypatch.setattr(torch.cuda, "max_memory_allocated", lambda index: 33)
    monkeypatch.setattr(torch.cuda, "synchronize", lambda: setattr(state, "synchronized", state.synchronized + 1))

    def bf16(including_emulation=True):
        state.emulation_arguments.append(including_emulation)
        return state.bf16

    monkeypatch.setattr(torch.cuda, "is_bf16_supported", bf16)
    monkeypatch.setattr(psutil, "virtual_memory", lambda: types.SimpleNamespace(total=251 * GIB, available=state.host))
    monkeypatch.delenv("CUBLAS_WORKSPACE_CONFIG", raising=False)

    def build(**options):
        fresh = B.PCCG2Backend(SOURCE, tmp_path / "content", HARNESS, B.FRESH, "cuda", full_model=True, **options)
        monkeypatch.setattr(fresh, "_weight_signature",
                            lambda: (("model-00001-of-00003.safetensors", WEIGHT_BYTES, 1, 1),))
        monkeypatch.setattr(fresh, "_verify_weights", lambda signature: setattr(fresh, "_weights_verified", signature))
        return fresh

    return build, state


def test_simulated_cuda_profile_and_metadata(simulated_cuda):
    build, _ = simulated_cuda
    fresh = build(attention="SDPA_MATH")
    meta = json.loads(json.dumps(fresh.metadata, allow_nan=False))
    assert meta["profile"] == "pccg2-qwen3-4b-cuda-bf16-source-pinned/1" and meta["device"] == "cuda"
    assert meta["attention"] == "SDPA_MATH" and "math kernel" in meta["attention_note"]
    assert meta["cross_hardware_bitwise_identity"] == "NOT_GUARANTEED" and meta["full_model_enabled"] is True
    assert meta["dependencies"]["torch"] in ("2.8.0", "2.8.0+cu128")


def test_simulated_cuda_preflight_is_ready_only_when_every_check_passes(simulated_cuda):
    build, state = simulated_cuda
    fresh = build()
    status = fresh.preflight()
    json.dumps(status, allow_nan=False)
    assert status["ready"] is True and status["status"] == "READY_FRESH_MODEL_EXECUTION"
    assert status["inference_executed"] is False and status["model_loaded"] is False
    cuda = status["hardware"]["cuda"]
    assert cuda["device_name"] == "TEST DOUBLE GPU" and cuda["bf16_native"] is True
    assert cuda["free_bytes"] == 70 * GIB and cuda["required_free_bytes"] == REQUIRED
    assert (cuda["allocated_bytes"], cuda["reserved_bytes"], cuda["peak_allocated_bytes"]) == (11, 22, 33)
    assert "driver version" in cuda["not_captured"] and "GPU UUID" in cuda["not_captured"]
    
    assert state.emulation_arguments and set(state.emulation_arguments) == {False}
    assert status["numerics"]["cross_hardware_bitwise_identity"] == "NOT_GUARANTEED"
    assert status["numerics"]["seeds_set_by_backend"] is False


@pytest.mark.parametrize("change,reason", [
    ({"available": False}, "CUDA device is not available"),
    ({"count": 0}, "CUDA device is not available"),
    ({"bf16": False}, "no native BF16"),
    ({"free": REQUIRED - 1}, "GPU memory preflight"),
    ({"host": REQUIRED - 1}, "Conservative BF16 memory preflight"),
])
def test_simulated_cuda_preflight_refusals(simulated_cuda, change, reason):
    build, state = simulated_cuda
    fresh = build()
    for name, value in change.items():
        setattr(state, name, value)
    status = fresh.preflight()
    assert status["ready"] is False and status["status"] == "UNAVAILABLE_HARDWARE" and reason in status["reason"]
    called = []
    with pytest.raises(B.RuntimeUnavailable, match="UNAVAILABLE_HARDWARE"):
        fresh.run(Q, decide=lambda: called.append(1) or B.PERMISSION_VERIFIED)
    with pytest.raises(B.RuntimeUnavailable):
        fresh.warmup()
    assert called == [] and fresh._content is None


def test_simulated_cuda_memory_boundary_is_inclusive(simulated_cuda):
    build, state = simulated_cuda
    state.free = state.host = REQUIRED
    assert build().preflight()["ready"] is True


def test_simulated_cuda_deterministic_policy_needs_the_cublas_setting_before_start(simulated_cuda, monkeypatch):
    build, _ = simulated_cuda
    fresh = build(attention="SDPA_MATH_DETERMINISTIC")
    assert "CUBLAS_WORKSPACE_CONFIG" in fresh.preflight()["reason"]
    monkeypatch.setenv("CUBLAS_WORKSPACE_CONFIG", ":8192:8")
    assert fresh.preflight()["ready"] is False
    for setting in (":4096:8", ":16:8"):
        monkeypatch.setenv("CUBLAS_WORKSPACE_CONFIG", setting)
        status = fresh.preflight()
        assert status["ready"] is True and status["numerics"]["cublas_workspace_config"] == setting
    
    monkeypatch.delenv("CUBLAS_WORKSPACE_CONFIG")
    assert build(attention="SDPA_MATH").preflight()["ready"] is True


@pytest.mark.parametrize("attention", B.ATTENTION)
def test_simulated_cuda_load_places_weights_and_gate_and_records_numerics(simulated_cuda, monkeypatch, attention):
    pass
    import transformers
    build, _ = simulated_cuda
    monkeypatch.setenv("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    fresh = build(attention=attention)
    model, events = FakeWeights(), []
    monkeypatch.setattr(transformers.AutoModelForCausalLM, "from_pretrained",
                        lambda path, **kwargs: events.append(("load", kwargs["attn_implementation"])) or model)
    monkeypatch.setattr(fresh, "_probe_device", lambda: events.append("probe"))
    monkeypatch.setattr(fresh, "_place_gate", lambda: events.append("gate"))
    monkeypatch.setattr(torch, "use_deterministic_algorithms", lambda flag: events.append(("deterministic", flag)))
    monkeypatch.setattr(torch, "are_deterministic_algorithms_enabled",
                        lambda: ("deterministic", True) in events)
    flags = ((torch.backends.cuda.matmul, "allow_tf32"), (torch.backends.cudnn, "allow_tf32"),
             (torch.backends.cudnn, "benchmark"))
    saved = [getattr(target, name) for target, name in flags]
    try:
        for target, name in flags:
            setattr(target, name, True)
        report = fresh.warmup()
        numerics = fresh.numerics()
    finally:
        for (target, name), value in zip(flags, saved):
            setattr(target, name, value)
    assert [getattr(target, name) for target, name in flags] == saved
    assert report["status"] == "WARM" and report["device"] == "cuda" and report["inference_executed"] is False
    assert model.moved == ["cuda"] and model.forward_calls == 0
    assert events[0] == "probe" and events[1] == ("load", "sdpa") and events[-1] == "gate"
    json.dumps(numerics, allow_nan=False)
    if attention == "SDPA_MATH_DETERMINISTIC":
        assert ("deterministic", True) in events
        assert numerics["tf32_matmul"] is False and numerics["tf32_cudnn"] is False
        assert numerics["cudnn_benchmark"] is False and numerics["deterministic_algorithms"] is True
        assert len(numerics["settings_applied_at_load"]) == 4
    else:
        assert not any(isinstance(event, tuple) and event[0] == "deterministic" for event in events)
        assert numerics["tf32_matmul"] is True and numerics["settings_applied_at_load"] == []
    assert isinstance(fresh._content, B._MathAttention) is (attention != "SDPA_DEFAULT")
    assert numerics["attention"] == attention and numerics["cross_hardware_bitwise_identity"] == "NOT_GUARANTEED"


def test_a_device_probe_error_is_unavailable_hardware_and_loads_nothing(simulated_cuda):
    pass
    build, _ = simulated_cuda
    fresh = build()
    with pytest.raises(B.RuntimeUnavailable, match="UNAVAILABLE_HARDWARE"):
        fresh.warmup()
    assert fresh._content is None


def test_math_attention_wrapper_restricts_the_kernel_for_each_call_only():
    from torch.nn.attention import SDPBackend
    seen = []

    def stand_in(**kwargs):
        seen.append((torch.backends.cuda.math_sdp_enabled(), torch.backends.cuda.flash_sdp_enabled(),
                     torch.backends.cuda.mem_efficient_sdp_enabled(), kwargs))
        return "returned"

    before = (torch.backends.cuda.math_sdp_enabled(), torch.backends.cuda.flash_sdp_enabled(),
              torch.backends.cuda.mem_efficient_sdp_enabled())
    assert B._MathAttention(stand_in)(input_ids=1) == "returned"
    assert seen == [(True, False, False, {"input_ids": 1})]
    assert (torch.backends.cuda.math_sdp_enabled(), torch.backends.cuda.flash_sdp_enabled(),
            torch.backends.cuda.mem_efficient_sdp_enabled()) == before
    assert SDPBackend.MATH is not None


def test_cuda_work_is_synchronized_before_the_scores_ready_timestamp(simulated_cuda):
    _, state = simulated_cuda
    B._sync("cpu")
    assert state.synchronized == 0
    B._sync("cuda")
    assert state.synchronized == 1
    forward = inspect.getsource(B._forward)
    assert forward.index("content(") < forward.index("_sync(device)") < forward.index("return out, stock")
    source = inspect.getsource(B._generate)
    assert source.index("_forward(content") < source.index("trace.scored(index, stock)")


def test_cpu_results_carry_numerics_and_no_cuda_record(replay, stubbed_fresh):
    fresh, holder = stubbed_fresh
    holder.stub = StubContent(witness_stock(replay), B.EOS)
    for result in (replay.run(Q, decide=verified), fresh.run(Q, decide=verified)):
        assert result["device"] == "cpu" and result["cuda"] is None
        assert result["numerics"]["decoding_uses_randomness"] is False
        assert result["numerics"]["cross_hardware_bitwise_identity"] == "NOT_GUARANTEED"
    assert replay.run(Q, decide=verified)["numerics"]["attention"] == "NOT_APPLICABLE_NO_FORWARD_PASS"


@pytest.fixture
def warm(tmp_path, monkeypatch, replay):
    loader_must_not_be_reached(monkeypatch)
    fresh = B.PCCG2Backend(SOURCE, tmp_path / "no-content", HARNESS, B.FRESH, full_model=True)
    stub = StubContent(witness_stock(replay), 19)
    monkeypatch.setattr(fresh, "_content", stub)
    monkeypatch.setattr(fresh, "_load_content", lambda: stub)
    return fresh, stub


def test_warm_forward_is_one_forward_pass_with_the_pinned_ids_and_selects_nothing(warm, replay, monkeypatch, clock):
    fresh, stub = warm
    monkeypatch.setattr(B, "apply_boundary", lambda *a, **k: pytest.fail("gate applied"))
    real = stub.__call__
    seen = {}

    def slow(input_ids, past_key_values, use_cache, logits_to_keep):
        seen.update(past=past_key_values, use_cache=use_cache, keep=logits_to_keep,
                    inference=torch.is_inference_mode_enabled())
        clock.advance(7.25)
        return real(input_ids, past_key_values, use_cache, logits_to_keep)

    monkeypatch.setattr(StubContent, "__call__", lambda self, **kwargs: slow(**kwargs))
    report = fresh.measure_warm_forward(Q)
    json.dumps({k: v for k, v in report.items() if k != "vectors"}, allow_nan=False)
    assert stub.calls == 1 and stub.fed == [replay.prompt_artifacts(Q)["input_ids"]]
    assert seen == {"past": None, "use_cache": True, "keep": 1, "inference": True}
    assert report["schema"] == "swiftapi-native-backend-warm-forward/2"
    assert report["purpose"] == "TIMING_PREFLIGHT_NOT_A_RESULT"
    assert (report["decision_asked"], report["gate_applied"], report["token_selected"], report["output_released"]) == (
        False, False, False, False)
    assert "generated_token_ids" not in report and not any(key.startswith("output_") and key != "output_released"
                                                          for key in report)
    stock = B._vector_bytes(witness_stock(replay))
    assert report["vectors"] == {"0-stock.bf16.bin": stock} and report["stock_vector_sha256"] == sha(stock)
    cut = 2 * B.EOS
    assert report["non_eos_sha256"] == sha(stock[:cut] + stock[cut + 2:])
    assert report["non_eos_matches_september_archive"] is True and report["stock_argmax_token_observed"] == 19
    assert report["input_ids_sha256"] == sha(json.dumps(replay.prompt_artifacts(Q)["input_ids"],
                                                         separators=(",", ":")).encode())
    assert report["execution_facts"] == {"content_model_loaded": True, "forward_passes_started": 1,
                                         "forward_passes_completed": 1, "model_executed": True,
                                         "decoder_selected_a_token": False}
    assert report["first_forward_seconds"] == 7.25 == report["timing"]["first_forward_seconds"]
    assert report["scores_ready_at"] == 1_800_000_007.25 and report["timing"]["run_started_at"] == 1_800_000_000.0
    assert report["timing"]["decision_outcome"] == "NOT_ASKED"
    assert report["gate"]["state_rechecked_this_run"] is True and report["device"] == "cpu"
    assert report["numerics"]["cross_hardware_bitwise_identity"] == "NOT_GUARANTEED"


def test_warm_forward_refuses_unless_enabled_fresh_and_already_warm(replay, tmp_path, monkeypatch):
    loader_must_not_be_reached(monkeypatch)
    with pytest.raises(B.RuntimeUnavailable, match="UNAVAILABLE_FULL_MODEL_NOT_ENABLED"):
        replay.measure_warm_forward(Q)
    with pytest.raises(B.RuntimeUnavailable, match="UNAVAILABLE_FULL_MODEL_NOT_ENABLED"):
        B.PCCG2Backend(SOURCE, tmp_path / "a", HARNESS, B.FRESH).measure_warm_forward(Q)
    cold = B.PCCG2Backend(SOURCE, tmp_path / "b", HARNESS, B.FRESH, full_model=True)
    monkeypatch.setattr(cold, "_load_content", lambda: pytest.fail("a cold backend must not be loaded by a measurement"))
    with pytest.raises(B.RuntimeUnavailable, match="BACKEND_NOT_WARM") as caught:
        cold.measure_warm_forward(Q)
    assert caught.value.evidence["execution"]["forward_passes_started"] == 0
    with pytest.raises(B.RequestRejected):
        cold.measure_warm_forward("unknown question")
    assert list(inspect.signature(cold.measure_warm_forward).parameters) == ["question"]


def test_warm_forward_error_keeps_the_vector_and_says_what_ran(warm, replay):
    fresh, stub = warm
    stub.first = witness_stock(replay)
    stub.first[3] = float("inf")
    with pytest.raises(B.BoundaryIntegrityError, match="Nonfinite") as caught:
        fresh.measure_warm_forward(Q)
    evidence = caught.value.evidence
    assert evidence["execution"]["forward_passes_completed"] == 1 and evidence["selected_token_ids"] == []
    assert set(evidence["vectors"]) == {"0-stock.bf16.bin"} and evidence["output_released"] is False


def test_warm_forward_and_decoding_share_one_forward_call_and_one_content_object(warm, replay):
    fresh, stub = warm
    assert inspect.getsource(B._generate).count("_forward(content") == 1
    assert inspect.getsource(B.PCCG2Backend.measure_warm_forward).count("_forward(content") == 1
    import re
    direct_call = re.compile(r"(?<![A-Za-z_.])content\(")
    assert not direct_call.search(inspect.getsource(B._generate))
    assert not direct_call.search(inspect.getsource(B.PCCG2Backend.measure_warm_forward))
    assert len(direct_call.findall(inspect.getsource(B._forward))) == 1
    source = inspect.getsource(B._forward)
    assert source.index("content(") < source.index("_sync(device)") < source.index("forward_completed")
    fresh.measure_warm_forward(Q)
    fresh.run(Q, decide=not_verified)
    assert stub.calls == 2 and stub.fed[0] == stub.fed[1]


def test_warm_forward_is_not_reachable_from_the_service_or_the_transport():
    for name in ("service.py", "httpd.py", "core.py", "client.py"):
        assert "measure_warm_forward" not in (PACKAGE / name).read_text(), name
    assert "def measure_warm_forward" in (PACKAGE / "backend.py").read_text()


def test_profile_check_is_pure_and_reads_nothing(monkeypatch):
    pass
    import builtins
    monkeypatch.setattr(builtins, "open", lambda *a, **k: pytest.fail("file access occurs"))
    monkeypatch.setattr(Path, "open", lambda *a, **k: pytest.fail("file access occurs"))
    monkeypatch.setattr(Path, "read_bytes", lambda *a, **k: pytest.fail("a file was read"))
    monkeypatch.setattr(Path, "stat", lambda *a, **k: pytest.fail("a file was inspected"))
    monkeypatch.setattr(torch.cuda, "is_available", lambda: pytest.fail("device queried"))
    monkeypatch.setattr(B.importlib.metadata, "version", lambda name: pytest.fail("dependency queried"))
    assert B.validate_backend_profile(B.REPLAY) == {
        "mode": B.REPLAY, "device": "cpu", "profile": B.PROFILE, "full_model_enabled": False,
        "attention": "NOT_APPLICABLE_NO_FORWARD_PASS", "max_new_tokens": 1}
    assert B.validate_backend_profile(B.FRESH, "cuda", full_model=True, attention="SDPA_MATH",
                                      max_new_tokens=8) == {
        "mode": B.FRESH, "device": "cuda", "profile": B.PROFILE_CUDA, "full_model_enabled": True,
        "attention": "SDPA_MATH", "max_new_tokens": 8}
    assert B.validate_backend_profile(B.FRESH)["full_model_enabled"] is False
    assert B.validate_backend_profile(B.REPLAY, full_model=True)["full_model_enabled"] is False
    source = inspect.getsource(B.validate_backend_profile)
    for forbidden in ("import ", "Path(", "open(", "torch", "os.", "_require("):
        assert forbidden not in source, forbidden
    parameters = inspect.signature(B.validate_backend_profile).parameters
    assert list(parameters) == ["mode", "device", "full_model", "attention", "max_new_tokens"]
    assert parameters["device"].default == "cpu" and parameters["full_model"].default is False
    assert parameters["attention"].default == "SDPA_DEFAULT" and parameters["max_new_tokens"].default == 4
    assert all(parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
               for name in ("full_model", "attention", "max_new_tokens"))


REFUSED_PROFILES = [
    ((B.REPLAY,), {"max_new_tokens": 1}, "always decodes exactly 1 token"),
    ((B.REPLAY,), {"max_new_tokens": 2}, "leave max_new_tokens at its default 4"),
    ((B.REPLAY,), {"max_new_tokens": 16}, "applies to fresh execution only"),
    ((B.REPLAY,), {"attention": "SDPA_MATH"}, "attention must be SDPA_DEFAULT"),
    ((B.REPLAY,), {"attention": "SDPA_MATH_DETERMINISTIC"}, "takes no attention option"),
    ((B.REPLAY, "cuda"), {}, "CPU only"),
    ((B.REPLAY, "cuda"), {"full_model": True}, "CPU only"),
    ((B.FRESH, "cuda"), {}, "requires full_model=True"),
    ((B.FRESH, "mps"), {"full_model": True}, "device must be one of cpu, cuda"),
    ((B.FRESH, "cuda:0"), {"full_model": True}, "device must be one of"),
    ((B.FRESH, None), {}, "device must be one of"),
    (("SIMULATED",), {}, "mode must be one of"),
    ((None,), {}, "mode must be one of"),
    ((B.FRESH,), {"full_model": 1}, "full_model must be a bool"),
    ((B.FRESH,), {"full_model": "yes"}, "full_model must be a bool"),
    ((B.FRESH,), {"attention": "FASTEST"}, "attention must be one of"),
    ((B.FRESH,), {"attention": None}, "attention must be one of"),
    ((B.FRESH,), {"max_new_tokens": 0}, "whole number from 1 to 16"),
    ((B.FRESH,), {"max_new_tokens": 17}, "whole number from 1 to 16"),
    ((B.FRESH,), {"max_new_tokens": True}, "whole number from 1 to 16"),
    ((B.FRESH,), {"max_new_tokens": 4.0}, "whole number from 1 to 16"),
    ((B.FRESH,), {"max_new_tokens": "4"}, "whole number from 1 to 16"),
]


@pytest.mark.parametrize("args,options,reason", REFUSED_PROFILES)
def test_refused_profiles_give_an_explicit_recordable_reason(args, options, reason):
    with pytest.raises(B.BackendConfigurationError) as caught:
        B.validate_backend_profile(*args, **options)
    error = caught.value
    assert reason in str(error)
    
    assert isinstance(error, ValueError) and isinstance(error, B.BackendError)
    assert type(error).__module__ == B.__name__ and error.evidence is None
    assert "/" not in str(error) and "swiftapi_live_" not in str(error)


@pytest.mark.parametrize("args,options,reason", REFUSED_PROFILES)
def test_constructor_refuses_the_same_profiles_with_the_same_reason_before_touching_any_file(
        tmp_path, monkeypatch, args, options, reason):
    pass
    monkeypatch.setattr(B, "_check_dependencies", lambda *a, **k: pytest.fail("dependencies were checked"))
    mode, device = (args + ("cpu",))[:2] if len(args) == 1 else args
    with pytest.raises(B.BackendConfigurationError) as caught:
        B.PCCG2Backend(tmp_path / "no-source", tmp_path / "no-content", tmp_path / "no-harness", mode, device,
                       **options)
    assert reason in str(caught.value)
    with pytest.raises(ValueError):
        B.PCCG2Backend(tmp_path / "no-source", tmp_path / "no-content", tmp_path / "no-harness", mode, device,
                       **options)


@pytest.mark.parametrize("args,options", [
    ((B.REPLAY,), {}), ((B.REPLAY, "cpu"), {"full_model": True}), ((B.REPLAY,), {"max_new_tokens": 4}),
    ((B.FRESH,), {}), ((B.FRESH, "cpu"), {"full_model": True, "attention": "SDPA_MATH", "max_new_tokens": 1}),
    ((B.FRESH, "cpu"), {"max_new_tokens": 16, "attention": "SDPA_MATH_DETERMINISTIC"}),
])
def test_a_profile_that_passes_the_check_is_never_refused_by_the_constructor_for_an_option(args, options):
    profile = B.validate_backend_profile(*args, **options)
    backend = B.PCCG2Backend(SOURCE, CONTENT, HARNESS, *args, **options)
    assert backend.mode == profile["mode"] and backend.device == profile["device"]
    assert backend.profile == profile["profile"] == backend.metadata["profile"]
    assert backend.metadata["full_model_enabled"] is profile["full_model_enabled"]
    assert backend.metadata["max_new_tokens"] == profile["max_new_tokens"]
    assert backend.metadata["attention"] == profile["attention"]


def test_the_stopped_live_replay_profile_now_says_why(tmp_path):
    pass
    with pytest.raises(B.BackendConfigurationError) as caught:
        B.PCCG2Backend(SOURCE, CONTENT, HARNESS, B.REPLAY, "cpu", full_model=False, attention="SDPA_DEFAULT",
                       max_new_tokens=1)
    message = str(caught.value)
    assert "always decodes exactly 1 token" in message and "default 4" in message
    
    recorded = message if type(caught.value).__module__ == "swiftapi_native_service.backend" else None
    assert recorded == message


def test_configuration_errors_are_distinct_from_identity_and_request_errors():
    assert issubclass(B.BackendConfigurationError, ValueError)
    assert issubclass(B.BackendConfigurationError, B.BackendError)
    for other in (B.SourceIdentityError, B.RuntimeUnavailable, B.RequestRejected, B.BoundaryIntegrityError):
        assert not issubclass(other, B.BackendConfigurationError)
        assert not issubclass(B.BackendConfigurationError, other)
        assert not issubclass(other, ValueError)
