
from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import json
import os
import re
import sys
import threading
import time
import types
from pathlib import Path

FRESH = "FRESH_MODEL_EXECUTION"
REPLAY = "RECORDED_LOGITS_REPLAY"
MODES = (FRESH, REPLAY)
PROFILE = "pccg2-qwen3-4b-cpu-bf16-source-pinned/1"
PROFILE_CUDA = "pccg2-qwen3-4b-cuda-bf16-source-pinned/1"
PROFILES = {"cpu": PROFILE, "cuda": PROFILE_CUDA}

PERMISSION_VERIFIED = "PERMISSION_VERIFIED"
PERMISSION_NOT_VERIFIED = "PERMISSION_NOT_VERIFIED"
PERMISSIONS = (PERMISSION_VERIFIED, PERMISSION_NOT_VERIFIED)
CONDITION_VERIFIED = "EQ(485487,485487)"
CONDITION_NOT_VERIFIED = "EQ(485487,485489)"
CONDITIONS = {PERMISSION_VERIFIED: CONDITION_VERIFIED, PERMISSION_NOT_VERIFIED: CONDITION_NOT_VERIFIED}


STOP_NONE, STOP_LEARNED_GATE, STOP_VETO = "NONE", "LEARNED_GATE", "VETO"
STOP_CAUSES = (STOP_LEARNED_GATE, STOP_VETO, STOP_NONE)
LEARNED_GATE = "PCCG2_LEARNED_GATE"
VETO_AFTER_GATE = "EOS_VETO_AFTER_LEARNED_GATE"
FINISH_EOS, FINISH_CAP, FINISH_REPLAY = "NATIVE_EOS", "TOKEN_CAP", "REPLAY_ONE_TOKEN_ONLY"
SCOPE_COMPLETE = "COMPLETE_TO_NATIVE_EOS"
SCOPE_TRUNCATED = "TRUNCATED_AT_TOKEN_CAP"
SCOPE_FIRST_TOKEN = "FIRST_TOKEN_ONLY_NOT_A_COMPLETE_ANSWER"

REPOSITORY = "sharthokrayanpal/PCCG-2-Qwen3-4B"
REVISION = "a3b952458a46b5547ba3cec7d03a37b395bed03a"
BASE_MODEL = "Qwen/Qwen3-4B"
BASE_REVISION = "1cfa9a7208912126459214e8b04321603b3df60c"
EOS = 151645
EOS_TEXT = "<|im_end|>"
VOCABULARY = 151936
GAIN = 32.0
GATE_PARAMETERS = 101
PERMISSION_SIGN = 1.0
BANK_QUESTIONS = 188
FRESH_MAX_NEW_TOKENS = 4
REPLAY_MAX_NEW_TOKENS = 1
CONDITION = re.compile(r"EQ\(([1-9][0-9]{5}),([1-9][0-9]{5})\)")
MAX_MANIFEST_BYTES = 1 << 20


HARNESS_MANIFEST_SHA256 = "16a65ed782e58e4dd1be57d2b3d43ceead8153d6e117437fb92edb7d65215bc6"
UPSTREAM_MANIFEST_SHA256 = "9ac9e796f291c3db9852e242744c8c097c9faaba9ce4b4281c7ecbe07252e726"

PINS = {
    "src/model.py": "b94e07a9543b0766f7811a7164d21ed34db3817696038153f9be7d610a81999f",
    "src/core.py": "bb751927c4df31253a8f3f85ab5d1c4e0295eee3c08dafab0f0dcc1b9beee39b",
    "gate/permission.safetensors": "17f2c83502ab96b3ee43c51c5c221df528f73bd378c02598c2cfbfdacd61cc26",
    "config.json": "a58ed18ace528b5f09aaba30cde828754ec8f296dda50bb740551a141791e5b7",
    "evidence/bank.json": "eaf3f02bb2a2ba1430296bceaa5118d55c79e88e186893716caaaa0c50be7e84",
    "evidence/bank-first-logits.safetensors": "84a0c1dfdbbba313c79afb5249d3f9162c65e1caddddbd65ffb9253c26e74e6b",
    "evidence/base-identity.json": "fafd6470dbaaf643f385b63c117a9a5735a7d7b9e7a983d48a4f522d2ffc3308",
    "content/tokenizer.json": "aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4",
}
DEPENDENCIES = {"torch": "2.8.0", "numpy": "2.3.3", "safetensors": "0.6.2", "tokenizers": "0.22.2"}
FRESH_DEPENDENCIES = {"transformers": "4.56.2"}
DEVICES = ("cpu", "cuda")  
TORCH_BUILDS = ("2.8.0", "2.8.0+cu128")  
CUDA_TORCH, CUDA_RUNTIME = "2.8.0+cu128", "12.8"
CUBLAS_SETTINGS = (":4096:8", ":16:8")
ATTENTION = ("SDPA_DEFAULT", "SDPA_MATH", "SDPA_MATH_DETERMINISTIC")
ATTENTION_NOTES = {
    "SDPA_DEFAULT": "attn_implementation=sdpa; the kernel is chosen by torch",
    "SDPA_MATH": "attn_implementation=sdpa restricted to the math kernel for every forward pass",
    "SDPA_MATH_DETERMINISTIC": ("math kernel, TF32 off, cudnn benchmark off, "
                                "torch.use_deterministic_algorithms(True)"),
}
MAX_NEW_TOKENS_BOUNDS = (1, 16)
ARCHIVE_CHECK = "SECONDARY_HARDWARE_SENSITIVE_NOT_ENFORCED"


CGROUP_MEMORY = (("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current"),
                 ("/sys/fs/cgroup/memory/memory.limit_in_bytes", "/sys/fs/cgroup/memory/memory.usage_in_bytes"))

_LOAD_LOCK = threading.Lock()


def _cgroup_memory():
    pass
    for limit_path, used_path in CGROUP_MEMORY:
        try:
            limit = Path(limit_path).read_text().strip()
            used = int(Path(used_path).read_text().strip())
        except (OSError, ValueError):
            continue
        if limit.isdigit() and int(limit) < 1 << 60:
            return int(limit), used
        return None, used
    return None, None


def _gate_state_sha(gate):
    pass
    digest = hashlib.sha256()
    for name, tensor in sorted(gate.state_dict().items()):
        digest.update(name.encode() + b"\0" + str(tensor.dtype).encode() + b"\0"
                      + json.dumps(list(tensor.shape)).encode() + b"\0" + _vector_bytes(tensor.reshape(-1)))
    return digest.hexdigest()


class BackendError(Exception):
    pass
    evidence = None


class SourceIdentityError(BackendError):
    pass


class RuntimeUnavailable(BackendError):
    pass


class BackendConfigurationError(BackendError, ValueError):
    pass


class RequestRejected(BackendError):
    pass


class BoundaryIntegrityError(BackendError):
    pass


def validate_backend_profile(mode, device="cpu", *, full_model=False, attention="SDPA_DEFAULT",
                             max_new_tokens=FRESH_MAX_NEW_TOKENS) -> dict:
    pass
    def refuse(condition, reason):
        if not condition:
            raise BackendConfigurationError(reason)

    refuse(isinstance(mode, str) and mode in MODES, "mode must be one of " + ", ".join(MODES))
    refuse(isinstance(device, str) and device in DEVICES, "device must be one of " + ", ".join(DEVICES))
    refuse(type(full_model) is bool, "full_model must be a bool")
    refuse(isinstance(attention, str) and attention in ATTENTION,
           "attention must be one of " + ", ".join(ATTENTION))
    refuse(type(max_new_tokens) is int
           and MAX_NEW_TOKENS_BOUNDS[0] <= max_new_tokens <= MAX_NEW_TOKENS_BOUNDS[1],
           "max_new_tokens must be a whole number from 1 to 16")
    if mode == REPLAY:
        
        refuse(device == "cpu", "Recorded-logits replay runs on the CPU only: device must be cpu")
        refuse(attention == "SDPA_DEFAULT",
               "Recorded-logits replay runs no forward pass and takes no attention option: "
               "attention must be SDPA_DEFAULT")
        refuse(max_new_tokens == FRESH_MAX_NEW_TOKENS,
               f"Recorded-logits replay always decodes exactly {REPLAY_MAX_NEW_TOKENS} token and takes no "
               f"token-cap option: leave max_new_tokens at its default {FRESH_MAX_NEW_TOKENS}, which "
               "applies to fresh execution only")
    refuse(device == "cpu" or full_model, "device cuda requires full_model=True")
    enabled = full_model and mode == FRESH
    return {"mode": mode, "device": device, "profile": PROFILES[device], "full_model_enabled": enabled,
            "attention": attention if mode == FRESH else "NOT_APPLICABLE_NO_FORWARD_PASS",
            "max_new_tokens": max_new_tokens if mode == FRESH else REPLAY_MAX_NEW_TOKENS}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require(value, error, message):
    if not value:
        raise error(message)


def _strict_json(raw: bytes, name: str):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, SourceIdentityError, "Duplicate JSON key in " + name)
            result[key] = value
        return result

    def constant(value):
        raise SourceIdentityError("Nonfinite JSON constant in " + name)

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceIdentityError("Unreadable JSON in " + name) from exc


def _regular_file(root: Path, name: str) -> Path:
    pass
    _require(name and not name.startswith(("/", "\\")) and ".." not in Path(name).parts,
             SourceIdentityError, "Unsafe inventory name: " + name)
    base = root.resolve(strict=True)
    path = (base / name).resolve(strict=False)
    _require(path == base or base in path.parents, SourceIdentityError, "Path escapes its root: " + name)
    _require(path.is_file(), SourceIdentityError, "Missing pinned file: " + name)
    return path


def _file_sha(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def evaluate_condition(condition) -> bool:
    pass
    _require(isinstance(condition, str), RequestRejected, "Condition must be a string")
    match = CONDITION.fullmatch(condition)
    _require(match is not None, RequestRejected, "Condition must be EQ(a,b) with two six-digit operands")
    return match.group(1) == match.group(2)


def _check_dependencies(extra=None):
    found = {}
    for name, expected in {**DEPENDENCIES, **(extra or {})}.items():
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RuntimeUnavailable("Missing pinned dependency: " + name) from exc
        accepted = TORCH_BUILDS if name == "torch" else (expected,)
        _require(version in accepted, SourceIdentityError,
                 f"Dependency {name} is {version}, pinned {expected}")
        found[name] = version
    return found


def _module_from_bytes(name: str, raw: bytes, path: Path):
    pass
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def _vector_bytes(tensor) -> bytes:
    import torch
    return tensor.detach().contiguous().view(torch.uint8).cpu().numpy().tobytes()


def _non_eos(tensor):
    import torch
    return torch.cat((tensor[:EOS], tensor[EOS + 1:]))


def _checked_stock(stock):
    import torch
    _require(stock.ndim == 1 and stock.numel() == VOCABULARY, BoundaryIntegrityError, "Unexpected score vector shape")
    _require(stock.dtype == torch.bfloat16, BoundaryIntegrityError, "Score vector is not BF16")
    _require(bool(torch.isfinite(stock).all().item()), BoundaryIntegrityError, "Nonfinite score vector")
    return stock


def _checked_condition(permission) -> str:
    pass
    _require(type(permission) is str and permission in PERMISSIONS, BoundaryIntegrityError,
             "Permission must be PERMISSION_VERIFIED or PERMISSION_NOT_VERIFIED")
    condition = CONDITIONS[permission]
    _require(evaluate_condition(condition) is (permission == PERMISSION_VERIFIED), BoundaryIntegrityError,
             "Published condition disagrees with its permission value")
    return condition


def apply_boundary(module, gate, stock, permission):
    pass
    import torch
    condition = _checked_condition(permission)
    stock = _checked_stock(stock)
    stock_is_eos = int(stock.float().argmax()) == EOS
    device = next(gate.parameters()).device
    model = module.SeparatedContinuationModel(torch.nn.Identity(), gate)
    ids = torch.tensor([module.condition_tokens(condition)], device=device)
    with torch.inference_mode():
        learned, state = model.boundary(stock[None], ids, True, PERMISSION_SIGN)
    result = learned[0].clone()
    _require(bool(torch.isfinite(state).all().item()), BoundaryIntegrityError, "Nonfinite permission state")
    intervention = LEARNED_GATE
    cause = STOP_LEARNED_GATE if int(result.float().argmax()) == EOS and not stock_is_eos else STOP_NONE
    if permission == PERMISSION_NOT_VERIFIED and int(result.float().argmax()) != EOS:
        intervention, cause = VETO_AFTER_GATE, STOP_VETO
        maximum = _non_eos(result).float().max()
        result[EOS] = (maximum + maximum.abs().clamp(min=1)).to(result.dtype)
        _require(bool(torch.isfinite(result[EOS]).item()) and bool((result[EOS].float() > maximum).item()),
                 BoundaryIntegrityError, "Cannot represent a strict EOS veto")
    _require(result.dtype == stock.dtype and bool(torch.isfinite(result).all().item()),
             BoundaryIntegrityError, "Nonfinite or retyped selected vector")
    _require(_vector_bytes(_non_eos(result)) == _vector_bytes(_non_eos(stock)),
             BoundaryIntegrityError, "Non-EOS mutation")
    return result, float(state[0]), intervention, cause, stock_is_eos


def _step(index, stock, selected, state, intervention, source):
    token = int(selected.float().argmax())
    stock_raw, selected_raw = _vector_bytes(stock), _vector_bytes(selected)
    return token, {
        "index": index, "score_source": source,
        "stock_vector_sha256": _sha(stock_raw), "selected_vector_sha256": _sha(selected_raw),
        "non_eos_sha256": _sha(_vector_bytes(_non_eos(selected))),
        "stock_eos_logit": float(stock[EOS]), "intervened_eos_logit": float(selected[EOS]),
        "stock_argmax_token": int(stock.float().argmax()),
        "selected_token": token, "selected_logit": float(selected[token]),
        "permission_state": state, "intervention": intervention,
    }, {f"{index}-stock.bf16.bin": stock_raw, f"{index}-selected.bf16.bin": selected_raw}


class _Trace:
    pass

    def __init__(self, source):
        self.source = source
        self.tokens, self.steps, self.vectors = [], [], {}
        self.permission = self.cause = self.stock_is_eos = None
        self.pending = None
        self.content_loaded = False
        self.forward_started = self.forward_completed = 0
        self._entered = self._forward = time.monotonic()
        self.timing = {"clock": "wall times are time.time() UTC epoch seconds; elapsed values are time.monotonic()",
                       "run_started_at": time.time(), "lock_wait_seconds": None, "content_ready_seconds": None,
                       "first_forward_seconds": None, "scores_ready_at": None,
                       "scores_ready_elapsed_seconds": None, "decision_outcome": "NOT_ASKED",
                       "decision_finished_at": None, "decision_elapsed_seconds": None}

    def locked(self):
        self._locked = time.monotonic()
        self.timing["lock_wait_seconds"] = self._locked - self._entered

    def content_ready(self, loaded):
        pass
        self.content_loaded = loaded
        self._forward = time.monotonic()
        self.timing["content_ready_seconds"] = self._forward - self._locked

    def forward(self):
        self.forward_started += 1
        if self.forward_started == 1:
            self._forward = time.monotonic()

    def scored(self, index, stock):
        pass
        self.pending = (index, stock)
        if index == 0:
            self._ready = time.monotonic()
            self.timing.update(scores_ready_at=time.time(), scores_ready_elapsed_seconds=self._ready - self._entered,
                               first_forward_seconds=(self._ready - self._forward) if self.forward_started else None)

    def first(self, module, gate, decide):
        index, stock = self.pending
        outcome = "RAISED"
        try:
            permission = decide()
            outcome = "INVALID_RETURN"
            _require(type(permission) is str and permission in PERMISSIONS, BoundaryIntegrityError,
                     "decide must return PERMISSION_VERIFIED or PERMISSION_NOT_VERIFIED")
            outcome = "RETURNED"
        finally:
            self.timing.update(decision_outcome=outcome, decision_finished_at=time.time(),
                               decision_elapsed_seconds=time.monotonic() - self._ready)
        self.permission = permission
        selected, state, intervention, self.cause, self.stock_is_eos = apply_boundary(module, gate, stock,
                                                                                    self.permission)
        return self.record(selected, state, intervention)

    def record(self, selected, state, intervention):
        index, stock = self.pending
        token, row, captured = _step(index, stock, selected, state, intervention, self.source)
        self.tokens.append(token)
        self.steps.append(row)
        self.vectors.update(captured)
        self.pending = None
        return token

    def execution(self):
        pass
        return {"content_model_loaded": self.content_loaded, "forward_passes_started": self.forward_started,
                "forward_passes_completed": self.forward_completed,
                "model_executed": self.forward_completed > 0,
                "decoder_selected_a_token": bool(self.tokens)}

    def evidence(self, mode):
        pass
        vectors, unselected = dict(self.vectors), None
        if self.pending is not None:
            try:
                raw = _vector_bytes(self.pending[1])
                vectors[f"{self.pending[0]}-stock.bf16.bin"] = raw
                unselected = {"index": self.pending[0], "stock_vector_sha256": _sha(raw)}
            except Exception:
                unselected = {"index": self.pending[0], "stock_vector_sha256": None}
        return {"schema": "swiftapi-native-backend-evidence/2", "mode": mode, "score_source": self.source,
                "permission": self.permission, "selected_token_ids": list(self.tokens), "steps": list(self.steps),
                "execution": self.execution(),
                "scores_ready_at": self.timing["scores_ready_at"],
                "scores_ready_elapsed_seconds": self.timing["scores_ready_elapsed_seconds"],
                "timing": dict(self.timing),
                "scored_without_selection": unselected, "output_released": False, "vectors": vectors}


def _attach(exc, trace, mode):
    pass
    try:
        exc.evidence = trace.evidence(mode)
    except Exception:
        pass


def _sync(device):
    pass
    if device == "cuda":
        import torch
        torch.cuda.synchronize()


class _MathAttention:
    pass

    def __init__(self, model):
        self.model = model

    def __call__(self, **kwargs):
        from torch.nn.attention import SDPBackend, sdpa_kernel
        with sdpa_kernel([SDPBackend.MATH]):
            return self.model(**kwargs)


def _forward(content, x, cache, device, trace):
    pass
    trace.forward()
    out = content(input_ids=x, past_key_values=cache, use_cache=True, logits_to_keep=1)
    stock = out.logits[0, -1, :]
    _sync(device)
    trace.forward_completed += 1
    return out, stock


def _generate(content, module, gate, input_ids, decide, device, cap, trace):
    pass
    import torch
    x = torch.tensor([input_ids], device=device)
    cache = None
    with torch.inference_mode():
        for index in range(cap):
            out, stock = _forward(content, x, cache, device, trace)
            trace.scored(index, stock)
            stock = _checked_stock(stock)
            if index == 0:
                token = trace.first(module, gate, decide)
                _require(trace.permission != PERMISSION_NOT_VERIFIED or token == EOS, BoundaryIntegrityError,
                         "Not-verified permission did not select native EOS")
            else:
                token = trace.record(stock, None, "NONE")
            if token == EOS:
                break
            x, cache = torch.tensor([[token]], device=device), out.past_key_values


class PCCG2Backend:
    pass

    def __init__(self, source_dir: Path, content_dir: Path, harness_dir: Path, mode: str, device: str = "cpu",
                 *, full_model: bool = False, attention: str = "SDPA_DEFAULT",
                 max_new_tokens: int = FRESH_MAX_NEW_TOKENS):
        
        checked = validate_backend_profile(mode, device, full_model=full_model, attention=attention,
                                           max_new_tokens=max_new_tokens)
        self.mode, self.device, self.attention = mode, device, attention
        self.profile = checked["profile"]
        self._cap = checked["max_new_tokens"]
        
        self._full_model = checked["full_model_enabled"]
        self._numerics_applied = None
        self._source = Path(source_dir)
        self._content_dir = Path(content_dir)
        self._harness = Path(harness_dir)
        self._lock = threading.Lock()
        self._content = None
        self._weights_verified = None
        self._dependencies = _check_dependencies(FRESH_DEPENDENCIES if mode == FRESH else None)
        if device == "cuda":
            import torch
            _require(str(torch.__version__) == CUDA_TORCH and torch.version.cuda == CUDA_RUNTIME, SourceIdentityError,
                     f"torch build is {torch.__version__} with CUDA {torch.version.cuda}; "
                     f"required {CUDA_TORCH} with {CUDA_RUNTIME}")

        self._inventory = self._load_inventory()
        verified = self._verify_source()
        config = _strict_json(verified["config.json"], "config.json")
        self._check_config(config, verified)
        self._system = config["system"]
        self._base_identity = _strict_json(verified["evidence/base-identity.json"], "base-identity.json")
        self._module = self._load_original_model(verified)
        self._gate = self._load_gate(verified["gate/permission.safetensors"])
        self._tokenizer = self._load_tokenizer(verified["content/tokenizer.json"])
        self._bank = self._load_bank(verified["evidence/bank.json"])
        self._index = {row["question"]: i for i, row in enumerate(self._bank)}
        self.allowed_questions = tuple(row["question"] for row in self._bank)
        self._logits = self._load_logits(verified["evidence/bank-first-logits.safetensors"]) if mode == REPLAY else None
        self.metadata = self._build_metadata()

    

    def _load_inventory(self):
        manifest_path = _regular_file(self._harness, "SOURCE_MANIFEST.json")
        original_path = _regular_file(self._harness, "upstream/SHA256SUMS.original")
        _require(manifest_path.stat().st_size <= MAX_MANIFEST_BYTES and original_path.stat().st_size <= MAX_MANIFEST_BYTES,
                 SourceIdentityError, "Oversized harness manifest")
        manifest_raw, original_raw = manifest_path.read_bytes(), original_path.read_bytes()
        _require(_sha(manifest_raw) == HARNESS_MANIFEST_SHA256, SourceIdentityError, "Harness manifest is not the pinned one")
        _require(_sha(original_raw) == UPSTREAM_MANIFEST_SHA256, SourceIdentityError, "Upstream manifest is not the pinned one")
        manifest = _strict_json(manifest_raw, "SOURCE_MANIFEST.json")
        _require(manifest["revision"] == REVISION and manifest["repository"] == REPOSITORY
                 and manifest["upstream_manifest_sha256"] == UPSTREAM_MANIFEST_SHA256,
                 SourceIdentityError, "Harness manifest identity mismatch")
        original = {}
        for line in original_raw.decode("utf-8").splitlines():
            digest, name = line.split("  ", 1)
            _require(name not in original, SourceIdentityError, "Duplicate upstream entry")
            original[name] = digest
        _require(original == manifest["all_upstream_files"], SourceIdentityError, "Upstream inventory mismatch")
        for name, item in manifest["files"].items():
            _require(original.get(name) == item["sha256"], SourceIdentityError, "Source pin mismatch: " + name)
        for name, digest in PINS.items():
            _require(manifest["files"].get(name, {}).get("sha256") == digest, SourceIdentityError,
                     "Module pin disagrees with inventory: " + name)
        return manifest

    def _verify_source(self):
        pass
        kept = {}
        for name, item in self._inventory["files"].items():
            path = _regular_file(self._source, name)
            _require(path.stat().st_size == item["bytes"], SourceIdentityError, "Source size mismatch: " + name)
            raw = path.read_bytes()
            _require(_sha(raw) == item["sha256"], SourceIdentityError, "Source hash mismatch: " + name)
            if name in PINS or name in ("content/tokenizer_config.json", "content/vocab.json"):
                kept[name] = raw
        return kept

    def _check_config(self, config, verified):
        _require(config.get("EOS") == EOS and config.get("base_model") == BASE_MODEL
                 and config.get("base_revision") == BASE_REVISION and config.get("logit_gain") == GAIN
                 and config.get("condition_trainable_parameters") == GATE_PARAMETERS
                 and config.get("base_identity_sha256") == PINS["evidence/base-identity.json"]
                 and isinstance(config.get("system"), str),
                 SourceIdentityError, "Release configuration differs from the pinned contract")
        added = _strict_json(verified["content/tokenizer_config.json"], "tokenizer_config.json")["added_tokens_decoder"]
        vocab = _strict_json(verified["content/vocab.json"], "vocab.json")
        _require(added[str(EOS)]["content"] == EOS_TEXT and vocab["4"] == 19, SourceIdentityError, "Native token identity")

    def _load_original_model(self, verified):
        pass
        src = self._source.resolve() / "src"
        with _LOAD_LOCK:
            missing = object()
            previous = sys.modules.get("core", missing)
            try:
                core = _module_from_bytes("core", verified["src/core.py"], src / "core.py")
                sys.modules["core"] = core
                module = _module_from_bytes("pccg2_original_model", verified["src/model.py"], src / "model.py")
            finally:
                if previous is missing:
                    sys.modules.pop("core", None)
                else:
                    sys.modules["core"] = previous
        _require(core.EOS == EOS and module.EOS == EOS, SourceIdentityError, "Upstream EOS constant")
        self._prompt = core.prompt
        return module

    def _load_gate(self, raw):
        import torch
        from safetensors.torch import load as load_tensors
        state = load_tensors(raw)
        _require(set(state) == {"gain", "offset", "pair_scores.weight"}, SourceIdentityError, "Gate tensor names")
        gate = self._module.ConditionChannel(GAIN)
        gate.load_state_dict(state, strict=True)
        gate.eval().requires_grad_(False)
        _require(sum(p.numel() for p in gate.parameters()) == GATE_PARAMETERS and float(gate.gain) == GAIN
                 and all(p.dtype == torch.float32 and bool(torch.isfinite(p).all()) for p in gate.parameters()),
                 SourceIdentityError, "Gate contract")
        gate = gate.to("cpu")
        
        self._gate_state_sha256 = _gate_state_sha(gate)
        return gate

    def _gate_provenance(self):
        pass
        current = _gate_state_sha(self._gate)
        _require(current == self._gate_state_sha256, SourceIdentityError, "Gate tensors changed after load")
        return {"file": "gate/permission.safetensors", "file_sha256": PINS["gate/permission.safetensors"],
                "state_sha256": current, "state_rechecked_this_run": True,
                "trainable_parameters": GATE_PARAMETERS, "gain": GAIN, "dtype": "float32",
                "device": str(next(self._gate.parameters()).device),
                "applied_by": "SeparatedContinuationModel.boundary executed from the verified src/model.py bytes",
                "original_model_py_sha256": PINS["src/model.py"], "original_core_py_sha256": PINS["src/core.py"],
                "permission_sign": PERMISSION_SIGN, "first_step_only": True,
                "reads": "the twelve digits of the derived condition; no key, grant or signature"}

    def _load_tokenizer(self, raw):
        from tokenizers import Tokenizer
        tokenizer = Tokenizer.from_str(raw.decode("utf-8"))
        _require(tokenizer.token_to_id(EOS_TEXT) == EOS and tokenizer.encode("4", add_special_tokens=False).ids == [19],
                 SourceIdentityError, "Tokenizer contract")
        return tokenizer

    def _load_bank(self, raw):
        bank = _strict_json(raw, "bank.json")
        _require(isinstance(bank, list) and len(bank) == BANK_QUESTIONS, SourceIdentityError, "Bank size")
        _require(len({row["question"] for row in bank}) == BANK_QUESTIONS, SourceIdentityError, "Duplicate bank question")
        for row in bank:
            ids = row["generated_ids"]
            _require(len(ids) == 2 and ids[1] == EOS and ids[0] != EOS, SourceIdentityError, "Bank trace shape")
            encoded = self._tokenizer.encode(self._prompt(self._system, row["question"]), add_special_tokens=False).ids
            _require(encoded == row["input_ids"], SourceIdentityError, "Tokenizer does not reproduce archived input ids")
            _require(self._tokenizer.decode([ids[0]], skip_special_tokens=False) == row["text"],
                     SourceIdentityError, "Tokenizer does not reproduce archived answer text")
        return bank

    def _load_logits(self, raw):
        import torch
        from safetensors.torch import load as load_tensors
        tensors = load_tensors(raw)
        _require(set(tensors) == {"first_logits"}, SourceIdentityError, "Archived logits tensor names")
        logits = tensors["first_logits"]
        _require(tuple(logits.shape) == (BANK_QUESTIONS, VOCABULARY) and logits.dtype == torch.bfloat16
                 and bool(torch.isfinite(logits).all().item()), SourceIdentityError, "Archived logits contract")
        for index, row in enumerate(self._bank):
            _require(_sha(_vector_bytes(_non_eos(logits[index]))) == row["nonEOS_bf16_sha256"],
                     SourceIdentityError, "Archived vector does not match its bank row")
            _require(int(logits[index].float().argmax()) == row["generated_ids"][0],
                     SourceIdentityError, "Archived vector argmax differs from its bank row")
        return logits

    def _build_metadata(self):
        files = self._inventory["files"]
        return {
            "schema": "swiftapi-native-backend-identity/2",
            "profile": self.profile,
            "mode": self.mode,
            "full_model_enabled": self._full_model,
            "attention": self.attention if self.mode == FRESH else "NOT_APPLICABLE_NO_FORWARD_PASS",
            "attention_note": ATTENTION_NOTES[self.attention] if self.mode == FRESH else None,
            "cross_hardware_bitwise_identity": "NOT_GUARANTEED",
            "non_eos_identity": "enforced within each run, between the stock and selected vector of one step",
            "september_archive_check": ARCHIVE_CHECK,
            "torch_builds_accepted": list(TORCH_BUILDS),
            "repository": REPOSITORY, "revision": REVISION,
            "base_model": BASE_MODEL, "base_revision": BASE_REVISION,
            "content_identity_sha256": PINS["evidence/base-identity.json"],
            "gate_sha256": PINS["gate/permission.safetensors"],
            "gate_trainable_parameters": GATE_PARAMETERS, "gate_gain": GAIN,
            "gate_state_sha256": self._gate_state_sha256,
            "original_model_py_sha256": PINS["src/model.py"], "original_core_py_sha256": PINS["src/core.py"],
            "release_config_sha256": PINS["config.json"],
            "tokenizer_json_sha256": PINS["content/tokenizer.json"],
            "bank_sha256": PINS["evidence/bank.json"],
            "bank_first_logits_sha256": PINS["evidence/bank-first-logits.safetensors"],
            "bank_questions": BANK_QUESTIONS,
            "source_manifest_sha256": HARNESS_MANIFEST_SHA256,
            "upstream_manifest_sha256": UPSTREAM_MANIFEST_SHA256,
            "verified_source_files": len(files),
            "system_prompt_sha256": _sha(self._system.encode("utf-8")),
            "native_eos": EOS, "native_eos_text": EOS_TEXT, "vocabulary": VOCABULARY,
            "decoding": "greedy argmax over the full vocabulary",
            "boundary": "first generated token only",
            "permission_sign": PERMISSION_SIGN,
            "permission_values": list(PERMISSIONS),
            "gate_conditions": dict(CONDITIONS),
            "gate_condition_token_ids": {name: list(self._module.condition_tokens(condition))
                                         for name, condition in CONDITIONS.items()},
            "condition_source": "derived from the permission value; never supplied by a caller",
            "stop_causes": list(STOP_CAUSES),
            "interventions": [LEARNED_GATE, VETO_AFTER_GATE],
            "finish_values": [FINISH_EOS, FINISH_CAP, FINISH_REPLAY],
            "answer_scopes": [SCOPE_COMPLETE, SCOPE_TRUNCATED, SCOPE_FIRST_TOKEN],
            "max_new_tokens": self._cap,
            "content_dtype": "bfloat16", "gate_dtype": "float32",
            "device": self.device,
            "dependencies": dict(self._dependencies),
            "python": ".".join(str(part) for part in sys.version_info[:3]),
            "scope": ("Stock Qwen3-4B at the pinned revision with the PCCG-2 gate, greedy decoding, first generated "
                      "token, the two published six-digit EQ conditions and the frozen 188-question bank. No other "
                      "model, prompt, condition or decoding rule is covered."),
            "limits": ("Selecting native EOS ends visible answer emission in this decoder. It does not stop compute "
                       "already performed, tools or other processes. Results are reported by the process that runs "
                       "this decoder and are not hardware attested. The gate reads the derived condition, not a "
                       "signature; the permission value is supplied by the operator's service."),
            "replay_notice": (None if self.mode == FRESH else
                              "One authentic archived first-token score vector is replayed through the boundary. "
                              "No model forward pass runs and no later token is generated. A replayed token other "
                              "than native EOS is the first token only, not a complete answer."),
        }

    

    def _content_names(self):
        return sorted(name for name in self._inventory["all_upstream_files"] if name.startswith("content/"))

    def _weight_signature(self):
        pass
        signature = []
        try:
            root = self._content_dir.resolve(strict=True)
        except OSError:
            return None
        for name in self._content_names():
            short = name.removeprefix("content/")
            path = root / short
            if not path.is_file():
                return None
            stat = path.stat()
            expected = self._base_identity.get(short, {}).get("bytes")
            if expected is None or stat.st_size != expected:
                return None
            signature.append((short, stat.st_size, stat.st_mtime_ns, stat.st_ino))
        return tuple(signature)

    def _verify_weights(self, signature):
        if self._weights_verified == signature:
            return
        upstream = self._inventory["all_upstream_files"]
        for name in self._content_names():
            short = name.removeprefix("content/")
            digest = _file_sha(_regular_file(self._content_dir, short))
            _require(digest == upstream[name] and digest == self._base_identity[short]["sha256"],
                     SourceIdentityError, "Content identity mismatch: " + short)
        _require(self._weight_signature() == signature, SourceIdentityError, "Content changed while being verified")
        self._weights_verified = signature

    def _cuda_report(self, required=None):
        pass
        import torch
        report = {"torch_runtime_version": str(torch.__version__), "torch_cuda_build": torch.version.cuda,
                  "expected_torch_runtime_version": CUDA_TORCH, "expected_cuda_build": CUDA_RUNTIME,
                  "cuda_available": bool(torch.cuda.is_available()), "device_count": 0, "device_name": None,
                  "bf16_native": None, "compute_capability": None, "free_bytes": None, "total_bytes": None,
                  "required_free_bytes": required, "allocated_bytes": None, "reserved_bytes": None,
                  "peak_allocated_bytes": None,
                  "not_captured": ["driver version", "GPU UUID", "other processes on the device"]}
        if report["cuda_available"]:
            report["device_count"] = int(torch.cuda.device_count())
            report["device_name"] = str(torch.cuda.get_device_name(0))
            report["compute_capability"] = list(torch.cuda.get_device_capability(0))
            
            report["bf16_native"] = bool(torch.cuda.is_bf16_supported(including_emulation=False))
            free, total = torch.cuda.mem_get_info(0)
            report.update(free_bytes=int(free), total_bytes=int(total),
                          allocated_bytes=int(torch.cuda.memory_allocated(0)),
                          reserved_bytes=int(torch.cuda.memory_reserved(0)),
                          peak_allocated_bytes=int(torch.cuda.max_memory_allocated(0)))
        return report

    def numerics(self) -> dict:
        pass
        import torch
        return {"device": self.device,
                "attention": self.attention if self.mode == FRESH else "NOT_APPLICABLE_NO_FORWARD_PASS",
                "tf32_matmul": bool(torch.backends.cuda.matmul.allow_tf32),
                "tf32_cudnn": bool(torch.backends.cudnn.allow_tf32),
                "cudnn_benchmark": bool(torch.backends.cudnn.benchmark),
                "deterministic_algorithms": bool(torch.are_deterministic_algorithms_enabled()),
                "cublas_workspace_config": os.environ.get("CUBLAS_WORKSPACE_CONFIG"),
                "torch_threads": int(torch.get_num_threads()),
                "torch_initial_seed": int(torch.initial_seed()), "seeds_set_by_backend": False,
                "decoding_uses_randomness": False,
                "settings_applied_at_load": self._numerics_applied,
                "cross_hardware_bitwise_identity": "NOT_GUARANTEED"}

    def _hardware(self):
        import torch
        details = {"device": self.device, "machine": os.uname().machine, "system": os.uname().sysname,
                   "torch_build": str(torch.__version__), "torch_threads": int(torch.get_num_threads())}
        capability = getattr(torch.backends.cpu, "get_cpu_capability", None)
        details["cpu_capability"] = str(capability()) if capability else None
        details["cuda"] = self._cuda_report() if self.device == "cuda" else None
        limit, used = _cgroup_memory()
        details.update(cgroup_memory_limit_bytes=limit, cgroup_memory_used_bytes=used)
        try:
            import psutil
            memory = psutil.virtual_memory()
            details.update(total_memory_bytes=int(memory.total), available_memory_bytes=int(memory.available))
        except ImportError:
            details.update(total_memory_bytes=None, available_memory_bytes=None)
        return details

    def preflight(self) -> dict:
        pass
        result = {"mode": self.mode, "profile": self.profile, "numerics": self.numerics(), "ready": False, "status": None, "inference_executed": False,
                  "full_model_enabled": self._full_model,
                  "quantization": False, "download": False, "fallback": False, "hardware": self._hardware()}
        if self.mode == REPLAY:
            result.update(ready=True, status="READY_RECORDED_LOGITS_REPLAY", model_loaded=False,
                          note="Archived first-token vectors only. Not fresh model execution.")
            return result
        result["model_loaded"] = self._content is not None
        if not self._full_model:
            result.update(status="UNAVAILABLE_FULL_MODEL_NOT_ENABLED",
                          reason="This backend was constructed without full_model=True; no weight file is accessed")
            return result
        signature = self._weight_signature()
        if signature is None:
            result.update(status="UNAVAILABLE_CONTENT", reason="Pinned full BF16 weights are missing or incomplete")
            return result
        weights = sum(size for name, size, _, _ in signature if name.endswith(".safetensors"))
        required = int(weights * 1.5 + 2 * 1024 ** 3)
        result["hardware"].update(local_weight_bytes=weights, required_available_bytes=required)
        if self.device == "cuda":
            report = result["hardware"]["cuda"] = self._cuda_report(required)
            refusal = None
            if not report["cuda_available"] or report["device_count"] < 1:
                refusal = "CUDA device is not available"
            elif report["bf16_native"] is not True:
                refusal = "CUDA device has no native BF16 support (emulation is not accepted)"
            elif (self.attention == "SDPA_MATH_DETERMINISTIC"
                  and os.environ.get("CUBLAS_WORKSPACE_CONFIG") not in CUBLAS_SETTINGS):
                refusal = "CUBLAS_WORKSPACE_CONFIG must be :4096:8 or :16:8 for the deterministic policy"
            elif self._content is None and (report["free_bytes"] is None or report["free_bytes"] < required):
                refusal = "Conservative BF16 GPU memory preflight"
            if refusal:
                result.update(status="UNAVAILABLE_HARDWARE", reason=refusal)
                return result
        if self._content is None:
            
            available = result["hardware"]["available_memory_bytes"]
            if available is None or available < required:
                result.update(status="UNAVAILABLE_HARDWARE", reason="Conservative BF16 memory preflight")
                return result
            limit, used = result["hardware"]["cgroup_memory_limit_bytes"], result["hardware"]["cgroup_memory_used_bytes"]
            if limit is not None and limit - (used or 0) < required:
                result.update(status="UNAVAILABLE_HARDWARE", reason="Conservative BF16 container memory preflight")
                return result
        try:
            self._verify_weights(signature)
        except SourceIdentityError as exc:
            result.update(status="UNSAFE_CONTENT_IDENTITY", reason=str(exc))
            return result
        result.update(ready=True, status="READY_FRESH_MODEL_EXECUTION", weights_sha256_verified=True)
        return result

    def _load_content(self):
        status = self.preflight()
        if not status["ready"]:
            if status["status"] == "UNSAFE_CONTENT_IDENTITY":
                raise SourceIdentityError(status["reason"])
            raise RuntimeUnavailable(f"{status['status']}: {status.get('reason', '')}")
        if self._content is not None:
            _require(self._weight_signature() == self._weights_verified, SourceIdentityError,
                     "Content changed after it was loaded")
            return self._content
        _require(self._full_model, RuntimeUnavailable, "UNAVAILABLE_FULL_MODEL_NOT_ENABLED")
        import torch
        from transformers import AutoModelForCausalLM
        try:
            self._probe_device()
            model = AutoModelForCausalLM.from_pretrained(
                str(self._content_dir.resolve()), local_files_only=True, trust_remote_code=False,
                use_safetensors=True, torch_dtype=torch.bfloat16, attn_implementation="sdpa")
            model = model.eval().requires_grad_(False).to(self.device)
        except (RuntimeError, MemoryError, TypeError, OSError, AssertionError) as exc:
            raise RuntimeUnavailable("UNAVAILABLE_HARDWARE: " + str(exc)) from exc
        _require(all(p.dtype == torch.bfloat16 for p in model.parameters()), SourceIdentityError, "Content is not BF16")
        _require(self._weight_signature() == self._weights_verified, SourceIdentityError,
                 "Content changed while it was loading")
        self._apply_numerics()
        self._place_gate()
        self._content = model if self.attention == "SDPA_DEFAULT" else _MathAttention(model)
        return self._content

    def _probe_device(self):
        pass
        import torch
        torch.zeros(1, dtype=torch.bfloat16, device=self.device)

    def _place_gate(self):
        self._gate = self._gate.to(self.device)

    def _apply_numerics(self):
        pass
        import torch
        applied = []
        if self.attention == "SDPA_MATH_DETERMINISTIC":
            torch.backends.cuda.matmul.allow_tf32 = False
            torch.backends.cudnn.allow_tf32 = False
            torch.backends.cudnn.benchmark = False
            torch.use_deterministic_algorithms(True)
            applied = ["tf32_matmul=False", "tf32_cudnn=False", "cudnn_benchmark=False",
                       "deterministic_algorithms=True"]
        self._numerics_applied = applied

    def warmup(self) -> dict:
        pass
        if self.mode == REPLAY:
            return {"mode": self.mode, "status": "NOT_APPLICABLE_RECORDED_LOGITS_REPLAY", "model_loaded": False,
                    "inference_executed": False}
        with self._lock:
            already = self._content is not None
            self._load_content()
        return {"mode": self.mode, "status": "WARM", "model_loaded": True, "loaded_by_this_call": not already,
                "weights_sha256_verified": True, "device": self.device, "inference_executed": False,
                "quantization": False, "download": False, "fallback": False}

    

    def _row(self, question):
        _require(isinstance(question, str) and question in self._index, RequestRejected,
                 "Question is not in the frozen bank")
        return self._bank[self._index[question]]

    def prompt_artifacts(self, question: str) -> dict:
        pass
        row = self._row(question)
        rendered = self._prompt(self._system, question)
        input_ids = self._tokenizer.encode(rendered, add_special_tokens=False).ids
        _require(input_ids == row["input_ids"], BoundaryIntegrityError, "Prompt ids differ from the archived bank ids")
        return {"rendered_prompt": rendered.encode("utf-8"), "input_ids": list(input_ids)}

    def measure_warm_forward(self, question: str) -> dict:
        pass
        _require(self.mode == FRESH and self._full_model, RuntimeUnavailable,
                 "UNAVAILABLE_FULL_MODEL_NOT_ENABLED: warm forward measurement needs an enabled fresh backend")
        row = self._row(question)
        prompt = self.prompt_artifacts(question)
        input_ids = prompt["input_ids"]
        trace = _Trace("FRESH_FORWARD_PASS")
        with self._lock:
            try:
                trace.locked()
                _require(self._content is not None, RuntimeUnavailable,
                         "BACKEND_NOT_WARM: load the verified weights with warmup() first")
                gate = self._gate_provenance()
                content = self._load_content()
                trace.content_ready(True)
                import torch
                with torch.inference_mode():
                    x = torch.tensor([input_ids], device=self.device)
                    _, stock = _forward(content, x, None, self.device, trace)
                    trace.scored(0, stock)
                    stock = _checked_stock(stock)
                    raw = _vector_bytes(stock)
                    non_eos = _sha(_vector_bytes(_non_eos(stock)))
                    eos_logit, argmax = float(stock[EOS]), int(stock.float().argmax())
            except Exception as exc:
                _attach(exc, trace, self.mode)
                raise
        return {
            "schema": "swiftapi-native-backend-warm-forward/2",
            "purpose": "TIMING_PREFLIGHT_NOT_A_RESULT",
            "profile": self.profile, "mode": self.mode, "device": self.device,
            "question": question, "question_id": row["question_id"],
            "question_sha256": _sha(question.encode("utf-8")),
            "rendered_prompt_sha256": _sha(prompt["rendered_prompt"]),
            "input_ids": input_ids,
            "input_ids_sha256": _sha(json.dumps(input_ids, separators=(",", ":")).encode()),
            "input_ids_role": "FED_TO_MODEL",
            "score_source": "FRESH_FORWARD_PASS", "step_index": 0,
            "stock_vector_sha256": _sha(raw), "non_eos_sha256": non_eos,
            "stock_eos_logit": eos_logit,
            
            "stock_argmax_token_observed": argmax,
            "decision_asked": False, "gate_applied": False, "token_selected": False, "output_released": False,
            "gate": gate,
            "september_archive_check": ARCHIVE_CHECK,
            "september_archive_non_eos_sha256": row["nonEOS_bf16_sha256"],
            "non_eos_matches_september_archive": non_eos == row["nonEOS_bf16_sha256"],
            "execution_facts": trace.execution(),
            "scores_ready_at": trace.timing["scores_ready_at"],
            "first_forward_seconds": trace.timing["first_forward_seconds"],
            "timing": dict(trace.timing),
            "numerics": self.numerics(),
            "cuda": self._cuda_report() if self.device == "cuda" else None,
            "vectors": {"0-stock.bf16.bin": raw},
        }

    def run(self, question: str, *, decide) -> dict:
        pass
        _require(callable(decide), TypeError, "decide must be callable")
        row = self._row(question)
        prompt = self.prompt_artifacts(question)
        input_ids = prompt["input_ids"]
        replay = self.mode == REPLAY
        cap = self._cap
        
        trace = _Trace("AUTHENTIC_BANK_FIRST_LOGITS" if replay else "FRESH_FORWARD_PASS")
        with self._lock:
            try:
                trace.locked()
                gate = self._gate_provenance()
                content = None if replay else self._load_content()
                trace.content_ready(content is not None)
                if replay:
                    trace.scored(0, self._logits[self._index[question]].clone())
                    trace.first(self._module, self._gate, decide)
                else:
                    _generate(content, self._module, self._gate, input_ids, decide, self.device, cap, trace)
                tokens = trace.tokens
                _require(1 <= len(tokens) <= cap and EOS not in tokens[:-1], BoundaryIntegrityError,
                         "Token trace is outside the decoding contract")
                _require(trace.permission != PERMISSION_NOT_VERIFIED or tokens == [EOS], BoundaryIntegrityError,
                         "Not-verified permission did not select native EOS")
                complete = tokens[-1] == EOS
                visible = tokens[:-1] if complete else tokens
                raw = self._tokenizer.decode(visible, skip_special_tokens=False).encode("utf-8") if visible else b""
                _require(not (trace.permission == PERMISSION_NOT_VERIFIED and raw), BoundaryIntegrityError,
                         "Not-verified permission has output bytes")
                gate = self._gate_provenance()  
            except Exception as exc:
                _attach(exc, trace, self.mode)
                raise
        first = tokens[0]
        if complete:
            finish, scope = FINISH_EOS, SCOPE_COMPLETE
        elif replay:
            finish, scope = FINISH_REPLAY, SCOPE_FIRST_TOKEN
        else:
            finish, scope = FINISH_CAP, SCOPE_TRUNCATED
        condition = CONDITIONS[trace.permission]
        ids_sha = _sha(json.dumps(input_ids, separators=(",", ":")).encode())
        return {
            "schema": "swiftapi-native-backend-result/2",
            "profile": self.profile,
            "mode": self.mode, "device": self.device,
            "execution": ("replay of one authentic archived first-token score vector; no forward pass" if replay
                          else "fresh local forward passes of the pinned model"),
            "question": question, "question_id": row["question_id"],
            "question_sha256": _sha(question.encode("utf-8")),
            "rendered_prompt_sha256": _sha(prompt["rendered_prompt"]),
            "rendered_prompt_bytes": len(prompt["rendered_prompt"]),
            "input_ids": input_ids, "input_ids_sha256": ids_sha,
            "input_ids_role": "IDENTIFIES_ARCHIVED_VECTOR_NOT_FED_TO_MODEL" if replay else "FED_TO_MODEL",
            "archived_input_ids_sha256": _sha(json.dumps(row["input_ids"], separators=(",", ":")).encode()),
            "permission": trace.permission,
            "gate_condition": condition, "gate_condition_truth": evaluate_condition(condition),
            "permission_sign": PERMISSION_SIGN,
            "stop_cause": trace.cause, "stock_first_token_is_eos": trace.stock_is_eos,
            "generated_token_ids": tokens,
            "first_token_is_native_eos": first == EOS,
            "archived_first_token": row["generated_ids"][0],
            
            "first_token_matches_archive": None if first == EOS else first == row["generated_ids"][0],
            "generation_complete": complete,
            "finish": finish, "answer_scope": scope,
            "later_tokens": "NOT_GENERATED" if replay else "GENERATED_FRESH",
            "text_container_present": True,
            "native_eos": EOS,
            "max_new_tokens": cap,
            "output_utf8_base64": base64.b64encode(raw).decode("ascii"),
            "output_bytes": len(raw), "output_sha256": _sha(raw),
            
            "non_eos_identity_within_run": True,
            
            "september_archive_check": ARCHIVE_CHECK,
            "september_archive_non_eos_sha256": row["nonEOS_bf16_sha256"],
            "first_step_non_eos_matches_september_archive": trace.steps[0]["non_eos_sha256"] == row["nonEOS_bf16_sha256"],
            "execution_facts": trace.execution(),
            "gate": dict(gate, permission_state=trace.steps[0]["permission_state"],
                         condition_token_ids=list(self._module.condition_tokens(condition))),
            "scores_ready_at": trace.timing["scores_ready_at"],
            "scores_ready_elapsed_seconds": trace.timing["scores_ready_elapsed_seconds"],
            "timing": dict(trace.timing),
            "numerics": self.numerics(),
            "cuda": self._cuda_report() if self.device == "cuda" else None,
            "steps": trace.steps,
            "vectors": trace.vectors,
        }
