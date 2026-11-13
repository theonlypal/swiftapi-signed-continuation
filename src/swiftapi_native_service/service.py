
import base64
import hashlib
import importlib.metadata
from pathlib import Path
import threading
import time
import uuid

from .core import (AUTHORITY_URL, SCOPE, MAX_GRANT_AGE, SWIFTAPI_PUBLIC_KEY_B64, Ledger,
                   RemoteAuthority, RuntimeSigner, ServiceError, canonical,
                   private_write, public_principal_identity, sha, strict_json, validate_key, validate_request)
from swiftapi.native_taxonomy import classification_record

VERIFIED = "PERMISSION_VERIFIED"
NOT_VERIFIED = "PERMISSION_NOT_VERIFIED"
DENIAL_CODES = {"INVALID_AUTHORITY_SIGNATURE", "GRANT_BINDING_MISMATCH",
                "GRANT_ACTION_ECHO_MISMATCH", "AUTHORITY_DENIED",
                "GRANT_EXPIRED", "GRANT_FUTURE", "INVALID_GRANT_ID", "INVALID_GRANT_TIME",
                "AUTHORITY_REVOKED", "REPLAYED_BOUNDARY_GRANT"}
AUTH_ERRORS = {"AUTHENTICATION_REJECTED", "AUTHENTICATION_REQUIRED"}


def source_identity():
    files = {p.name: sha(p.read_bytes()) for p in sorted(Path(__file__).parent.glob("*.py"))}
    return {"files": files, "sha256": sha(canonical(files))}


def sdk_identity():
    import swiftapi.client
    import swiftapi.verifier
    import swiftapi.native
    import swiftapi.native_verify
    import swiftapi.native_taxonomy
    return {"distribution": "swiftapi-python", "version": importlib.metadata.version("swiftapi-python"),
            "native_client_sha256": sha(Path(swiftapi.native.__file__).read_bytes()),
            "native_verifier_sha256": sha(Path(swiftapi.native_verify.__file__).read_bytes()),
            "classifier_sha256": sha(Path(swiftapi.native_taxonomy.__file__).read_bytes()),
            "client_sha256": sha(Path(swiftapi.client.__file__).read_bytes()),
            "verifier_sha256": sha(Path(swiftapi.verifier.__file__).read_bytes())}


class NativeService:
    def __init__(self, backend, runtime_dir, authority=None, *, purpose="DEVELOPMENT_QUALIFICATION",
                 study_registration=None, require_known_action_type=False, runtime_signing_seed=None):
        if purpose not in {"DEVELOPMENT_QUALIFICATION", "DEVELOPMENT_SMOKE", "PREREGISTERED_STUDY"}:
            raise ValueError("Invalid receipt purpose")
        if purpose == "PREREGISTERED_STUDY":
            
            if (not isinstance(study_registration,dict)
                    or study_registration.get('author_freeze_approved') is not True
                    or not study_registration.get('public_registration_timestamp')
                    or any(len(study_registration.get(k,''))!=64 for k in
                           ('registration_sha256','author_predictions_sha256'))):
                raise ValueError('Study execution requires author freeze and registration identities')
        self.backend = backend
        self.signer = RuntimeSigner(runtime_dir,seed=runtime_signing_seed)
        if (study_registration and study_registration.get('runtime_public_key') is not None
                and self.signer.public!=study_registration['runtime_public_key']):
            raise ValueError('Runtime signer differs from the registered public key')
        self.ledger = Ledger(self.signer.directory / "ledger.sqlite3")
        self.authority = authority or RemoteAuthority()
        self.purpose = purpose
        self.decode_lock = threading.Lock()
        self.source = source_identity()
        self.sdk = sdk_identity()
        self.require_known_action_type = require_known_action_type
        self.unsigned_refusals = {}

    def health(self):
        return {"service": "swiftapi-native-service", "version": "0.2.0.dev0",
                "transport_ready": True, "backend": self.readiness(), "profile": self.backend.metadata,
                "instance_id": self.signer.instance, "authority_url": AUTHORITY_URL,
                "authority_public_key": self.authority.public_key,
                "runtime_public_key": self.signer.public, "runtime_issuer": "LOCAL_RUNTIME",
                "hardware_attested": False, "primary_experiment_executed": False,
                "source": self.source, "purpose": self.purpose}

    def readiness(self):
        report = dict(self.backend.preflight())
        if (self.backend.metadata["mode"] == "FRESH_MODEL_EXECUTION" and report.get("ready") is True
                and report.get("model_loaded") is not True):
            report.update(ready=False, resources_ready=True, status="BACKEND_NOT_WARM")
        return report

    def _authenticate(self, key):
        principal = validate_key(key)
        auth = self.authority.authenticate(key, self.signer.instance)
        action = auth["action"]
        if (action.get("scope") != "swiftapi.native_service.connection_check"
                or action.get("principal_sha256") != principal
                or action.get("instance_id") != self.signer.instance):
            raise ServiceError("AUTHENTICATION_BINDING_MISMATCH", 401)
        self.authority.validate(auth["grant"], action)
        return principal, auth

    def auth_check(self, key):
        _, auth = self._authenticate(key)
        return {"status": "AUTHORITY_VERIFIED", **auth, "inference_executed": False}

    def reject(self, code, http_status, *, authentication=None):
        if authentication is None and not self.ledger.reserve_anonymous():
            raise ServiceError('ANONYMOUS_RECEIPT_LIMIT', 429)
        execution_id = str(uuid.uuid4())
        self.ledger.begin_attempt(execution_id)
        folder = self.signer.directory / "evidence" / execution_id
        private_write(folder / "output.bin", b"")
        payload = {"schema": "swiftapi-native-service-receipt/2", "execution_id": execution_id,
                   "runtime_instance": self.signer.instance, "mode": self.backend.metadata["mode"],
                   "purpose": self.purpose, "hardware_attested": False,
                   "source": self.source, "sdk": self.sdk, "status": "OPERATIONAL",
                   "principal_identity": None,
                   "error_code": code, "http_status": http_status, "output": "",
                   "model_executed": False, "decoder_executed": False,
                   "authority_decision": None, "grant": None, "authentication": authentication,
                   "boundary_authentication": None, "gate_condition": None, "stop_cause": "NONE",
                   "authority_public_key": self.authority.public_key,
                   "authority_evidence_kind": self.authority.evidence_kind,
                   "assets": {"output.bin": {"sha256": sha(b""), "bytes": 0}}, "vector_files": {},
                   "retry_permitted": False, "started_at": time.time(), "finished_at": time.time(),
                   "taxonomy": classification_record(b"", "OPERATIONAL")}
        if authentication is not None:
            raw = canonical(authentication)
            private_write(folder / 'authentication.json', raw)
            payload['assets']['authentication.json'] = {'sha256':sha(raw),'bytes':len(raw)}
        receipt = self.signer.sign(payload)
        private_write(folder / "receipt.json", canonical(receipt) + b"\n")
        self.ledger.finish_attempt(execution_id, receipt)
        return receipt

    def action(self, principal, request):
        inputs = self.backend.prompt_artifacts(request["question"])
        action = {"scope": SCOPE, "request": request,
                "profile": dict(self.backend.metadata, max_grant_age_seconds=MAX_GRANT_AGE),
                "principal_sha256": principal, "instance_id": self.signer.instance,
                "rendered_prompt_sha256": sha(inputs["rendered_prompt"]),
                "input_ids_sha256": sha(canonical(inputs["input_ids"])),
                "service_source_sha256": self.source["sha256"]}
        if self.require_known_action_type:
            action['strict_action_type'] = True
        return action, inputs

    def authorize(self, key, request):
        principal, authentication = self._authenticate(key)
        try:
            request = validate_request(request, self.backend.allowed_questions)
        except ServiceError as exc:
            exc.authentication = authentication
            raise
        action, _ = self.action(principal, request)
        try:
            grant = self.authority.authorize(key, action)
            if grant.get('approved') is not False:
                self.authority.validate(grant, action)
            return {"action": action, "grant": grant, "authentication": authentication,
                    "authority_refusal": 'AUTHORITY_DENIED' if grant.get('approved') is False else None,
                    "denial_authority_signed": grant.get('approved') is False}
        except ServiceError as exc:
            if exc.code != "AUTHORITY_DENIED":
                raise
            if len(self.unsigned_refusals) >= 1024:
                raise ServiceError('ISSUANCE_RECORD_LIMIT', 503)
            self.unsigned_refusals[sha(canonical(action))] = exc.code
            return {"action": action, "grant": None, "authentication": authentication,
                    "authority_refusal": exc.code, "denial_authority_signed": False}

    def generate(self, key, body, *, raw_request=None):
        arrival = time.time()
        try:
            principal, authentication = self._authenticate(key)
        except ServiceError as exc:
            return self.reject(exc.code, exc.status)
        execution_id = str(uuid.uuid4())
        self.ledger.begin_attempt(execution_id)
        folder = self.signer.directory / "evidence" / execution_id
        payload = {"schema": "swiftapi-native-service-receipt/2", "execution_id": execution_id,
                   "runtime_instance": self.signer.instance, "started_at": arrival,
                   "mode": self.backend.metadata["mode"], "purpose": self.purpose,
                   "hardware_attested": False, "authority_public_key": self.authority.public_key,
                   "authority_evidence_kind": self.authority.evidence_kind,
                   "source": self.source, "sdk": self.sdk, "output": "",
                   "principal_identity": public_principal_identity(key),
                   "model_executed": False, "decoder_executed": False,
                   "authority_decision": None, "gate_condition": None, "stop_cause": "NONE",
                   "assets": {}, "vector_files": {}, "authentication": None, "grant": None,
                   "boundary_authentication": None, "retry_permitted": False}
        reserved = False
        request = None
        raw_output = b""

        def artifact(name, data):
            private_write(folder / name, data)
            payload["assets"][name] = {"sha256": sha(data), "bytes": len(data)}

        try:
            validate_key(key)
            payload["authentication"] = authentication
            artifact("authentication.json", canonical(authentication))
            if not isinstance(body, dict) or not {"request_id", "question"} <= set(body) or set(body) - {"request_id", "question", "grant"}:
                raise ServiceError("INVALID_REQUEST_FIELDS")
            if key.encode() in canonical(body):
                raise ServiceError("CREDENTIAL_IN_PAYLOAD", 400)
            request = validate_request({k: body[k] for k in ("request_id", "question")}, self.backend.allowed_questions)
            if raw_request is not None and strict_json(raw_request) != body:
                raise ServiceError("RAW_REQUEST_MISMATCH")
            available = self.readiness()
            if available.get("ready") is not True:
                raise ServiceError(available.get("status", "BACKEND_UNAVAILABLE"), 503)
            if source_identity() != self.source:
                raise ServiceError("SOURCE_CHANGED", 503)
            action, inputs = self.action(principal, request)
            payload.update(action=action, action_sha256=sha(canonical(action)), grant=body.get("grant"))
            payload['times'] = {'request_arrival_at':arrival,
                'grant_issued_at':body.get('grant',{}).get('issued_at') if isinstance(body.get('grant'),dict) else None,
                'scores_ready_at':None,'decision_at':None}
            payload['grant_refusal_code'] = self.unsigned_refusals.get(payload['action_sha256']) if body.get('grant') is None else None
            artifact("request.json", raw_request if raw_request is not None else canonical(body))
            artifact("prompt.utf8.bin", inputs["rendered_prompt"])
            artifact("input-token-ids.json", canonical(inputs["input_ids"]))
            artifact("grant.json", canonical(body.get("grant")))
            reserved = self.ledger.reserve_request(principal, request["request_id"], payload["action_sha256"])

            def decide():
                payload['times']['scores_ready_at'] = time.time()
                if payload["authority_decision"] is not None:
                    raise ServiceError("MULTIPLE_BOUNDARY_CHECKS", 500)
                reason = None
                grant = payload["grant"]
                try:
                    _, current = self._authenticate(key)
                    payload["boundary_authentication"] = current
                except ServiceError as exc:
                    if exc.code in AUTH_ERRORS:
                        reason = "KEY_REJECTED_AT_BOUNDARY"
                    else:
                        raise
                if not reserved and reason is None:
                    reason = "REPLAYED_REQUEST"
                verified_signature = False
                revocation_evidence = None
                evaluated = time.time()
                if reason is None:
                    if grant is None:
                        reason = 'AUTHORITY_DENIED_UNSIGNED' if payload['grant_refusal_code'] else "MISSING_PERMISSION"
                    else:
                        try:
                            self.authority.validate(grant, action)
                            verified_signature = True
                            self.authority.recheck(key, grant, action)
                            evaluated = time.time()
                            self.authority.validate(grant, action, now=evaluated)
                            self.ledger.claim_boundary_grant(grant["jti"], payload["action_sha256"])
                        except ServiceError as exc:
                            evaluated = time.time()
                            if exc.code in DENIAL_CODES:
                                reason = exc.code
                                revocation_evidence = getattr(exc,'revocation_evidence',None)
                                if reason == 'AUTHORITY_REVOKED':
                                    try:self.authority.validate(grant,action,now=evaluated)
                                    except ServiceError as age_error:
                                        if age_error.code not in DENIAL_CODES:raise
                                        reason=age_error.code;revocation_evidence=None
                            else:
                                raise
                
                signed_denial = False
                if isinstance(grant, dict) and grant.get('approved') is False:
                    try:
                        self.authority.validate(grant, action)
                    except ServiceError as exc:
                        signed_denial = exc.code == 'AUTHORITY_DENIED'
                if signed_denial:
                    artifact('authority-denial.json', canonical(grant))
                signed_revocation = bool(revocation_evidence and revocation_evidence.get('authority_signed') is True)
                if signed_revocation:
                    from swiftapi.native_verify import verify_revocation_entry
                    try:
                        verify_revocation_entry(revocation_evidence['entry'],grant['jti'],self.authority.public_key,
                                                decision_at=evaluated)
                    except Exception as evidence_error:
                        signed_revocation=False
                        revocation_evidence={'reason':'REVOKED_AT_AFTER_DECISION_CLOCK'
                            if str(evidence_error)=='Revocation was not established at decision'
                            else 'FEED_ENTRY_SIGNATURE_NOT_VERIFIED_AT_DECISION'}
                    else:
                        artifact('authority-revocation.json',canonical(revocation_evidence['entry']))
                payload['times']['decision_at'] = evaluated
                payload["authority_decision"] = {
                    "permission": VERIFIED if reason is None else NOT_VERIFIED,
                    "reason": reason or "VERIFIED_EXACT_REQUEST",
                    "authority_reported_approved": grant.get("approved") if isinstance(grant, dict) else None,
                    "grant_checks_passed": verified_signature,
                    "denial_authority_signed": signed_denial,
                    "revocation_authority_signed": signed_revocation,
                    "revocation_evidence_limit": (revocation_evidence or {}).get('reason'),
                    "evaluated_at": evaluated,
                    "revocation_observation": "AUTHORITY_SIGNED_ENTRY" if signed_revocation else "RUNTIME_REPORTED",
                }
                return payload["authority_decision"]["permission"]

            with self.decode_lock:
                payload["decoder_executed"] = True
                result = dict(self.backend.run(request["question"], decide=decide))
                payload['execution_facts'] = result['execution_facts']
                payload["model_executed"] = result['execution_facts']['model_executed']
                payload['times']['backend_timing'] = result['timing']
            if payload["authority_decision"] is None:
                raise ServiceError("BOUNDARY_CHECK_MISSING", 500)
            vectors = result.pop("vectors")
            decision = payload["authority_decision"]["permission"]
            if result["mode"] != payload["mode"] or result["permission"] != decision:
                raise ServiceError("BACKEND_DECISION_MISMATCH", 500)
            expected_condition = "EQ(485487,485487)" if decision == VERIFIED else "EQ(485487,485489)"
            if (result["gate_condition"] != expected_condition
                    or result["gate_condition_truth"] is not (decision == VERIFIED)):
                raise ServiceError("BACKEND_CONDITION_MISMATCH", 500)
            raw_output = base64.b64decode(result["output_utf8_base64"], validate=True)
            if result["output_bytes"] != len(raw_output) or result["output_sha256"] != sha(raw_output):
                raise ServiceError("BACKEND_OUTPUT_MISMATCH", 500)
            if decision == NOT_VERIFIED and (raw_output or result["generated_token_ids"] != [151645]):
                raise ServiceError("DENIAL_BOUNDARY_VIOLATION", 500)
            steps = result["steps"]
            if len(steps) != len(result["generated_token_ids"]):
                raise ServiceError("VECTOR_STEP_COUNT_MISMATCH", 500)
            expected_files = {f"{i}-{kind}.bf16.bin" for i in range(len(steps)) for kind in ("stock", "selected")}
            if set(vectors) != expected_files:
                raise ServiceError("VECTOR_SET_MISMATCH", 500)
            for i, step in enumerate(steps):
                stock, selected = (vectors[f"{i}-{kind}.bf16.bin"] for kind in ("stock", "selected"))
                if (not isinstance(stock, bytes) or not isinstance(selected, bytes)
                        or len(stock) != 303872 or len(selected) != 303872 or step["index"] != i
                        or step["stock_vector_sha256"] != sha(stock)
                        or step["selected_vector_sha256"] != sha(selected)
                        or stock[:303290] + stock[303292:] != selected[:303290] + selected[303292:]
                        or step["non_eos_sha256"] != sha(selected[:303290] + selected[303292:])):
                    raise ServiceError("BACKEND_VECTOR_MISMATCH", 500)
            for name, value in vectors.items():
                private_write(folder / name, value)
                payload["vector_files"][name] = sha(value)
            if (result["rendered_prompt_sha256"] != action["rendered_prompt_sha256"]
                    or result["input_ids"] != inputs["input_ids"]
                    or result["input_ids_sha256"] != action["input_ids_sha256"]):
                raise ServiceError("BACKEND_INPUT_MISMATCH", 500)
            artifact("output.bin", raw_output)
            payload.update(status="COMPLETED", result=result, output=raw_output.decode("utf-8"),
                           gate_condition=result["gate_condition"], stop_cause=result["stop_cause"])
        except Exception as exc:
            raw_output = b""
            payload.update(status="OPERATIONAL", error_code=exc.code if isinstance(exc, ServiceError) else "EXECUTION_FAILED",
                           http_status=exc.status if isinstance(exc, ServiceError) else 500)
            
            evidence = getattr(exc, "evidence", None)
            if isinstance(evidence, dict):
                payload['execution_facts'] = evidence.get('execution', {})
                payload['model_executed'] = payload['execution_facts'].get('model_executed',False)
                partial = dict(evidence)
                captures = partial.pop("vectors", {})
                for name, value in captures.items():
                    if isinstance(name, str) and "/" not in name and "\\" not in name and isinstance(value, bytes):
                        artifact("partial-" + name, value)
                artifact("partial-trace.json", canonical(partial))
            if "output.bin" not in payload["assets"]:
                artifact("output.bin", b"")
        payload["finished_at"] = time.time()
        payload["taxonomy"] = classification_record(raw_output, payload["status"], payload.get("result"))
        receipt = self.signer.sign(payload)
        private_write(folder / "receipt.json", canonical(receipt) + b"\n")
        self.ledger.finish_attempt(execution_id, receipt)
        if reserved:
            self.ledger.finish(principal, request["request_id"], receipt)
        return receipt
