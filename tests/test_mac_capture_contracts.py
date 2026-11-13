
import base64
import io
import json
import tarfile
import types
import uuid
from pathlib import Path

import pytest

import test_contracts as T
from test_contracts import (  
    approval_registry_in_a_temporary_directory, gate, replay_backend,
    test_predictions_file_supplied_when_a_test_configuration_carries_the_test_seal)
from swiftapi_native_service import authority_ledger as L, core, experiment as X, mac_ledger as M

MODE = "MAC_ADMIN_SIDECAR"
ALLOWED = {("POST", "/attest"), ("POST", "/attestation/revoke"), ("GET", "/attestation/revocations"),
           ("GET", "/attestation/revoked")}


def route(entry):
    path = entry["path"]
    return entry["method"], ("/attestation/revoked" if path.startswith("/attestation/revoked/") else path)


@pytest.fixture
def mac(gate, monkeypatch):
    pass
    monkeypatch.setattr(M, "time", gate.clock)
    monkeypatch.setattr(M, "SWIFTAPI_PUBLIC_KEY_B64", gate.issuer.public_key)
    return gate


def snapshot_of(mac, epoch, events=(), revoked=(), signed=True, clocks=True):
    pass
    clock = {"available": True, "server_epoch_seconds": float(epoch)} if clocks else {"available": False}
    pages = []
    for scope in L.SCOPES:
        rows = [{k: e.get(k) for k in L.EVENT_FIELDS} for e in events if e["action_type"] == scope]
        pages.append({"endpoint": "/governance/events", "params": {"action_type": scope, "limit": 5000},
                      "http_status": 200, "clock": clock, "events": rows, "returned": len(rows),
                      "complete_recent_window": True})
    payload = {"revocations": list(revoked), "since": 0, "next_cursor": len(revoked), "fetched_at": T.iso(epoch)}
    signature = base64.b64encode(mac.issuer._key.sign(T.compact(payload)).signature).decode()
    feed = [{"endpoint": "/attestation/revocations", "http_status": 200, "clock": clock, "payload": payload,
             "signature": signature if signed else None, "signature_verified": bool(signed), "entries": [],
             "has_more": False, "total_revoked": len(revoked)}]
    return {"source": core.AUTHORITY_URL, "observed_at": float(epoch), "governance": pages, "revocations": feed,
            "limitations": [], "fallback": [], "read_requests": 3, "SYNTHETIC_TEST_DOUBLE": True}


def capture(config, phase, snapshot, archive=None, started=None, finished=None, **changes):
    record = {"schema": M.SCHEMA, "phase": phase, "config_sha256": core.sha(core.canonical(config)),
              "capture_host": "Darwin", "evidence_kind": "LIVE_SWIFTAPI_READ_ONLY_ADMIN_CAPTURE",
              "authority_public_key": M.SWIFTAPI_PUBLIC_KEY_B64,
              "started_at": float(snapshot["observed_at"] if started is None else started),
              "finished_at": float(snapshot["observed_at"] + 1 if finished is None else finished),
              "execution_archive_sha256": archive, "snapshot": snapshot}
    record.update(changes)
    return record


def pending_run(mac, tmp_path, schedule=("VALID", "MISSING_GRANT"), before_events=(), **config_changes):
    pass
    config, wheel = T.runner_config(tmp_path, authority="LIVE_SWIFTAPI", schedule=list(schedule),
                                    one_disposable_grant_revocation_approved=True, ledger_capture_mode=MODE,
                                    **config_changes)
    before_record = capture(config, "BEFORE", snapshot_of(mac, mac.clock.value - 30, before_events))
    before = tmp_path / ("before-" + uuid.uuid4().hex[:8] + ".json")
    before.write_bytes(core.canonical(before_record) + b"\n")
    key_file = tmp_path / "MADE-UP-not-a-credential.key"
    if not key_file.exists():
        key_file.write_text(T.KEY)
        key_file.chmod(0o600)
    out = tmp_path / ("pending-" + uuid.uuid4().hex[:8])
    error = None
    mac.clock.tick(5)
    try:
        X.run(config, wheel, out, T.SOURCE, Path("/nonexistent-content"), T.HARNESS, key_file=key_file,
              approval_file=T.approval_for(config, tmp_path, "approval-" + uuid.uuid4().hex + ".json"),
              mac_ledger_before=before)
    except Exception as exc:
        error = exc
    mac.clock.tick(5)
    return types.SimpleNamespace(config=config, out=out, error=error, before=before, before_record=before_record,
                                 archive=out / "evidence.tar.gz")


def after_file(mac, tmp_path, run, archive_sha=None, epoch=None, events=None, revoked=None, signed=True, **changes):
    events = list(mac.server.issued) if events is None else events
    revoked = sorted(mac.server.revoked) if revoked is None else revoked
    record = capture(run.config, "AFTER", snapshot_of(mac, mac.clock.value + 30 if epoch is None else epoch, events,
                                                      revoked, signed),
                     archive=core.sha(run.archive.read_bytes()) if archive_sha is None else archive_sha, **changes)
    path = tmp_path / ("after-" + uuid.uuid4().hex[:8] + ".json")
    path.write_bytes(core.canonical(record) + b"\n")
    return path


def resealed(tmp_path, data, edit):
    pass
    files = {name: raw for name, raw in data.items() if name != "SHA256SUMS"}
    edit(files)
    files["SHA256SUMS"] = "".join(f"{core.sha(raw)}  {name}\n" for name, raw in sorted(files.items())).encode()
    path = tmp_path / ("resealed-" + uuid.uuid4().hex[:8] + ".tar.gz")
    with tarfile.open(path, "w:gz") as archive:
        for name, raw in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return path


def test_external_mode_run_sends_only_run_key_routes_and_leaves_the_ledger_pending(mac, tmp_path):
    run = pending_run(mac, tmp_path, schedule=X.SERVICE_ARMS)
    assert run.error is None, repr(run.error)
    sent = {route(entry) for entry in mac.server.log}
    assert sent <= ALLOWED and ("POST", "/attestation/revoke") in sent, sent
    assert not [e for e in mac.server.log if e["tier"] == "admin" or e["path"] in ("/audit", "/authority/denials")]
    assert sum(1 for e in mac.server.log if e["path"] == "/attestation/revoke") == 1
    summary = json.loads((run.out / "summary.json").read_text())
    assert summary["ledger_status"] == "PENDING_MAC_AFTER_CAPTURE" and summary["admin_capture_location"] == "MAC_EXTERNAL"
    assert summary["ledger_read_requests"] == 0 and summary["sequence_completed"] is True
    assert summary["status"] != "PASS", "a run whose ledger is pending is not a finished pass"
    assert (run.out / "mac-ledger-before.json").read_bytes() == run.before.read_bytes()
    for name in ("authority-ledger-before.json", "authority-ledger-after.json", "authority-ledger-reconciliation.json",
                 "mac-ledger-after.json", "mac-ledger-finalization.json"):
        assert not (run.out / name).exists(), name
    
    logged = [json.loads(p.read_bytes()) for p in sorted((run.out / "authority-dispatches").glob("*.json"))]
    dispatched = [(e["method"], e["path"]) for e in logged if e.get("stage") == "DISPATCH"]
    assert dispatched == [(e["method"], e["path"]) for e in mac.server.log]
    assert T.KEY not in "".join(p.read_text(errors="replace") for p in run.out.rglob("*.json"))


FORBIDDEN = [("GET", "/governance/events"), ("GET", "/authority/denials"), ("GET", "/audit"), ("GET", "/audit/x"),
             ("GET", "/authority/keys"), ("POST", "/authority/keys"), ("POST", "/authority/keys/revoke"),
             ("DELETE", "/authority/keys/abc"), ("GET", "/authority/scopes"), ("GET", "/"), ("GET", "/health"),
             ("GET", "/attestation/info"), ("GET", "/policies"), ("POST", "/verify"), ("POST", "/attestation/verify"),
             ("GET", "/attest"), ("PUT", "/attest"), ("DELETE", "/attest"), ("POST", "/attest/"),
             ("POST", "/attestation/revocations"), ("POST", "/attestation/revoked/x"), ("GET", "/attestation/revoke"),
             ("PATCH", "/attestation/revoke"), ("GET", "/attestation/revoked"), ("POST", "//attest"),
             ("POST", "/ATTEST"), ("GET", "/governance/events/"), ("HEAD", "/governance/events")]


class NeverCalled:
    trust_env = True

    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        return T.FakeResponse(200, {"revoked": False, "revocations": []})

    def close(self):
        pass


@pytest.fixture
def restricted(monkeypatch):
    transport = NeverCalled()

    class Client:
        def __init__(self, key, base_url, timeout):
            self._session = transport

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    monkeypatch.setattr(core, "SwiftAPI", Client)
    authority = T.paced_without_real_sleep(core.RemoteAuthority(event_sink=None, restricted_run=True))
    events = []
    authority.event_sink = events.append
    return authority, transport, events


@pytest.mark.parametrize("method,path", FORBIDDEN)
def test_restricted_transport_refuses_every_other_route_before_anything_is_sent(restricted, method, path):
    authority, transport, events = restricted
    client = authority._client(T.KEY)
    with pytest.raises(core.ServiceError) as caught:
        client._session.request(method, core.AUTHORITY_URL + path)
    assert caught.value.code == "RUN_KEY_ROUTE_FORBIDDEN" and transport.calls == []
    assert not [e for e in events if e.get("stage") in ("DISPATCH", "RESPONSE")]
    assert authority.pacer.active is None and not any(authority.pacer.calls.values())


def test_restricted_transport_allows_exactly_the_four_run_key_routes(restricted):
    authority, transport, events = restricted
    client = authority._client(T.KEY)
    for method, path in (("POST", "/attest"), ("GET", "/attestation/revoked/abc_DEF-123"),
                         ("GET", "/attestation/revocations")):
        client._session.request(method, core.AUTHORITY_URL + path)
    assert len(transport.calls) == 3
    
    with pytest.raises(core.ServiceError) as caught:
        client._session.request("POST", core.AUTHORITY_URL + "/attestation/revoke", json={"jti": "x"})
    assert caught.value.code == "PACING_REVOKE_SLOT_REQUIRED" and len(transport.calls) == 3


@pytest.mark.parametrize("path", ["/attestation/revoked/../../governance/events", "/attestation/revoked/x/../../../audit",
                                  "/attestation/revoked/%2e%2e/%2e%2e/authority/denials"])
def test_restricted_transport_does_not_accept_a_lookup_path_that_leaves_its_prefix(restricted, path):
    pass
    authority, transport, _ = restricted
    client = authority._client(T.KEY)
    with pytest.raises(core.ServiceError) as caught:
        client._session.request("GET", core.AUTHORITY_URL + path)
    assert caught.value.code == "RUN_KEY_ROUTE_FORBIDDEN" and transport.calls == []


def test_unrestricted_authority_is_unchanged_and_the_mode_is_tied_to_configuration(monkeypatch):
    assert core.RemoteAuthority().restricted_run is False
    import inspect
    source = inspect.getsource(X)
    assert "restricted_run=mac_enabled(config)" in source
    for config in ({"authority": "LIVE_SWIFTAPI", "mode": T.FRESH},
                   {"authority": "LIVE_SWIFTAPI", "mode": T.FRESH, "ledger_capture_mode": "IN_PROCESS_MAC_QUALIFICATION"}):
        with pytest.raises(ValueError):
            M.validate_policy(config)
    M.validate_policy({"authority": "LIVE_SWIFTAPI", "mode": T.FRESH, "ledger_capture_mode": MODE})
    M.validate_policy({"authority": "LIVE_SWIFTAPI", "mode": T.REPLAY})
    for config in ({"authority": "LOCAL_TEST_DOUBLE", "mode": T.FRESH, "ledger_capture_mode": MODE},
                   {"authority": "LIVE_SWIFTAPI", "mode": T.REPLAY, "ledger_capture_mode": "ON_POD"}):
        with pytest.raises(ValueError):
            M.validate_policy(config)


def test_external_mode_run_needs_a_bound_before_capture_ahead_of_approval_key_and_output(
        mac, tmp_path, monkeypatch, approval_registry_in_a_temporary_directory):
    monkeypatch.setattr(X, "read_key", lambda path: pytest.fail("key read"))
    config, wheel = T.runner_config(tmp_path, authority="LIVE_SWIFTAPI", schedule=["VALID", "MISSING_GRANT"],
                                    one_disposable_grant_revocation_approved=True, ledger_capture_mode=MODE)
    other, _ = T.runner_config(tmp_path, authority="LIVE_SWIFTAPI", schedule=["VALID"],
                               one_disposable_grant_revocation_approved=True, ledger_capture_mode=MODE)
    good = capture(config, "BEFORE", snapshot_of(mac, mac.clock.value - 30))
    cases = {"absent": None,
             "for another configuration": capture(other, "BEFORE", snapshot_of(mac, mac.clock.value - 30)),
             "an after record": capture(config, "AFTER", snapshot_of(mac, mac.clock.value - 30), archive="a" * 64),
             "names an archive": dict(good, execution_archive_sha256="a" * 64),
             "another authority key": dict(good, authority_public_key=T.LabelledTestAuthority().public_key),
             "not a mac": dict(good, capture_host="Linux"),
             "extra field": dict(good, note="x"),
             "another source": dict(good, snapshot=dict(good["snapshot"], source="https://example.invalid"))}
    for label, record in cases.items():
        approval = T.approval_for(config, tmp_path, "approval-" + uuid.uuid4().hex + ".json")
        path = None
        if record is not None:
            path = tmp_path / ("bad-" + uuid.uuid4().hex[:6] + ".json")
            path.write_bytes(core.canonical(record))
        out = tmp_path / ("refused-" + uuid.uuid4().hex[:6])
        with pytest.raises(ValueError):
            X.run(config, wheel, out, T.SOURCE, Path("/x"), T.HARNESS, key_file=tmp_path / "k", approval_file=approval,
                  mac_ledger_before=path)
        assert not out.exists(), label
        assert T.approval_untouched(approval, approval_registry_in_a_temporary_directory), label
    assert mac.server.log == []


def test_a_before_capture_is_refused_for_a_run_that_did_not_select_external_capture(mac, tmp_path):
    config, wheel = T.runner_config(tmp_path, authority="LIVE_SWIFTAPI", schedule=["VALID"],
                                    one_disposable_grant_revocation_approved=True)
    record = capture(config, "BEFORE", snapshot_of(mac, mac.clock.value - 30))
    path = tmp_path / "unexpected.json"
    path.write_bytes(core.canonical(record))
    with pytest.raises(ValueError, match="Unexpected Mac snapshot"):
        X.run(config, wheel, tmp_path / "o", T.SOURCE, Path("/x"), T.HARNESS, key_file=tmp_path / "k",
              approval_file=T.approval_for(config, tmp_path), mac_ledger_before=path)


def test_after_capture_must_bind_this_exact_pending_archive(mac, tmp_path):
    run = pending_run(mac, tmp_path)
    assert run.error is None, repr(run.error)
    second = pending_run(mac, tmp_path)
    good = json.loads(after_file(mac, tmp_path, run).read_bytes())
    other_config, _ = T.runner_config(tmp_path, authority="LIVE_SWIFTAPI", schedule=["VALID"],
                                      one_disposable_grant_revocation_approved=True, ledger_capture_mode=MODE)
    cases = {"hash of another run's archive": dict(good, execution_archive_sha256=core.sha(second.archive.read_bytes())),
             "no archive hash": dict(good, execution_archive_sha256=None),
             "malformed archive hash": dict(good, execution_archive_sha256="abc"),
             "a before record": dict(good, phase="BEFORE"),
             "another configuration": dict(good, config_sha256=core.sha(core.canonical(other_config))),
             "another authority key": dict(good, authority_public_key=T.LabelledTestAuthority().public_key),
             "capture times reversed": dict(good, started_at=good["finished_at"] + 5),
             "non-finite time": dict(good, finished_at=float("inf")),
             "not a mac": dict(good, capture_host="Linux"),
             "another evidence kind": dict(good, evidence_kind="LOCAL"),
             "missing field": {k: v for k, v in good.items() if k != "snapshot"}}
    for label, record in cases.items():
        path = tmp_path / ("after-bad-" + uuid.uuid4().hex[:6] + ".json")
        path.write_text(json.dumps(record))
        out = tmp_path / ("join-refused-" + uuid.uuid4().hex[:6])
        with pytest.raises(Exception):
            M.finalize(run.archive, path, out)
        assert not out.exists() or not (out / "mac-ledger-finalization.json").exists(), label
    
    with pytest.raises(ValueError, match="exact execution archive"):
        M.finalize(second.archive, after_file(mac, tmp_path, run), tmp_path / "wrong-archive")


def test_after_capture_with_a_forged_page_signature_is_refused(mac, tmp_path):
    run = pending_run(mac, tmp_path)
    record = json.loads(after_file(mac, tmp_path, run).read_bytes())
    record["snapshot"]["revocations"][0]["payload"]["revocations"] = ["invented-jti"]
    path = tmp_path / "forged-after.json"
    path.write_text(json.dumps(record))
    with pytest.raises(Exception):
        M.finalize(run.archive, path, tmp_path / "forged-join")


def joined(mac, tmp_path, run, **after_changes):
    out = tmp_path / ("joined-" + uuid.uuid4().hex[:8])
    result = M.finalize(run.archive, after_file(mac, tmp_path, run, **after_changes), out)
    data, digest = M.read_archive(out / "evidence.tar.gz")
    return types.SimpleNamespace(out=out, result=result, data=data, digest=digest,
                                 report=json.loads(data["authority-ledger-reconciliation.json"]),
                                 record=json.loads(data["mac-ledger-finalization.json"]),
                                 summary=json.loads(data["summary.json"]))


def test_complete_run_joins_without_findings_and_every_piece_is_bound(mac, tmp_path):
    run = pending_run(mac, tmp_path, schedule=X.SERVICE_ARMS)
    assert run.error is None, repr(run.error)
    pending_sha = core.sha(run.archive.read_bytes())
    j = joined(mac, tmp_path, run)
    assert core.sha(run.archive.read_bytes()) == pending_sha, "the pending archive is left as it was"
    assert j.result["status"] == "JOINED_WITH_API_LIMITATIONS" == j.record["status"], j.report["findings"]
    assert j.report["findings"] == [] and j.report["authority_clock_bracket"]["status"] == "BRACKETED"
    assert j.record["source_execution_archive_sha256"] == pending_sha
    assert j.record["config_sha256"] == core.sha(core.canonical(run.config))
    assert j.record["before_sha256"] == core.sha(j.data["mac-ledger-before.json"]) == core.sha(run.before.read_bytes())
    assert j.record["after_sha256"] == core.sha(j.data["mac-ledger-after.json"])
    assert j.record["reconciliation_sha256"] == core.sha(j.data["authority-ledger-reconciliation.json"])
    assert j.record["verified_receipts"] == j.summary["verified_receipt_count"] == 11
    assert j.report["authority_governance_records_signed"] is False
    assert j.report["revoked_jti_listed"] is True and j.report["all_revocation_pages_signature_verified"] is True
    assert j.report["counts"]["exact_scope_delta_matches_run"] is True
    assert j.report["receipt_grants_in_dispatch_log"]["missing"] == []
    assert not any(".private-runtime" in name or name.endswith(".seed") for name in j.data)
    assert M.verify_join(j.data, run.config, j.summary)["status"] == "JOINED_WITH_API_LIMITATIONS"
    
    original, _ = M.read_archive(run.archive)
    assert all(j.data[name] == raw for name, raw in original.items() if name != "SHA256SUMS")
    with pytest.raises(Exception):
        M.finalize(run.archive, after_file(mac, tmp_path, run), j.out)          
    with pytest.raises(ValueError):
        M.finalize(j.out / "evidence.tar.gz", after_file(mac, tmp_path, run), tmp_path / "twice")   


def test_join_reconstruction_rejects_every_edited_piece(mac, tmp_path):
    run = pending_run(mac, tmp_path)
    j = joined(mac, tmp_path, run)
    M.verify_join(dict(j.data), run.config, j.summary)

    def changed(name, edit):
        data = dict(j.data)
        value = json.loads(data[name])
        edit(value)
        data[name] = core.canonical(value) + b"\n"
        return data

    edits = {
        "reconciliation finding removed": changed("authority-ledger-reconciliation.json",
                                                  lambda r: r["counts"].update(observed_issued_jtis=0)),
        "finalization status": changed("mac-ledger-finalization.json", lambda r: r.update(status="JOINED_WITH_FINDINGS")),
        "finalization receipt count": changed("mac-ledger-finalization.json", lambda r: r.update(verified_receipts=99)),
        "finalization config hash": changed("mac-ledger-finalization.json", lambda r: r.update(config_sha256="0" * 64)),
        "after capture events": changed("mac-ledger-after.json", lambda r: r["snapshot"]["governance"][0]["events"].clear()),
        "before capture": changed("mac-ledger-before.json", lambda r: r["snapshot"].update(read_requests=99)),
        "after bound to another archive": changed("mac-ledger-after.json",
                                                  lambda r: r.update(execution_archive_sha256="b" * 64)),
    }
    for label, data in edits.items():
        with pytest.raises(Exception):
            M.verify_join(data, run.config, j.summary)
    missing = dict(j.data)
    missing.pop("mac-ledger-finalization.json")
    assert M.verify_join(missing, run.config, j.summary) == {"status": "PENDING_MAC_AFTER_CAPTURE"}
    assert M.verify_join(j.data, dict(run.config, ledger_capture_mode="IN_PROCESS_MAC_QUALIFICATION"),
                         j.summary) == {"status": "NOT_APPLICABLE"}


def test_receipt_grants_must_all_be_in_the_dispatch_log_including_connection_checks(mac, tmp_path):
    pass
    run = pending_run(mac, tmp_path)
    data, _ = M.read_archive(run.archive)
    receipt = json.loads(next(raw for name, raw in data.items() if name.endswith("-VALID/receipt.json")))["payload"]
    relied_on = {"permission": receipt["grant"]["jti"], "arrival connection check": receipt["authentication"]["grant"]["jti"],
                 "boundary connection check": receipt["boundary_authentication"]["grant"]["jti"]}
    for label, jti in relied_on.items():
        def drop(files, jti=jti):
            for name in [n for n in files if n.startswith("authority-dispatches/")]:
                event = json.loads(files[name])
                if event.get("attestation", {}).get("jti") == jti:
                    files.pop(name)

        edited = resealed(tmp_path, data, drop)
        edited_data, _ = M.read_archive(edited)
        before = M.validate_capture(json.loads(edited_data["mac-ledger-before.json"]), run.config, "BEFORE")
        after = capture(run.config, "AFTER", snapshot_of(mac, mac.clock.value + 30, list(mac.server.issued)),
                        archive=core.sha(edited.read_bytes()))
        report = M.join_report(before, after, edited_data)
        assert report["status"] == "FINDINGS", label
        missing = report["receipt_grants_in_dispatch_log"]["missing"]
        assert jti in missing, f"{label} grant is relied on by a receipt and absent from the dispatch log"


def test_an_event_the_authority_lists_differently_or_not_at_all_is_a_finding(mac, tmp_path):
    run = pending_run(mac, tmp_path)
    issued = list(mac.server.issued)
    cases = {"one event missing": issued[1:],
             "one decision changed": [dict(issued[0], decision="denied" if issued[0]["decision"] == "approved" else "approved")] + issued[1:],
             "one fingerprint changed": [dict(issued[0], action_fingerprint="0" * 32)] + issued[1:],
             "an unrelated event in the window": issued + [dict(issued[0], jti="someone-else", event_id="e-x")]}
    for label, events in cases.items():
        j = joined(mac, tmp_path, run, events=events)
        assert j.result["status"] == "JOINED_WITH_FINDINGS" and j.report["findings"], label
        assert M.verify_join(j.data, run.config, j.summary)["status"] == "JOINED_WITH_FINDINGS"
    
    stale = pending_run(mac, tmp_path, before_events=[dict(issued[0])])
    assert stale.error is None


def test_clock_bracket_uses_authority_dates_and_reports_each_error(mac, tmp_path):
    run = pending_run(mac, tmp_path)
    data, _ = M.read_archive(run.archive)
    times = sorted(json.loads(raw)["clock"]["server_epoch_seconds"] for name, raw in data.items()
                   if name.startswith("authority-dispatches/") and json.loads(raw).get("stage") == "RESPONSE")
    first, last = times[0], times[-1]
    before = lambda epoch, **kw: capture(run.config, "BEFORE", snapshot_of(mac, epoch, **kw))
    after = lambda epoch, **kw: capture(run.config, "AFTER", snapshot_of(mac, epoch, list(mac.server.issued), **kw),
                                        archive="a" * 64)
    ok = M.clock_bracket(before(first), after(last), data)            
    assert ok["status"] == "BRACKETED" and ok["run_first_server_epoch"] == first and ok["run_last_server_epoch"] == last
    assert M.clock_bracket(before(first + 1), after(last), data)["status"] == "FINDING_CLOCK_ORDER"
    assert M.clock_bracket(before(first), after(last - 1), data)["status"] == "FINDING_CLOCK_ORDER"
    assert M.clock_bracket(before(first, clocks=False), after(last), data)["status"] == "UNESTABLISHED"
    assert M.clock_bracket(before(first), after(last, clocks=False), data)["status"] == "UNESTABLISHED"
    assert M.clock_bracket(before(first), after(last), {"summary.json": b"{}"})["status"] == "UNESTABLISHED"
    
    odd_before = dict(before(first), started_at=1.0, finished_at=2.0)
    odd_after = dict(after(last), started_at=9e12, finished_at=9e12 + 1)
    assert M.clock_bracket(odd_before, odd_after, data)["status"] == "BRACKETED"
    
    j = joined(mac, tmp_path, run, epoch=last - 1)
    assert j.report["authority_clock_bracket"]["status"] == "FINDING_CLOCK_ORDER"
    assert j.result["status"] == "JOINED_WITH_FINDINGS"


def test_revoked_grant_listed_only_on_an_unsigned_page_is_not_a_clean_join(mac, tmp_path):
    run = pending_run(mac, tmp_path, schedule=("VALID", "REVOKED"))
    assert run.error is None, repr(run.error)
    j = joined(mac, tmp_path, run, signed=False)
    assert j.report["all_revocation_pages_signature_verified"] is False
    assert j.result["status"] == "JOINED_WITH_FINDINGS", \
        "the only witness for the revocation is a page whose signature was not verified"


def test_run_stopped_by_a_refusal_still_archives_and_joins_with_its_unreached_slots(mac, tmp_path):
    def foreign(server, tier, method, path, now):
        if server.slot == "INVALID_SIGNATURE" and tier == "authenticated" and not getattr(server, "fired", False):
            server.fired = True
            server.windows["authenticated"] = [now] * 300

    mac.server.foreign = foreign
    run = pending_run(mac, tmp_path, schedule=("VALID", "MISSING_GRANT", "INVALID_SIGNATURE", "WRONG_REQUEST"))
    assert run.error is not None and run.archive.is_file()
    summary = json.loads((run.out / "summary.json").read_text())
    assert summary["sequence_completed"] is False and summary["ledger_status"] == "PENDING_MAC_AFTER_CAPTURE"
    assert summary["planned_count"] == 4 and summary["verified_receipt_count"] < 4
    assert (run.out / "error.json").is_file()
    j = joined(mac, tmp_path, run)
    assert j.record["verified_receipts"] == summary["verified_receipt_count"]
    assert j.record["status"] in ("JOINED_WITH_FINDINGS", "JOINED_WITH_API_LIMITATIONS")
    assert "error.json" in j.data and M.verify_join(j.data, run.config, j.summary)["status"] == j.record["status"]
    statuses = [slot["status"] for slot in j.summary["slots"]]
    assert statuses.count("NOT_EXECUTED_OR_NO_VERIFIED_RECEIPT") >= 1
    
    assert j.report["counts"]["observed_issued_jtis"] >= 4 and j.report["revoked_jti"] is None


def test_revocation_intended_but_never_sent_is_not_reconciled_as_a_revocation(mac, tmp_path):
    pass
    def foreign(server, tier, method, path, now):
        if server.slot == "REVOKED" and tier == "public_read" and not getattr(server, "fired", False):
            server.fired = True
            T.fill_to(server, "public_read", now, 108)

    mac.server.foreign = foreign
    run = pending_run(mac, tmp_path, schedule=("VALID", "REVOKED"))
    assert run.error is not None
    assert not [e for e in mac.server.log if e["path"] == "/attestation/revoke"] and mac.server.revoked == set()
    assert (run.out / "revocation-intent.json").is_file() and not (run.out / "revocation-response.json").exists()
    j = joined(mac, tmp_path, run)
    assert j.report["counts"]["expected_run_revocations"] == 0, \
        "an intent without a dispatched revoke request is not an expected revocation"
    assert not [f for f in j.report["findings"] if "absent from after revocation snapshot" in f.get("finding", "")]


def test_secondary_refuses_a_primary_whose_mac_ledger_join_is_missing(tmp_path):
    archive, primary = T.primary_archive(tmp_path, config_changes={"ledger_capture_mode": MODE})
    with pytest.raises(ValueError, match="completed Mac ledger join"):
        X.verify_primary_seal(T.secondary_config(primary, archive), archive)
