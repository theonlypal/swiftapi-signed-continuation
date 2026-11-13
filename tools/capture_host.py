
import argparse
import datetime
import email.utils
import hashlib
import importlib.metadata
import json
import platform
import resource
import shutil
import subprocess
import time
from pathlib import Path


def command(args):
    if not shutil.which(args[0]):
        return {"available": False, "argv": args}
    completed = subprocess.run(args, capture_output=True, text=True, timeout=10, check=False)
    return {"argv": args, "exit_code": completed.returncode,
            "stdout": completed.stdout, "stderr": completed.stderr}


def capture(authority_clock=False):
    root = Path(__file__).resolve().parents[1]
    import re
    names = re.findall(r"^([a-z0-9_-]+)==", (root / "requirements-runpod-cu128.lock").read_text(), re.M)
    packages = {}
    for name in names:
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = "NOT_INSTALLED"
    report = {
        "schema": "swiftapi-native-host-preflight/1", "model_loaded": False, "model_forward_passes": 0,
        "credentials_read": False, "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "system": platform.system(), "machine": platform.machine(), "kernel": platform.release(),
        "python": platform.python_version(), "installed_packages": packages,
        "core_dump_limits": list(resource.getrlimit(resource.RLIMIT_CORE)),
        "nvidia_smi": command(["nvidia-smi", "--query-gpu=name,uuid,driver_version,pci.bus_id,memory.total",
                               "--format=csv,noheader,nounits"]),
        "ntp_state": command(["timedatectl", "show", "--property=NTPSynchronized", "--property=TimeUSec"]),
        "clock_offset": "UNMEASURED", "authority_http_date_is_not_trusted_timestamp": True,
    }
    for key, path in (("os_release", "/etc/os-release"), ("swaps", "/proc/swaps")):
        report[key] = Path(path).read_text() if Path(path).is_file() else "UNAVAILABLE"
    if authority_clock:
        import requests
        transport = requests.Session()
        transport.trust_env = False
        start_wall, start_mono = time.time(), time.monotonic()
        response = transport.get("https://swiftapi.ai/health", timeout=15, allow_redirects=False)
        elapsed = time.monotonic() - start_mono
        date = response.headers.get("Date")
        observation = {"status": response.status_code, "http_date": date,
                       "request_start_unix": start_wall, "elapsed_monotonic_seconds": elapsed}
        if date:
            remote = email.utils.parsedate_to_datetime(date).timestamp()
            observation.update(offset_midpoint_seconds=remote - (start_wall + elapsed / 2),
                               uncertainty_at_least_seconds=elapsed / 2 + 1,
                               limitation="HTTP Date may be proxy-generated; not a signed time source or NTP substitute")
        report["clock_offset"] = observation
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--authority-clock", action="store_true")
    args = parser.parse_args()
    report = capture(args.authority_clock)
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    with args.out.open("xb") as stream:
        stream.write(raw)
    print(json.dumps({"written": str(args.out), "sha256": hashlib.sha256(raw).hexdigest(),
                      "credentials_read": False, "model_forward_passes": 0}))


if __name__ == "__main__":
    main()
