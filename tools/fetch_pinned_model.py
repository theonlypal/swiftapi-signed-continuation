
import argparse
import hashlib
import json
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]
REPO = "sharthokrayanpal/PCCG-2-Qwen3-4B"
REV = "a3b952458a46b5547ba3cec7d03a37b395bed03a"


def download(destination,inventory,deadline,fetch=None):
    """Resume pinned downloads on transient network errors, never on an integrity mismatch."""
    import requests
    if fetch is None:
        from huggingface_hub import snapshot_download
        fetch=snapshot_download
    attempt=0
    while time.time()<deadline:
        try:
            fetch(repo_id=REPO,revision=REV,token=False,
                  allow_patterns=[row['file'] for row in inventory],local_dir=str(destination))
            return
        except (requests.ConnectionError,requests.Timeout,requests.HTTPError) as exc:
            response=getattr(exc,'response',None)
            status=response.status_code if response is not None else None
            if status is not None and status not in (408,429,500,502,503,504):raise
            attempt+=1;delay=min(30,2**min(attempt,5),max(0,deadline-time.time()))
            print(json.dumps({'stage':'MODEL_DOWNLOAD_WAIT','status':status,'seconds':delay}),flush=True)
            if delay<=0:break
            time.sleep(delay)
    raise TimeoutError('Pinned model download deadline')


def verify_files(destination, inventory):
    destination = Path(destination).resolve()
    rows = []
    for row in inventory:
        relative = Path(row["file"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe inventory path")
        path = destination / relative
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(destination):
            raise ValueError("Required regular file unavailable: " + row["file"])
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if path.stat().st_size != row["bytes"] or actual != row["sha256"]:
            raise ValueError("Pinned file mismatch: " + row["file"])
        rows.append({"file": row["file"], "bytes": row["bytes"], "sha256": actual})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--deadline-epoch",type=float)
    args = parser.parse_args()
    identity = json.loads((ROOT / "pins/model-files.json").read_text())
    if identity["repository"] != REPO or identity["revision"] != REV:
        raise ValueError("Pinned inventory identity changed")
    if not args.verify_only:
        download(args.destination,identity['files'],args.deadline_epoch or time.time()+1800)
    rows = verify_files(args.destination, identity["files"])
    print(json.dumps({"status": "PASS", "repository": REPO, "revision": REV,
                      "files_verified": len(rows), "bytes_verified": sum(r["bytes"] for r in rows),
                      "model_loaded": False, "forward_passes": 0}, indent=2))


if __name__ == "__main__":
    main()
