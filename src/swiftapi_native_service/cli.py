import argparse
import json
from pathlib import Path

from .core import ServiceError, canonical, private_write


def main():
    p = argparse.ArgumentParser(description="SwiftAPI local PCCG-2 service")
    sub = p.add_subparsers(dest="command", required=True)
    server = sub.add_parser("serve")
    server.add_argument("--port", type=int, default=8766)
    server.add_argument("--mode", choices=["FRESH_MODEL_EXECUTION", "RECORDED_LOGITS_REPLAY"], default="RECORDED_LOGITS_REPLAY")
    server.add_argument("--runtime", type=Path, required=True)
    server.add_argument("--source", type=Path, required=True)
    server.add_argument("--content", type=Path, required=True)
    server.add_argument("--harness", type=Path, required=True)
    server.add_argument("--device", choices=["cpu", "cuda"], default="cpu")
    server.add_argument("--enable-full-model", action="store_true", help="Explicit future operator permission; never required for replay")
    server.add_argument("--warmup", action="store_true", help="Operator-only weight load before accepting requests; no forward pass")
    for command in ("check-authority", "generate"):
        q = sub.add_parser(command)
        q.add_argument("--key-file", type=Path, required=True)
        q.add_argument("--url", default="http://127.0.0.1:8766")
        q.add_argument("--out", type=Path)
        if command == "generate":
            q.add_argument("--question", required=True)
            q.add_argument("--request-id")
    args = p.parse_args()
    try:
        if args.command == "serve":
            from .backend import PCCG2Backend
            from .httpd import LocalServer
            from .service import NativeService
            backend = PCCG2Backend(args.source, args.content, args.harness, args.mode, args.device,
                                  full_model=args.enable_full_model)
            if args.warmup:
                print(json.dumps({"warmup": backend.warmup()}), flush=True)
            service = NativeService(backend, args.runtime)
            httpd = LocalServer(("127.0.0.1", args.port), service)
            print(json.dumps({"listening": f"http://127.0.0.1:{httpd.server_port}",
                              "health": service.health()}), flush=True)
            try:
                httpd.serve_forever(poll_interval=0.5)
            finally:
                httpd.server_close()
        else:
            from .client import NativeEOSClient
            with NativeEOSClient(key_file=args.key_file, base_url=args.url) as client:
                if args.command == "check-authority":
                    result = client.check_authority()
                    summary = {"status": result["status"], "inference_executed": False,
                               "authorization_jti": result["grant"]["jti"]}
                else:
                    result = client.generate(args.question, request_id=args.request_id)
                    row = result["payload"]
                    summary = {"status": row["status"], "mode": row["mode"],
                               "execution_id": row["execution_id"],
                               "generated_token_ids": row.get("result", {}).get("generated_token_ids"),
                               "output_bytes": row.get("result", {}).get("output_bytes")}
                if args.out:
                    private_write(args.out, canonical(result) + b"\n")
                    summary["saved"] = str(args.out)
                print(json.dumps(summary, indent=2))
    except ServiceError as exc:
        print(json.dumps({"error": exc.code, "status": exc.status, "native_void_claimed": False}))
        raise SystemExit(2)


if __name__ == "__main__":
    main()
