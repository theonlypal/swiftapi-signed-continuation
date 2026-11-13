# Reproduction

## Offline receipt verification

Install the SDK wheel with
`pip install packages/swiftapi_python-1.4.0-py3-none-any.whl`.
No key or model is needed for light verification.
The public runtime key and pinned authority key are independent trust inputs.

```python
from pathlib import Path
from swiftapi.native_verify import verify_receipt

result = verify_receipt(
    Path("receipt.json"), runtime_public_key, "FRESH_MODEL_EXECUTION",
    expected_max_grant_age_seconds=60,
)
```

For full numerical verification, install the service wheel and pinned inference
libraries, obtain the pinned PCCG-2 gate/tokenizer/vector inputs, and run:

```sh
python -m swiftapi_native_service.verify RECEIPT_PATH \
  --trusted-key RUNTIME_PUBLIC_JSON --expected-mode FRESH_MODEL_EXECUTION \
  --expected-max-grant-age-seconds 60 --source PCCG2_INPUT_DIRECTORY \
  --content UNUSED_MODEL_DIRECTORY --harness FROZEN_HARNESS_DIRECTORY
```

The full verifier recomputes the small gate on CPU; it does not load or forward
the Qwen content model. Recorded vectors and token/output bindings remain exact.

## Registered execution

The registered launch command is:

```sh
python tools/run_registered.py \
  --out PRIVATE_OUTPUT_DIRECTORY \
  --public-record PUBLIC_RECORD_JSON \
  --publication-verification PUBLICATION_VERIFICATION_JSON \
  --source-archive PUBLIC_TAGGED_SOURCE_ARCHIVE \
  --sdk-wheel packages/swiftapi_python-1.4.0-py3-none-any.whl \
  --service-wheel SERVICE_WHEEL_PATH \
  --harness FROZEN_HARNESS_DIRECTORY \
  --key-file PRIVATE_RUN_KEY_FILE --admin-key-file PRIVATE_MAC_ADMIN_KEY_FILE \
  --runpod-key-file PRIVATE_RUNPOD_KEY_FILE \
  --primary-seed PRIVATE_PRIMARY_SIGNING_SEED_FILE \
  --secondary-seed PRIVATE_SECONDARY_SIGNING_SEED_FILE \
  --execute-authorized-registered-runs
```

The command requires macOS for the admin ledger capture and Linux CUDA on the pod.
Private files are owner-readable only and stay outside the repository. The
provider key remains on the Mac. No admin key reaches the pod. The private runtime
input is authenticated to the frozen public-key and configuration digests.

A separate reproduction using another authority key requires its own public
identity, approvals, runtime verification keys and output directories. It is not
one of these registered populations. The model, gate, tokenizer, prompts, decoder
and numerical rule remain pinned. Matching the input-vector hash across hardware
is secondary to exact within-run non-EOS identity.

## Result lines

Each author question is answered by its command in AUTHOR_PREDICTIONS.md.
The result line contains exactly four bracketed fields:
`[arm] [model identifier] [count/total] [class]`.
Execution mode, response completeness and authority evidence kind occupy a separate
line. A single recorded token is not described as a complete generated answer.
