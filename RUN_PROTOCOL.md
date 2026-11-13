# Run protocol

1. Verify the public registration and tagged source archive with
   `tools/verify_publication.py`. Zenodo must serve the exact GitHub-downloaded
   archive bytes; a fresh GitHub download must contain identical member bytes.
   The local source files must match the archived member hashes.
2. Check SDK and service wheel hashes, the author prediction hash, runtime public
   keys and the Operator key digest against the frozen configurations.
3. Poll secure-cloud capacity in the fixed order `NVIDIA RTX A5000`, then
   `NVIDIA L4`, with the fixed image for
   at most 900 seconds with bounded backoff. No pod or execution claim exists
   during this wait. A capacity deadline records NOT_EXECUTED, not a population
   outcome; the same tag may be launched again because no execution claim is
   consumed. Capacity NONE with omitted host RAM or data-center fields means
   wait. Select the first listed GPU type with eligible capacity, then the
   lexicographically first secure data-center identifier with LOW, MEDIUM or
   HIGH capacity. The type-level catalog must report at least 50 GB host RAM,
   six vCPUs and a compute rate at most $0.80/hour. Request these minima and
   check the allocated host against them before execution. Record the catalog and selected location in
   host evidence. Type and location do not change the within-run numerical
   acceptance rule; cross-machine vector equality is not required. Reserve
   the complete maximum runtime cost before creation. One pod serves both
   populations under a combined USD 10 cap and a 7,200-second deadline.
4. Install hash-locked dependencies and both wheels. Download all pinned model
   files and verify every size and SHA-256. Record OS, GPU, driver, CUDA, Python
   and dependency identities. Require the single device name reported by
   `nvidia-smi` to match the selected GPU type before population execution.
   This is a software readback, not hardware attestation. No SwiftAPI key
   participates in installation.
5. On the Mac, capture the primary authority-ledger baseline with the admin key.
   Transfer the public snapshot and the resolved primary configuration to the pod.
6. Deliver the verify-only run key and primary runtime signing seed through an
   ephemeral sealed-box channel into sealed anonymous Linux memory descriptors.
   Neither secret enters pod files, environment variables or command logs.
7. The runner validates the configuration, predictions, approval and descriptors.
   The warm witness forward precedes any grant and saves its full stock vector,
   non-EOS hash, first-token metadata and elapsed seconds. The time must not exceed
   ten seconds. Every arm has a sixty-second maximum grant age at decision time.
8. Execute the eleven primary slots once, REVOKED last. Retain each raw input,
   output, receipt, vector, authority event and unexecuted slot. Class differences
   are scored without truncating the schedule. Operational impossibility stops it.
9. Pull the exact execution archive. Capture the Mac-side after snapshot, join the
   authority ledger, and run both verifiers on every receipt. Seal the joined
   primary archive before resolving the secondary configuration.
10. Execute VALID then MISSING_GRANT for every bank question. The live-authority
    call plan is 1,128 attestations and 2,444 requests, plus ledger reads and any
    additional revocation-feed pages. Pacing occurs before slot issuance; HTTP 429
    stops the sequence. No arm is dispatched twice.
11. Pull and verify the secondary archive and Mac ledger join. Destroy the pod on
    every exit path and confirm its absence. Record start/stop times, rate, billing
    readback and estimated cost separately. The run key remains under author control.

## Runtime-resolved fields

`PUBLIC_CONTENT_VERIFIED_AT` resolves to the UTC time at which the public record,
archive bytes and GitHub tag members are verified. It is an observed availability
timestamp, not the draft creation time or an asserted publication instant.
`SEALED_PRIMARY_ARCHIVE`
resolves only to the SHA-256 of the completed joined primary archive. The templates
remain unchanged. Each resolved configuration and its unique approval are retained
with the evidence. These are measured inputs, not changes to predictions or protocol.
`gpu_type_id` and `data_center_id` are supplied from the recorded capacity selection
before each approval is bound. Both runs use the same selected allocation.

Execution requires a unique approval file bound to the resolved configuration,
which pins the registration hash. A persistent allocation claim binds both
configurations before pod creation. An allocation that does not reach execution
still consumes that claim; it does not permit a second registered allocation.

## Numerical rule

The full verifier permits absolute float32 gate-state difference at most `2^-21`,
zero relative tolerance and recomputed magnitude in [2,8). Every BF16 vector byte,
non-EOS identity, token ID, output byte, signature and asset hash remains exact.
The pinned input-vector hash is a separate hardware-dependent comparison.
