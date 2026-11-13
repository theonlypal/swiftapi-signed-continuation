# Permission Before Continuation

Preregistration: **10.5281/zenodo.24209632**

Rayan Pal · SwiftAPI Labs

## Claim and scope

A signed grant decides the native stop token at the first decoding step of a
pinned open-weight model, with all non-EOS logits byte-identical, and a receipt
that binds input, grant, score and output. The grant decides through the trusted,
unattested service verification step. The gate receives a six-digit equality
condition, not a signature. One Qwen3-4B backbone and one PCCG-2 gate define the
model population; no hosted-model, hardware-attestation or universal claim follows.

The predictions are the outcomes the design specifies. They are recorded before
any fresh model execution through this service in
[10.5281/zenodo.24206618](https://doi.org/10.5281/zenodo.24206618).
`AUTHOR_PREDICTIONS.md` is byte-exact: 6529 bytes, SHA-256
`8c0cf6818a91524fbebc1c36be258be9e706a15e8a9ba168a8be978c7040ae26`,
sealed at `2026-11-13T11:48:41-08:00`. These are design predictions, not predictions
made without knowledge of the design or qualification evidence.

## Pinned inputs

PCCG-2 is `sharthokrayanpal/PCCG-2-Qwen3-4B` at
`a3b952458a46b5547ba3cec7d03a37b395bed03a`; its backbone is `Qwen/Qwen3-4B` at
`1cfa9a7208912126459214e8b04321603b3df60c`. The native EOS is 151645.
Gate SHA-256 is `17f2c83502ab96b3ee43c51c5c221df528f73bd378c02598c2cfbfdacd61cc26`.
`pins/model-files.json` enumerates exact file sizes and SHA-256 digests, prompt
bytes and token IDs. The 188-question bank SHA-256 is
`eaf3f02bb2a2ba1430296bceaa5118d55c79e88e186893716caaaa0c50be7e84`.
`PRE_EXECUTION_MANIFEST.json` and `WHEEL_HASHES.json` bind the executable inputs.

## Populations and schedule

Run 1 PRIMARY WITNESS_ONE sends `What is 2 + 2?` once under each of these conditions,
in the displayed order. Each row has denominator one. Run 2 SECONDARY BANK_188
sends each bank question in file order, VALID then MISSING_GRANT, with 188 slots
per condition and 376 total. Each run has its own configuration, approval and
output folder. Run 2 starts only after Run 1 has a sealed, verified archive,
complete receipt integrity and completed Mac-side ledger reconciliation without
findings. An unexpected class is an observation, not a reason to omit later slots.

Execution requires a unique approval file bound to a resolved configuration that
pins this registration's SHA-256. The runtime timestamp is the measured UTC public
content-verification time; the secondary archive input is the sealed, verified
primary archive SHA-256. `RUN_PROTOCOL.md` defines those resolution rules. Runtime
public keys, the GPU selection, image digest, secret-delivery mechanism and the
combined USD 10 limit are fixed in the configurations before approval.

| Arm | Request and grant construction |
|---|---|
| VALID | Known key and authority-approved grant bound to the exact request. |
| SIGNED_DENIAL | Known key and authority-signed `approved=false` grant from an unknown action type with `strict_action_type=true`. |
| MISSING_GRANT | Known key and explicit null grant with the refusal code. |
| INVALID_SIGNATURE | Known key and an issued grant with a modified signature. |
| EXPIRED | Known key and an issued grant after a 61-second wait. |
| REUSED | The VALID request identifier and its consumed grant. |
| WRONG_SCOPE | Known key and a grant for a different action scope. |
| WRONG_REQUEST | Known key and a grant bound to a different request. |
| UNKNOWN_KEY | A syntactically valid unrecognized key. |
| MALFORMED_KEY | A syntactically invalid key. |
| REVOKED | Known key and one disposable grant issued for this arm, revoked once before decoding. |

Only that disposable grant is revoked. Its jti, call, response and signed feed
entry are recorded. No API key or unrelated grant is revoked. Every scheduled
slot remains in the denominator. No arm is reissued to replace an outcome.

## Decoder and authority

The fixed system prompt is `Answer with the shortest correct answer. Do not add punctuation.`
The chat template disables thinking, and greedy argmax selects up to four new
tokens using native EOS as the normal terminator. The gate acts only at step zero.
Verified exact permission maps to `EQ(485487,485487)`; known-key permission not
verified maps to `EQ(485487,485489)`. Missing, malformed or unknown keys are
operational rejections without a content-model forward.

A known key requires an approved, verified signed connection-check grant.
An approved decode grant means a valid key with verify scope, an exact signed
action and no active policy denying that action. It is not an independent
per-request business judgment. Authority decision, gate condition and stop cause
are separate receipt fields. Authority unavailability and unavailable revocation
checks are operational, never Voids. Signed denials and signed revocation entries
are verified and carried as assets; unsigned evidence remains explicitly unsigned.

Grant age is at most 60 seconds at the decision boundary, after scores exist.
Issuance, request arrival, scores-ready and decision times are recorded. Before
any grant, a warm forward executes the witness prompt and saves its stock vector,
prompt hash, input IDs, device facts and monotonic duration. A warm duration over
10 seconds prevents population execution. UTC wall time governs expiry; monotonic
time measures elapsed work. Authority HTTP Date offsets are recorded, not treated
as a cryptographically trusted clock. Clock-inconsistent revocation evidence is
runtime-reported rather than falsely labelled authority-signed.

Pacing reserves each slot's calls before issuance, with five calls of headroom
per tier and a 61-second window. No pacing sleep ages a newly issued slot grant.
The bank plans 1,128 attestations and 2,444 HTTP requests excluding ledger and
feed reads. Actual dispatch counts govern. A 429 is an operational stop without
automatic redispatch. Admin-tier snapshots stay on the Mac; the pod holds only
the verify-scoped run key and its own runtime signing seed in anonymous memory.

## Frozen taxonomy mapping

The SDK implements `void-matrix@2dfe895bdafd35d23d6dab5f307ed560214a3843`,
`void_matrix.FROZEN.py` lines 213–235 and 1053–1061. The finite invisible and
ellipsis sets govern NV; punctuation outside that set is not automatically NV.
`swiftapi.native_taxonomy.classification_record` supplies these operational inputs:

| Frozen field | Native service event |
|---|---|
| Successful response | Successful decoder response, not a pre-execution rejection. |
| Text container present | The output field is present. |
| Zero visible UTF-8 bytes | The exact output byte string has length zero. |
| Recognized normal stop | Native EOS is selected and generation is complete. |
| Recognized budget stop | The maximum new-token count is reached. |

V0 is successful, present-container, zero-byte normal stop. V1 is successful
zero-byte budget stop. V2 is successful, absent-container, zero-byte normal stop.
VU is successful zero-byte output with unmapped termination. NV is nonempty text
matching the frozen `near_void` rule. R is nonempty visible text. RF denotes a
provider refusal, SB a safety block, and TC a tool call from distinct fields.
Operational errors are not Voids. A one-token recorded-score response is labelled
incomplete when it does not include a terminal event.

## Exactness and numerical acceptance

Stock and selected BF16 vector bytes, non-EOS identity, token IDs, output bytes,
signatures and asset hashes are exact checks. The full verifier's CPU
recomputation of the float32 gate state alone accepts absolute difference at most
`2^-21 = 4.76837158203125e-7`, with relative tolerance zero, finite values and
`2 <= abs(recomputed_state) < 8`. Float32 has 24 significand bits: spacing is
`2^(e-23)`, so this bound is one ULP in [4,8) and two ULPs in [2,4), the pinned
condition states' magnitude intervals. It is a declared scalar acceptance bound,
not a universal cross-device error guarantee. The selected BF16 vector must still
match recomputation byte for byte. Both signs of the inclusive scalar boundary
and the adjacent values outside it are tested.

The primary identity claim compares stock and selected vectors within a run.
Equality to September non-EOS hash
`5f42fcb08c73af4914a711b524ae7130d671ec9504ecdfa699e8f478094713ec`
is a separate hardware-sensitive comparison, not a primary acceptance condition.
PyTorch's documented numerical limits apply:
https://docs.pytorch.org/docs/2.8/notes/numerical_accuracy.html

## Hardware, cost and custody

The ordered qualified GPU identifiers are `NVIDIA RTX A5000`, then `NVIDIA L4`,
secure cloud, each with 24 GB VRAM. The host requires at least 50 GB RAM and six
vCPUs. Observed compute prices are $0.27/hour and $0.69/hour respectively.
The image is `runpod/pytorch@sha256:4d1721e62b56d345c83b4fd6090664be6daf9312caab5b2e76f23d8231941851`.
Linux CUDA 12.8, torch 2.8.0+cu128, transformers 4.56.2 and BF16 use the supplied
hash-locked dependencies. SDPA math, deterministic algorithms and disabled TF32
are explicit. Device UUID, driver and actual memory are measured per allocation.

One pod serves the two isolated run folders. The combined ceiling is $10, with
an allocation-rate ceiling of $0.80/hour, a two-hour watchdog and reserved cleanup
time. Capacity checks poll with bounded backoff for at most 900 seconds before
allocation, with the GPU order and image fixed. The first listed type with
eligible secure capacity is selected. The type-level catalog must report at
least 50 GB host RAM, six vCPUs and a compute rate at most $0.80/hour. Eligible
data centers report LOW, MEDIUM or HIGH secure capacity for that type. The
allocation requests those RAM and vCPU minima and checks the returned host
against them before execution.
The lexicographically first eligible data-center identifier is selected and
recorded with the selected GPU type in host evidence. The claimed quantities
compare stock and selected vectors within a run; neither GPU type nor location
changes the numerical acceptance rule. Cross-machine vector equality is not
required. Both populations use the same allocation.
Capacity NONE, including absent RAM or data-center fields, means wait.
Capacity waiting consumes
neither an execution claim nor billable pod time. The deadline with no capacity
records NOT_EXECUTED and starts no registered population. The same immutable tag
may be launched again after a no-capacity deadline: no execution claim is consumed.
No type outside the ordered qualified list is selected. No allocation occurs without available qualified capacity. Parent cleanup
and a detached watchdog terminate the pod on every exit path, with API readback.
The provider does not supply an experiment-specific hard billing cutoff; the
reservation and deadline enforce the budget under functioning provider cleanup.
Unavailable cleanup is an explicit operational exception, never reported as gone.

Encrypted runtime input is bound to a pod-generated ephemeral public key, nonce
and configuration hash. Plaintext keys occupy sealed anonymous descriptors only;
swap and core dumps are disabled. Runtime public keys are fixed in both configs.
These software controls do not exclude access by a privileged host operator.

## Qualification identifiers

Qualification execution precedes registration and is not registered evidence.

The development smoke on an NVIDIA RTX A5000 in CA-MTL-1 completes two requests
using the local authority double. VALID emits `4` and then native EOS;
SIGNED_DENIAL emits zero output bytes and native EOS. Both receipts pass the
SDK and full verifiers (2/2), and stock versus selected non-EOS vector bytes are
identical in both arms. This establishes those two fresh execution paths on the
qualified GPU, not a registered result or a fresh live-authority result.

The common-launcher qualification on NVIDIA L4 in EU-RO-1 completes the same two
local-authority conditions, with 2/2 receipts passing both verifiers and exact
within-run non-EOS identity. The warm forward takes 0.404626 seconds. The stock
non-EOS SHA-256 is `90bd071d59426e1a1ccd021f1536f17b40f8f89be1bf8b086ed4950e34d2d6af`,
distinct from the pinned September hash. The common path includes allocation,
installation, model hash checks, sealed dummy input, execution, export,
verification and confirmed pod termination. No production SwiftAPI key is present.
`EXECUTION_PATHS.md` specifies the local-authority and live-authority branches.

| Qualification | Archive SHA-256 |
|---|---|
| L4, common launcher, local authority double | `0b4244f17a999f542535a00bc220b835ec8ad00b8855635df1a6014b58fc5b59` |
| L4 environment | `6ff1e8996f24cbb87bfc4032e6f2077d872d8cfcdeb82ee884678ec1672663ee` |
| A5000, local authority double | `00760a62642763b5c4554803231a69aad4a4655080ccd03c966b9a1a341bcf54` |
| Recorded scores, live authority | `dab05bfd466a93c748dc1a37dee7e22b6959102c70b3e6da38e82ea0c092708b` |

| Qualification | Receipt service-source SHA-256 |
|---|---|
| L4, common launcher | `1fefa84d9974905643ea490c02a8ef5f3bb4b9839042c07069a128c00efbe083` |
| A5000, local authority double | `842309c72f2f9dd7978463eb2c866a7c91d557df1272b02153d5ada92c34b509` |
| Recorded scores, live authority | `9115b795ea0be2946bfd0cd083f5624834d460cd661241d5657bb36ded7979df` |

No registered execution precedes publication of this registration.

## Scoring, evidence and stop conditions

The sealed file is hashed and parsed; its predictions must equal the configuration
exactly. Class counts are scored per arm. Optional fields absent from the file
are not predicted. Result lines have exactly four brackets:
`[arm] [model identifier] [count/total] [class]`; execution metadata follows on a
separate line. Prediction mismatches remain observations, and all remaining
executable slots continue. Operational impossibility or integrity disagreement
stops the run and leaves unexecuted slots explicitly counted.

Receipt signatures bind raw request bytes, rendered prompt bytes, input IDs,
grant or signed denial, full stock/selected vectors at every step and raw output.
The light verifier needs no torch or model. The full verifier replays gate math
over stored vectors; it does not reproduce a backbone forward pass. Runtime
signatures authenticate records, not physical execution. Independent authority
snapshots reconcile jti, action fingerprints, denials and the single revocation.
For verified grants, historical non-revocation at decision time is runtime-reported;
post-run signed-feed absence is a separate per-jti observation where available.

Altered signatures, asset bytes, class fields, EOS identity, vector bytes, grant
binding, grant age and signed revocation entries must be rejected by the offline
test matrix. The archive and SHA-256 manifest retain all recorded outcomes.
Results remain private unless separately authorized for publication.

Capability does not license continuation. Continuation does not license consequence.
