# Native receipt contract

## Numerical comparison

The full verifier requires byte-exact BF16 stock and selected vectors, byte-exact
non-EOS identity, token IDs, output bytes, signatures and asset hashes. Only the
float32 gate-state scalar uses absolute tolerance `2^-21 = 0.000000476837158203125`,
with zero relative tolerance, finite values required, and recomputed magnitude
restricted to [2, 8). The inclusive bound is
one binary32 spacing in [4, 8) and two spacings in [2, 4): binary32 has 24
significand bits, so spacing at exponent 2 is `2^(2-23)`. The two pinned condition
states have magnitudes in these intervals. This is a fixed acceptance rule,
not a universal cross-device error guarantee. The reconstructed selected BF16
vector must still match every byte. The verifier reports both scalars and their
absolute difference. PyTorch 2.8 does not guarantee identical CPU and GPU
floating-point results for identical inputs:
https://docs.pytorch.org/docs/2.8/notes/numerical_accuracy.html.

Schema: swiftapi-native-service-receipt/2. Envelope: payload, Ed25519 signature and runtime
public-key identity. The runtime public key exists before any receipt. Verification
uses a separately trusted public anchor, not a key accepted solely from an envelope.

The signed payload binds service source, SDK version, classifier identity, model
and gate pins, request, authority decision, gate condition, stop cause, output and
classification fields. A missing grant is JSON null with a refusal code. An
authority-signed denial is distinct from a runtime-reported refusal.

Assets are request.json, prompt.utf8.bin, input-token-ids.json, grant.json,
output.bin, authentication.json and applicable authority-denial.json and
authority-revocation.json. Each decoding step has complete stock and selected BF16
vectors. Every asset hash and byte length appears in the signed payload.

Timing fields include request_arrival_at, grant_issued_at, scores_ready_at and
decision_at. The signed action profile carries max_grant_age_seconds. Verification
requires its registered expected value independently. Native normal stop means EOS
selection and complete generation. A replayed non-EOS token is an incomplete
first-token response, not a complete answer.

The SDK verifier requires no torch or model files. It checks both signature chains,
grant binding, asset hashes, vector argmax, exact non-EOS identity and frozen class.
The full verifier additionally reconstructs gate behavior from the pinned inputs.

The frozen NV rule is the finite helper at void-matrix
2dfe895bdafd35d23d6dab5f307ed560214a3843, lines 213–235 and 1053–1061. Punctuation
alone is not a general NV rule. A lone question mark or exclamation mark is R.
R denotes visible response; RF denotes a distinct refusal field. Operational
errors are not Voids. Classifier hashes are declared against the SDK release list.

The authority-signed revocation entry concerns one JTI. A runtime decision that a
grant is not revoked remains runtime-reported. Reconciliation also checks its
absence from signed feed pages whose fetched time covers the decision, with
coverage limits explicit. A timeout is an unresolved outcome, not evidence of no
remote change.
# Public identifier of the API key

The runtime-signed `principal_identity` contains two digests. `principal_sha256`
is SHA-256 over the ASCII prefix `swiftapi-native-principal-v2`, one zero byte,
and the ASCII API key. `operator_key_sha256` is SHA-256 over the ASCII API key,
the identifier used by the Operator. Its prefix permits a public comparison
without publishing the key. This association is a runtime-signed mapping, not
an independent authority attestation of the mapping. Test-authority receipts
identify their synthetic client key, not a production Operator key.
