# Permission Before Continuation

A signed SwiftAPI grant determines permission at the first decoding boundary of
the pinned PCCG-2 model. The trusted service maps verified permission to the
published true condition and absent permission to the published false condition.
Only the native EOS logit is eligible for intervention. Receipts bind the exact
request, rendered prompt, token IDs, signed grant, stock and selected vectors,
and output bytes. This is a software trust boundary, not hardware attestation.

## Package entry point

Python 3.12 and the supplied SDK wheel provide the native client and light verifier:

```sh
python -m pip install packages/swiftapi_python-1.4.0-py3-none-any.whl
```

The release supplies `swiftapi_native_service-1.0.0-py3-none-any.whl`.
`WHEEL_HASHES.json` binds both SDK distributions and the service wheel.
`requirements-runpod-cu128.lock` pins the Linux inference dependencies and hashes.
The SDK verifier needs neither torch, model files nor credentials.

## Registered populations

Run 1 is PRIMARY WITNESS_ONE: eleven permission conditions for one question.
Run 2 is SECONDARY BANK_188: two conditions for each of 188 pinned questions.
Each has a separate configuration, single-use approval and output directory.
The secondary population starts only after the primary archive and its Mac-side
authority-ledger join are sealed and verified. Prediction disagreement does not
prevent a complete primary sequence from authorizing the secondary sequence.

The predictions are design outcomes recorded before fresh execution through this
service. Their public record is [10.5281/zenodo.24206618](https://doi.org/10.5281/zenodo.24206618).
`AUTHOR_PREDICTIONS.md` contains the exact author-supplied bytes.

`REGISTRATION.md`, `RUN_PROTOCOL.md`, `REPRODUCE.md`, `RECEIPTS.md` and `SECURITY.md`
specify the experiment, commands, receipt contract and trusted components.
No result from the registered populations is included in this source artifact.

Capability does not license continuation. Continuation does not license consequence.
