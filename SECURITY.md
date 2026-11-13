# Trusted boundary

The host, interpreter, dependencies, authority public key, clock, replay database,
decoder and runtime signer are trusted software. A runtime signature authenticates
its statement; it does not prove honest physical execution. The model has neither
an authority credential nor access to the runtime signing seed.

Private inputs are API keys, runtime signing seeds, credential paths and runtime
databases. They stay outside this repository and its evidence exports. Public
objects are public keys, hash pins, grants, denial objects, revocation entries,
vectors, output bytes and receipts. Credential values never enter command lines.

The capture host creates one runtime signing seed for each registered run and
publishes its verification key with the configuration. The pod receives the seed
through a sealed anonymous Linux memory descriptor. The seed is never written to
the pod filesystem. The capture host and seed custodian can also sign receipts;
the runtime signature is not independent hardware attestation.

A registered pod holds a new verify-only key that the author supplies and retires
after both runs. It needs POST /attest and one POST /attestation/revoke. Public
revocation lookups require no credential scope. The verify scope itself is broader
than the single-JTI restriction; the trusted runner enforces that restriction.
Admin does not imply verify. No key-management or policy-write capability is used.

Mac-side admin capture reads governance and authentication-denial listings. The
admin principal must have visibility into the run key's tenant. The pod sends no
admin listing request. Governance listings are unsigned, window-limited and not
filterable by key identifier. Signed revocation pages provide a separate witness.

HTTP clients disable redirects and environment proxies. The native client accepts
loopback only. Anonymous signed operational records are bounded to 64 per runtime
database. This is a local research service, not an internet-facing deployment.

Approval identifiers are config-bound and single-use. Model-loading and config
checks precede approval consumption. No retry follows an ambiguous remote outcome.
Runtime and provider time estimates are recorded as software observations.
