# Execution paths

`tools/run_registered.py` supplies both registered execution and development
qualification. Both modes call the same capacity selector, allocation builder,
readiness poller, bundle uploader, environment preparer, worker, sealed-input
transport, experiment runner, evidence downloader, two receipt verifiers and
pod cleanup functions.

| Parameter or branch | DEVELOPMENT_SMOKE | PREREGISTERED_STUDY |
|---|---|---|
| Source acceptance | Local archive member bytes and wheel pins | Public registration, tagged archive member bytes and wheel pins |
| Population | SMOKE: VALID and SIGNED_DENIAL once | PRIMARY eleven arms, then SECONDARY 376 slots |
| Authority | Local test double | Live SwiftAPI |
| Private input | Fixed public dummy value and ephemeral signing seed | Verify-only run key and registered signing seeds |
| Key transport and checks | Sealed box, anonymous sealed descriptors, hash binding | Same |
| Mac administrative ledger | Not applicable to the local double | Before/after capture, join and primary integrity gate |
| Allocation authorization | One source-bound development approval | Persistent registration/configuration claim |
| Cost reservation | Cumulative USD 2 including prior charges | Combined USD 10 |
| Runtime deadline | 3,600 seconds | 7,200 seconds |

Capacity waiting has a separate 900-second deadline and consumes no allocation
claim. The worker permits SMOKE only with DEVELOPMENT_SMOKE and LOCAL_TEST_DOUBLE;
PRIMARY and SECONDARY require PREREGISTERED_STUDY and LIVE_SWIFTAPI. A development
receipt is not evidence of a live-authority registered execution.

`--no-allocation` runs local artifact, private-input identity, budget, provider
schema and live catalog checks without consuming a claim, sending an authority
request or creating a pod. Public-registration verification remains mandatory
for registered allocation and is explicitly reported when not evaluated.
