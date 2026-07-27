# Deliverable-B composition runner

`deliverable_b_runner.py` is a fail-closed, manifest-driven runner for the five
cases in `composition-input-manifest-v0.5.json`.

It is deliberately limited to:

> ENGINEERING VALIDATION — NON-EVIDENTIARY — NOT A DELIVERABLE-B RESULT

The executable refuses `--mode final`. A final evidence-generating run requires
a separately reviewed runner/version, final immutable coordinates, owner
confirmation, and explicit authorization.

The rehearsal verifies the four ORPRG release-asset hashes, executes both ORPRG
package verifiers, verifies the prior AEP vector, confirms the MachineMandate
runtime files against commit `e440286d`, uses the pinned AAC and `scitt-cose`
implementations by reference, and emits one hash-manifested archive plus a
detached SHA-256 sidecar.

Each case captures the exact SD-JWT+KB-JWT presentation, disclosures,
holder-binding proof, verifier nonce/audience, issuer-signed JWS preimage and
digest, issuer JWK, synthetic trust input, owner-verifier identity and appraisal
record, Capsule JSON, COSE Signed Statement, gate trace, and relevant hashes.
Live AEP quotes are produced by an ephemeral `swtpm` and verified offline with
`tpm2_checkquote`.

Example:

```sh
python3 interop/deliverable_b_runner.py \
  --orprg-assets /path/to/four-release-assets \
  --orprg-root /path/to/orprg-ietf126-payment-composition-v0.1 \
  --aac-repo /path/to/agent-action-capsule-at-c19e82a \
  --aep-repo /path/to/aep-pcr16-vector-at-9521185 \
  --scitt-cose-repo /path/to/scitt-cose-at-2146e39 \
  --out /new/path/rehearsal-run
```

The output path must not already exist. Private signing keys are ephemeral and
are not written to the package. The MachineMandate L2 self-check remains the
frozen replayed `swtpm` fixture and is labeled separately from the live
per-case AEP quote.
