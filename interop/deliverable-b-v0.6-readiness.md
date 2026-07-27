# Deliverable-B v0.6 readiness record

Date: 2026-07-27

Status: **PREPARED FOR OWNER REVIEW — FINAL EVIDENCE RUN NOT AUTHORIZED**

This record does not modify or supersede
`composition-input-manifest-v0.5.json` (SHA-256
`7d76335f0cd5517d415506309294a7b83ac622a0134f618dafdf18b3a3cea882`).
It identifies the candidate coordinate updates and remaining gates for a future
v0.6 issuance.

## Candidate immutable coordinates

| Surface | Candidate coordinate | Treatment |
|:--|:--|:--|
| MachineMandate runtime | `e440286dec11c43ad39ebcc7d0001fa0987e7bd8` | unchanged frozen runtime |
| AAC composition profile | `c19e82a4f73a7be3f97b99e53a900adee6b74392` | descendant of the v0.5 `46bfb4a…` pin; includes the v0.5 gate-name correction |
| AEP prior vector | `9521185f77c3dce292d7b4bd8a8100ca11fb50be` | unchanged prior-vector input; not proof of the new composition |
| `scitt-cose` rehearsal substrate | `2146e39d298e2f92df2fe39fbf70a15f267b3ab1` | candidate explicit pin for COSE Signed Statement build/verification |
| ORPRG payment tuple | tag `ietf126-payment-composition-v0.1`; ZIP SHA-256 `d13c740c47710e4b28a1d2d511aa63574200256ce310f0e03ec618b383583c2f` | unchanged |

## Rehearsal-only implementation

`deliverable_b_runner.py`:

- refuses final/evidentiary mode;
- verifies every frozen hash and owner verifier before executing cases;
- executes the six composition gates in order and short-circuits at the first
  rejection;
- creates fresh per-case OID4VP challenges and preserves the complete
  SD-JWT+KB-JWT evidence requested by Lee;
- produces live ephemeral-`swtpm` AEP quotes for the positive and
  representation cases, and an offline-verified stale-quote rejection for the
  replay case;
- emits one synthetic sandbox commit marker only for the positive case;
- writes a full file-hash manifest, a single archive, and a detached archive
  SHA-256 sidecar.

The MachineMandate owner-verifier L2 input remains its frozen replayed fixture
and is labeled separately from the live AEP quote. The run-specific issuer is
self-signed and synthetic; `qtsp://issuer` is not represented as a real QTSP.

## Conditions before any final evidence-generating run

1. Owners review the runner source, evidence schema, and candidate coordinates.
2. A new v0.6 manifest is issued under a new filename and SHA-256; v0.5 remains
   unchanged.
3. The run-specific final MachineMandate credential, issuer JWK/trust input,
   preimage digest, and validity window are frozen and circulated before
   execution.
4. The exact final runner commit/source digest and environment are recorded.
5. Explicit authorization to execute the final evidence run is recorded.

Until all five conditions are satisfied, the only permitted output label is:

> ENGINEERING VALIDATION — NON-EVIDENTIARY — NOT A DELIVERABLE-B RESULT
