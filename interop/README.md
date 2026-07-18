# interop/ — IETF 126 deliverable-B composition inputs

Frozen pre-execution inputs for the three-party composition exercise
(Meridian Verity / Tyche Institute / Action State). **Nothing here is a result.**

| File | What it is |
|:--|:--|
| `composition-input-manifest-v0.4.json` | the composition input manifest, sha256 `db9cf7f2…9b3f` |
| `mint_run_credential.py` | mints the ONE MachineMandate run credential and self-checks it |
| `run-credential-preimage.jwt` | the frozen credential preimage: the exact issuer-signed JWT component bytes (option (a)), 1190 bytes, no trailing newline |
| `run-credential-issuer.jwk` | issuer public key, to verify the preimage signature |
| `run-credential-mint-record.json` | the freeze record: digest, claims, provenance, self-check, disclosures |

## Verify the frozen digest

```bash
sha256sum interop/run-credential-preimage.jwt
# 5df4d32df57650f27b6a65df041b708de80d69c0ca82a1044334f5e2edef5ce2
```

Equivalently, from the full credential: hash the first `~`-separated component only —
no trailing `~`, no newline. Hashing the whole SD-JWT file gives a different value.

## Boundaries

- The credential is synthetic and sandbox-only. No live payment, no real payment data.
- The issuer key is generated per run and self-signed; `iss` is the placeholder
  `qtsp://issuer`. Do **not** pin its thumbprint as a stable endorser identity.
- The mint record's self-check is evidence about the **credential**, produced inside one
  Tyche process with its own keys, verifier, harness-built trust list and the
  repository's pre-captured emulated-TPM (swtpm) fixtures. It is **not** a composition
  or interoperability result.
- The digest is a one-shot commitment to these exact bytes: fresh keys, random SD salts
  and `iat`/`exp` enter the preimage, so re-minting necessarily changes it. A re-mint
  voids the freeze and is re-notified explicitly on the review thread.
