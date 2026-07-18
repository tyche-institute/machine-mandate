# interop/ — IETF 126 composition inputs

Frozen pre-execution inputs for a pre-registered, three-party interoperability exercise
carried out around the IETF 126 hackathon, Vienna, July 2026. **Nothing in this directory is
a result.** These are inputs, published so that every value in the exercise can be checked
against bytes rather than taken on trust.

| File | What it is |
|:--|:--|
| `composition-input-manifest-v0.5.json` | the governing composition input manifest, sha256 `7d76335f…a882` |
| `composition-input-manifest-v0.4.json` | the preceding version, sha256 `db9cf7f2…9b3f`, kept on file unchanged |
| `mint_run_credential.py` | mints the single MachineMandate run credential and self-checks it |
| `run-credential-preimage.jwt` | the frozen credential preimage: the exact issuer-signed JWT component bytes, 1190 bytes, no trailing newline |
| `run-credential-issuer.jwk` | issuer public key, for verifying the preimage signature |
| `run-credential-mint-record.json` | the freeze record: digest, claims, provenance, self-check, disclosures |
| `presentation_invariance_check.py` | reproduces the preimage across varied presentations |
| `run-credential-presentation-invariance.json` | six presentations preserved as transmitted, with their digests |

Versioned files are never edited in place. A change is issued under a new filename and a new
SHA-256, and earlier versions stay on file, so that any digest quoted in a review record keeps
resolving to the bytes it was quoted against.

## Verify the frozen preimage

```bash
sha256sum interop/run-credential-preimage.jwt
# 5df4d32df57650f27b6a65df041b708de80d69c0ca82a1044334f5e2edef5ce2
```

The digest covers the **issuer-signed JWT component only** — the first `~`-separated
component of the SD-JWT as transmitted, with no separator and no trailing newline. Hashing
the whole credential file gives a different value.

That component is fixed at issuance. The holder signs a fresh key-binding JWT for every
presentation and may disclose a different subset of claims each time, and none of that
changes the frozen bytes:

```bash
python3 interop/presentation_invariance_check.py --run-dir <dir-holding-the-credential>
```

Six presentations, varying verifier nonce, audience and revealed-claim subset from the empty
subset through all four claims, each verified to round-trip, each preserved as transmitted.
One of them discloses every selectively-disclosable claim, so the disclosure encodings can be
checked against the credential's `_sd` commitments from these published files alone.

## Boundaries

- The credential is synthetic and sandbox-only. No live payment, no real payment data.
- The issuer key is generated per run and self-signed, and `iss` carries the placeholder
  `qtsp://issuer`. It is a run-specific synthetic trust input: do **not** pin its JWK
  thumbprint as a stable endorser identity, and do not read it as a real or anchored QTSP.
- The attestation root in this deployment is an emulated software TPM (swtpm). The RATS
  freshness logic is real; the hardware root is not, and no property of a hardware root may
  be read into it.
- The self-check in the mint record is evidence about the **credential**, produced inside a
  single process with its own issuer key, holder key, verifier, harness-built trust list and
  the repository's pre-captured fixtures. It is not a composition or interoperability result.
- Any freshness statement must distinguish a live verifier challenge issued during a composed
  run from freshness logic exercised against a replayed fixture.
- The frozen digest is a one-shot commitment to these exact bytes. Fresh keys, random salts
  and `iat`/`exp` all enter the preimage, so re-issuing the credential necessarily produces a
  different digest. A re-issue voids the freeze and is notified explicitly rather than
  performed quietly.

## Licence

Apache-2.0, as the repository root.
