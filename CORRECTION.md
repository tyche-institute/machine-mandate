# Correction — the L2 freshness check verified itself (2026-08-11)

This corrects a security claim in the preprint *Machine Mandates in the EU Digital Identity
Wallet* (v1.0, 7 July 2026, [10.5281/zenodo.21229865](https://doi.org/10.5281/zenodo.21229865))
and in this repository. The defect was found by the author during a self-directed adversarial
review, before any third party ran the artifact, and is reported here in full.

## What was wrong

`src/verifier_core.py` set the "session" nonce with

```python
_SESSION_NONCE = quote_bound_nonce(_QUOTE_GOOD)
```

that is, it derived the freshness challenge **from the very quote the challenge was meant to
check**. The comparison `session_nonce == quote_nonce` was therefore a tautology. The same
pattern was in `src/agent_demo.py`.

Three consequences, each reproduced by execution:

1. **A literal replay passed.** The same captured quote, re-presented in five fresh sessions,
   was accepted 5/5 with L2 green. That is precisely the attacker capability the paper's
   threat model (D) claims to deny.
2. **The check itself was correct; its input was degenerate.** Given an independent random
   challenge, the same presentation is correctly denied with
   `L2: replay (session nonce != quote nonce)`. Nothing was missing — the challenge side was
   simply derived from the evidence side.
3. **Table §8.6 never tested freshness.** The row labelled "replayed stale attestation"
   substituted a *different* quote whose EAR was `contraindicated`, so the denial came from the
   affirming sub-check. With the freshness term deleted entirely, all seven rows still produced
   the published verdicts and the script still printed
   `PASS … the composition is minimal`. The headline minimality result survived deletion of the
   check it was supposed to exercise.

`src/mock_verifier.py`'s own self-test did contain a correct replay case (quote A against an
independent nonce, which denies). The honest test existed; it was not the one the README,
ARTIFACT.md or Table §8.6 pointed at.

## What was changed

- `MockVerifier.request()` now issues a **verifier-chosen 32-byte challenge** (`rp.challenge`),
  distinct from the OID4VP `nonce` that binds the KB-JWT.
- `mock_verifier.rebind_evidence()` builds a synthetic Attester-response fixture for that challenge.
  The captures are static, so the helper splices the challenge into the quote's `extraData` and the
  EAR's `eat_nonce` to exercise the gate logic. It does **not** create a matching TPM signature or a
  newly appraised EAR and is not new attestation evidence; a live flow must obtain those from the
  Attester.
- A replay is now what the name says: evidence that is **good, affirming and correctly
  EAR-bound**, produced for an *earlier* challenge. Freshness is the only term that can deny it.
- `src/agent_demo.py` no longer derives its session nonce from the quote.
- A row **"attestation contraindicated"** was added so the affirming sub-term keeps the coverage
  it previously provided by accident. Table §8.6 therefore has **eight** rows, not seven.
- `ARTIFACT.md` referenced a `--replay` CLI flag that `run_ablation.py` never implemented; the
  reference is removed.

## How to verify the correction

```bash
python run_ablation.py          # 8 rows, PASS, exit 0
python src/mock_verifier.py     # 5 self-test rows, PASS
```

And the test that matters — delete the term and watch the claim break:

```python
# replace  fresh = (session_nonce == bound)
# with     fresh = True
# in src/mock_verifier.py, then:
python run_ablation.py          # "replayed stale attestation" wrongly ACCEPTs
                                # FAIL 1 verdict(s) did not match the paper; exit 1
```

Before this correction that same probe left all seven rows passing. That is the difference
between a check that is present and a check that is load-bearing.

## What is *not* affected

Checked by grep for `quote_bound_nonce|session_nonce` across the sibling repositories: **zero
occurrences** in `eatf`, `eatf-verifier` and `aep-pcr16-vector`. The pattern was local to this
artifact. The composition Internet-Draft's §5.4 claim is a different and correct test — "replay
under a fresh challenge rejected (rc≠0)" — in a different codebase, and stands unchanged.

The emulated-root caveat is unchanged and unrelated: the Attester was and remains a software TPM.

## Addendum (2026-08-11, later the same day)

Two refinements to the statements above, recorded after the correction was first published
(Zenodo version 2.1, 10.5281/zenodo.21888986):

- **"The pattern was local to this artifact" was scoped too narrowly.** The grep covered the
  sibling repositories `eatf`, `eatf-verifier` and `aep-pcr16-vector` only. The same wiring also
  existed in the GATEHOUSE demo backend (`agent.eatf.eu`) and in the verifier bench's agent-gate
  demo; both were corrected the same day, and the live GATEHOUSE deployment now denies its replay
  card on freshness (`L2: replay (session nonce != quote nonce)`) over the public tunnel. Some
  bench drivers retain quote-derived session values in their ACCEPT-row fixtures; their replay
  rows use independent nonces and are honest, and that cleanup is tracked in the bench.
- **This repository now also implements the manuscript §3.1 seal normalisation** (`deps/jcs.py`
  NFC-normalises string keys and values, refusing NFC-equivalent duplicate keys;
  `tests/test_nfc_seal.py` covers canonical-equivalence, lookalike-payee and duplicate-key
  vectors), and rewords the ablation's "sole denier / composition is minimal" claims to
  first-denier-in-evaluation-order: L4 re-verifies the presentation's signatures, so removing L1
  alone would not admit the forged-credential vector. The freshness term remains the executably
  load-bearing claim demonstrated above.

## Second addendum (2026-08-11, evening) — two further defects found by adversarial review

The correction above was itself put through an adversarial review. It found two things
in the *corrected* code, both now fixed in this repository:

- **The action seal truncated instead of refusing.** `action_hash()` coerced its fields
  with `int()`/`str()`, so an executed action of **EUR 250.99 produced the same seal as an
  approved EUR 250** and passed all four gates — the fractional part was simply unsealed.
  This is not the description-to-effect gap of Assumption A1; it is the seal failing to
  bind a *declared* value it claimed to bind. The seal now refuses any non-integer amount
  and any non-string field, and `verify_l4_scope` returns `L4 malformed action` (a denial)
  rather than raising through `evaluate()`. Regression: `tests/test_seal_types.py`.
- **`deps/jcs.py` described itself as "a faithful subset of RFC 8785".** With the NFC
  pre-pass added earlier the same day, it is not: for a decomposed input this module and a
  conformant RFC 8785 implementation emit different bytes and different digests. The
  docstring now states the divergence explicitly and scopes the number-format gap.

Two `interop/` drivers still read their session nonce back out of the static quote
(`mint_run_credential.py`, `deliverable_b_runner.py`). Neither claims to test freshness —
the first checks digest invariance, the second carries a real `tpm2_checkquote` replay
case — but because that line looks exactly like the defect corrected above, each now
carries an inline note saying so. The freshness gate is exercised in `run_ablation.py`,
`tests/test_freshness.py`, and the Deliverable-B runner's case 5.
