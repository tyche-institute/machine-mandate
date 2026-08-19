# MachineMandate — reproducible artifact

**Paper:** *Enforcement, not Alignment: an Action-Sealed Authority Gate for Autonomous AI Agents in the
EU Digital Identity Wallet.* Anton Sokolov, Tyche Institute. Preprint PDF in [`paper/`](paper/) —
version 2.1 (11 August 2026), which carries the correction described in [`CORRECTION.md`](CORRECTION.md).
**Preprint DOI, all versions:** [10.5281/zenodo.21229864](https://doi.org/10.5281/zenodo.21229864);
**this version:** [10.5281/zenodo.21914667](https://doi.org/10.5281/zenodo.21914667) ·
**Real-phone evidence bundle:** [10.5281/zenodo.21229257](https://doi.org/10.5281/zenodo.21229257).

A **MachineMandate** is an SD-JWT verifiable credential that binds a bounded grant of authority to *one
exact action* via an action-hash tamper-seal, presented over OpenID4VP to a **four-gate verifier** that
*denies* out-of-mandate actions — enforcement at verification time, not alignment at inference time.

## One command

```bash
pip install -r requirements.txt
python run_ablation.py
```

This reproduces the paper's **gate-ablation table (§8.6)** and self-checks every verdict: each of the
four gates (L1 credential crypto, L2 attestation freshness, L3 issuer-on-trusted-list, L4 mandate
scope + action-hash) is the first denier of at least one attack in evaluation order. For the freshness
term the claim is executable: disabling only the freshness comparison admits the replay row and fails
the run (`CORRECTION.md` shows both sides). L4 independently re-verifies the presentation's signatures,
so the layering is defence-in-depth, not strict per-gate minimality.
It is fully offline — no network, no LLM, no Docker.

Expected output ends with `PASS  every gate is the first denier of >=1 attack; the freshness term is executably load-bearing (CORRECTION.md).`

## What is here

- `src/` — the four-gate verifier, the mandate presentation/verification, and the action-hash seal.
- `deps/` — pure-crypto helpers (JCS canonicalization, SD-JWT VC issue/verify, EC keys).
- `fixtures/` — pre-captured attestation quotes/EARs used by the L2 freshness check.
- `run_ablation.py` — the self-checking reproduction of §8.6.

**Honest scope (as in the paper).** The captured attestation root is an **emulated software TPM
(swtpm)**. The offline ablation exercises the corrected freshness decision: the relying party issues
the challenge, the nonce is re-derived from quote bytes, and evidence bound to an earlier challenge is
rejected. Because the captures are static, `rebind_evidence()` synthetically changes the fixture's
`extraData` and EAR nonce; it does **not** create a matching TPM signature or a newly appraised EAR.
Live use must obtain fresh signed evidence from the Attester. (Corrected 2026-08-11: until that date the
shipped reproduction path derived the "session" nonce from the quote it was checking, so a literal
replay passed. See CORRECTION.md.) The verifier enforces the **declared** action,
sealed by the action-hash — not an oracle on the real-world effect (Assumption A1, paper §5). No real
money moves. The wallet used in the phone demonstration is a commit-pinned rebuild of the EU reference
wallet, not an official release.

The live LLM-robustness measurement (paper §8.4) needs an LLM endpoint and is not required to reproduce
the security result; the ablation above is the load-bearing, offline reproduction.

Licensed under Apache-2.0.
