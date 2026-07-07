# MachineMandate — reproducible artifact

**Paper:** *Enforcement, not Alignment: an Action-Sealed Authority Gate for Autonomous AI Agents in the
EU Digital Identity Wallet.* Anton Sokolov, Tyche Institute. Preprint PDF in [`paper/`](paper/).
**Preprint DOI:** [10.5281/zenodo.21229865](https://doi.org/10.5281/zenodo.21229865) ·
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
scope + action-hash) is the sole denier of at least one attack; removing any gate admits that attack.
It is fully offline — no network, no LLM, no Docker.

Expected output ends with `PASS  every gate is the sole denier of >=1 attack; the composition is minimal.`

## What is (and is not) here

- `src/` — the four-gate verifier, the mandate presentation/verification, and the action-hash seal.
- `deps/` — pure-crypto helpers (JCS canonicalization, SD-JWT VC issue/verify, EC keys).
- `fixtures/` — pre-captured attestation quotes/EARs used by the L2 freshness check.
- `run_ablation.py` — the self-checking reproduction of §8.6.

**Honest scope (as in the paper).** The attestation root is an **emulated software TPM (swtpm)**: the
RATS/Veraison freshness *logic* is real (the nonce is re-derived from the raw quote bytes and a replayed
quote is rejected), only the hardware root is emulated. The verifier enforces the **declared** action,
sealed by the action-hash — not an oracle on the real-world effect (Assumption A1, paper §5). No real
money moves. The wallet used in the phone demonstration is a commit-pinned rebuild of the EU reference
wallet, not an official release.

The live LLM-robustness measurement (paper §8.4) needs an LLM endpoint and is not required to reproduce
the security result; the ablation above is the load-bearing, offline reproduction.

Licensed under Apache-2.0.
