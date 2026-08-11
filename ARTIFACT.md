# Artifact appendix — claim → evidence map

| Paper claim | How to reproduce | Where |
|---|---|---|
| §8.6 Each gate is the first denier of ≥1 attack; the freshness term is executably load-bearing | `python run_ablation.py` (offline, self-checking); note L4 re-verifies signatures, so removing L1 alone is masked — defence-in-depth, not strict per-gate minimality | this repo |
| §3.1 Action-hash binds one exact action | `src/` (`action_hash` = SHA-256 over RFC-8785 JCS of the action, string fields NFC-normalised in `deps/jcs.py`); the "payee swapped after approval" ablation row and `tests/test_nfc_seal.py` (canonical-equivalence + lookalike-payee vectors) exercise it | this repo |
| §5 L2 freshness rejects a replayed quote | the "replayed stale attestation" row of `run_ablation.py`: the relying party issues a fresh 32-byte challenge, the row re-presents evidence bound to an earlier challenge, and freshness is the **sole** denier (verify by deleting the `fresh` term — the row then wrongly ACCEPTs and the script exits non-zero) | this repo |
| §5 L2 rejects a non-affirming appraisal | the "attestation contraindicated" row of `run_ablation.py` | this repo |
| §8.4 Agent fooled ≈100%, gate denies 100% | needs an LLM endpoint (`meta/llama-3.1-8b-instruct`); the deterministic gate half is covered by the ablation | paper §8.4 |
| Real-phone end-to-end (2026-07-06) | the `vp_token` (scope + action_hash), four verdicts, screenshots | Zenodo 10.5281/zenodo.21229257 |

**Environment.** Python 3.10+; `pip install -r requirements.txt` (only `cryptography` and `PyJWT`).
Runs in a few seconds on a laptop. No network access is required or made.
