"""
Regression guard for credential/mandate expiry.

Expiry IS enforced in this verifier, but only because verify_presentation_sd delegates
to PyJWT, whose jwt.decode default checks `exp`. That enforcement is invisible in the
source (no explicit expiry logic) and unguarded: adding one key to the options dict --
options={"verify_aud": False, "verify_exp": False} -- silently flips an expired mandate
from DENY to ACCEPT, and nothing else in the suite would notice.

These tests convert that silent dependency default into a stated, guarded requirement:
  1. an expired mandate is denied (behavioural);
  2. the options passed to jwt.decode do not disable exp/signature (static).

Added 2026-08-11 after a cross-artifact probe (Tyche research vault:
notes/eudiw-cc/mandate-gate-census/docs/CROSS-ARTIFACT-EXPIRY.md). Does not touch
run_ablation.py or its published Table 8.6.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "deps"), str(ROOT)]

import crypto  # noqa: E402
import mandate  # noqa: E402
import verifier_core as core  # noqa: E402

SCOPE = {"allowed_actions": ["x"], "max_spend": 500, "currency": "EUR"}


def _present(ttl: int):
    holder_jwk = crypto.pub_jwk(core._HOLDER)
    full = mandate.issue_sd(core._ISK, "agent-1", SCOPE, "ah", holder_jwk,
                            {"given_name": "Anna"}, ttl=ttl)
    return mandate.present_sd(full, core._HOLDER, nonce="n", aud=core.AUD,
                              reveal={"given_name"})


def test_fresh_mandate_is_accepted() -> None:
    claims = mandate.verify_presentation_sd(_present(ttl=300), core._IJWK, "n", core.AUD)
    assert claims["given_name"] == "Anna"


def test_expired_mandate_is_denied() -> None:
    try:
        mandate.verify_presentation_sd(_present(ttl=-5000), core._IJWK, "n", core.AUD)
    except Exception:
        return
    raise AssertionError("expired mandate was accepted -- expiry enforcement regressed")


def test_verify_options_do_not_disable_exp_or_signature() -> None:
    """Static guard: the options dict passed to jwt.decode must not turn off the checks
    PyJWT enforces by default. This is what stops the one-key regression."""
    src = (ROOT / "deps" / "mandate.py").read_text()
    for opt in ("verify_exp", "verify_signature", "verify_nbf"):
        for m in re.finditer(rf'["\']{opt}["\']\s*:\s*(\w+)', src):
            assert m.group(1) != "False", f"{opt} is disabled in a jwt.decode options dict"
