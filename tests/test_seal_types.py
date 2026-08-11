"""The action seal rejects what it cannot represent, instead of coercing it.

Regression for a defect found 2026-08-11 by adversarial review: action_hash()
coerced its fields with int()/str(), so an executed action of EUR 250.99 sealed
identically to an approved EUR 250 and passed all four gates — the fractional
part was simply unsealed. The profile declares integer euros (manuscript 3.1);
the seal now enforces that, and L4 denies rather than crashing.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "deps"), str(ROOT)]

import agent_demo as ad  # noqa: E402
import verifier_core as core  # noqa: E402

SCOPE = {"allowed_actions": ["pay-invoice/sepa-demo"], "max_spend": 500, "currency": "EUR"}
APPROVED = {"tool": "pay-invoice/sepa-demo", "amount_eur": 250, "to": "acme"}


@pytest.mark.parametrize("bad", [250.99, 250.0, "250", True, None])
def test_seal_refuses_non_integer_amounts(bad):
    with pytest.raises(ValueError):
        ad.action_hash({**APPROVED, "amount_eur": bad})


@pytest.mark.parametrize("bad", [None, 42, ["acme"]])
def test_seal_refuses_non_string_fields(bad):
    with pytest.raises(ValueError):
        ad.action_hash({**APPROVED, "to": bad})


def test_fractional_amount_is_denied_not_truncated():
    # the defect: 250.99 executed under a seal for 250 used to give all gates green
    gates = core.evaluate(SCOPE, {**APPROVED, "amount_eur": 250.99}, APPROVED)["gates"]
    assert gates["L4"] is False


def test_honest_action_still_accepts():
    gates = core.evaluate(SCOPE, APPROVED, APPROVED)["gates"]
    assert all(v is True for v in gates.values())
