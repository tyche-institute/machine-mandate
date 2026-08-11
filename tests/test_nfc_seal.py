"""The action seal is NFC-normalised (manuscript §3.1).

Two canonically equivalent Unicode encodings of the same payee must seal
identically; a codepoint-distinct lookalike payee must stay distinct and be
denied at L4 by the ordinary hash comparison.
"""
from __future__ import annotations

import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "deps"), str(ROOT)]

import agent_demo as ad  # noqa: E402
import verifier_core as core  # noqa: E402

SCOPE = {"allowed_actions": ["pay-invoice/sepa-demo"], "max_spend": 500, "currency": "EUR"}

COMPOSED = {"tool": "pay-invoice/sepa-demo", "amount_eur": 120,
            "to": "ACM\u00c9 O\u00dc"}          # E-acute, U-diaeresis (precomposed)
DECOMPOSED = {"tool": "pay-invoice/sepa-demo", "amount_eur": 120,
              "to": "ACME\u0301 OU\u0308"}      # E + combining acute, U + combining diaeresis
LATIN = {"tool": "pay-invoice/sepa-demo", "amount_eur": 120, "to": "ACME"}
LOOKALIKE = {"tool": "pay-invoice/sepa-demo", "amount_eur": 120,
             "to": "\u0410CME"}                  # Cyrillic A + Latin CME


def test_canonically_equivalent_encodings_seal_identically():
    assert COMPOSED["to"] != DECOMPOSED["to"]
    assert unicodedata.normalize("NFC", DECOMPOSED["to"]) == COMPOSED["to"]
    assert ad.action_hash(COMPOSED) == ad.action_hash(DECOMPOSED)


def test_verifier_accepts_across_equivalent_encodings():
    g = core.evaluate(SCOPE, DECOMPOSED, COMPOSED)["gates"]
    assert g["L4"] is True


def test_lookalike_payee_stays_distinct():
    assert LATIN["to"] != LOOKALIKE["to"]
    assert ad.action_hash(LATIN) != ad.action_hash(LOOKALIKE)


def test_verifier_denies_lookalike_payee_at_l4():
    g = core.evaluate(SCOPE, LOOKALIKE, LATIN)["gates"]
    assert g["L4"] is False
