from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "deps"), str(ROOT)]

import agent_demo as ad  # noqa: E402
import verifier_core as core  # noqa: E402
from mock_verifier import MockVerifier, make_tl, rebind_evidence  # noqa: E402


SCOPE = {
    "allowed_actions": ["pay-invoice/sepa-demo"],
    "max_spend": 500,
    "currency": "EUR",
}
ACTION = {"tool": "pay-invoice/sepa-demo", "amount_eur": 120, "to": "acme"}


def test_literal_replay_is_denied_in_five_fresh_sessions() -> None:
    results = [core.evaluate(SCOPE, ACTION, replay=True) for _ in range(5)]

    assert [result["verdict"] for result in results] == ["DENY"] * 5
    assert all(
        result["gates"] == {"L1": True, "L2": False, "L3": True, "L4": None}
        for result in results
    )


def test_replay_evidence_is_otherwise_valid_and_fails_only_freshness() -> None:
    trusted_list = make_tl(core._ICERT, core.AGENT_ENDORSER)
    try:
        relying_party = MockVerifier(trusted_list)
        relying_party.aud = core.AUD
        relying_party.request()
        presentation = ad.issue_action_mandate(
            core._ISK,
            core._HOLDER,
            SCOPE,
            ACTION,
            "affirming",
            relying_party.nonce,
            relying_party.aud,
        )
        stale_challenge = bytes(range(32))
        with tempfile.TemporaryDirectory() as tmpdir:
            quote, ear = rebind_evidence(
                core._QUOTE_GOOD,
                core._EAR_GOOD,
                stale_challenge,
                tmpdir,
            )
            accepted_for_original_challenge = relying_party.verify(
                presentation,
                core._IJWK,
                core._ITHUMB,
                ear,
                quote,
                stale_challenge,
            )
            replayed_under_fresh_challenge = relying_party.verify(
                presentation,
                core._IJWK,
                core._ITHUMB,
                ear,
                quote,
                relying_party.challenge,
            )
    finally:
        os.unlink(trusted_list)

    assert accepted_for_original_challenge["verdict"] == "ACCEPT"
    assert replayed_under_fresh_challenge["L1_crypto"] is True
    assert replayed_under_fresh_challenge["L2_attested"] is False
    assert replayed_under_fresh_challenge["L3_endorser_role"] is True
    assert replayed_under_fresh_challenge["reasons"] == [
        "L2: replay (session nonce != quote nonce)"
    ]


def test_affirming_and_freshness_have_separate_negative_vectors() -> None:
    replay = core.evaluate(SCOPE, ACTION, replay=True)
    contraindicated = core.evaluate(SCOPE, ACTION, contraindicated=True)

    assert replay["gates"] == {"L1": True, "L2": False, "L3": True, "L4": None}
    assert contraindicated["gates"] == {
        "L1": True,
        "L2": False,
        "L3": True,
        "L4": None,
    }
