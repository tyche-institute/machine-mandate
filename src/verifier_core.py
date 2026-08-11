"""The four-gate verifier core, extracted for the reproducible artifact.

Pure Python; no network, no LLM, no server. It sets up an issuer, a holder, and pre-captured
attestation fixtures, then exposes `evaluate(scope, action)` running the four gates:

    L1  credential cryptography          (SD-JWT VC + KB-JWT signatures)
    L2  attestation freshness            (nonce re-derived from the raw quote bytes; replay -> fail)
    L3  issuer on the trusted list       (endorser role)
    L4  mandate scope + action-hash      (allowed-tools, spend-limit, per-action tamper-seal)

Honest scope: the attestation root is an emulated software TPM (swtpm); the freshness logic is real,
only the hardware root is emulated.
"""
from __future__ import annotations
import os
import tempfile

import crypto as aaa_crypto
import agent_demo as ad
from mock_verifier import (AGENT_ENDORSER, MockVerifier, make_tl, quote_bound_nonce,
                           rebind_evidence, self_signed, x5t)

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")
AUD = ad.AUD

# one-time crypto setup (mirrors agent_demo.main)
_ISK, _ICERT = self_signed("Tyche Agent-Runtime Endorser")
_IJWK = aaa_crypto.pub_jwk(_ISK); _ITHUMB = x5t(_ICERT)
_HOLDER = aaa_crypto.gen_ec()
_QUOTE_GOOD = os.path.join(FIX, "token-A_good_fresh.bin")
_EAR_GOOD = os.path.join(FIX, "ear-A_good_fresh.json")
_QUOTE_REPLAY = os.path.join(FIX, "token-B_outcome_swapped.bin")
_EAR_REPLAY = os.path.join(FIX, "ear-B_outcome_swapped.json")
# NOTE 2026-08-11: the previous line here derived the "session" nonce from the very
# quote it was meant to freshness-check (_SESSION_NONCE = quote_bound_nonce(_QUOTE_GOOD)),
# which made the comparison a tautology and let a literal replay through. The relying
# party now issues the challenge (MockVerifier.request -> rp.challenge) and the Attester
# answers it; a stale quote is one bound to an earlier challenge.
_STALE_CHALLENGE = bytes(range(32))   # a challenge from an earlier, already-finished session


def action_hash(a):
    return ad.action_hash(a)


def evaluate(scope, executed_action, mandated_action=None, replay=False, contraindicated=False):
    """Run the four gates for an action against a domain scope. Returns per-gate booleans + verdict."""
    mandated = mandated_action or executed_action
    tl = make_tl(_ICERT, AGENT_ENDORSER)
    try:
        rp = MockVerifier(tl); rp.aud = AUD; rp.request()
        vp = ad.issue_action_mandate(_ISK, _HOLDER, scope, mandated, "affirming", rp.nonce, rp.aud)
        # The Attester answers the challenge the relying party just chose. A replay is the
        # same good, affirming, EAR-bound evidence produced for an EARLIER challenge, so
        # freshness is the only term that can deny it.
        answered = _STALE_CHALLENGE if replay else rp.challenge
        with tempfile.TemporaryDirectory() as td:
            if contraindicated:
                qf, ef = rebind_evidence(_QUOTE_REPLAY, _EAR_REPLAY, answered, td)
            else:
                qf, ef = rebind_evidence(_QUOTE_GOOD, _EAR_GOOD, answered, td)
            base = rp.verify(vp, _IJWK, _ITHUMB, ef, qf, rp.challenge)
            l4_ok = False
            if base["L1_crypto"] and base["L2_attested"] and base["L3_endorser_role"]:
                l4_ok, _, _ = ad.verify_l4_scope(vp, _IJWK, rp.nonce, executed_action)
        gates = {
            "L1": bool(base["L1_crypto"]), "L2": bool(base["L2_attested"]),
            "L3": bool(base["L3_endorser_role"]), "L4": bool(l4_ok),
        }
        return {"gates": gates, "verdict": "ACCEPT" if all(gates.values()) else "DENY"}
    finally:
        try:
            os.unlink(tl)
        except FileNotFoundError:
            pass
