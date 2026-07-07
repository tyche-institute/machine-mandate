#!/usr/bin/env python3
"""Reproduce the four-gate ablation (Table §8.6 of the paper).

Hermetic: pure Python + `cryptography` + `PyJWT`. No network, no LLM, no Docker.
Each attack is denied by exactly one gate; removing that gate admits the attack.

    pip install -r requirements.txt
    python run_ablation.py            # prints the table and self-checks every verdict
"""
import os, sys
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "deps"))

import verifier_core as m               # four-gate verifier (offline)
import agent_demo as ad
from mock_verifier import self_signed, make_tl, MockVerifier

SCOPE = {"allowed_actions": ["pay-invoice/sepa-demo"], "max_spend": 500, "currency": "EUR"}
A = lambda tool, amt, to: {"tool": tool, "amount_eur": amt, "to": to}
GOOD = A("pay-invoice/sepa-demo", 120, "acme")


def gates(ex, man=None, replay=False):
    return m.evaluate(SCOPE, ex, man, replay=replay)["gates"]


def forged_credential():
    """Flip bytes in the presented signature -> L1 (credential crypto) must deny."""
    tl = make_tl(m._ICERT, m.AGENT_ENDORSER); rp = MockVerifier(tl); rp.aud = m.AUD; rp.request()
    vp = ad.issue_action_mandate(m._ISK, m._HOLDER, SCOPE, GOOD, "affirming", rp.nonce, rp.aud)
    parts = vp.split("~"); jwt = parts[0].split("."); sig = jwt[2]
    jwt[2] = sig[:-4] + ("AAAA" if sig[-4:] != "AAAA" else "BBBB"); parts[0] = ".".join(jwt)
    try:
        b = rp.verify("~".join(parts), m._IJWK, m._ITHUMB, m._EAR_GOOD, m._QUOTE_GOOD, m._SESSION_NONCE)
        return {"L1": bool(b["L1_crypto"]), "L2": None, "L3": None, "L4": None}
    except Exception:
        return {"L1": False, "L2": None, "L3": None, "L4": None}


def untrusted_issuer():
    """Trusted list rooted in a DIFFERENT issuer -> L3 (endorser) must deny."""
    r = self_signed("CN=Rogue Issuer"); cert = next(x for x in r if hasattr(x, "public_bytes"))
    tl = make_tl(cert, m.AGENT_ENDORSER); rp = MockVerifier(tl); rp.aud = m.AUD; rp.request()
    vp = ad.issue_action_mandate(m._ISK, m._HOLDER, SCOPE, GOOD, "affirming", rp.nonce, rp.aud)
    b = rp.verify(vp, m._IJWK, m._ITHUMB, m._EAR_GOOD, m._QUOTE_GOOD, m._SESSION_NONCE)
    return {"L1": bool(b["L1_crypto"]), "L2": bool(b["L2_attested"]), "L3": bool(b["L3_endorser_role"]), "L4": None}


CASES = [
    ("legitimate in-scope payment (EUR 120)", lambda: gates(GOOD),                                   "ACCEPT", None),
    ("forged / altered credential",           forged_credential,                                     "DENY",   "L1"),
    ("replayed stale attestation",            lambda: gates(GOOD, replay=True),                      "DENY",   "L2"),
    ("issuer not on the trusted list",        untrusted_issuer,                                      "DENY",   "L3"),
    ("over-limit payment (EUR 4800)",         lambda: gates(A("pay-invoice/sepa-demo", 4800, "acme")), "DENY", "L4"),
    ("prompt-injected wire transfer",         lambda: gates(A("wire-transfer/vendor-x", 250, "vendor-x")), "DENY", "L4"),
    ("payee swapped after approval",          lambda: gates(A("pay-invoice/sepa-demo", 120, "IBAN-ATTACKER"), man=GOOD), "DENY", "L4"),
]


def mark(v):
    return " ok" if v is True else ("DEN" if v is False else "  -")


def main():
    print("MachineMandate four-gate ablation (paper Table §8.6)\n")
    print(f"{'action':42}{'L1':>4}{'L2':>4}{'L3':>4}{'L4':>4}  {'verdict':9}{'denier':>7}")
    print("-" * 78)
    fails = 0
    for name, fn, exp_v, exp_gate in CASES:
        g = fn()
        verdict = "ACCEPT" if all(g.get(k) is True for k in ("L1", "L2", "L3", "L4")) else "DENY"
        denier = next((k for k in ("L1", "L2", "L3", "L4") if g.get(k) is False), None)
        ok = (verdict == exp_v) and (exp_gate is None or denier == exp_gate)
        fails += 0 if ok else 1
        tail = "" if ok else "  <-- MISMATCH"
        print(f"{name:42}{mark(g.get('L1')):>4}{mark(g.get('L2')):>4}{mark(g.get('L3')):>4}"
              f"{mark(g.get('L4')):>4}  {verdict:9}{str(denier or '-'):>7}{tail}")
    print("-" * 78)
    if fails == 0:
        print("PASS  every gate is the sole denier of >=1 attack; the composition is minimal.")
    else:
        print(f"FAIL  {fails} verdict(s) did not match the paper.")
    return fails


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
