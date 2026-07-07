#!/usr/bin/env python3
"""Layer-4 MANDATE-SCOPE enforcement: catch the confused-deputy / over-scope attack
WITHIN an otherwise-valid mandate.

L1 (crypto), L2 (attestation re-derived from the raw TPM quote) and L3 (the issuer's
AgentRuntimeEndorser trusted-list role) each answer a different question — is the
presentation genuine, is the runtime attested, is the issuer authorised to endorse it.
None of them answers the LAST one: is the action the agent is presenting actually
WITHIN the authority the mandate granted? A valid, fresh, endorser-signed mandate for
"read the compliance file, spend up to EUR 200" does not authorise "wire EUR 5000" or
"delete the account". That gap is the confused-deputy hole: the agent is a genuine,
attested deputy that gets steered into using its legitimate authority for an act
outside the mandate's scope.

L4 closes it. The MachineMandate carries a MACHINE-READABLE scope, not a bare label:

    scope = { "allowed_actions": [<action_id>, ...],   # the permitted action set
              "action_commitments": [H(action_id, outcome), ...],  # bound hashes
              "max_spend": <int, minor units> }

The wallet presents the action it wants to perform (action_id + outcome + amount) and
the credential-bound `action_hash`. The verifier, having already recovered the signed
mandate, RE-DERIVES the presented action's hash and gates ACCEPT on:

  * action_id in scope.allowed_actions                       (in the permitted set)
  * re-derived H(action) == credential-bound action_hash     (not a substituted act)
  * re-derived H(action) in scope.action_commitments         (pre-authorised instance)
  * amount <= scope.max_spend                                 (within the spend limit)

If any fails while L1+L2+L3 pass, the verdict is DENY with reason "scope_violation".
This is the AEP `exceed -> DENY:scope_violation` direction made concrete on the
OpenID4VP rail: a real mandate, a real attested runtime, a real endorser — and still a
refusal, because the ACT is outside the granted authority.

Reuses mock_verifier's L1/L2/L3 verbatim (imported, not reimplemented) and adds L4.
"""
from __future__ import annotations
import base64, json, os, sys

from cryptography.hazmat.primitives.asymmetric import ec

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "fixtures")
sys.path.insert(0, HERE)
sys.path.insert(0, os.environ.get("AAA_DEMO") or os.path.join(HERE, "..", "deps"))

import crypto as aaa_crypto            # noqa: E402
import mandate                         # noqa: E402
from jcs import H                      # noqa: E402

# Reuse the existing verifier's L1/L2/L3 machinery verbatim — no reimplementation.
import mock_verifier as mv             # noqa: E402
from mock_verifier import (            # noqa: E402
    MockVerifier, self_signed, x5t, make_tl, ear_of, quote_bound_nonce,
    AGENT_ENDORSER, CA_QC, AEP,
)


def action_hash_of(action_id: str, outcome: str) -> str:
    """The SAME derivation the wallet/credential uses (mock_verifier.wallet_present):
    H({action_id, outcome})."""
    return H({"action_id": action_id, "outcome": outcome})


def scope_for(allowed_action_ids, action_commitments, max_spend):
    """Build the machine-readable scope object carried inside the MachineMandate."""
    return {"allowed_actions": sorted(allowed_action_ids),
            "action_commitments": sorted(action_commitments),
            "max_spend": int(max_spend)}


def scoped_wallet_present(issuer_key, holder_key, nonce, aud, ear_status,
                          scope_obj, action_id, outcome):
    """A MachineMandate SD-JWT VC whose `scope` is the structured object above and whose
    bound `action_hash` is H({action_id, outcome}) for the action being requested.

    Mirrors mock_verifier.wallet_present but (a) uses a structured scope and (b) lets us
    vary the requested action so we can drive an in-scope vs. over-scope presentation."""
    holder_jwk = aaa_crypto.pub_jwk(holder_key)
    action_hash = action_hash_of(action_id, outcome)
    sd_full = mandate.issue_sd(
        issuer_key, agent=AEP["sub"], scope=scope_obj, action_hash=action_hash,
        holder_jwk=holder_jwk,
        sd_claims={"principal": AEP["authorizing_principal"]["token_ref"],
                   "swname": AEP["swname"], "ear_status": ear_status,
                   "aep_receipt_hash": AEP["receipt_hash"]})
    return mandate.present_sd(sd_full, holder_key, nonce=nonce, aud=aud,
                              reveal={"principal", "swname", "ear_status"})


class ScopeAwareVerifier(MockVerifier):
    """MockVerifier + a 4th layer: MANDATE-SCOPE enforcement (confused-deputy / over-scope).

    L1/L2/L3 are the inherited base check. L4 runs only when the base ACCEPTs, and can
    still flip the final verdict to DENY(scope_violation) — a valid mandate whose issuer
    is a listed endorser and whose runtime is attested, presenting an act OUTSIDE the
    authority the mandate granted."""

    def verify_scoped(self, vp_token, issuer_jwk, issuer_x5t, ear_file, quote_file,
                      session_nonce, requested):
        # --- L1/L2/L3 exactly as the base verifier does it -------------------------
        base = self.verify(vp_token, issuer_jwk, issuer_x5t, ear_file, quote_file,
                           session_nonce)
        r = dict(base)
        r["L4_in_scope"] = False

        # Recover the signed mandate claims (scope + bound action_hash) independently.
        try:
            claims = mandate.verify_presentation_sd(vp_token, issuer_jwk, self.nonce,
                                                    self.aud)
        except Exception as e:
            r["reasons"].append("L4: cannot recover mandate claims: %s" % type(e).__name__)
            r["verdict"] = "DENY"
            return r

        scope = claims.get("scope") or {}
        bound_action_hash = claims.get("action_hash")
        # The verifier re-derives the requested action's hash from the request itself,
        # NOT by trusting a value handed to it.
        req_hash = action_hash_of(requested["action_id"], requested["outcome"])
        amount = int(requested.get("amount", 0))

        in_set = requested["action_id"] in set(scope.get("allowed_actions", []))
        bound_ok = (req_hash == bound_action_hash)
        committed = req_hash in set(scope.get("action_commitments", []))
        within_limit = amount <= int(scope.get("max_spend", 0))

        r["L4_in_scope"] = bool(in_set and bound_ok and committed and within_limit)
        r["scope_check"] = {
            "requested_action": requested["action_id"], "requested_amount": amount,
            "max_spend": scope.get("max_spend"),
            "action_in_allowed_set": in_set,
            "hash_matches_bound_mandate": bound_ok,
            "instance_pre_authorised": committed,
            "amount_within_limit": within_limit,
        }
        if not in_set:
            r["reasons"].append("L4: action '%s' not in mandate's allowed set %s"
                                % (requested["action_id"], scope.get("allowed_actions")))
        if not bound_ok:
            r["reasons"].append("L4: requested action hash != credential-bound action_hash")
        if not committed:
            r["reasons"].append("L4: action instance not among pre-authorised commitments")
        if not within_limit:
            r["reasons"].append("L4: amount %d exceeds mandate spend-limit %s"
                                % (amount, scope.get("max_spend")))

        # Final verdict: L4 can only ever REVOKE an otherwise-ACCEPT — never grant.
        if r["verdict"] == "ACCEPT" and not r["L4_in_scope"]:
            r["verdict"] = "DENY"
            r["scope_violation"] = True
            r.setdefault("disclosed", None)
        return r


def main():
    # One issuer, listed as an endorser; one holder key — held constant so the ONLY
    # thing that changes across the over-scope case is the ACT being presented.
    issuer_key, issuer_cert = self_signed("Tyche Agent-Runtime Endorser")
    issuer_jwk = aaa_crypto.pub_jwk(issuer_key); ix5t = x5t(issuer_cert)
    other_key, other_cert = self_signed("Some Unrelated QTSP")
    holder_key = ec.generate_private_key(ec.SECP256R1())

    A_ear = os.path.join(FIX, "ear-A_good_fresh.json"); A_q = os.path.join(FIX, "token-A_good_fresh.bin")
    B_ear = os.path.join(FIX, "ear-B_outcome_swapped.json"); B_q = os.path.join(FIX, "token-B_outcome_swapped.bin")
    nonce_A = quote_bound_nonce(A_q); nonce_B = quote_bound_nonce(B_q); OTHER = bytes(range(32))

    # The mandate's authority: a small allowed action set + a EUR 200,00 spend-limit.
    OUTCOME = AEP["measurements"]["outcome_sha256"]
    IN_SCOPE_ACTION = AEP["action_id"]                         # "review-clause-4.3-gdpr-art22"
    OTHER_ALLOWED = "read-compliance-file/clause-5.1"
    OVER_SCOPE_ACTION = "wire-transfer/vendor-x"               # NOT granted by this mandate
    MAX_SPEND = 20000                                          # EUR 200,00 in minor units

    # Commitments the issuer pre-authorised (hashes of the two allowed acts).
    commit_in = action_hash_of(IN_SCOPE_ACTION, OUTCOME)
    commit_other = action_hash_of(OTHER_ALLOWED, OUTCOME)
    SCOPE = scope_for([IN_SCOPE_ACTION, OTHER_ALLOWED], [commit_in, commit_other], MAX_SPEND)

    # An OVER-LIMIT scope that still contains the action id (isolates the spend-limit gate):
    #   same allowed set, but the requested amount will exceed max_spend.
    print("=== L4 MANDATE-SCOPE enforcement — confused-deputy / over-scope on OID4VP ===")
    print("mandate scope: allowed=%s  max_spend=%d (minor units)"
          % (SCOPE["allowed_actions"], SCOPE["max_spend"]))

    cases = [
        # label, TL(cert,type), ear, quote, session, ear_status,
        #        scope_obj, presented action_id, requested{action,amount}, expect
        ("in_scope",
         (issuer_cert, AGENT_ENDORSER), A_ear, A_q, nonce_A, "affirming",
         SCOPE, IN_SCOPE_ACTION,
         {"action_id": IN_SCOPE_ACTION, "outcome": OUTCOME, "amount": 15000}, "ACCEPT"),

        ("exceed_scope_action",   # L1+L2+L3 pass; ACT is outside the allowed set
         (issuer_cert, AGENT_ENDORSER), A_ear, A_q, nonce_A, "affirming",
         SCOPE, OVER_SCOPE_ACTION,
         {"action_id": OVER_SCOPE_ACTION, "outcome": OUTCOME, "amount": 100}, "DENY"),

        ("exceed_spend_limit",    # L1+L2+L3 pass; action allowed but amount over the cap
         (issuer_cert, AGENT_ENDORSER), A_ear, A_q, nonce_A, "affirming",
         SCOPE, IN_SCOPE_ACTION,
         {"action_id": IN_SCOPE_ACTION, "outcome": OUTCOME, "amount": 500000}, "DENY"),

        ("wrong_role",            # L3 fails independently — scope never rescues it
         (issuer_cert, CA_QC), A_ear, A_q, nonce_A, "affirming",
         SCOPE, IN_SCOPE_ACTION,
         {"action_id": IN_SCOPE_ACTION, "outcome": OUTCOME, "amount": 15000}, "DENY"),

        ("replay",                # L2 fails (replayed quote)
         (issuer_cert, AGENT_ENDORSER), A_ear, A_q, OTHER, "affirming",
         SCOPE, IN_SCOPE_ACTION,
         {"action_id": IN_SCOPE_ACTION, "outcome": OUTCOME, "amount": 15000}, "DENY"),

        ("unlisted",              # L3 fails (issuer not on the endorser list)
         (other_cert, AGENT_ENDORSER), A_ear, A_q, nonce_A, "affirming",
         SCOPE, IN_SCOPE_ACTION,
         {"action_id": IN_SCOPE_ACTION, "outcome": OUTCOME, "amount": 15000}, "DENY"),
    ]

    out = []
    for (label, (cert, stype), ear, q, sess, ear_status,
         scope_obj, present_action, requested, expect) in cases:
        tl_path = make_tl(cert, stype)
        rp = ScopeAwareVerifier(tl_path); rp.request()
        # The wallet presents the action it wants performed; the mandate is minted with
        # the structured scope and bound to THAT action's hash.
        vp = scoped_wallet_present(issuer_key, holder_key, rp.nonce, rp.aud, ear_status,
                                   scope_obj, present_action, requested["outcome"])
        res = rp.verify_scoped(vp, issuer_jwk, ix5t, ear, q, sess, requested)
        res.update({"case": label, "expected": expect, "match": res["verdict"] == expect})
        out.append(res); os.unlink(tl_path)
        sv = " scope_violation" if res.get("scope_violation") else ""
        print("[%-20s] L1=%s L2=%s L3=%s L4=%s -> %-6s (want %s) %s%s" % (
            label, res["L1_crypto"], res["L2_attested"], res["L3_endorser_role"],
            res["L4_in_scope"], res["verdict"], expect,
            "ok" if res["match"] else "!!", sv))
        if res["reasons"]:
            print("    reasons:", "; ".join(res["reasons"]))

    art = os.path.join(HERE, "..", "artifacts"); os.makedirs(art, exist_ok=True)
    json.dump(out, open(os.path.join(art, "scope-enforce.json"), "w"), indent=2)

    ok = all(r["match"] for r in out)
    # Sharpest evidence for the paper: the confused-deputy case where L1+L2+L3 all PASS
    # yet the verdict is still DENY because the ACT is beyond the mandate's authority.
    cd = next((r for r in out if r["case"] == "exceed_scope_action"), None)
    if cd:
        print("\nconfused-deputy witness (exceed_scope_action): "
              "L1=%s L2=%s L3=%s all pass, L4=%s -> %s (scope_violation=%s)"
              % (cd["L1_crypto"], cd["L2_attested"], cd["L3_endorser_role"],
                 cd["L4_in_scope"], cd["verdict"], cd.get("scope_violation", False)))
    print("\nSCOPE ENFORCE:", "PASS — a valid, attested, endorser-signed mandate is still "
          "DENIED when the ACT exceeds the granted scope (exceed -> DENY:scope_violation)"
          if ok else "CHECK — a verdict did not match expectation")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
