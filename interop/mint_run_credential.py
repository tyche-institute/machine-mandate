#!/usr/bin/env python3
"""Mint the ONE MachineMandate credential for the IETF-126 deliverable-B composition run,
freeze its preimage digest, and self-check that the frozen credential drives the gate
ordering the composition manifest promises.

Preimage rule (option (a), agreed by all three owners on the review thread):

    the exact issuer-signed JWT component bytes of the SD-JWT
    -- the FIRST "~"-separated component as transmitted.

That component is invariant under presentation: the holder re-signs a fresh KB-JWT for
every OpenID4VP session, but the issuer-signed component does not change. The self-check
below exercises that invariance across presentations rather than only asserting it.

The action, scope and case amounts are READ FROM the published composition manifest, not
restated here, so they cannot drift from the record the owners review. Two values are
NOT taken from the manifest because the manifest does not pin them: the credential
subject (AGENT_ID below, chosen to mirror the ORPRG protected request's agent_id) and
the expiry window. Both are recorded verbatim in mint-record.json and disclosed on the
review thread.

Scope note: this credential is the MANDATE side only. It does not bind the ORPRG
permit-side digests -- those are carried by the frozen ORPRG tuple, and the AAC Capsule
co-binds the two references. The permit-side digests are copied into the mint record as
context only, explicitly marked as not bound by this credential.

Run:  python3 interop/mint_run_credential.py [--out DIR] [--exp ISO8601]

Writes to DIR (default /srv/tyche/runs/ietf126-composition):
  credential.sdjwt        the issuance-form SD-JWT (issuer JWT + disclosures)
  issuer.jwk              issuer PUBLIC key (verification input)
  issuer-key.pem          issuer PRIVATE key   (0600, never published)
  holder-key.pem          holder PRIVATE key   (0600, never published)
  mint-record.json        the freeze record: digest, preimage length, claims, self-check
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "src"))
sys.path.insert(0, os.path.join(REPO, "deps"))

import crypto as aaa_crypto            # noqa: E402
import mandate                         # noqa: E402
import mock_verifier as mv             # noqa: E402
from mock_verifier import (            # noqa: E402
    AGENT_ENDORSER, make_tl, quote_bound_nonce, self_signed, x5t,
)
from scope_enforce import ScopeAwareVerifier, action_hash_of, scope_for  # noqa: E402

MANIFEST = os.path.join(HERE, "composition-input-manifest-v0.4.json")
FIX = os.path.join(REPO, "fixtures")
DEFAULT_OUT = "/srv/tyche/runs/ietf126-composition"
DEFAULT_EXP = "2026-07-24T23:59:59Z"   # covers the hackathon AND the Wed 22 Jul RATS slot
AGENT_ID = "agent:vienna-interop:001"   # = agent_id in the frozen ORPRG protected request


def frozen_inputs(manifest_path):
    """Pull the frozen action, scope and case amounts straight out of the manifest."""
    with open(manifest_path, "rb") as fh:
        raw = fh.read()
    m = json.loads(raw)
    mandate_side = m["shared_synthetic_action"]["mandate_side"]
    orprg = m["frozen_owner_artifacts"]["orprg_payment_composition_tuple"]["in_zip_pins"]
    return {
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "manifest_version": m["version"],
        "action_id": mandate_side["action_object"]["action_id"],
        "outcome": mandate_side["action_object"]["outcome"],
        "action_hash": mandate_side["action_hash_claim"],
        "max_spend": mandate_side["scope"]["max_spend"],
        "allowed_actions": mandate_side["scope"]["allowed_actions"],
        "action_commitments": mandate_side["scope"]["action_commitments"],
        "positive_amount": mandate_side["amount_paths"]["positive_requested_amount"],
        "over_limit_amount": mandate_side["amount_paths"]["over_limit_requested_amount"],
        # mirrors agent_id in the frozen ORPRG protected request, so the same agent
        # identity appears on both sides of the composition
        "agent_id": AGENT_ID,
        "composition_action_id": m["shared_synthetic_action"]["composition_action_id"],
        "orprg_positive_digest": orprg["cases"]["positive"]["action_digest_unprefixed"],
        "orprg_over_limit_digest": orprg["cases"]["mandate_over_limit"]["action_digest_unprefixed"],
    }


def preimage_digest(sd_jwt_issuance_form: str):
    """Option (a): SHA-256 over the exact bytes of the first '~'-separated component."""
    component = sd_jwt_issuance_form.split("~")[0].encode("utf-8")
    return hashlib.sha256(component).hexdigest(), len(component)


def self_check(sd_full, holder_key, issuer_key, issuer_cert, issuer_jwk, f):
    """Drive BOTH frozen cases through the four-gate verifier using the ONE minted
    credential, and confirm the preimage digest is invariant across presentations."""
    ix5t = x5t(issuer_cert)
    ear = os.path.join(FIX, "ear-A_good_fresh.json")
    quote = os.path.join(FIX, "token-A_good_fresh.bin")
    session_nonce = quote_bound_nonce(quote)
    reveal = {"principal", "swname", "ear_status"}

    cases = [
        ("positive", f["positive_amount"], "ACCEPT"),
        ("mandate-over-limit", f["over_limit_amount"], "DENY"),
    ]
    results = []
    for case_id, amount, expected in cases:
        tl_path = make_tl(issuer_cert, AGENT_ENDORSER)
        rp = ScopeAwareVerifier(tl_path)
        rp.request()
        # The SAME frozen credential; only a fresh holder KB-JWT per session.
        vp = mandate.present_sd(sd_full, holder_key, nonce=rp.nonce, aud=rp.aud,
                                reveal=reveal)
        requested = {"action_id": f["action_id"], "outcome": f["outcome"],
                     "amount": amount}
        r = rp.verify_scoped(vp, issuer_jwk, ix5t, ear, quote, session_nonce, requested)
        os.unlink(tl_path)

        sc = r["scope_check"]
        # the preimage digest recomputed from the PRESENTED token, not from our copy
        presented_digest, presented_len = preimage_digest(vp)
        results.append({
            "case_id": case_id,
            "requested_amount": amount,
            "verdict": r["verdict"],
            "expected_verdict": expected,
            "match": r["verdict"] == expected,
            "gates": {
                "action_in_allowed_set": sc["action_in_allowed_set"],
                "hash_matches_bound_mandate": sc["hash_matches_bound_mandate"],
                "instance_pre_authorised": sc["instance_pre_authorised"],
                "amount_within_limit": sc["amount_within_limit"],
            },
            "L1_crypto": r["L1_crypto"],
            "L2_attested": r["L2_attested"],
            "L3_endorser_role": r["L3_endorser_role"],
            "L4_in_scope": r["L4_in_scope"],
            "reasons": r["reasons"],
            "preimage_digest_from_presentation": presented_digest,
            "preimage_length_from_presentation": presented_len,
        })
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--exp", default=DEFAULT_EXP,
                    help="credential expiry, ISO-8601 Z (default %s)" % DEFAULT_EXP)
    ap.add_argument("--orprg-dir", default=None,
                    help="extracted ORPRG payment composition tuple; when given, the "
                         "credential subject is asserted byte-identical against the "
                         "agent_id in BOTH frozen protected requests")
    args = ap.parse_args()

    f = frozen_inputs(MANIFEST)
    os.makedirs(args.out, exist_ok=True)

    # --- the subject is the one value the manifest does not pin: check it against the
    # --- permit owner's own frozen artifact rather than trusting a source comment.
    agent_id_provenance = "hardcoded; NOT checked against the ORPRG tuple"
    if args.orprg_dir:
        seen = {}
        for case_dir in ("positive", "mandate-over-limit"):
            p = os.path.join(args.orprg_dir, "cases", case_dir, "protected-request.json")
            with open(p) as fh:
                seen[case_dir] = json.load(fh)["agent_id"]
        if set(seen.values()) != {f["agent_id"]}:
            raise SystemExit("ABORT: credential subject %r != ORPRG protected-request "
                             "agent_id %r" % (f["agent_id"], seen))
        agent_id_provenance = ("verified byte-identical against agent_id in BOTH frozen "
                               "ORPRG protected requests (package %s)"
                               % os.path.basename(args.orprg_dir.rstrip("/")))

    # --- the frozen action, re-derived rather than trusted -------------------------
    derived = action_hash_of(f["action_id"], f["outcome"])
    if derived != f["action_hash"]:
        raise SystemExit("ABORT: re-derived action_hash %s != manifest %s"
                         % (derived, f["action_hash"]))
    scope_obj = scope_for(f["allowed_actions"], [derived], f["max_spend"])
    if scope_obj["action_commitments"] != sorted(f["action_commitments"]):
        raise SystemExit("ABORT: scope action_commitments differ from the manifest")
    if scope_obj["max_spend"] != f["max_spend"]:
        raise SystemExit("ABORT: max_spend differs from the manifest")

    # --- keys ----------------------------------------------------------------------
    issuer_key, issuer_cert = self_signed("Tyche Agent-Runtime Endorser")
    issuer_jwk = aaa_crypto.pub_jwk(issuer_key)
    holder_key = ec.generate_private_key(ec.SECP256R1())

    # --- mint ONCE ------------------------------------------------------------------
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    exp = dt.datetime.strptime(args.exp, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc)
    ttl = int((exp - now).total_seconds())
    if ttl <= 0:
        raise SystemExit("ABORT: --exp is in the past")
    jti = "mm-%s" % f["composition_action_id"]

    sd_full = mandate.issue_sd(
        issuer_key, agent=f["agent_id"], scope=scope_obj, action_hash=derived,
        holder_jwk=aaa_crypto.pub_jwk(holder_key),
        # Accountability claims for THIS run. The repo demo carries the 24 June Veraison
        # compliance-review values here; reusing them under a payment action would assert
        # an authorizing principal and a software identity that describe a different act,
        # and an aep_receipt_hash binding this mandate to a June AEP receipt that has
        # nothing to do with this run. Replaced with coherent, explicitly synthetic
        # values; the fourth claim stays undisclosed at presentation, which is what
        # exercises selective disclosure.
        sd_claims={"principal": "auth-synthetic-vienna-interop-2026-001",
                   "swname": "vienna-interop-payment-agent/synthetic-v1",
                   "ear_status": "affirming",
                   "composition_action_id": f["composition_action_id"]},
        ttl=ttl, jti=jti)

    digest, length = preimage_digest(sd_full)

    # --- self-check: the frozen credential drives both frozen cases -----------------
    checks = self_check(sd_full, holder_key, issuer_key, issuer_cert, issuer_jwk, f)
    invariant = {c["preimage_digest_from_presentation"] for c in checks} == {digest}
    all_match = all(c["match"] for c in checks)
    over = next(c for c in checks if c["case_id"] == "mandate-over-limit")
    ordering_ok = (over["gates"]["action_in_allowed_set"]
                   and over["gates"]["hash_matches_bound_mandate"]
                   and over["gates"]["instance_pre_authorised"]
                   and not over["gates"]["amount_within_limit"])

    # --- persist ---------------------------------------------------------------------
    def write(name, data, mode=0o644, binary=False):
        p = os.path.join(args.out, name)
        with open(p, "wb" if binary else "w") as fh:
            fh.write(data)
        os.chmod(p, mode)
        return p

    write("credential.sdjwt", sd_full)
    # The preimage itself, as its own file with NO trailing newline, so anyone can run
    # `sha256sum credential-preimage.jwt` and land on the frozen digest directly.
    write("credential-preimage.jwt", sd_full.split("~")[0])
    write("issuer.jwk", json.dumps(issuer_jwk, indent=1, sort_keys=True) + "\n")
    write("issuer-key.pem", issuer_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()), mode=0o600, binary=True)
    write("holder-key.pem", holder_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()), mode=0o600, binary=True)

    record = {
        "artifact": "MachineMandate run credential — IETF 126 deliverable B",
        "status": "FROZEN PRE-EXECUTION INPUT — NOT A RESULT",
        "minted_at_utc": now.isoformat().replace("+00:00", "Z"),
        "bound_manifest": {
            "file": os.path.basename(MANIFEST),
            "version": f["manifest_version"],
            "sha256": f["manifest_sha256"],
        },
        "credential_preimage": {
            "rule": "option (a): the exact issuer-signed JWT component bytes of the "
                    "SD-JWT (the first ~-separated component as transmitted)",
            "digest_alg": "SHA-256",
            "digest": digest,
            "preimage_length_bytes": length,
            "invariant_across_presentations": invariant,
        },
        "credential_claims": {
            "sub_agent_id": f["agent_id"],
            "sub_agent_id_provenance": agent_id_provenance,
            "vct": "https://vocab.tyche.institute/vct/machine-mandate",
            "jti": jti,
            "iat_utc": now.isoformat().replace("+00:00", "Z"),
            "exp_utc": exp.isoformat().replace("+00:00", "Z"),
            "action_hash": derived,
            "scope": scope_obj,
            "issuer_jwk_thumbprint": aaa_crypto.jwk_thumbprint(issuer_jwk),
        },
        "frozen_action": {
            "action_id": f["action_id"],
            "outcome": f["outcome"],
            "outcome_note": "opaque frozen descriptor; no amount or currency semantics "
                            "may be derived from it",
        },
        "permit_side_context_not_bound_by_this_credential": {
            "note": "the ORPRG action digests are recorded here for cross-reading only; "
                    "this MachineMandate does not bind them. The permit-to-mandate "
                    "relationship is carried by the AAC Capsule co-binding the two typed "
                    "references, per the manifest's links.permit_to_mandate = XREF",
            "orprg_positive_action_digest": f["orprg_positive_digest"],
            "orprg_over_limit_action_digest": f["orprg_over_limit_digest"],
        },
        "self_check": {
            "what_this_is": "evidence about the CREDENTIAL only, produced entirely inside "
                            "one Tyche process: Tyche's issuer key, Tyche's holder key, "
                            "Tyche's verifier, a trust list built by the test harness, and "
                            "the repository's pre-captured emulated-TPM (swtpm) fixtures. "
                            "It is not a composition result, not an interoperability "
                            "result, and not evidence of the run",
            "attestation_note": "L2 is satisfied from replayed fixture quotes with the "
                                "session nonce derived from the fixture, so the freshness "
                                "logic is exercised but not under a live challenge",
            "all_verdicts_as_expected": all_match,
            "over_limit_gate_ordering_ok": ordering_ok,
            "over_limit_first_rejecting_gate": "machine_mandate_spend"
            if ordering_ok else "UNEXPECTED",
            "cases": checks,
        },
        "reproducibility": {
            "commitment_kind": "one-shot pre-registration commitment to these exact bytes",
            "note": "the digest is NOT a function of the logical inputs and cannot be "
                    "regenerated: fresh issuer and holder EC keys, random SD salts, and "
                    "iat/exp enter the preimage. A counterparty VERIFIES it against the "
                    "published preimage, and re-running the mint necessarily yields a "
                    "different credential and a different digest",
            "preimage_file": "credential-preimage.jwt (no trailing newline)",
        },
        "boundary": "Synthetic sandbox credential for a pre-registered composition run. "
                    "No live payment, no real payment data. This record is a frozen "
                    "pre-execution input, not a composition or interoperability result.",
    }
    write("mint-record.json", json.dumps(record, indent=2, sort_keys=True) + "\n")

    print("preimage digest (SHA-256): %s" % digest)
    print("preimage length          : %d bytes" % length)
    print("invariant across present.: %s" % invariant)
    print("self-check verdicts      : %s" % ("PASS" if all_match else "FAIL"))
    print("over-limit gate ordering : %s" % ("PASS (spend gate rejects first)"
                                             if ordering_ok else "FAIL"))
    print("written to               : %s" % args.out)
    if not (all_match and ordering_ok and invariant):
        raise SystemExit("SELF-CHECK FAILED — do not freeze this credential")


if __name__ == "__main__":
    main()
