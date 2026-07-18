#!/usr/bin/env python3
"""Presentation-invariance check for the frozen MachineMandate run credential.

WHY THIS EXISTS, STATED PLAINLY. The committed self-check inside
mint_run_credential.py constructs exactly TWO case presentations (positive and
mandate-over-limit), each following a separate verifier request, and both using
the same reveal set {principal, swname, ear_status}. A thread summary on
2026-07-18 described a wider check -- four presentations varying nonce, audience
and revealed-claim subset -- which had been run ad hoc during review but whose
inputs and outputs were NOT preserved. That summary therefore overstated what
the committed record documented. Scott Lee caught it.

This script is the correction: it makes the wider check real, reproducible and
preserved, rather than asserted. It produces N presentations from the ALREADY
FROZEN credential, deliberately varying the verifier nonce, the audience, and
the revealed-claim subset, verifies each presentation round-trips, and confirms
that the issuer-signed component -- the frozen preimage under option (a) -- is
byte-identical in every one of them.

It does NOT re-mint. It cannot change the frozen digest: the issuer-signed
component is fixed at issuance, and only the holder's KB-JWT and the disclosed
subset differ per presentation. That is precisely the property being checked.

Run:
  python3 interop/presentation_invariance_check.py \
      --run-dir /srv/tyche/runs/ietf126-composition \
      --out interop/run-credential-presentation-invariance.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "src"))
sys.path.insert(0, os.path.join(REPO, "deps"))

import mandate  # noqa: E402

FROZEN_DIGEST = "5df4d32df57650f27b6a65df041b708de80d69c0ca82a1044334f5e2edef5ce2"

# Deliberately varied: nonce, audience, and revealed-claim subset -- including
# the empty subset and the subset containing the claim the case presentations
# never reveal (composition_action_id).
VARIATIONS = [
    ("nonce-inv-01", "https://verifier.example/paygate-a",
     {"principal", "swname", "ear_status"}),
    ("nonce-inv-02", "https://verifier.example/paygate-b",
     {"principal", "swname"}),
    ("nonce-inv-03", "https://verifier.example/paygate-c",
     {"ear_status"}),
    ("nonce-inv-04", "https://verifier.example/paygate-d",
     {"composition_action_id"}),
    ("nonce-inv-05", "https://verifier.example/paygate-e",
     {"principal", "swname", "ear_status", "composition_action_id"}),
    ("nonce-inv-06", "https://verifier.example/paygate-f",
     set()),
]


def issuer_component_digest(token: str):
    """Option (a): the first '~'-separated component, no separator, no newline."""
    comp = token.split("~")[0].encode("utf-8")
    return hashlib.sha256(comp).hexdigest(), len(comp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", default="/srv/tyche/runs/ietf126-composition")
    ap.add_argument("--out", default=os.path.join(
        HERE, "run-credential-presentation-invariance.json"))
    args = ap.parse_args()

    with open(os.path.join(args.run_dir, "credential.sdjwt")) as fh:
        sd_full = fh.read()
    with open(os.path.join(args.run_dir, "holder-key.pem"), "rb") as fh:
        holder_key = serialization.load_pem_private_key(fh.read(), password=None)
    with open(os.path.join(args.run_dir, "issuer.jwk")) as fh:
        issuer_jwk = json.load(fh)

    frozen, frozen_len = issuer_component_digest(sd_full)
    if frozen != FROZEN_DIGEST:
        raise SystemExit("ABORT: run-dir credential is not the frozen one "
                         "(%s != %s)" % (frozen, FROZEN_DIGEST))

    records = []
    for nonce, aud, reveal in VARIATIONS:
        presentation = mandate.present_sd(sd_full, holder_key, nonce=nonce,
                                          aud=aud, reveal=reveal)
        digest, length = issuer_component_digest(presentation)

        # Independently confirm the presentation actually verifies, so that an
        # invariant digest cannot come from a malformed presentation.
        try:
            claims = mandate.verify_presentation_sd(presentation, issuer_jwk,
                                                    nonce=nonce, aud=aud)
            verified, disclosed = True, sorted(
                k for k in reveal if k in claims)
        except Exception as exc:                       # noqa: BLE001
            verified, disclosed = False, []
            claims = {"error": type(exc).__name__}

        records.append({
            "verifier_nonce": nonce,
            "audience": aud,
            "reveal_requested": sorted(reveal),
            "claims_actually_disclosed": disclosed,
            "presentation_verified": verified,
            "presentation_length_bytes": len(presentation.encode("utf-8")),
            "issuer_component_digest": digest,
            "issuer_component_length_bytes": length,
            "matches_frozen_digest": digest == FROZEN_DIGEST,
            "presentation_as_transmitted": presentation,
        })

    all_match = all(r["matches_frozen_digest"] for r in records)
    all_verified = all(r["presentation_verified"] for r in records)
    distinct_kb = len({r["presentation_as_transmitted"] for r in records})

    out = {
        "artifact": "MachineMandate run credential — presentation-invariance check",
        "status": "FROZEN PRE-EXECUTION INPUT — NOT A RESULT",
        "what_this_is": "a post-hoc, preserved check that the option-(a) preimage "
                        "is byte-identical across presentations that vary the "
                        "verifier nonce, the audience, and the revealed-claim "
                        "subset. It does not re-mint and cannot alter the frozen "
                        "digest. It is evidence about the credential only, "
                        "produced inside one Tyche process; it is not a "
                        "composition or interoperability result",
        "supersedes_claim": "corrects the 2026-07-18 thread summary, which "
                            "described four such presentations without preserving "
                            "their inputs and outputs; the committed self-check in "
                            "mint_run_credential.py documents two case "
                            "presentations sharing one reveal set",
        "frozen_preimage": {
            "rule": "option (a): the exact issuer-signed JWT component bytes of "
                    "the SD-JWT (the first ~-separated component as transmitted)",
            "digest_alg": "SHA-256",
            "digest": FROZEN_DIGEST,
            "length_bytes": frozen_len,
        },
        "result": {
            "presentations": len(records),
            "distinct_presentations": distinct_kb,
            "all_presentations_verified": all_verified,
            "preimage_invariant_across_all": all_match,
        },
        "presentations": records,
    }
    with open(args.out, "w") as fh:
        fh.write(json.dumps(out, indent=2, sort_keys=True) + "\n")

    print("presentations           : %d (%d distinct)" % (len(records), distinct_kb))
    print("all verified            : %s" % all_verified)
    print("preimage invariant      : %s" % all_match)
    print("frozen digest           : %s" % FROZEN_DIGEST)
    print("written to              : %s" % args.out)
    if not (all_match and all_verified and distinct_kb == len(records)):
        raise SystemExit("CHECK FAILED")


if __name__ == "__main__":
    main()
