#!/usr/bin/env python3
"""Two-sided CPB-registry vector set for the machine-mandate artifact type.

Generates and verifies machine-mandate-vectors-v0.1.json from this repository's
own canonicalisation (deps/jcs.py) so the vectors cannot drift from the code.

Positive vectors pin the two frozen derivations (credential derived identifier;
bound action digest) plus invariance probes. Negative vectors discriminate the
proposed `jcs-s` algorithm (RFC 8785 subset, NO member removal, integers only)
from `jcs-n` (null/empty-member removal) and pin the representation rules.

Usage:  python3 gen_vectors.py            # regenerate the JSON
        python3 gen_vectors.py --verify   # recompute and compare against the JSON
"""
import hashlib, json, sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from deps.jcs import jcs, H  # the audited canonicalisation — single source of truth

PREIMAGE = REPO / "interop" / "run-credential-preimage.jwt"
ACTION = {"action_id": "pay-invoice/acme-corp",
          "outcome": "eur:250:acme-corp:vienna-interop-2026-001"}

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def jcs_n(obj):
    """Reference implementation of the REGISTRY's jcs-n removal pass (bottom-up
    removal of null / empty-array / empty-object members) — used ONLY to produce
    the discriminating wrong-algorithm digest in fail-01. Not used by machine-mandate."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            v2 = jcs_n(v)
            if v2 is None or v2 == [] or v2 == {}:
                continue
            out[k] = v2
        return out
    if isinstance(obj, list):
        return [jcs_n(v) for v in obj]
    return obj

def build():
    pre = PREIMAGE.read_bytes()
    assert not pre.endswith(b"\n"), "frozen preimage must carry no trailing newline"

    null_member = {"a": None, "b": [], "c": {}, "d": 1}
    nonascii = {"action_id": "pay/åäö-№5", "outcome": "€250:тест"}
    permuted_bytes = json.dumps({"outcome": ACTION["outcome"],
                                 "action_id": ACTION["action_id"]},
                                sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False).encode("utf-8")

    v = {
        "artifact_type": "machine-mandate",
        "canonicalization": "jcs-s (name pending registry decision; semantics: RFC 8785 subset - code-point key sort, no insignificant whitespace, UTF-8, NO member removal, integer-only numbers)",
        "version": "0.1",
        "source_commit": None,  # stamped by CI/reader from git, never hand-edited
        "positive": [
            {
                "id": "mm-kat-01-credential-derived-identifier",
                "description": "Derived identifier = SHA-256 over the exact issuer-signed JWT component bytes (first ~-separated component as transmitted). Field set: every issuer-signed claim as serialized; exclusion set: everything after the first ~. Representation: BARE 64-char lowercase hex.",
                "preimage_file": "interop/run-credential-preimage.jwt",
                "preimage_length_bytes": len(pre),
                "expected_digest_bare_hex": sha256_hex(pre),
            },
            {
                "id": "mm-kat-02-action-object-digest",
                "description": "Bound action digest (action_hash claim): field set exactly {action_id, outcome}, exclusion set empty. Representation: sha256:-prefixed lowercase hex.",
                "input": ACTION,
                "canonical_bytes_hex": jcs(ACTION).hex(),
                "canonical_length_bytes": len(jcs(ACTION)),
                "expected_digest_prefixed": H(ACTION),
            },
            {
                "id": "mm-kat-03-key-order-invariance",
                "description": "Member order in the input object MUST NOT change the digest (keys sort by code point).",
                "input_permuted": {"outcome": ACTION["outcome"], "action_id": ACTION["action_id"]},
                "expected_digest_prefixed": "sha256:" + sha256_hex(permuted_bytes),
                "must_equal": "mm-kat-02-action-object-digest.expected_digest_prefixed",
            },
            {
                "id": "mm-kat-04-non-ascii-utf8",
                "description": "Non-ASCII values serialize as raw UTF-8 (ensure_ascii=false); pins the UTF-8 rule.",
                "input": nonascii,
                "canonical_bytes_hex": jcs(nonascii).hex(),
                "expected_digest_prefixed": H(nonascii),
            },
        ],
        "negative": [
            {
                "id": "mm-fail-01-member-removal-discriminator",
                "description": "THE jcs-s vs jcs-n DISCRIMINATOR. jcs-s retains null/empty members; jcs-n removes them. An implementation that removes members produces wrong_digest_jcs_n and MUST FAIL this vector.",
                "input": null_member,
                "expected_digest_prefixed_jcs_s": H(null_member),
                "wrong_digest_prefixed_jcs_n": H(jcs_n(null_member)),
                "must_fail_if_digest_equals": "wrong_digest_prefixed_jcs_n",
            },
            {
                "id": "mm-fail-02-float-rejected",
                "description": "Numbers are restricted to integers (ES6 number formatting per RFC 8785 3.2.2 is not implemented). A producer MUST reject a payload containing a non-integer number rather than serialize it.",
                "input": {"action_id": "x", "amount": 1.5},
                "expected": "REJECT (non-integer number)",
            },
            {
                "id": "mm-fail-03-trailing-newline",
                "description": "The credential preimage is the exact transmitted bytes; appending a single 0x0A changes the identifier. Pins byte-exactness.",
                "preimage_file": "interop/run-credential-preimage.jwt",
                "mutation": "append 0x0A",
                "wrong_digest_bare_hex": sha256_hex(pre + b"\n"),
                "must_not_equal": "mm-kat-01-credential-derived-identifier.expected_digest_bare_hex",
            },
            {
                "id": "mm-fail-04-representation-confusion",
                "description": "Representations are not interchangeable: the derived identifier is BARE hex; claim-level hashes carry the sha256: prefix. Comparing one form against the other MUST fail rather than normalise.",
                "bare_form_of_kat02": H(ACTION).split(":", 1)[1],
                "prefixed_form_of_kat02": H(ACTION),
                "expected": "REJECT on form mismatch (no silent stripping/adding of the prefix)",
            },
            {
                "id": "mm-fail-05-uppercase-hex",
                "description": "Identifier validation is exactly [0-9a-f]{64}; uppercase hex MUST be rejected, not case-folded.",
                "input_digest": sha256_hex(pre).upper(),
                "expected": "REJECT (fails [0-9a-f]{64})",
            },
        ],
    }
    return v

def main():
    out = Path(__file__).with_name("machine-mandate-vectors-v0.1.json")
    built = build()
    if "--verify" in sys.argv:
        on_disk = json.loads(out.read_text())
        on_disk["source_commit"] = built["source_commit"] = None
        if on_disk != built:
            print("MISMATCH between generator and on-disk vectors"); sys.exit(1)
        print("verify: OK — all vectors reproduce from deps/jcs.py")
        return
    out.write_text(json.dumps(built, indent=2, ensure_ascii=False) + "\n")
    print("wrote", out.name)
    print("kat-01:", built["positive"][0]["expected_digest_bare_hex"])
    print("kat-02:", built["positive"][1]["expected_digest_prefixed"],
          f"({built['positive'][1]['canonical_length_bytes']} bytes)")

if __name__ == "__main__":
    main()
