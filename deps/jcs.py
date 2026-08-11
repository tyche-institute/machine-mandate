"""Canonicalisation + hashing.

jcs(): a subset of RFC 8785 (JSON Canonicalisation Scheme) — sorted keys, no
whitespace, UTF-8 — PLUS an NFC pre-pass, and it is not byte-compatible with
RFC 8785 in either direction. Do not describe it as "RFC 8785 canonicalisation"
without this paragraph:

  * NFC: a deliberate VIOLATION of a normative MUST, not a gap in the spec.
    RFC 8785 §3.1 is explicit that normalization is not performed: "all
    components involved in a scheme depending on JCS MUST preserve Unicode
    string data 'as is'". This module normalises string keys and values to NFC
    before serialising, so for a decomposed input it and a conformant RFC 8785
    implementation emit DIFFERENT bytes and different digests, and this module
    is NOT RFC 8785 conformant. The mandate profile takes that trade knowingly:
    it prefers that two canonically equivalent encodings of one payee cannot
    yield diverging seals (manuscript §3.1) over byte-level JCS conformance.
    Anything that must interoperate with a conformant JCS implementation — the
    composition draft's digest join, for one — must NOT use this function.
  * Number formatting. Full ES6 number formatting (RFC 8785 §3.2.2) is not
    implemented. The profile carries integer euros only, and the seal now
    REFUSES a non-integer amount rather than coercing it
    (src/agent_demo.py action_hash), so the unimplemented cases are unreachable
    from the verification path rather than silently wrong.

Codepoint-distinct lookalikes stay distinct by design — a swapped-in lookalike
payee fails the seal comparison, which is the safe direction.
"""
import hashlib
import json
import unicodedata


def _nfc(obj):
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            nk = unicodedata.normalize("NFC", k) if isinstance(k, str) else k
            if nk in out:
                # two distinct keys that are NFC-equivalent would silently merge
                # (last-writer-wins) and drop a claim before sealing - refuse instead
                raise ValueError("NFC-equivalent duplicate key: %r" % (nk,))
            out[nk] = _nfc(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [_nfc(v) for v in obj]
    return obj


def jcs(obj) -> bytes:
    return json.dumps(_nfc(obj), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def H(obj) -> str:
    return "sha256:" + hashlib.sha256(jcs(obj)).hexdigest()


def Hs(s: str) -> str:
    # deliberately NOT normalised: hashes byte-exact compact serialisations (sd_hash)
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()
