"""Canonicalisation + hashing.

jcs(): a faithful subset of RFC 8785 (JSON Canonicalisation Scheme) — sorted keys,
no whitespace, UTF-8. Sufficient for our values (strings, ints, bools, arrays,
objects); full ES6 number formatting (RFC 8785 §3.2.2) is not exercised here and is
a noted M2 item if floats enter the schema.

String keys and values are NFC-normalised before serialisation: RFC 8785 leaves
Unicode normalization to the caller, and the mandate profile requires NFC so that
two canonically equivalent encodings of the same string cannot yield diverging
seals (manuscript §3.1). Codepoint-distinct lookalikes stay distinct by design —
a swapped-in lookalike payee fails the seal comparison.
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
