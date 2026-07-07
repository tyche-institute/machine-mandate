"""Canonicalisation + hashing.

jcs(): a faithful subset of RFC 8785 (JSON Canonicalisation Scheme) — sorted keys,
no whitespace, UTF-8. Sufficient for our values (strings, ints, bools, arrays,
objects); full ES6 number formatting (RFC 8785 §3.2.2) is not exercised here and is
a noted M2 item if floats enter the schema.
"""
import hashlib
import json


def jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def H(obj) -> str:
    return "sha256:" + hashlib.sha256(jcs(obj)).hexdigest()


def Hs(s: str) -> str:
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()
