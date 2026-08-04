#!/usr/bin/env python3
"""Recompute every pinned byte string and digest in the three day-2
spec-mutation vectors (kat-utf16-key-order, kat-identifier-trailing-newline,
kat-identifier-surrounding-whitespace) from the standard library alone.

Independence rule: the UTF-16 sort key is built by explicit surrogate-pair
decomposition, NOT str.encode("utf-16-be"), so this check shares no code
path with either serializer that produced the pins.  Exits non-zero on any
mismatch.
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def utf16_units(s: str) -> list[int]:
    units: list[int] = []
    for ch in s:
        cp = ord(ch)
        if cp <= 0xFFFF:
            units.append(cp)
        else:
            v = cp - 0x10000
            units.append(0xD800 + (v >> 10))
            units.append(0xDC00 + (v & 0x3FF))
    return units


def esc(s: str) -> str:
    out = []
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif cp < 0x20:
            out.append({0x08: "\\b", 0x09: "\\t", 0x0A: "\\n",
                        0x0C: "\\f", 0x0D: "\\r"}.get(cp, f"\\u{cp:04x}"))
        else:
            out.append(ch)
    return "".join(out)


def ser(obj, sort_key) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, str):
        return f'"{esc(obj)}"'
    if isinstance(obj, list):
        return "[" + ",".join(ser(x, sort_key) for x in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: sort_key(kv[0]))
        return "{" + ",".join(f'"{esc(k)}":{ser(v, sort_key)}' for k, v in items) + "}"
    raise ValueError(f"unsupported type {type(obj)}")


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


failures: list[str] = []


def expect(label: str, got: str, want: str) -> None:
    if got != want:
        failures.append(f"{label}:\n  want {want}\n  got  {got}")


# --- kat-utf16-key-order: both sort policies, every pinned digest ---
v = json.loads((HERE / "kat-utf16-key-order.json").read_text(encoding="utf-8"))
for case in v["cases"]:
    cid = case["case_id"]
    witness = case["witness_value"]
    mp = case["must_pass"]
    conforming = ser(witness, utf16_units)
    expect(f"{cid}/must_pass bytes", conforming, mp["jcs_bytes"])
    expect(f"{cid}/must_pass hex", conforming.encode("utf-8").hex(), mp["jcs_bytes_hex"])
    expect(f"{cid}/must_pass sha256", sha(conforming), mp["sha256"])
    wrong = ser(witness, lambda k: [ord(c) for c in k])
    for mf in case["must_fail"]:
        expect(f"{cid}/{mf['diagnosis']} bytes", wrong, mf["jcs_bytes"])
        expect(f"{cid}/{mf['diagnosis']} sha256", sha(wrong), mf["sha256"])

# --- the two identifier-grammar vectors: cited artifact + carrier grammar ---
for name in ("kat-identifier-trailing-newline.json",
             "kat-identifier-surrounding-whitespace.json"):
    v = json.loads((HERE / name).read_text(encoding="utf-8"))
    cited = v["cited_artifact"]
    canonical = ser(cited["payload"], utf16_units)
    expect(f"{name}/cited bytes", canonical, cited["jcs_bytes"])
    expect(f"{name}/cited hex", canonical.encode("utf-8").hex(), cited["jcs_bytes_hex"])
    expect(f"{name}/cited sha256", sha(canonical), cited["sha256"])
    correct = cited["sha256"]
    expect(f"{name}/must_pass carrier", v["must_pass"]["carried_identifier"], correct)
    for mf in v["must_fail"]:
        carried = mf["carried_identifier"]
        if carried == correct:
            failures.append(f"{name}/{mf['case_id']}: carried == correct, nothing demonstrated")
        if carried.strip() != correct:
            failures.append(f"{name}/{mf['case_id']}: stripped carrier != correct digest — "
                            f"the vector would test content, not representation")
        if len(carried) == 64 and all(c in "0123456789abcdef" for c in carried):
            failures.append(f"{name}/{mf['case_id']}: carrier IS valid bare hex — no grammar violation")

if failures:
    print(f"FAIL: {len(failures)} mismatch(es)")
    for f in failures:
        print(f)
    sys.exit(1)
print("day-2 vectors: all pinned bytes and digests reproduce; carrier grammar violations confirmed")
