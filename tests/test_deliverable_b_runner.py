from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

MODULE_PATH = Path(__file__).resolve().parents[1] / "interop" / "deliverable_b_runner.py"
SPEC = importlib.util.spec_from_file_location("deliverable_b_runner", MODULE_PATH)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def test_manifest_hash_pin() -> None:
    manifest = MODULE_PATH.parent / "composition-input-manifest-v0.5.json"
    assert runner.sha256_file(manifest) == runner.MANIFEST_SHA256


def test_evidence_schema_accepts_runner_record_shape() -> None:
    schema = json.loads(
        (MODULE_PATH.parent / "deliverable-b-evidence-schema-v0.1.json").read_text()
    )
    record = {
        "case_count": 5,
        "classification": runner.CLASSIFICATION,
        "final_evidence_authorized": False,
        "input_pins": {
            "manifest_sha256": runner.MANIFEST_SHA256,
            "machine_mandate_runtime": runner.MACHINE_MANDATE_PIN,
            "aac_rehearsal": runner.AAC_REHEARSAL_PIN,
            "aep": runner.AEP_PIN,
            "scitt_cose_rehearsal": runner.SCITT_COSE_REHEARSAL_PIN,
        },
        "result": "PASS",
        "started_at": "2026-07-27T00:00:00Z",
        "completed_at": "2026-07-27T00:00:01Z",
    }
    Draft202012Validator(schema).validate(record)


def test_permit_mutation_digest_derivation() -> None:
    preimage = (
        b"orprg-ietf126-payment-composition:"
        b"negative-case:permit-reference-mutation:v1"
    )
    assert hashlib.sha256(preimage).hexdigest() == runner.FIXED_BAD_PERMIT_DIGEST


def test_raw_and_ascii_pcr_folds_are_distinct() -> None:
    response_digest = hashlib.sha256(b"synthetic response").hexdigest()
    assert runner.pcr_fold_raw(response_digest) != runner.pcr_fold_ascii(response_digest)


def test_gate_sequence_short_circuits() -> None:
    raw = [
        {"name": name, "passed": name != runner.GATE_ORDER[0], "reason": name}
        for name in runner.GATE_ORDER
    ]
    records, first = runner.sequential_gates(raw)
    assert first == "permit_receipt_reference_bound"
    assert records[0]["status"] == "DENY"
    assert all(record["status"] == "not reached" for record in records[1:])


def test_qualification_uses_prefixed_transcript_only() -> None:
    digest = "ab" * 32
    transcript, qual = runner.qualification("cd" * 32, digest, "nonce-1")
    assert f"outcome=sha256:{digest}" in transcript
    assert len(qual) == 64


def test_final_mode_is_refused_before_output_creation(tmp_path: Path) -> None:
    args = runner.argparse.Namespace(mode="final", out=tmp_path / "must-not-exist")
    with pytest.raises(RuntimeError, match="not authorized"):
        runner.run(args)
    assert not args.out.exists()
