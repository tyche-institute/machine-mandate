#!/usr/bin/env python3
"""Fail-closed five-case runner for the IETF-126 composition exercise.

This executable is intentionally rehearsal-only. It consumes the immutable
v0.5 input manifest, runs the owner implementations by reference, captures the
evidence Lee requested, and refuses to represent any output as a final
Deliverable-B result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CLASSIFICATION = "ENGINEERING VALIDATION — NON-EVIDENTIARY — NOT A DELIVERABLE-B RESULT"
MANIFEST_SHA256 = "7d76335f0cd5517d415506309294a7b83ac622a0134f618dafdf18b3a3cea882"
MACHINE_MANDATE_PIN = "e440286dec11c43ad39ebcc7d0001fa0987e7bd8"
AAC_REHEARSAL_PIN = "c19e82a4f73a7be3f97b99e53a900adee6b74392"
AEP_PIN = "9521185f77c3dce292d7b4bd8a8100ca11fb50be"
SCITT_COSE_REHEARSAL_PIN = "2146e39d298e2f92df2fe39fbf70a15f267b3ab1"
FIXED_BAD_PERMIT_DIGEST = "32694d981a3c1c52864f79b8d3f1c4149866af6830d7f2c25edadbe743f973db"
GATE_ORDER = [
    "permit_receipt_reference_bound",
    "permit_receipt_appraised",
    "machine_mandate_reference_bound",
    "machine_mandate_appraised",
    "machine_mandate_action_hash",
    "machine_mandate_spend",
]
MACHINE_RUNTIME_PATHS = [
    "deps/crypto.py",
    "deps/jcs.py",
    "deps/mandate.py",
    "fixtures/demo.aep.json",
    "fixtures/ear-A_good_fresh.json",
    "fixtures/token-A_good_fresh.bin",
    "src/mock_verifier.py",
    "src/scope_enforce.py",
    "src/tl_xml.py",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def git_head(repo: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


class CommandRecorder:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.sequence = 0

    def run(
        self,
        name: str,
        argv: list[str],
        *,
        cwd: Path,
        env: dict[str, str] | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        self.sequence += 1
        started = utc_now()
        result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, check=False)
        ended = utc_now()
        stem = f"{self.sequence:03d}-{name}"
        stdout_path = self.root / f"{stem}.stdout"
        stderr_path = self.root / f"{stem}.stderr"
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_bytes(result.stdout)
        stderr_path.write_bytes(result.stderr)
        write_json(
            self.root / f"{stem}.json",
            {
                "argv": argv,
                "cwd": str(cwd),
                "ended_at": ended,
                "exit_code": result.returncode,
                "started_at": started,
                "stderr_sha256": sha256_bytes(result.stderr),
                "stdout_sha256": sha256_bytes(result.stdout),
            },
        )
        if check and result.returncode != 0:
            raise RuntimeError(
                f"command {name!r} failed with exit {result.returncode}; "
                f"see {stderr_path}"
            )
        return result


def verify_runtime_pin(repo: Path) -> dict[str, str]:
    observed: dict[str, str] = {}
    for rel in MACHINE_RUNTIME_PATHS:
        current = (repo / rel).read_bytes()
        frozen = subprocess.run(
            ["git", "show", f"{MACHINE_MANDATE_PIN}:{rel}"],
            cwd=repo,
            capture_output=True,
            check=True,
        ).stdout
        require(current == frozen, f"MachineMandate runtime drift at {rel}")
        observed[rel] = sha256_bytes(current)
    return observed


def copy_and_verify_orprg_assets(
    manifest: dict[str, Any],
    source: Path,
    destination: Path,
) -> list[dict[str, Any]]:
    pins = manifest["frozen_owner_artifacts"]["orprg_payment_composition_tuple"][
        "explicit_release_assets"
    ]["assets"]
    destination.mkdir(parents=True)
    records: list[dict[str, Any]] = []
    for pin in pins:
        src = source / pin["filename"]
        require(src.is_file(), f"missing ORPRG release asset: {src}")
        observed = sha256_file(src)
        require(observed == pin["sha256"], f"ORPRG asset hash mismatch: {src.name}")
        dst = destination / src.name
        shutil.copy2(src, dst)
        records.append(
            {
                "filename": src.name,
                "expected_sha256": pin["sha256"],
                "observed_sha256": observed,
                "size_bytes": src.stat().st_size,
            }
        )
    return records


def load_orprg_case(root: Path, case_name: str) -> dict[str, Any]:
    base = root / "cases" / case_name
    return {
        "auth_ref": read_json(base / "authorization-ref.json"),
        "carrier": read_json(base / "authorization-ref-carrier.json"),
        "permit_receipt": read_json(base / "permit-receipt.json"),
    }


def pcr_fold_raw(response_digest: str) -> str:
    return sha256_bytes(b"\x00" * 32 + bytes.fromhex(response_digest))


def pcr_fold_ascii(response_digest: str) -> str:
    return sha256_bytes(b"\x00" * 32 + response_digest.encode("ascii"))


def qualification(
    capsule_id: str,
    response_digest: str,
    verifier_nonce: str,
) -> tuple[str, str]:
    transcript = (
        "tyche.aep.qual.v1"
        f"|capsule={capsule_id}"
        f"|outcome=sha256:{response_digest}"
        f"|nonce={verifier_nonce}"
    )
    return transcript, sha256_bytes(transcript.encode("utf-8"))


def first_free_port_pair() -> int:
    for _ in range(100):
        with socket.socket() as first:
            first.bind(("127.0.0.1", 0))
            port = first.getsockname()[1]
        if port >= 65534:
            continue
        with socket.socket() as second:
            try:
                second.bind(("127.0.0.1", port + 1))
            except OSError:
                continue
        return port
    raise RuntimeError("could not reserve adjacent swtpm ports")


def make_tpm_quote(
    *,
    response_digest: str,
    qualifying_data_hex: str,
    case_dir: Path,
    commands: CommandRecorder,
) -> dict[str, Any]:
    tpm_dir = case_dir / "aep" / "tpm"
    tpm_dir.mkdir(parents=True)
    state_dir = Path(tempfile.mkdtemp(prefix="deliverable-b-swtpm-"))
    port = first_free_port_pair()
    swtpm_stdout = (tpm_dir / "swtpm.stdout").open("wb")
    swtpm_stderr = (tpm_dir / "swtpm.stderr").open("wb")
    process = subprocess.Popen(
        [
            "swtpm",
            "socket",
            "--tpmstate",
            f"dir={state_dir}",
            "--ctrl",
            f"type=tcp,port={port + 1}",
            "--server",
            f"type=tcp,port={port}",
            "--tpm2",
            "--flags",
            "not-need-init,startup-clear",
        ],
        stdout=swtpm_stdout,
        stderr=swtpm_stderr,
    )
    env = dict(os.environ)
    env["TPM2TOOLS_TCTI"] = f"swtpm:host=127.0.0.1,port={port}"
    try:
        time.sleep(0.6)
        commands.run("tpm-startup", ["tpm2_startup", "-c"], cwd=tpm_dir, env=env, check=False)
        commands.run(
            "tpm-createek",
            ["tpm2_createek", "-G", "rsa", "-c", "ek.ctx"],
            cwd=tpm_dir,
            env=env,
        )
        commands.run("tpm-flush-1", ["tpm2_flushcontext", "-t"], cwd=tpm_dir, env=env)
        commands.run(
            "tpm-createak",
            ["tpm2_createak", "-C", "ek.ctx", "-c", "ak.ctx", "-u", "ak.pub"],
            cwd=tpm_dir,
            env=env,
        )
        commands.run("tpm-flush-2", ["tpm2_flushcontext", "-t"], cwd=tpm_dir, env=env)
        commands.run("tpm-pcr-reset", ["tpm2_pcrreset", "16"], cwd=tpm_dir, env=env)
        commands.run(
            "tpm-pcr-extend",
            ["tpm2_pcrextend", f"16:sha256={response_digest}"],
            cwd=tpm_dir,
            env=env,
        )
        commands.run(
            "tpm-quote",
            [
                "tpm2_quote",
                "-c",
                "ak.ctx",
                "-l",
                "sha256:16",
                "-q",
                qualifying_data_hex.encode("ascii").hex(),
                "-m",
                "quote.msg",
                "-s",
                "quote.sig",
                "-o",
                "pcr.bin",
                "-g",
                "sha256",
            ],
            cwd=tpm_dir,
            env=env,
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        swtpm_stdout.close()
        swtpm_stderr.close()
        shutil.rmtree(state_dir, ignore_errors=True)

    return {
        "ak_pub": tpm_dir / "ak.pub",
        "pcr_bin": tpm_dir / "pcr.bin",
        "quote_msg": tpm_dir / "quote.msg",
        "quote_sig": tpm_dir / "quote.sig",
        "expected_pcr_raw_fold": pcr_fold_raw(response_digest),
    }


def check_quote(
    *,
    quote: dict[str, Any],
    qualifying_data_hex: str,
    case_dir: Path,
    commands: CommandRecorder,
    name: str,
    expect_success: bool,
) -> subprocess.CompletedProcess[bytes]:
    result = commands.run(
        name,
        [
            "tpm2_checkquote",
            "-u",
            str(quote["ak_pub"]),
            "-m",
            str(quote["quote_msg"]),
            "-s",
            str(quote["quote_sig"]),
            "-q",
            qualifying_data_hex.encode("ascii").hex(),
            "-g",
            "sha256",
            "-f",
            str(quote["pcr_bin"]),
        ],
        cwd=case_dir,
        check=False,
    )
    require(
        (result.returncode == 0) is expect_success,
        f"{name}: unexpected tpm2_checkquote exit {result.returncode}",
    )
    return result


def gate_record(name: str, status: str, reason: str) -> dict[str, str]:
    return {"name": name, "status": status, "reason": reason}


def sequential_gates(raw_gates: list[dict[str, Any]]) -> tuple[list[dict[str, str]], str | None]:
    by_name = {gate["name"]: gate for gate in raw_gates}
    records: list[dict[str, str]] = []
    rejected: str | None = None
    for name in GATE_ORDER:
        if rejected is not None:
            records.append(gate_record(name, "not reached", f"short-circuited after {rejected}"))
            continue
        raw = by_name[name]
        status = "PASS" if raw["passed"] else "DENY"
        records.append(gate_record(name, status, raw["reason"]))
        if not raw["passed"]:
            rejected = name
    return records, rejected


def evidence_hashes(root: Path) -> list[str]:
    lines: list[str] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if path.name == "file-hashes.sha256":
            continue
        lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    return lines


def archive_evidence(root: Path) -> tuple[Path, str]:
    archive = root.with_suffix(".tar.gz")
    with tarfile.open(archive, "w:gz") as stream:
        stream.add(root, arcname=root.name, recursive=True)
    digest = sha256_file(archive)
    archive.with_suffix(archive.suffix + ".sha256").write_text(
        f"{digest}  {archive.name}\n",
        encoding="utf-8",
    )
    return archive, digest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=here / "composition-input-manifest-v0.5.json")
    parser.add_argument("--orprg-assets", type=Path, required=True)
    parser.add_argument("--orprg-root", type=Path, required=True)
    parser.add_argument("--aac-repo", type=Path, required=True)
    parser.add_argument("--aep-repo", type=Path, required=True)
    parser.add_argument("--scitt-cose-repo", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--mode", choices=["rehearsal", "final"], default="rehearsal")
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.mode != "rehearsal":
        raise RuntimeError(
            "final evidence generation is not authorized by this executable; "
            "issue a reviewed runner/version and obtain explicit run authorization"
        )
    require(not args.out.exists(), f"refusing to overwrite output path: {args.out}")
    args.out.mkdir(parents=True)
    commands = CommandRecorder(args.out / "commands")
    started_at = utc_now()

    require(sha256_file(args.manifest) == MANIFEST_SHA256, "v0.5 manifest hash mismatch")
    manifest = read_json(args.manifest)
    require(manifest.get("version") == "v0.5", "runner requires manifest version v0.5")
    shutil.copy2(args.manifest, args.out / "composition-input-manifest-v0.5.json")

    observed_heads = {
        "aac": git_head(args.aac_repo),
        "aep": git_head(args.aep_repo),
        "scitt_cose": git_head(args.scitt_cose_repo),
    }
    require(observed_heads["aac"] == AAC_REHEARSAL_PIN, "AAC rehearsal pin mismatch")
    require(observed_heads["aep"] == AEP_PIN, "AEP pin mismatch")
    require(
        observed_heads["scitt_cose"] == SCITT_COSE_REHEARSAL_PIN,
        "scitt-cose rehearsal pin mismatch",
    )
    machine_hashes = verify_runtime_pin(Path(__file__).resolve().parents[1])
    machine_repo = Path(__file__).resolve().parents[1]
    runner_sources = machine_repo / "interop"
    captured_runner_dir = args.out / "inputs" / "runner-source"
    captured_runner_dir.mkdir(parents=True)
    for name in (
        "deliverable_b_runner.py",
        "deliverable-b-evidence-schema-v0.1.json",
        "deliverable-b-v0.6-readiness.md",
        "DELIVERABLE-B-RUNNER.md",
    ):
        shutil.copy2(runner_sources / name, captured_runner_dir / name)
    runner_source_sha256 = sha256_file(runner_sources / "deliverable_b_runner.py")
    runner_repository_commit = git_head(machine_repo)
    asset_records = copy_and_verify_orprg_assets(
        manifest,
        args.orprg_assets,
        args.out / "inputs" / "orprg-release-assets",
    )

    commands.run(
        "orprg-sidecar-check",
        ["sha256sum", "-c", "orprg-ietf126-payment-composition-v0.1.zip.sha256"],
        cwd=args.orprg_assets,
    )
    package_verify = commands.run(
        "orprg-verify-tuple",
        [sys.executable, "verify-tuple.py"],
        cwd=args.orprg_root,
    )
    independent_verify = commands.run(
        "orprg-independent-verify",
        [sys.executable, "independent-verify.py"],
        cwd=args.orprg_root,
    )
    require(
        b"PASS: 203/203 checks" in package_verify.stdout,
        "ORPRG package verifier summary missing",
    )
    require(
        b"PASS: 74/74 independent checks" in independent_verify.stdout,
        "ORPRG independent verifier summary missing",
    )
    commands.run("aep-prior-vector-verify", ["bash", "verify.sh"], cwd=args.aep_repo)
    commands.run("python-version", [sys.executable, "--version"], cwd=machine_repo)
    commands.run("git-version", ["git", "--version"], cwd=machine_repo)
    commands.run("swtpm-version", ["swtpm", "--version"], cwd=machine_repo)
    commands.run("tpm2-tools-version", ["tpm2_checkquote", "--version"], cwd=machine_repo)

    sys.path.insert(0, str(args.scitt_cose_repo))
    sys.path.insert(0, str(args.aac_repo / "python"))
    sys.path.insert(0, str(machine_repo / "deps"))
    sys.path.insert(0, str(machine_repo / "src"))

    import crypto as aaa_crypto  # type: ignore
    import mandate  # type: ignore
    from agent_action_capsule.canonical import json_digest
    from agent_action_capsule.contracts import EffectRecord
    from agent_action_capsule.emit import emit
    from agent_action_capsule.verify import verify
    from agent_action_capsule.verify_composition import verify_permitreceipt_mandate
    from agent_action_capsule.verify_composition_orprg import (
        ORPRG_VERIFIER_ID,
        appraise_orprg_permit_receipt,
        machine_mandate_action_hash_gate,
        machine_mandate_spend_gate,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from scitt_cose import build_signed_statement, parse_signed_statement

    from scope_enforce import (
        AEP,
        AGENT_ENDORSER,
        ScopeAwareVerifier,
        action_hash_of,
        make_tl,
        quote_bound_nonce,
        scope_for,
        self_signed,
        x5t,
    )

    shared = {
        "mapping_profile": read_json(args.orprg_root / "mapping-profile.json"),
        "machine_mandate_action": read_json(
            args.orprg_root / "shared" / "machine-mandate-action.json"
        ),
        "permit_provenance": read_json(
            args.orprg_root / "shared" / "permit-provenance.json"
        ),
        "policy": read_json(args.orprg_root / "shared" / "policy.json"),
        "revocation_state": read_json(
            args.orprg_root / "shared" / "revocation-state.json"
        ),
        "trust_inputs": read_json(args.orprg_root / "shared" / "trust-inputs.json"),
        "verifier_context": read_json(
            args.orprg_root / "shared" / "verifier-context.json"
        ),
    }
    positive = load_orprg_case(args.orprg_root, "positive")
    over_limit = load_orprg_case(args.orprg_root, "mandate-over-limit")

    issuer_key, issuer_cert = self_signed("Tyche Rehearsal Agent-Runtime Endorser")
    holder_key = ec.generate_private_key(ec.SECP256R1())
    issuer_jwk = aaa_crypto.pub_jwk(issuer_key)
    holder_jwk = aaa_crypto.pub_jwk(holder_key)
    issuer_x5t = x5t(issuer_cert)
    tl_temp = Path(make_tl(issuer_cert, AGENT_ENDORSER))
    tl_path = args.out / "inputs" / "machine-mandate-trusted-list.xml"
    tl_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(tl_temp, tl_path)
    tl_temp.unlink()
    issuer_cert_pem = issuer_cert.public_bytes(serialization.Encoding.PEM)
    (args.out / "inputs" / "machine-mandate-issuer-cert.pem").write_bytes(issuer_cert_pem)
    write_json(args.out / "inputs" / "machine-mandate-issuer.jwk", issuer_jwk)
    write_json(
        args.out / "inputs" / "machine-mandate-trust-input.json",
        {
            "classification": CLASSIFICATION,
            "issuer_jwk": issuer_jwk,
            "issuer_x5t_s256": issuer_x5t,
            "role": AGENT_ENDORSER,
            "trust_model": "run-specific synthetic self-signed rehearsal input",
        },
    )

    mm_action = shared["machine_mandate_action"]
    mm_profile = shared["mapping_profile"]["machine_mandate"]
    action_hash = action_hash_of(mm_action["action_id"], mm_action["outcome"])
    require(action_hash == mm_profile["action_hash"], "MachineMandate action hash drift")
    scope = scope_for(
        [mm_action["action_id"]],
        [action_hash],
        mm_profile["scope_max_spend_minor"],
    )
    sd_full = mandate.issue_sd(
        issuer_key,
        agent=AEP["sub"],
        scope=scope,
        action_hash=action_hash,
        holder_jwk=holder_jwk,
        sd_claims={
            "principal": AEP["authorizing_principal"]["token_ref"],
            "swname": AEP["swname"],
            "ear_status": "affirming",
            "aep_receipt_hash": AEP["receipt_hash"],
        },
        ttl=3600,
        jti=f"rehearsal-{started_at}",
    )
    issuer_jws_preimage = sd_full.split("~", 1)[0]
    issuer_jws_digest = sha256_bytes(issuer_jws_preimage.encode("ascii"))
    credential_record = {
        "classification": CLASSIFICATION,
        "credential_kind": "run-specific rehearsal credential; not the frozen final credential",
        "issuer_jws_preimage": issuer_jws_preimage,
        "issuer_jws_preimage_sha256": issuer_jws_digest,
        "issuer_jwk": issuer_jwk,
        "holder_public_jwk": holder_jwk,
        "issuer_x5t_s256": issuer_x5t,
        "owner_verifier": {
            "id": "tyche.machine-mandate.scope-aware-verifier",
            "runtime_pin": MACHINE_MANDATE_PIN,
        },
    }
    write_json(args.out / "inputs" / "rehearsal-credential-record.json", credential_record)

    cose_private = ed25519.Ed25519PrivateKey.generate()
    cose_private_pem = cose_private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cose_public_pem = cose_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (args.out / "inputs" / "cose-rehearsal-public-key.pem").write_bytes(cose_public_pem)

    response = {
        "external_effect": False,
        "processor": "synthetic-sandbox",
        "status": "rehearsal-observation",
    }
    response_digest = sha256_bytes(json_bytes(response))
    write_json(
        args.out / "inputs" / "synthetic-response.json",
        {"response": response, "response_digest_unprefixed": response_digest},
    )
    static_ear = machine_repo / "fixtures" / "ear-A_good_fresh.json"
    static_quote = machine_repo / "fixtures" / "token-A_good_fresh.bin"
    static_session_nonce = quote_bound_nonce(static_quote)

    case_specs = [
        (1, "positive-path", positive, 25000, None),
        (2, "permit-reference-failure", positive, 25000, FIXED_BAD_PERMIT_DIGEST),
        (3, "mandate-spend-gate-failure", over_limit, 75000, None),
        (4, "outcome-digest-representation-failure", positive, 25000, None),
        (5, "freshness-failure-replayed-quote", positive, 25000, None),
    ]
    summaries: list[dict[str, Any]] = []
    case_one_quote: dict[str, Any] | None = None
    case_one_qual: str | None = None
    fixed_capsule_timestamp = started_at

    for case_id, slug, orprg_case, amount, bad_permit_digest in case_specs:
        case_dir = args.out / "cases" / f"case-{case_id:02d}-{slug}"
        case_dir.mkdir(parents=True)
        receipt_core = orprg_case["permit_receipt"]["receipt_core"]
        receipt_digest = json_digest(receipt_core)
        mandate_digest = json_digest(mm_action)
        authorization = {
            "permit_receipt_digest": {
                "type": "PermitReceipt",
                "digest_alg": "SHA-256",
                "digest": bad_permit_digest or receipt_digest,
            },
            "machine_mandate_digest": {
                "type": "MachineMandate",
                "digest_alg": "SHA-256",
                "digest": mandate_digest,
            },
        }
        action_digest = orprg_case["permit_receipt"]["receipt_core"]["action_digest"]
        capsule = emit(
            action_id="vienna-interop-2026-001",
            action_type="decide",
            operator="tyche-rehearsal",
            developer="deliverable-b-runner@v0.1",
            timestamp=fixed_capsule_timestamp,
            effect=EffectRecord(
                status="confirmed",
                type="payment",
                request_digest=action_digest,
                response_digest=response_digest,
                effect_attestation="runtime_claimed",
                authorization=authorization,
            ),
        )
        class_one = verify(capsule)
        require(class_one.ok, f"case {case_id}: emitted Capsule failed Class-1 verification")
        capsule_payload = json_bytes(capsule)
        statement = build_signed_statement(
            capsule_payload,
            alg="EdDSA",
            private_key_pem=cose_private_pem,
            issuer="urn:tyche:rehearsal",
            subject=f"urn:sha256:{capsule['capsule_id']}",
            content_type="application/agent-action-capsule+json",
        )
        parsed = parse_signed_statement(statement, public_key_pem=cose_public_pem)
        require(parsed["signature_verified"] is True, f"case {case_id}: COSE verify failed")
        require(parsed["payload"] == capsule_payload, f"case {case_id}: COSE payload drift")
        (case_dir / "capsule.json").write_bytes(capsule_payload + b"\n")
        (case_dir / "capsule.signed-statement.cose").write_bytes(statement)
        write_json(
            case_dir / "capsule-verification.json",
            {
                "capsule_id": capsule["capsule_id"],
                "class_1_ok": class_one.ok,
                "cose_alg": parsed["alg"],
                "cose_content_type": parsed["content_type"],
                "cose_signature_verified": parsed["signature_verified"],
                "payload_sha256": sha256_bytes(capsule_payload),
                "signed_statement_sha256": sha256_bytes(statement),
            },
        )

        verifier = ScopeAwareVerifier(str(tl_path))
        request = verifier.request()
        presentation = mandate.present_sd(
            sd_full,
            holder_key,
            nonce=request["nonce"],
            aud=request["client_id"],
            reveal={"principal", "swname", "ear_status"},
        )
        parts = presentation.split("~")
        disclosures = [part for part in parts[1:-1] if part]
        holder_binding = parts[-1]
        requested = {
            "action_id": mm_action["action_id"],
            "outcome": mm_action["outcome"],
            "amount": amount,
        }
        mm_result = verifier.verify_scoped(
            presentation,
            issuer_jwk,
            issuer_x5t,
            str(static_ear),
            str(static_quote),
            static_session_nonce,
            requested,
        )
        mm_owner_appraised = bool(
            mm_result["L1_crypto"]
            and mm_result["L2_attested"]
            and mm_result["L3_endorser_role"]
        )
        write_json(
            case_dir / "machine-mandate-evidence.json",
            {
                "classification": CLASSIFICATION,
                "disclosures": disclosures,
                "holder_binding_proof": holder_binding,
                "issuer_jws_preimage": issuer_jws_preimage,
                "issuer_jws_preimage_sha256": issuer_jws_digest,
                "issuer_jwk": issuer_jwk,
                "owner_appraisal_result": {
                    "base_owner_appraised": mm_owner_appraised,
                    "full_scope_verifier_result": mm_result,
                },
                "owner_verifier": {
                    "id": "tyche.machine-mandate.scope-aware-verifier",
                    "runtime_pin": MACHINE_MANDATE_PIN,
                },
                "presentation_sha256": sha256_bytes(presentation.encode("ascii")),
                "presentation_transmitted": presentation,
                "verifier_audience": request["client_id"],
                "verifier_nonce": request["nonce"],
                "fixture_freshness_boundary": (
                    "OID4VP challenge is live per case; inherited L2 runtime evidence is "
                    "the frozen replayed swtpm fixture and is not new-composition evidence"
                ),
            },
        )

        appraisal_ok, appraisal_record = appraise_orprg_permit_receipt(
            orprg_case["carrier"],
            orprg_case["auth_ref"],
            orprg_case["permit_receipt"],
            policy=shared["policy"],
            trust_inputs=shared["trust_inputs"],
            revocation_state=shared["revocation_state"],
            verifier_context=shared["verifier_context"],
            permit_provenance=shared["permit_provenance"],
        )
        write_json(
            case_dir / "orprg-owner-appraisal.json",
            {
                "appraisal_ok": appraisal_ok,
                "appraisal_record": appraisal_record,
                "owner_verifier_id": ORPRG_VERIFIER_ID,
                "source_case": (
                    "mandate-over-limit" if orprg_case is over_limit else "positive"
                ),
            },
        )
        binding = verify_permitreceipt_mandate(
            capsule,
            receipt_core,
            mm_action,
            permit_receipt_appraised=appraisal_ok,
            machine_mandate_appraised=mm_owner_appraised,
        )
        action_gate = machine_mandate_action_hash_gate(mm_action, mm_profile["action_hash"])
        spend_gate = machine_mandate_spend_gate(
            orprg_case["permit_receipt"],
            mm_profile["scope_max_spend_minor"],
        )
        gates, first_reject = sequential_gates(binding["gates"] + [action_gate, spend_gate])

        attestation: list[dict[str, str]] = []
        verifier_nonce = hashlib.sha256(
            f"{started_at}|case={case_id}|aep-verifier".encode()
        ).hexdigest()[:32]
        transcript, qual = qualification(capsule["capsule_id"], response_digest, verifier_nonce)
        write_json(
            case_dir / "aep" / "qualification.json",
            {
                "extra_data_hex": qual,
                "extra_data_semantics": "UTF-8 bytes of this 64-character lowercase hex value",
                "response_digest_unprefixed": response_digest,
                "transcript": transcript,
                "transcript_sha256": qual,
                "verifier_nonce": verifier_nonce,
            },
        )

        if first_reject is not None:
            attestation = [
                gate_record(
                    "attestation qualifying-data (extraData) byte comparison",
                    "not reached",
                    f"short-circuited after {first_reject}",
                ),
                gate_record(
                    "attestation PCR comparison",
                    "not reached",
                    f"short-circuited after {first_reject}",
                ),
            ]
        elif case_id in (1, 4):
            quote = make_tpm_quote(
                response_digest=response_digest,
                qualifying_data_hex=qual,
                case_dir=case_dir,
                commands=commands,
            )
            check = check_quote(
                quote=quote,
                qualifying_data_hex=qual,
                case_dir=case_dir,
                commands=commands,
                name=f"case-{case_id:02d}-checkquote",
                expect_success=True,
            )
            expected_raw = pcr_fold_raw(response_digest)
            require(
                expected_raw.encode("ascii") in check.stdout.lower(),
                f"case {case_id}: quoted PCR does not contain expected raw-byte fold",
            )
            attestation.append(
                gate_record(
                    "attestation qualifying-data (extraData) byte comparison",
                    "PASS",
                    "offline tpm2_checkquote accepted the current transcript digest bytes",
                )
            )
            if case_id == 1:
                attestation.append(
                    gate_record(
                        "attestation PCR comparison",
                        "PASS",
                        "quoted PCR16 equals sha256(zeros32 || bytes.fromhex(response_digest))",
                    )
                )
                case_one_quote = quote
                case_one_qual = qual
            else:
                wrong = pcr_fold_ascii(response_digest)
                require(wrong != expected_raw, "ASCII and raw-byte PCR folds unexpectedly equal")
                attestation.append(
                    gate_record(
                        "attestation PCR comparison",
                        "DENY",
                        "mutated adapter computed sha256(zeros32 || utf8(hex)); "
                        "application verifier recomputed from 32 raw bytes",
                    )
                )
                first_reject = "attestation PCR comparison"
                write_json(
                    case_dir / "aep" / "representation-mutation.json",
                    {
                        "correct_raw_byte_fold": expected_raw,
                        "incorrect_ascii_hex_fold": wrong,
                        "sole_injected_mutation": (
                            "PCR fold consumes 64 UTF-8 hex characters instead of 32 raw bytes"
                        ),
                    },
                )
        else:
            require(case_id == 5, f"unexpected attestation path for case {case_id}")
            require(case_one_quote is not None and case_one_qual is not None, "case-1 quote missing")
            require(qual != case_one_qual, "case-5 fresh challenge did not change qualifying data")
            replay_dir = case_dir / "aep" / "replayed-quote"
            replay_dir.mkdir(parents=True)
            replay_quote: dict[str, Any] = {}
            for key in ("ak_pub", "pcr_bin", "quote_msg", "quote_sig"):
                src = Path(case_one_quote[key])
                dst = replay_dir / src.name
                shutil.copy2(src, dst)
                replay_quote[key] = dst
            check_quote(
                quote=replay_quote,
                qualifying_data_hex=qual,
                case_dir=case_dir,
                commands=commands,
                name="case-05-checkquote-replayed-under-fresh-qual",
                expect_success=False,
            )
            attestation = [
                gate_record(
                    "attestation qualifying-data (extraData) byte comparison",
                    "DENY",
                    "previous valid quote rejected under the current fresh transcript digest",
                ),
                gate_record(
                    "attestation PCR comparison",
                    "not reached",
                    "short-circuited after qualifying-data mismatch",
                ),
            ]
            first_reject = "attestation qualifying-data (extraData) byte comparison"
            write_json(
                case_dir / "aep" / "replay-mutation.json",
                {
                    "current_extra_data_hex": qual,
                    "previous_extra_data_hex": case_one_qual,
                    "sole_injected_mutation": (
                        "quote from previous verifier nonce replayed under current fresh challenge"
                    ),
                },
            )

        expected_first = {
            1: None,
            2: "permit_receipt_reference_bound",
            3: "machine_mandate_spend",
            4: "attestation PCR comparison",
            5: "attestation qualifying-data (extraData) byte comparison",
        }[case_id]
        require(first_reject == expected_first, f"case {case_id}: first rejection drift")
        effect_commit_count = 1 if first_reject is None else 0
        if effect_commit_count:
            write_json(
                case_dir / "external-effect-commit-marker.json",
                {
                    "classification": CLASSIFICATION,
                    "count": 1,
                    "kind": "synthetic sandbox marker; no live payment occurred",
                },
            )
        case_summary = {
            "case_id": case_id,
            "case_name": slug,
            "capsule_id": capsule["capsule_id"],
            "classification": CLASSIFICATION,
            "external_effect_commit_count": effect_commit_count,
            "first_rejecting_gate": first_reject,
            "gates": gates + attestation,
            "outcome": "PASS" if first_reject is None else "EXPECTED FAIL-CLOSED",
        }
        write_json(case_dir / "case-result.json", case_summary)
        summaries.append(case_summary)

    expected_commits = [1, 0, 0, 0, 0]
    require(
        [item["external_effect_commit_count"] for item in summaries] == expected_commits,
        "external-effect commit-count vector drift",
    )
    write_json(args.out / "case-summary.json", summaries)
    run_record = {
        "archive_created_after_record": True,
        "case_count": len(summaries),
        "classification": CLASSIFICATION,
        "completed_at": utc_now(),
        "final_evidence_authorized": False,
        "environment": {
            "platform": platform.platform(),
            "python": sys.version,
        },
        "input_pins": {
            "aac_rehearsal": observed_heads["aac"],
            "aep": observed_heads["aep"],
            "machine_mandate_runtime": MACHINE_MANDATE_PIN,
            "manifest_sha256": MANIFEST_SHA256,
            "scitt_cose_rehearsal": observed_heads["scitt_cose"],
        },
        "machine_mandate_runtime_hashes": machine_hashes,
        "orprg_release_assets": asset_records,
        "result": "PASS — all five rehearsal cases matched the frozen fail-closed expectations",
        "runner_repository_commit": runner_repository_commit,
        "runner_source_sha256": runner_source_sha256,
        "started_at": started_at,
    }
    write_json(args.out / "run-record.json", run_record)
    (args.out / "CLASSIFICATION.txt").write_text(CLASSIFICATION + "\n", encoding="utf-8")
    hash_lines = evidence_hashes(args.out)
    (args.out / "file-hashes.sha256").write_text("\n".join(hash_lines) + "\n", encoding="utf-8")
    archive, archive_digest = archive_evidence(args.out)
    return {
        **run_record,
        "archive": str(archive),
        "archive_sha256": archive_digest,
        "evidence_directory": str(args.out),
    }


def main(argv: list[str] | None = None) -> int:
    try:
        result = run(parse_args(argv))
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL-CLOSED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
