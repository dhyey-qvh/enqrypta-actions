#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

REQUIRED_METADATA = {
    "enqrypta_rule_id",
    "algorithm",
    "primitive",
    "usage",
    "confidence",
}
SEVERITY = {"ERROR": "high", "WARNING": "med", "INFO": "low"}
EXACT_ALGORITHM_PATTERNS = {
    "RSA": re.compile(r"(?i)\bRSA[-_ ]?(?:1024|2048|3072|4096)\b"),
    "ECDH": re.compile(
        r"(?i)\b(?:DH|ECDH|X25519|X448|prime256v1|secp384r1|secp521r1|SM2)\b"
    ),
    "ECDSA": re.compile(
        r"(?i)\b(?:ECDSA|Ed25519|Ed448|secp256k1|prime256v1Sig|"
        r"secp384r1Sig|secp521r1Sig|SM2Sig)\b"
    ),
    "AES": re.compile(r"(?i)\bAES[-_ ]?(?:128|192|256)\b"),
    "ML-KEM": re.compile(r"(?i)\bML[-_ ]?KEM[-_ ]?(?:512|768|1024)\b"),
    "ML-DSA": re.compile(r"(?i)\bML[-_ ]?DSA[-_ ]?(?:44|65|87)\b"),
    "PQC-KEM": re.compile(
        r"(?i)\b(?:BIKE[-_ ]?L[135]|ClassicMcEliece\w+|FrodoKEM\w+|"
        r"HQC[-_ ]?(?:128|192|256)|Kyber[-_ ]?(?:512|768|1024)|"
        r"NtruPrimeSntrup761|sntrup761)\b"
    ),
    "PQC-SIGNATURE": re.compile(
        r"(?i)\b(?:CROSS\w+|Dilithium[235]|Falcon(?:512|1024)|Mayo[1235]|"
        r"SPHINCS\w+|UOV\w+)\b"
    ),
}
KEY_SIZE_PATTERN = re.compile(r"(?i)^(?:RSA|AES)[-_ ]?(\d+)$")
GROUP_ORDER_BITS = {
    "PRIME256V1": 256,
    "SECP256K1": 256,
    "SECP384R1": 384,
    "SECP521R1": 521,
    "X25519": 252,
    "X448": 446,
    "ED25519": 252,
    "ED448": 446,
}


def normalize_path(path: str, workspace: Path) -> str:
    workspace = workspace.resolve()
    normalized = path.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", normalized):
        raise ValueError(f"finding path escapes GITHUB_WORKSPACE: {path}")
    candidate = Path(normalized)
    if not candidate.is_absolute():
        candidate = workspace / candidate
    try:
        relative = candidate.resolve().relative_to(workspace).as_posix()
    except ValueError as exc:
        raise ValueError(f"finding path escapes GITHUB_WORKSPACE: {path}") from exc
    if relative in {"", "."}:
        raise ValueError(f"finding path must identify a repository file: {path}")
    return relative


def matched_span(result: dict) -> str:
    lines = str((result.get("extra") or {}).get("lines") or "").splitlines()
    if not lines:
        return ""
    start_column = max(int(result["start"].get("col", 1)) - 1, 0)
    end_column = max(int(result["end"].get("col", len(lines[-1]) + 1)) - 1, 0)
    if len(lines) == 1:
        return lines[0][start_column:end_column]
    return "\n".join([lines[0][start_column:], *lines[1:-1], lines[-1][:end_column]])


def normalize_result(result: dict, workspace: Path | None = None) -> dict:
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") or {}
    missing = REQUIRED_METADATA - metadata.keys()
    if missing:
        raise ValueError(f"{result.get('check_id')}: missing metadata {sorted(missing)}")

    algorithm = str(metadata["algorithm"]).upper()
    pattern = EXACT_ALGORITHM_PATTERNS.get(algorithm)
    exact_match = pattern.search(matched_span(result)) if pattern else None
    workspace = workspace or Path(os.environ["GITHUB_WORKSPACE"])

    finding = {
        "rule_id": str(metadata["enqrypta_rule_id"]),
        "file_path": normalize_path(str(result["path"]), workspace),
        "line_start": int(result["start"]["line"]),
        "line_end": int(result["end"]["line"]),
        "language": extra.get("metadata", {}).get("language"),
        "algorithm": algorithm,
        "primitive": str(metadata["primitive"]),
        "usage": str(metadata["usage"]),
        "severity": SEVERITY.get(str(extra.get("severity", "WARNING")).upper(), "med"),
        "confidence": float(metadata["confidence"]),
    }
    evidence = {
        "cryptographic_role": str(metadata["primitive"]),
    }
    if exact_match:
        evidence["parameter_set"] = exact_match.group(0)
    key_size = KEY_SIZE_PATTERN.match(exact_match.group(0)) if exact_match else None
    if key_size:
        evidence["key_size_bits"] = int(key_size.group(1))
    group_order = GROUP_ORDER_BITS.get(
        exact_match.group(0).upper().replace("_", "").replace("-", "")
        if exact_match
        else ""
    )
    if group_order:
        evidence["group_order_bits"] = group_order
    finding["assessment_evidence"] = evidence
    return finding


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--scanner-version", required=True)
    args = parser.parse_args()

    raw = json.loads(Path(args.input).read_text())
    output = {
        "schema_version": "2.0",
        "scanner_version": args.scanner_version,
        "findings": [normalize_result(result) for result in raw.get("results", [])],
    }
    Path(args.output).write_text(json.dumps(output, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
