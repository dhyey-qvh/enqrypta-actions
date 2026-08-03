#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

REQUIRED_METADATA = {
    "algorithm",
    "primitive",
    "usage",
    "quantum_risk",
    "target_algorithm",
    "confidence",
}
SEVERITY = {"ERROR": "high", "WARNING": "med", "INFO": "low"}
GENERIC_ALGORITHMS = {"RSA", "ECDH", "ECDSA", "PQC-KEM", "PQC-SIGNATURE"}
EXACT_ALGORITHM_PATTERN = re.compile(
    r"(?i)\b(?:"
    r"RSA[-_ ]?(?:1024|2048|3072|4096)|"
    r"DH|ECDH|ECDSA|X25519|X448|Ed25519|Ed448|"
    r"prime256v1Sig|secp384r1Sig|secp521r1Sig|SM2Sig|"
    r"prime256v1|secp256k1|secp384r1|secp521r1|SM2|"
    r"ML[-_ ]?KEM[-_ ]?(?:512|768|1024)|ML[-_ ]?DSA[-_ ]?(?:44|65|87)|"
    r"BIKE[-_ ]?L[135]|ClassicMcEliece\w+|FrodoKEM\w+|"
    r"HQC[-_ ]?(?:128|192|256)|Kyber[-_ ]?(?:512|768|1024)|"
    r"NtruPrimeSntrup761|sntrup761|"
    r"CROSS\w+|Dilithium[235]|Falcon(?:512|1024)|Mayo[1235]|SPHINCS\w+|UOV\w+"
    r")\b"
)
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


def fingerprint(finding: dict) -> str:
    canonical = "\0".join(
        [
            finding["rule_id"],
            finding["file_path"],
            str(finding["line_start"]),
            str(finding["line_end"]),
            finding["algorithm"],
            finding["usage"],
        ]
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def normalize_result(result: dict) -> dict:
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") or {}
    missing = REQUIRED_METADATA - metadata.keys()
    if missing:
        raise ValueError(f"{result.get('check_id')}: missing metadata {sorted(missing)}")

    algorithm = str(metadata["algorithm"])
    if algorithm.upper() in GENERIC_ALGORITHMS:
        match = EXACT_ALGORITHM_PATTERN.search(str(extra.get("lines") or ""))
        if match:
            algorithm = match.group(0)

    finding = {
        "rule_id": str(result["check_id"]),
        "file_path": str(result["path"]),
        "line_start": int(result["start"]["line"]),
        "line_end": int(result["end"]["line"]),
        "language": extra.get("metadata", {}).get("language"),
        "algorithm": algorithm,
        "primitive": str(metadata["primitive"]),
        "usage": str(metadata["usage"]),
        "severity": SEVERITY.get(str(extra.get("severity", "WARNING")).upper(), "med"),
        "quantum_risk": str(metadata["quantum_risk"]),
        "target_algorithm": str(metadata["target_algorithm"]),
        "confidence": float(metadata["confidence"]),
    }
    evidence = {
        "parameter_set": algorithm,
        "cryptographic_role": str(metadata["primitive"]),
    }
    key_size = KEY_SIZE_PATTERN.match(algorithm)
    if key_size:
        evidence["key_size_bits"] = int(key_size.group(1))
    group_order = GROUP_ORDER_BITS.get(
        algorithm.upper().replace("_", "").replace("-", "")
    )
    if group_order:
        evidence["group_order_bits"] = group_order
    finding["assessment_evidence"] = evidence
    finding["fingerprint"] = fingerprint(finding)
    return finding


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--scanner-version", required=True)
    args = parser.parse_args()

    raw = json.loads(Path(args.input).read_text())
    output = {
        "schema_version": "1.0",
        "scanner_version": args.scanner_version,
        "commit_sha": __import__("os").environ["GITHUB_SHA"],
        "findings": [normalize_result(result) for result in raw.get("results", [])],
    }
    Path(args.output).write_text(json.dumps(output, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
