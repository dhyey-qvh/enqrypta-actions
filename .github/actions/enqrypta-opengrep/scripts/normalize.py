#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import defaultdict
from pathlib import Path

SCHEMA_VERSION = "3.0"
SITE_KEY_VERSION = "site-v2"
FINDING_KINDS = {"inventory", "misuse"}
CWE_PATTERN = re.compile(r"^CWE-[1-9][0-9]{0,4}$")
# Evidence fields a rule may declare in ``metadata.parameters``. A declared
# parameter that the match does not resolve to a literal is reported in
# ``unresolved_parameters`` instead of being guessed.
EVIDENCE_PARAMETERS = {
    "key_size_bits",
    "group_order_bits",
    "parameter_set",
    "mode",
    "padding",
    "iv_length_bits",
    "tag_length_bits",
    "protocol",
}
# Static evidence a rule may set in metadata (e.g. iv_generation: hardcoded),
# for APIs where the call itself fixes the value (Go ``cipher.NewGCM``, Rust
# ``Aes256Gcm``).
STATIC_EVIDENCE = {"iv_generation", "protocol", "mode", "padding", "parameter_set"}
STATIC_INTEGER_EVIDENCE = {"key_size_bits", "tag_length_bits", "iv_length_bits"}
KNOWN_MODES = {
    "ECB", "CBC", "CFB", "CFB8", "OFB", "CTR", "GCM", "CCM", "EAX", "SIV", "OCB",
    "GCM-SIV", "XTS",
}
KNOWN_PADDINGS = {
    "OAEP": "OAEP",
    "PKCS1OAEP": "OAEP",
    "PKCS1V15": "PKCS1v15",
    "PKCS1": "PKCS1v15",
    "PSS": "PSS",
    "PKCS1PSS": "PSS",
    "NOPADDING": "NoPadding",
}
CIPHER_FAMILIES = {
    "aes", "des", "des3", "chacha20", "camellia", "aria", "sm4", "bf", "blowfish", "rc2",
    "rc4", "cast5", "idea", "seed",
}
PQC_PARAMETER_CONSTANT = re.compile(
    r"(?i)^(?P<family>ml_?kem|ml_?dsa)_?(?P<level>[0-9]+)$"
)
DIGIT_BOUNDARY = re.compile(r"(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])")
CONSTANT_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./+-]{0,63}$")
# Decimal or hex integer literals, with Java/C (L, U) or Rust (u32, _usize) suffixes.
INTEGER_PATTERN = re.compile(
    r"^(?P<digits>0[xX][0-9a-fA-F_]+|[0-9][0-9_]*)"
    r"(?:[lLuU]*|_?[uUiI](?:8|16|32|64|128|size))$"
)
PROTOCOL_PATTERNS = (
    (re.compile(r"(?i)SSL[_ v-]?3"), "SSL 3.0"),
    (re.compile(r"(?i)TLS[_ v-]?1[._]?3|TLS13"), "TLS 1.3"),
    (re.compile(r"(?i)TLS[_ v-]?1[._]?2|TLS12"), "TLS 1.2"),
    (re.compile(r"(?i)TLS[_ v-]?1[._]?1|TLS11"), "TLS 1.1"),
    (re.compile(r"(?i)TLS[_ v-]?1(?:[._]?0)?(?![.0-9]|_[0-9])|TLS10"), "TLS 1.0"),
)

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
    "P256": 256,
    "P384": 384,
    "P521": 521,
    "SECP256R1": 256,
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


def _strip_literal(raw: str) -> str | None:
    """Return the literal value of a metavariable, or None if it is not a literal."""
    value = raw.strip()
    for prefix in ("br", "rb", "b", "r", "u", "f"):
        if (
            len(value) > len(prefix) + 1
            and value[: len(prefix)].lower() == prefix
            and value[len(prefix)] in "'\"`"
        ):
            if "f" in prefix:
                return None  # interpolated string, not a literal
            value = value[len(prefix):]
            break
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"`":
        if value[0] == "`" and "${" in value:
            return None  # JS template with substitutions
        return value[1:-1]
    if INTEGER_PATTERN.match(value):
        return value
    return None


def metavariable_literal(result: dict, name: str) -> str | None:
    """Literal value captured by ``$NAME``, using Opengrep constant propagation."""
    metavar = ((result.get("extra") or {}).get("metavars") or {}).get(name)
    if not isinstance(metavar, dict):
        return None
    propagated = metavar.get("propagated_value") or {}
    for raw in (propagated.get("svalue_abstract_content"), metavar.get("abstract_content")):
        if isinstance(raw, str):
            literal = _strip_literal(raw)
            if literal is not None:
                return literal
    return None


def metavariable_constant(result: dict, name: str) -> str | None:
    """Final identifier of a non-literal capture: ``ec.SECP384R1()`` -> ``SECP384R1``.

    Used only where the identifier names an enumerated constant (curve, mode,
    protocol version) that is then checked against a known set.
    """
    metavar = ((result.get("extra") or {}).get("metavars") or {}).get(name)
    raw = metavar.get("abstract_content") if isinstance(metavar, dict) else None
    if not isinstance(raw, str):
        return None
    value = raw.strip().lstrip("&").strip()
    if value.endswith(")") and "(" in value:
        value = value[: value.index("(")].strip()
    value = re.split(r"\.|::", value)[-1]
    return value if CONSTANT_NAME_PATTERN.match(value) else None


def _integer(value: str | None) -> int | None:
    match = INTEGER_PATTERN.match(value) if value is not None else None
    if match is None:
        return None
    digits = match.group("digits").replace("_", "")
    if digits[:2].lower() == "0x":
        if len(digits) == 2:
            return None
        number = int(digits, 16)
    elif len(digits) > 1 and digits[0] == "0":
        return None  # octal in Java/C/JS, decimal in Rust: ambiguous, leave unresolved
    else:
        number = int(digits, 10)
    return number if number > 0 else None


def _token(value: str | None) -> str | None:
    return value if value is not None and TOKEN_PATTERN.match(value) else None


def _protocol(value: str | None) -> str | None:
    if value is None:
        return None
    for pattern, protocol in PROTOCOL_PATTERNS:
        if pattern.search(value):
            return protocol
    return None


def _group_order(value: str) -> int | None:
    return GROUP_ORDER_BITS.get(value.upper().replace("_", "").replace("-", ""))


def _mode(value: str | None) -> str | None:
    if value is None:
        return None
    mode = value.upper().removeprefix("MODE_").replace("_", "-")
    return mode if mode in KNOWN_MODES else None


def _cipher_name(value: str) -> dict:
    """Evidence from an OpenSSL-style cipher name, e.g. ``aes-256-gcm``.

    ``parameter_set`` is the cipher and key size only (``AES-256``): the API
    derives asset identity from it, and the mode is not part of what an asset
    is. The mode is reported in ``mode``.
    """
    name = value.strip().lower()
    parts = name.split("-")
    if not TOKEN_PATTERN.match(name) or parts[0] not in CIPHER_FAMILIES:
        return {}
    evidence: dict = {}
    sizes = [int(part) for part in parts[1:] if part in {"128", "192", "256"}]
    if sizes:
        evidence["key_size_bits"] = sizes[0]
        evidence["parameter_set"] = f"{parts[0].upper()}-{sizes[0]}"
    mode = _mode(parts[-1]) if len(parts) > 1 else None
    if mode:
        evidence["mode"] = mode
    return evidence


def parameter_evidence(result: dict, algorithm: str) -> dict:
    """Evidence resolved from rule metavariables; literal values only."""
    evidence: dict = {}
    transformation = metavariable_literal(result, "$TRANSFORMATION")
    if transformation:
        parts = [part.strip() for part in transformation.split("/")]
        if parts and parts[0]:
            pattern = EXACT_ALGORITHM_PATTERNS.get(algorithm)
            exact = pattern.search(parts[0]) if pattern else None
            if exact:
                evidence["parameter_set"] = exact.group(0)
        # JCA spells RSA as "RSA/ECB/<padding>"; that ECB is a placeholder, not a mode.
        if len(parts) > 1 and _token(parts[1]) and algorithm != "RSA":
            evidence["mode"] = parts[1].upper()
        if len(parts) > 2 and _token(parts[2]):
            evidence["padding"] = parts[2]

    key_bits = _integer(metavariable_literal(result, "$KEY_SIZE"))
    key_bytes = _integer(metavariable_literal(result, "$KEY_BYTES"))
    if key_bits or key_bytes:
        evidence["key_size_bits"] = key_bits or key_bytes * 8

    cipher = metavariable_literal(result, "$CIPHER")
    if cipher is None:
        # openssl Cipher::aes_256_gcm(), ring AES_256_GCM, RustCrypto Aes256Gcm
        constant = metavariable_constant(result, "$CIPHER")
        cipher = DIGIT_BOUNDARY.sub("-", constant.replace("_", "-")) if constant else None
    if cipher:
        evidence.update(_cipher_name(cipher))

    curve = _token(metavariable_literal(result, "$CURVE"))
    if curve is None:
        constant = metavariable_constant(result, "$CURVE")
        curve = constant if constant and _group_order(constant) else None
    if curve:
        evidence["parameter_set"] = curve
        if _group_order(curve):
            evidence["group_order_bits"] = _group_order(curve)

    parameter_set = _token(metavariable_literal(result, "$PARAMETER_SET"))
    if parameter_set is None:
        constant = metavariable_constant(result, "$PARAMETER_SET")  # BC ml_kem_768
        match = PQC_PARAMETER_CONSTANT.match(constant) if constant else None
        if match:
            family = "ML-KEM" if match.group("family").upper().endswith("KEM") else "ML-DSA"
            parameter_set = f"{family}-{match.group('level')}"
    if parameter_set:
        evidence["parameter_set"] = parameter_set

    mode = _mode(metavariable_literal(result, "$MODE") or metavariable_constant(result, "$MODE"))
    if mode:
        evidence["mode"] = mode
    padding = _token(metavariable_literal(result, "$PADDING"))
    if padding is None:
        constant = metavariable_constant(result, "$PADDING")
        padding = KNOWN_PADDINGS.get(constant.upper().replace("_", "")) if constant else None
    if padding:
        evidence["padding"] = padding

    for prefix, field in (("IV", "iv_length_bits"), ("TAG", "tag_length_bits")):
        bits = _integer(metavariable_literal(result, f"${prefix}_BITS"))
        byte_count = _integer(metavariable_literal(result, f"${prefix}_BYTES"))
        if bits or byte_count:
            evidence[field] = bits or byte_count * 8

    protocol = _protocol(
        metavariable_literal(result, "$PROTOCOL") or metavariable_constant(result, "$PROTOCOL")
    )
    if protocol:
        evidence["protocol"] = protocol
    return evidence


def _finding_kind(rule_id: str, metadata: dict) -> str:
    kind = str(metadata.get("finding_kind", "inventory"))
    if kind not in FINDING_KINDS:
        raise ValueError(f"{rule_id}: unknown finding_kind {kind!r}")
    if rule_id.startswith("enqrypta.misuse.") != (kind == "misuse"):
        raise ValueError(f"{rule_id}: enqrypta.misuse.* rules must use finding_kind 'misuse'")
    return kind


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

    rule_id = str(metadata["enqrypta_rule_id"])
    finding_kind = _finding_kind(rule_id, metadata)
    finding = {
        "rule_id": rule_id,
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
    # Rule metadata is the rule author's statement about the API and overrides
    # values guessed from the matched name.
    for field in sorted(STATIC_EVIDENCE):
        if field in metadata:
            raw_value = str(metadata[field])
            value = _protocol(raw_value) if field == "protocol" else _token(raw_value)
            if value is None:
                raise ValueError(f"{rule_id}: metadata {field} must be a short token")
            evidence[field] = value
    for field in sorted(STATIC_INTEGER_EVIDENCE):
        if field in metadata:
            value = metadata[field]
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{rule_id}: metadata {field} must be a positive integer")
            evidence[field] = value
    if "parameter_set" in metadata:
        evidence.pop("group_order_bits", None)
        static_order = _group_order(evidence["parameter_set"])
        if static_order:
            evidence["group_order_bits"] = static_order
    evidence.update(parameter_evidence(result, algorithm))
    finding["assessment_evidence"] = evidence

    finding["finding_kind"] = finding_kind
    if finding_kind == "misuse":
        cwe = str(metadata.get("cwe", ""))
        if not CWE_PATTERN.match(cwe):
            raise ValueError(f"{rule_id}: misuse rules require metadata cwe like CWE-327")
        finding["cwe"] = cwe
    declared = metadata.get("parameters") or []
    unknown = set(declared) - EVIDENCE_PARAMETERS
    if unknown:
        raise ValueError(f"{rule_id}: unknown declared parameters {sorted(unknown)}")
    unresolved = sorted(field for field in set(declared) if field not in evidence)
    if unresolved:
        finding["unresolved_parameters"] = unresolved
    return finding


def site_text(result: dict) -> str:
    """Whitespace-normalized matched text; hashed into the site key, never sent."""
    return " ".join(matched_span(result).split())


def assign_site_keys(results: list[dict], findings: list[dict]) -> None:
    """Give each finding a site key that survives line shifts.

    The key covers finding kind, file, normalized matched text and the
    occurrence ordinal of that text in the file, so identical matches in one
    file stay distinct while edits elsewhere do not change the key.
    """
    order = sorted(
        range(len(findings)),
        key=lambda i: (
            findings[i]["file_path"],
            int(results[i]["start"].get("line", 0)),
            int(results[i]["start"].get("col", 0)),
            findings[i]["rule_id"],
        ),
    )
    ordinals: dict[tuple[str, str, str], int] = defaultdict(int)
    for index in order:
        finding = findings[index]
        text = site_text(results[index]) or finding["rule_id"]
        group = (finding["finding_kind"], finding["file_path"], text)
        raw = "\0".join(
            [SITE_KEY_VERSION, *group, str(ordinals[group])]
        )
        finding["site_key"] = hashlib.sha256(raw.encode()).hexdigest()
        ordinals[group] += 1


def git_blob_sha(path: Path) -> str | None:
    """Git blob SHA-1 of a file, identical to ``git hash-object``."""
    try:
        content = path.read_bytes()
    except OSError:
        return None
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()


def assign_file_blob_shas(findings: list[dict], workspace: Path) -> None:
    cache: dict[str, str | None] = {}
    for finding in findings:
        path = finding["file_path"]
        if path not in cache:
            cache[path] = git_blob_sha(workspace / path)
        if cache[path]:
            finding["file_blob_sha"] = cache[path]


def rules_digest(rules: Path) -> str:
    """SHA-256 over every rule file (path and bytes) under ``rules``."""
    files = (
        [rules]
        if rules.is_file()
        else sorted(p for p in rules.rglob("*") if p.suffix in {".yml", ".yaml"})
    )
    if not files:
        raise ValueError(f"no rule files found under {rules}")
    digest = hashlib.sha256()
    for path in files:
        relative = path.name if rules.is_file() else path.relative_to(rules).as_posix()
        digest.update(relative.encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--scanner-version", required=True)
    parser.add_argument("--rules", help="rule file or directory used for the scan")
    args = parser.parse_args()

    workspace = Path(os.environ["GITHUB_WORKSPACE"])
    raw = json.loads(Path(args.input).read_text())
    results = raw.get("results", [])
    findings = [normalize_result(result, workspace) for result in results]
    assign_site_keys(results, findings)
    assign_file_blob_shas(findings, workspace.resolve())
    output = {
        "schema_version": SCHEMA_VERSION,
        "scanner_version": args.scanner_version,
        "findings": findings,
    }
    if args.rules:
        output["rules_digest"] = rules_digest(Path(args.rules))
    Path(args.output).write_text(json.dumps(output, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
