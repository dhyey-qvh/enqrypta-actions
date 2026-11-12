#!/usr/bin/env python3
"""Classify crypto artifacts (PEM blocks, SSH keys, JWTs) with the EnQrypta classification API.

The artifact rules only locate a value. This module extracts that value from
the raw Opengrep result, sends it to the API and fills the finding's algorithm,
key size and provenance from the API's parsed ``inventory``. Model answers are
never requested: the request carries no questions, so every fact comes from the
API's parser.

The extracted value is sent to the API and is never written to the findings
payload; only its SHA-256 is kept.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.error
import urllib.request

USER_AGENT = "EnQrypta-GitHub-Action/7.0"  # the API's CDN rejects clients without one
TIMEOUT_SECONDS = 10
MAX_ARTIFACT_BYTES = 16_384
MAX_REQUESTS = 200
MAX_CONSECUTIVE_FAILURES = 3

PLACEHOLDER_ALGORITHM = "UNCLASSIFIED"
PEM_LABEL = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----")
# What a PEM label states on its own, used when the API gives no answer.
PRIVATE_KEY_LABEL_ALGORITHMS = {
    "RSA PRIVATE KEY": "RSA",
    "EC PRIVATE KEY": "ECDSA",
    "DSA PRIVATE KEY": "DSA",
}
QUOTE_PREFIX = re.compile(r"""^[bBrRuU]{0,2}["'`]""")
QUOTE_SUFFIX = re.compile(r"""["'`]\s*[+,;\\.)\]]*$""")
CURVE_ORDER_BITS = {"P-256": 256, "P-384": 384, "P-521": 521}
JOSE_CURVES = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}
PQC_PARAMETER_SET = re.compile(r"^(ML-KEM|ML-DSA)-[0-9]+$")


def artifact_text(kind: str, matched: str) -> str:
    """The value to classify, recovered from the matched source text."""
    if kind == "pem":
        # A PEM block in code is usually a quoted, possibly concatenated string
        # with escaped newlines. Base64 never contains quotes, so stripping
        # them and the concatenation around them is lossless.
        lines = []
        for line in matched.replace("\\r", "").replace("\\n", "\n").splitlines():
            # Suffix first, so a line holding only a closing quote and "+" vanishes.
            line = QUOTE_PREFIX.sub("", QUOTE_SUFFIX.sub("", line.strip())).strip()
            if line:
                lines.append(line)
        return "\n".join(lines)
    if kind == "jwt":
        # The signing algorithm is in the header; the claims and signature are
        # not needed, so a usable bearer token never leaves the runner.
        return matched.split(".", 1)[0] + ".."
    return matched.strip()


class Classifier:
    """Calls the classification API, once per distinct artifact."""

    def __init__(self, url: str):
        self.url = url.rstrip("/") + "/decide"
        self.cache: dict[str, dict | None] = {}
        self.requests = 0
        self.failures = 0
        self.consecutive_failures = 0
        self.skipped = 0

    def classify(self, artifact: str) -> dict | None:
        digest = hashlib.sha256(artifact.encode()).hexdigest()
        if digest not in self.cache:
            self.cache[digest] = self._request(artifact)
        return self.cache[digest]

    def _request(self, artifact: str) -> dict | None:
        if (
            len(artifact.encode()) > MAX_ARTIFACT_BYTES
            or self.requests >= MAX_REQUESTS
            or self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES
        ):
            self.skipped += 1
            return None
        self.requests += 1
        body = {"engine": "product", "state": {"artifact": artifact}, "questions": {}}
        request = urllib.request.Request(
            self.url,
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                parsed = json.loads(response.read())
            if not isinstance(parsed, dict) or not isinstance(parsed.get("inventory"), dict):
                raise ValueError("response has no inventory")
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            # A classification failure never fails the scan. Includes HTTP
            # errors and the CDN's non-JSON 403 page.
            self.failures += 1
            self.consecutive_failures += 1
            print(f"classification request failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return None
        self.consecutive_failures = 0
        return parsed


def _evidence(response: dict) -> dict:
    evidence = response.get("evidence")
    first = evidence[0] if isinstance(evidence, list) and evidence else None
    return first if isinstance(first, dict) else {}


def interpret(response: dict) -> dict | None:
    """Finding fields for an artifact the API parsed, or None if it could not."""
    inventory = response["inventory"]
    evidence = _evidence(response)
    if inventory.get("source") in (None, "none"):
        return None
    is_certificate = evidence.get("artifact_class") == "certificate"
    key_algorithm = str(inventory.get("key_algorithm") or "").lower()
    signature = str(inventory.get("signature_algorithm") or "").upper()
    fields: dict = {"evidence": {}}

    if inventory.get("source") == "jose_header":
        if signature.startswith(("RS", "PS")):
            fields.update(algorithm="RSA", primitive="signature", usage="signing")
        elif signature in JOSE_CURVES:
            fields.update(algorithm="ECDSA", primitive="signature", usage="signing")
            fields["evidence"]["parameter_set"] = JOSE_CURVES[signature]
        elif signature == "EDDSA":
            fields.update(algorithm="ED25519", primitive="signature", usage="signing")
        elif signature.startswith("HS") and signature[2:] in {"256", "384", "512"}:
            fields.update(algorithm=f"HMAC-SHA{signature[2:]}", primitive="mac", usage="mac")
        else:
            return None
    elif key_algorithm == "rsa":
        fields.update(
            algorithm="RSA",
            primitive="signature" if is_certificate else "asymmetric",
            usage="signing" if is_certificate else "unknown",
        )
    elif key_algorithm == "ec":
        # An EC key can serve ECDSA or ECDH; both are equally quantum-vulnerable.
        fields.update(
            algorithm="ECDSA",
            primitive="signature",
            usage="signing" if is_certificate else "unknown",
        )
        if inventory.get("curve"):
            fields["evidence"]["parameter_set"] = str(inventory["curve"])
    elif key_algorithm == "ed25519":
        fields.update(algorithm="ED25519", primitive="signature", usage="signing")
        fields["evidence"]["parameter_set"] = "Ed25519"
    elif key_algorithm in {"ml-dsa", "ml-kem"}:
        signing = key_algorithm == "ml-dsa"
        fields.update(
            algorithm=key_algorithm.upper(),
            primitive="signature" if signing else "key_establishment",
            usage="signing" if signing else "key_establishment",
        )
        declared = str(evidence.get("declared_algorithm") or "").upper()
        if PQC_PARAMETER_SET.match(declared):
            fields["evidence"]["parameter_set"] = declared
    else:
        return None

    key_bits = inventory.get("key_bits")
    if fields["algorithm"] == "RSA" and isinstance(key_bits, int) and key_bits > 0:
        fields["evidence"]["key_size_bits"] = key_bits
    order = CURVE_ORDER_BITS.get(fields["evidence"].get("parameter_set", ""))
    if order:
        fields["evidence"]["group_order_bits"] = order
    return fields


def provenance(response: dict, artifact: str, *, confirmed: bool) -> dict:
    """Where the classification came from; stored with the finding."""
    inventory = response["inventory"]
    evidence = _evidence(response)
    record = {
        "status": "confirmed" if confirmed else "unconfirmed",
        "source": str(inventory.get("source") or "none"),
        "model_version": str(response.get("model_version") or "unknown"),
        "artifact_sha256": hashlib.sha256(artifact.encode()).hexdigest(),
        "is_private_key": bool(evidence.get("is_private_key")),
        "encrypted": bool(inventory.get("encrypted")),
    }
    for key in ("artifact_class", "container"):
        if isinstance(evidence.get(key), str):
            record[key] = evidence[key]
    strength = evidence.get("evidence_strength")
    if isinstance(strength, int | float) and not isinstance(strength, bool):
        record["evidence_strength"] = max(0.0, min(float(strength), 1.0))
    possible = [str(item) for item in evidence.get("possible_algorithms") or []][:8]
    if possible and not confirmed:
        record["possible_algorithms"] = possible
    return record


def _label_algorithm(artifact: str) -> str | None:
    label = PEM_LABEL.search(artifact)
    return PRIVATE_KEY_LABEL_ALGORITHMS.get(label.group(1)) if label else None


def apply(
    results: list[dict], findings: list[dict], classifier: Classifier | None, matched_span
) -> list[dict]:
    """Complete artifact findings from the API and return the findings to publish.

    - Parsed artifact: the finding gets the algorithm, usage, parameters and
      provenance the API reported.
    - Not parsed, or no answer: an inventory finding is dropped, because an
      unidentified string is not a crypto asset. A private-key finding is kept:
      the PEM label already proves a private key is stored in the repository.
    """
    published = []
    for result, finding in zip(results, findings, strict=True):
        kind = ((result.get("extra") or {}).get("metadata") or {}).get("artifact")
        if not kind:
            published.append(finding)
            continue
        artifact = artifact_text(str(kind), matched_span(result))
        response = classifier.classify(artifact) if classifier else None
        fields = interpret(response) if response else None
        if fields:
            finding.update({k: v for k, v in fields.items() if k != "evidence"})
            finding["assessment_evidence"] = {
                "cryptographic_role": fields["primitive"],
                **fields["evidence"],
            }
        if response:
            finding["classification"] = provenance(response, artifact, confirmed=bool(fields))
            if fields and "evidence_strength" in finding["classification"]:
                if finding["finding_kind"] == "inventory":
                    finding["confidence"] = finding["classification"]["evidence_strength"]
        if finding["algorithm"] == PLACEHOLDER_ALGORITHM:
            continue
        if not fields and finding["finding_kind"] == "misuse":
            finding["algorithm"] = _label_algorithm(artifact) or finding["algorithm"]
        published.append(finding)
    if classifier:
        print(
            f"artifact classification: {classifier.requests} request(s), "
            f"{classifier.failures} failed, {classifier.skipped} skipped",
            file=sys.stderr,
        )
    return published
