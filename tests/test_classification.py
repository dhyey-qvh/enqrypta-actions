"""Artifact classification: extraction, API response mapping and failure handling.

Responses under tests/fixtures/classification are real API responses recorded
for throwaway keys.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / ".github" / "actions" / "enqrypta-opengrep" / "scripts"
RESPONSES = REPO / "tests" / "fixtures" / "classification"
PEM = (
    "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq+hkiG9w0B/AQEF\nAAOCAQ8AMIIB\n"
    "-----END PUBLIC KEY-----"
)
PRIVATE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B\n"
    "-----END RSA PRIVATE KEY-----"
)


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def response(name: str) -> dict:
    return json.loads((RESPONSES / f"{name}.json").read_text())


def raw_result(rule_id: str, text: str, *, artifact: str, kind: str = "inventory") -> dict:
    lines = text.splitlines()
    metadata = {
        "enqrypta_rule_id": rule_id,
        "artifact": artifact,
        "algorithm": "PRIVATE-KEY" if kind == "misuse" else "UNCLASSIFIED",
        "primitive": "asymmetric",
        "usage": "unknown",
        "confidence": 0.5,
    }
    if kind == "misuse":
        metadata.update(finding_kind="misuse", cwe="CWE-321")
    return {
        "check_id": rule_id,
        "path": "config/keys.conf",
        "start": {"line": 1, "col": 1},
        "end": {"line": len(lines), "col": len(lines[-1]) + 1},
        "extra": {"severity": "WARNING", "lines": text, "metadata": metadata},
    }


class FakeClassifier:
    requests = failures = skipped = 0

    def __init__(self, answer: dict | None):
        self.answer = answer
        self.sent: list[str] = []

    def classify(self, artifact: str) -> dict | None:
        self.sent.append(artifact)
        return self.answer


def published(results: list[dict], classifier, tmp_path) -> list[dict]:
    normalizer, classify = load("normalize"), load("classify")
    findings = [normalizer.normalize_result(result, tmp_path) for result in results]
    normalizer.assign_site_keys(results, findings)
    return classify.apply(results, findings, classifier, normalizer.matched_span)


def test_pem_is_recovered_from_escaped_and_concatenated_source_strings():
    classify = load("classify")
    escaped = PEM.replace("\n", "\\n")
    concatenated = " +\n".join(f'    "{line}\\n"' for line in PEM.split("\n")).strip().lstrip('"')

    assert classify.artifact_text("pem", PEM) == PEM
    assert classify.artifact_text("pem", escaped) == PEM
    assert classify.artifact_text("pem", concatenated) == PEM


def test_only_the_jwt_header_is_sent():
    classify = load("classify")
    assert classify.artifact_text("jwt", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln") == (
        "eyJhbGciOiJSUzI1NiJ9.."
    )


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("rsa2048_public_pem", ("RSA", "unknown", {"key_size_bits": 2048})),
        ("rsa_x509_cert_pem", ("RSA", "signing", {"key_size_bits": 2048})),
        ("rsa2048_private_pem", ("RSA", "unknown", {"key_size_bits": 2048})),
        (
            "ec_p256_public_pem",
            ("ECDSA", "unknown", {"parameter_set": "P-256", "group_order_bits": 256}),
        ),
        ("ssh_ed25519_public", ("ED25519", "signing", {"parameter_set": "Ed25519"})),
        ("mldsa65_public_pem", ("ML-DSA", "signing", {"parameter_set": "ML-DSA-65"})),
        ("mlkem768_public_pem", ("ML-KEM", "key_establishment", {"parameter_set": "ML-KEM-768"})),
        ("jwt_rs256", ("RSA", "signing", {})),
        ("jwt_hs256", ("HMAC-SHA256", "mac", {})),
    ],
)
def test_parsed_inventory_maps_to_finding_fields(name, expected):
    fields = load("classify").interpret(response(name))
    assert (fields["algorithm"], fields["usage"], fields["evidence"]) == expected


@pytest.mark.parametrize("name", ["aes256_hex", "uuid", "rsa_encrypted_private_pem"])
def test_unparsed_artifacts_are_not_identified(name):
    assert load("classify").interpret(response(name)) is None


def test_classified_artifact_becomes_an_inventory_finding_with_provenance(tmp_path):
    classifier = FakeClassifier(response("rsa2048_public_pem"))
    [finding] = published(
        [raw_result("enqrypta.crypto.artifact.pem", PEM, artifact="pem")], classifier, tmp_path
    )

    assert classifier.sent == [PEM]
    assert (finding["algorithm"], finding["usage"]) == ("RSA", "unknown")
    assert finding["assessment_evidence"]["key_size_bits"] == 2048
    assert finding["confidence"] == 0.95
    assert finding["classification"] == {
        "status": "confirmed",
        "source": "parsed_public_key",
        "model_version": response("rsa2048_public_pem")["model_version"],
        "artifact_sha256": finding["classification"]["artifact_sha256"],
        "is_private_key": False,
        "encrypted": False,
        "artifact_class": "public_key",
        "container": "pem",
        "evidence_strength": 0.95,
    }
    assert len(finding["classification"]["artifact_sha256"]) == 64
    assert "MIIB" not in json.dumps(finding)


@pytest.mark.parametrize("answer", [None, "aes256_hex"])
def test_unidentified_inventory_artifact_is_dropped(tmp_path, answer):
    classifier = FakeClassifier(response(answer) if answer else None)
    assert published(
        [raw_result("enqrypta.crypto.artifact.pem", PEM, artifact="pem")], classifier, tmp_path
    ) == []


def test_private_key_is_reported_even_without_the_api(tmp_path):
    results = [
        raw_result("enqrypta.crypto.artifact.pem", PRIVATE_PEM, artifact="pem"),
        raw_result(
            "enqrypta.misuse.artifact.private-key", PRIVATE_PEM, artifact="pem", kind="misuse"
        ),
    ]
    [finding] = published(results, None, tmp_path)

    assert finding["rule_id"] == "enqrypta.misuse.artifact.private-key"
    assert (finding["finding_kind"], finding["cwe"]) == ("misuse", "CWE-321")
    assert finding["algorithm"] == "RSA"  # from the "RSA PRIVATE KEY" label
    assert "classification" not in finding


def test_encrypted_private_key_is_kept_as_unconfirmed(tmp_path):
    text = PRIVATE_PEM.replace("RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY")
    [finding] = published(
        [raw_result("enqrypta.misuse.artifact.private-key", text, artifact="pem", kind="misuse")],
        FakeClassifier(response("rsa_encrypted_private_pem")),
        tmp_path,
    )

    assert finding["algorithm"] == "PRIVATE-KEY"
    assert finding["classification"]["status"] == "unconfirmed"
    assert finding["classification"]["is_private_key"] is True
    assert finding["classification"]["encrypted"] is True


def test_classifier_sends_no_questions_and_caches_by_artifact(monkeypatch):
    classify = load("classify")
    calls = []

    def urlopen(request, timeout):
        calls.append(request)
        return io.BytesIO(json.dumps(response("rsa2048_public_pem")).encode())

    monkeypatch.setattr(classify.urllib.request, "urlopen", urlopen)
    classifier = classify.Classifier("https://classification.example/")

    assert classifier.classify(PEM)["inventory"]["key_algorithm"] == "rsa"
    assert classifier.classify(PEM) is classifier.classify(PEM)
    assert len(calls) == 1
    assert calls[0].full_url == "https://classification.example/decide"
    assert calls[0].get_header("User-agent") == "EnQrypta-GitHub-Action/7.0"
    assert json.loads(calls[0].data) == {
        "engine": "product", "state": {"artifact": PEM}, "questions": {}
    }


def test_api_failures_never_fail_the_scan_and_stop_after_three(monkeypatch, capsys):
    classify = load("classify")
    calls = []

    def urlopen(request, timeout):
        calls.append(request)
        if len(calls) == 1:
            return io.BytesIO(b"<html>403 Forbidden</html>")  # CDN block page
        raise urllib.error.HTTPError(request.full_url, 503, "unavailable", {}, io.BytesIO(b""))

    monkeypatch.setattr(classify.urllib.request, "urlopen", urlopen)
    classifier = classify.Classifier("https://classification.example")

    assert [classifier.classify(f"artifact-{i}") for i in range(6)] == [None] * 6
    assert len(calls) == 3
    assert (classifier.failures, classifier.skipped) == (3, 3)
    assert "classification request failed" in capsys.readouterr().err


def test_oversized_artifact_is_not_sent(monkeypatch):
    classify = load("classify")
    monkeypatch.setattr(
        classify.urllib.request, "urlopen", lambda *a, **k: pytest.fail("must not be called")
    )
    classifier = classify.Classifier("https://classification.example")

    assert classifier.classify("A" * (classify.MAX_ARTIFACT_BYTES + 1)) is None
    assert classifier.skipped == 1


def test_main_classifies_artifacts_and_never_writes_them_to_the_payload(monkeypatch, tmp_path):
    normalizer = load("normalize")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "keys.conf").write_text(PEM + "\n")
    raw, out = tmp_path / "raw.json", tmp_path / "out.json"
    raw.write_text(
        json.dumps({"results": [raw_result("enqrypta.crypto.artifact.pem", PEM, artifact="pem")]})
    )
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout: io.BytesIO(json.dumps(response("rsa2048_public_pem")).encode()),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["normalize.py", "--input", str(raw), "--output", str(out), "--scanner-version", "1.22.0",
         "--classification-url", "https://classification.example"],
    )

    normalizer.main()

    payload = out.read_text()
    assert json.loads(payload)["findings"][0]["algorithm"] == "RSA"
    assert "MIIB" not in payload and "BEGIN" not in payload
