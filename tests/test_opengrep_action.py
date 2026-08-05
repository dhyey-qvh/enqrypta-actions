from __future__ import annotations

import importlib.util
import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github" / "actions" / "enqrypta-opengrep"


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ACTION / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def result(
    algorithm: str,
    source: str,
    *,
    rule_id: str = "enqrypta.crypto.test",
    path: str = "src/crypto.py",
    start_col: int = 1,
    end_col: int | None = None,
) -> dict:
    return {
        "check_id": f"rules.crypto.{rule_id}",
        "path": path,
        "start": {"line": 4, "col": start_col},
        "end": {"line": 4, "col": end_col or len(source) + 1},
        "extra": {
            "severity": "WARNING",
            "lines": source,
            "metadata": {
                "enqrypta_rule_id": rule_id,
                "algorithm": algorithm,
                "primitive": "asymmetric",
                "usage": "encryption",
                "confidence": 0.9,
            },
        },
    }


def test_rules_have_unique_stable_ids_without_policy_metadata():
    rules = yaml.safe_load((ACTION / "rules" / "crypto.yml").read_text())["rules"]
    required = {"enqrypta_rule_id", "algorithm", "primitive", "usage", "confidence"}
    stable_ids = [rule["metadata"]["enqrypta_rule_id"] for rule in rules]

    assert len(stable_ids) == len(set(stable_ids))
    for rule, stable_id in zip(rules, stable_ids, strict=True):
        assert required <= rule["metadata"].keys()
        assert stable_id == rule["id"]
        assert stable_id.startswith("enqrypta.crypto.")
        assert "quantum_risk" not in rule["metadata"]
        assert "target_algorithm" not in rule["metadata"]


def test_normalizer_uses_stable_metadata_id_and_omits_source_and_policy(tmp_path):
    normalizer = load_script("normalize")
    source = "secret_key = RSA_3072(private_material)"
    start = source.index("RSA_3072") + 1
    finding = normalizer.normalize_result(
        result("RSA", source, start_col=start, end_col=start + len("RSA_3072")), tmp_path
    )

    assert finding["rule_id"] == "enqrypta.crypto.test"
    assert finding["algorithm"] == "RSA"
    assert finding["assessment_evidence"]["parameter_set"] == "RSA_3072"
    assert finding["assessment_evidence"]["key_size_bits"] == 3072
    for forbidden in (
        "lines",
        "code_snippet",
        "commit_sha",
        "fingerprint",
        "quantum_risk",
        "target_algorithm",
    ):
        assert forbidden not in finding
    assert source not in json.dumps(finding)


def test_prefixed_opengrep_check_id_does_not_change_stable_rule_id(tmp_path):
    normalizer = load_script("normalize")
    first = result("RSA", "RSA")
    second = result("RSA", "RSA")
    first["check_id"] = "rules.crypto.enqrypta.crypto.test"
    second["check_id"] = "release-v5.rules.crypto.enqrypta.crypto.test"

    assert normalizer.normalize_result(first, tmp_path) == normalizer.normalize_result(
        second, tmp_path
    )


def test_main_writes_observation_only_schema_2_payload(monkeypatch, tmp_path):
    normalizer = load_script("normalize")
    input_path = tmp_path / "raw.json"
    output_path = tmp_path / "normalized.json"
    input_path.write_text(json.dumps({"results": [result("AES", "AES-256")]}))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("GITHUB_SHA", "untrusted-payload-sha")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "normalize.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--scanner-version",
            "1.22.0",
        ],
    )

    normalizer.main()

    payload = json.loads(output_path.read_text())
    assert set(payload) == {"schema_version", "scanner_version", "findings"}
    assert payload["schema_version"] == "2.0"
    assert payload["findings"][0]["algorithm"] == "AES"
    assert payload["findings"][0]["assessment_evidence"]["parameter_set"] == "AES-256"


@pytest.mark.parametrize(
    ("family", "variant"),
    [
        ("RSA", "RSA_3072"),
        ("ECDH", "X25519"),
        ("ECDSA", "Ed25519"),
        ("AES", "AES-256"),
        ("ML-KEM", "ML-KEM-768"),
        ("ML-DSA", "ML-DSA-65"),
        ("PQC-KEM", "ClassicMcEliece8192128f"),
        ("PQC-SIGNATURE", "Dilithium3"),
    ],
)
def test_exact_variant_is_constrained_to_declared_family(family, variant, tmp_path):
    normalizer = load_script("normalize")
    finding = normalizer.normalize_result(result(family, variant), tmp_path)

    assert finding["algorithm"] == family
    assert finding["assessment_evidence"]["parameter_set"] == variant


def test_exact_variant_is_restricted_to_matched_columns(tmp_path):
    normalizer = load_script("normalize")
    source = "ECDSA then RSA_3072"
    rsa_start = source.index("RSA_3072") + 1
    finding = normalizer.normalize_result(
        result("RSA", source, start_col=rsa_start, end_col=len(source) + 1), tmp_path
    )

    assert finding["algorithm"] == "RSA"
    assert finding["assessment_evidence"]["parameter_set"] == "RSA_3072"


def test_wrong_family_variant_is_not_promoted(tmp_path):
    normalizer = load_script("normalize")
    finding = normalizer.normalize_result(result("RSA", "ECDSA"), tmp_path)

    assert finding["algorithm"] == "RSA"
    assert "parameter_set" not in finding["assessment_evidence"]


@pytest.mark.parametrize(
    "path", ["../secret.py", "..\\secret.py", "/tmp/secret.py", "C:\\secret.py"]
)
def test_normalizer_rejects_paths_outside_workspace(path, tmp_path):
    normalizer = load_script("normalize")
    with pytest.raises(ValueError, match="escapes GITHUB_WORKSPACE"):
        normalizer.normalize_result(result("RSA", "RSA", path=path), tmp_path)


def test_normalizer_returns_relative_posix_path(tmp_path):
    normalizer = load_script("normalize")
    source_path = tmp_path / "src" / "crypto.py"
    finding = normalizer.normalize_result(
        result("RSA", "RSA", path=str(source_path)), tmp_path
    )

    assert finding["file_path"] == "src/crypto.py"


def test_publisher_keeps_controls_user_agent_and_api_error_details(
    monkeypatch, tmp_path, capsys
):
    publisher = load_script("publish")
    payload_path = tmp_path / "findings.json"
    payload_path.write_text('{"schema_version":"2.0","scanner_version":"1.22.0","findings":[]}')
    requests = []
    error = urllib.error.HTTPError(
        "https://api.example.test/scans/opengrep",
        403,
        "Forbidden",
        {"x-request-id": "request-123"},
        io.BytesIO(b'{"detail":"untrusted GitHub workflow SHA"}'),
    )

    def fail(request, timeout):  # noqa: ARG001
        requests.append(request)
        raise error

    monkeypatch.setenv("ENQRYPTA_API_URL", "https://api.example.test")
    monkeypatch.setenv("ENQRYPTA_NOTIFY_ON_COMPLETE", "true")
    monkeypatch.setenv("ENQRYPTA_NOTIFICATION_EMAIL", "owner@example.test")
    monkeypatch.setenv(
        "ENQRYPTA_NIGHTLY_JOB_TASK_ID", "job-task-00000000-0000-0000-0000-000000000001"
    )
    monkeypatch.setattr(publisher, "request_oidc_token", lambda: "secret-token")
    monkeypatch.setattr(publisher.urllib.request, "urlopen", fail)
    monkeypatch.setattr(sys, "argv", ["publish.py", "--input", str(payload_path)])

    with pytest.raises(SystemExit, match="1"):
        publisher.main()

    request = requests[0]
    body = json.loads(request.data)
    stderr = capsys.readouterr().err
    assert body["notify_on_complete"] is True
    assert body["notification_email"] == "owner@example.test"
    assert body["nightly_job_task_id"].startswith("job-task-")
    assert "EnQrypta-GitHub-Action/5.0" in request.get_header("User-agent")
    assert "HTTP 403 Forbidden" in stderr
    assert '{"detail":"untrusted GitHub workflow SHA"}' in stderr
    assert "Request ID: request-123" in stderr
    assert "secret-token" not in stderr


def test_action_and_workflows_are_valid_yaml_and_use_v5():
    action = yaml.safe_load((ACTION / "action.yml").read_text())
    reusable = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "enqrypta-opengrep.yml").read_text()
    )
    consumer = yaml.safe_load((ROOT / ".github" / "workflows" / "enqrypta-scan.yml").read_text())

    assert action["runs"]["using"] == "composite"
    assert "@enqrypta-opengrep-workflow-v5" in reusable["jobs"]["scan"]["steps"][1]["uses"]
    assert "@enqrypta-opengrep-workflow-v5" in consumer["jobs"]["scan"]["uses"]
