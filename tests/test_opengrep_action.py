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


def test_fallback_rules_have_unique_stable_ids_without_policy_metadata():
    rules = yaml.safe_load((ACTION / "rules" / "fallback" / "generic.yml").read_text())["rules"]
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


def test_main_writes_observation_only_schema_3_payload(monkeypatch, tmp_path):
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
    assert payload["schema_version"] == "3.0"
    assert payload["findings"][0]["algorithm"] == "AES"
    assert payload["findings"][0]["assessment_evidence"]["parameter_set"] == "AES-256"
    assert payload["findings"][0]["finding_kind"] == "inventory"
    assert len(payload["findings"][0]["site_key"]) == 64


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
    finding = normalizer.normalize_result(result("RSA", "RSA", path=str(source_path)), tmp_path)

    assert finding["file_path"] == "src/crypto.py"


def test_publisher_keeps_controls_user_agent_and_api_error_details(monkeypatch, tmp_path, capsys):
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
    assert "@enqrypta-opengrep-workflow-v6" in reusable["jobs"]["scan"]["steps"][1]["uses"]
    assert "@enqrypta-opengrep-workflow-v6" in consumer["jobs"]["scan"]["uses"]


def test_publisher_forwards_exact_launch_id(monkeypatch, tmp_path):
    publisher = load_script("publish")
    path = tmp_path / "findings.json"
    path.write_text('{"schema_version":"2.0","scanner_version":"1","findings":[]}')
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"{}"

    def send(request, timeout):
        requests.append(request)
        return Response()

    monkeypatch.setenv("ENQRYPTA_API_URL", "https://api.example.test")
    monkeypatch.setenv("ENQRYPTA_CODE_SCAN_ID", "code-launch-00000000-0000-0000-0000-000000000001")
    monkeypatch.setattr(publisher, "request_oidc_token", lambda: "token")
    monkeypatch.setattr(publisher.urllib.request, "urlopen", send)
    monkeypatch.setattr(sys, "argv", ["publish.py", "--input", str(path)])
    publisher.main()
    assert json.loads(requests[0].data)["code_scan_id"].startswith("code-launch-")


def test_bind_execution_uses_oidc_before_scanning(monkeypatch):
    publisher = load_script("publish")
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"{}"

    def send(request, timeout):
        requests.append(request)
        return Response()

    monkeypatch.setenv("ENQRYPTA_API_URL", "https://api.example.test")
    monkeypatch.setenv("ENQRYPTA_CODE_SCAN_ID", "code-launch-00000000-0000-0000-0000-000000000001")
    monkeypatch.setattr(publisher, "request_oidc_token", lambda: "oidc-token")
    monkeypatch.setattr(publisher.urllib.request, "urlopen", send)
    monkeypatch.setattr(sys, "argv", ["publish.py", "--bind-execution"])
    publisher.main()
    assert requests[0].full_url.endswith(
        "/code-launch-00000000-0000-0000-0000-000000000001/execution"
    )
    assert requests[0].get_header("Authorization") == "Bearer oidc-token"
    assert json.loads(requests[0].data) == {}


# ── schema 3.0: parameters, misuse, site keys, file and rule digests ───────

def with_metavars(finding: dict, **metavars) -> dict:
    finding["extra"]["metavars"] = {
        f"${name}": (value if isinstance(value, dict) else {"abstract_content": value})
        for name, value in metavars.items()
    }
    return finding


def with_metadata(finding: dict, **metadata) -> dict:
    finding["extra"]["metadata"].update(metadata)
    return finding


def test_transformation_string_yields_mode_padding_and_parameter_set(tmp_path):
    normalizer = load_script("normalize")
    raw = with_metavars(
        result("AES", 'Cipher.getInstance("AES_256/GCM/NoPadding")'),
        TRANSFORMATION='"AES_256/GCM/NoPadding"',
        TAG_BITS="128",
        IV_BYTES="12",
    )
    evidence = normalizer.normalize_result(raw, tmp_path)["assessment_evidence"]

    assert evidence["parameter_set"] == "AES_256"
    assert evidence["mode"] == "GCM"
    assert evidence["padding"] == "NoPadding"
    assert evidence["tag_length_bits"] == 128
    assert evidence["iv_length_bits"] == 96


@pytest.mark.parametrize(
    ("metavars", "expected"),
    [
        ({"KEY_SIZE": "2048"}, {"key_size_bits": 2048}),
        ({"KEY_SIZE": "4_096usize"}, {"key_size_bits": 4096}),
        ({"KEY_SIZE": "0x800L"}, {"key_size_bits": 2048}),
        ({"KEY_BYTES": "32"}, {"key_size_bits": 256}),
        (
            {"KEY_SIZE": {"abstract_content": "keyBits",
                          "propagated_value": {"svalue_abstract_content": "3072"}}},
            {"key_size_bits": 3072},
        ),
        ({"CURVE": "'secp384r1'"}, {"parameter_set": "secp384r1", "group_order_bits": 384}),
        ({"CURVE": '"P-256"'}, {"parameter_set": "P-256", "group_order_bits": 256}),
        ({"PROTOCOL": '"TLSv1.2"'}, {"protocol": "TLS 1.2"}),
        ({"PROTOCOL": "tls.VersionTLS13"}, {"protocol": "TLS 1.3"}),
        ({"PROTOCOL": "rustls::version::TLS12"}, {"protocol": "TLS 1.2"}),
        ({"PROTOCOL": "'TLSv1_method'"}, {"protocol": "TLS 1.0"}),
        ({"PROTOCOL": "minVersion"}, {}),
        ({"CURVE": "ec.SECP384R1()"}, {"parameter_set": "SECP384R1", "group_order_bits": 384}),
        ({"CURVE": "elliptic.P256()"}, {"parameter_set": "P256", "group_order_bits": 256}),
        ({"CURVE": "curve"}, {}),
        ({"PROTOCOL": '"TLS1_1_VERSION"'}, {"protocol": "TLS 1.1"}),
        ({"PROTOCOL": '"PROTOCOL_TLSv1"'}, {"protocol": "TLS 1.0"}),
    ],
)
def test_metavariables_resolve_literals_only(tmp_path, metavars, expected):
    normalizer = load_script("normalize")
    evidence = normalizer.normalize_result(
        with_metavars(result("RSA", "generate(...)"), **metavars), tmp_path
    )["assessment_evidence"]
    observed = {key: value for key, value in evidence.items() if key in expected or key in {
        "key_size_bits", "parameter_set", "group_order_bits", "protocol"}}
    assert observed == expected


def test_declared_parameters_that_are_not_literals_are_reported_unresolved(tmp_path):
    normalizer = load_script("normalize")
    raw = with_metadata(
        with_metavars(result("RSA", "generate_private_key(key_size=bits)"), KEY_SIZE="bits"),
        parameters=["key_size_bits"],
    )
    finding = normalizer.normalize_result(raw, tmp_path)

    assert "key_size_bits" not in finding["assessment_evidence"]
    assert finding["unresolved_parameters"] == ["key_size_bits"]

    resolved = with_metadata(
        with_metavars(result("RSA", "generate_private_key(key_size=2048)"), KEY_SIZE="2048"),
        parameters=["key_size_bits"],
    )
    assert "unresolved_parameters" not in normalizer.normalize_result(resolved, tmp_path)


def test_unknown_declared_parameter_is_a_rule_error(tmp_path):
    normalizer = load_script("normalize")
    with pytest.raises(ValueError, match="unknown declared parameters"):
        normalizer.normalize_result(
            with_metadata(result("RSA", "RSA"), parameters=["colour"]), tmp_path
        )


def test_misuse_finding_carries_kind_and_cwe(tmp_path):
    normalizer = load_script("normalize")
    raw = with_metadata(
        result("TLS", "verify=False", rule_id="enqrypta.misuse.python.tls-verify-disabled"),
        finding_kind="misuse",
        cwe="CWE-295",
    )
    finding = normalizer.normalize_result(raw, tmp_path)

    assert finding["finding_kind"] == "misuse"
    assert finding["cwe"] == "CWE-295"


@pytest.mark.parametrize(
    ("rule_id", "metadata", "message"),
    [
        ("enqrypta.misuse.java.ecb", {"cwe": "CWE-327"}, "must use finding_kind"),
        ("enqrypta.crypto.test", {"finding_kind": "misuse", "cwe": "CWE-327"}, "must use"),
        ("enqrypta.misuse.java.ecb", {"finding_kind": "misuse"}, "require metadata cwe"),
        ("enqrypta.crypto.test", {"finding_kind": "policy"}, "unknown finding_kind"),
        ("enqrypta.crypto.test", {"iv_generation": "a value with spaces"}, "short token"),
    ],
)
def test_rule_metadata_contract_errors(tmp_path, rule_id, metadata, message):
    normalizer = load_script("normalize")
    with pytest.raises(ValueError, match=message):
        normalizer.normalize_result(
            with_metadata(result("AES", "AES", rule_id=rule_id), **metadata), tmp_path
        )


def test_static_metadata_evidence_is_passed_through(tmp_path):
    normalizer = load_script("normalize")
    raw = with_metadata(
        result("AES", "IvParameterSpec(FIXED)", rule_id="enqrypta.misuse.java.static-iv"),
        finding_kind="misuse",
        cwe="CWE-329",
        iv_generation="hardcoded",
    )
    assert normalizer.normalize_result(raw, tmp_path)["assessment_evidence"][
        "iv_generation"
    ] == "hardcoded"


def _keys(normalizer, raws, tmp_path):
    findings = [normalizer.normalize_result(raw, tmp_path) for raw in raws]
    normalizer.assign_site_keys(raws, findings)
    return [finding["site_key"] for finding in findings]


def test_site_key_survives_line_shift_and_separates_identical_matches(tmp_path):
    normalizer = load_script("normalize")
    first = result("RSA", "RSA.generate(2048)")
    shifted = result("RSA", "RSA.generate(2048)")
    shifted["start"]["line"] = shifted["end"]["line"] = 40
    twin = result("RSA", "RSA.generate(2048)")
    twin["start"]["line"] = twin["end"]["line"] = 80

    (original,) = _keys(normalizer, [first], tmp_path)
    (moved,) = _keys(normalizer, [shifted], tmp_path)
    pair = _keys(normalizer, [first, twin], tmp_path)

    assert original == moved
    assert len(set(pair)) == 2 and pair[0] == original


def test_site_key_does_not_expose_source(tmp_path):
    normalizer = load_script("normalize")
    source = "private_key = load('hunter2-secret-material')"
    finding = normalizer.normalize_result(result("RSA", source), tmp_path)
    normalizer.assign_site_keys([result("RSA", source)], [finding])
    assert "hunter2" not in json.dumps(finding)


def test_file_blob_sha_matches_git_hash_object(tmp_path):
    import subprocess

    normalizer = load_script("normalize")
    source = tmp_path / "src" / "crypto.py"
    source.parent.mkdir()
    source.write_bytes(b"from cryptography import x509\n")
    expected = subprocess.run(
        ["git", "hash-object", str(source)], capture_output=True, text=True, check=True
    ).stdout.strip()
    findings = [{"file_path": "src/crypto.py"}, {"file_path": "src/missing.py"}]

    normalizer.assign_file_blob_shas(findings, tmp_path)

    assert findings[0]["file_blob_sha"] == expected
    assert "file_blob_sha" not in findings[1]


def test_rules_digest_tracks_rule_content(tmp_path):
    normalizer = load_script("normalize")
    rules = tmp_path / "rules"
    (rules / "crypto-inventory").mkdir(parents=True)
    rule = rules / "crypto-inventory" / "java.yml"
    rule.write_text("rules: []\n")
    first = normalizer.rules_digest(rules)
    assert first == normalizer.rules_digest(rules)
    rule.write_text("rules: [] # changed\n")
    assert normalizer.rules_digest(rules) != first
    assert len(normalizer.rules_digest(ACTION / "rules")) == 64


def test_main_emits_rules_digest_and_blob_hash(monkeypatch, tmp_path):
    normalizer = load_script("normalize")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "crypto.py").write_text("AES-256\n")
    input_path = tmp_path / "raw.json"
    output_path = tmp_path / "normalized.json"
    input_path.write_text(json.dumps({"results": [result("AES", "AES-256")]}))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "normalize.py", "--input", str(input_path), "--output", str(output_path),
            "--scanner-version", "1.22.0", "--rules", str(ACTION / "rules"),
        ],
    )

    normalizer.main()

    payload = json.loads(output_path.read_text())
    assert payload["rules_digest"] == normalizer.rules_digest(ACTION / "rules")
    assert len(payload["findings"][0]["file_blob_sha"]) == 40


@pytest.mark.parametrize("value", ["0755", "00", "0x_", "0x"])
def test_ambiguous_or_malformed_integers_are_unresolved_not_errors(tmp_path, value):
    normalizer = load_script("normalize")
    raw = with_metadata(
        with_metavars(result("RSA", "generate(...)"), KEY_SIZE=value),
        parameters=["key_size_bits"],
    )
    finding = normalizer.normalize_result(raw, tmp_path)

    assert "key_size_bits" not in finding["assessment_evidence"]
    assert finding["unresolved_parameters"] == ["key_size_bits"]


@pytest.mark.parametrize(
    "transformation", ['f"AES/{mode}/NoPadding"', "`AES/${mode}/NoPadding`"]
)
def test_interpolated_strings_are_not_literals(tmp_path, transformation):
    normalizer = load_script("normalize")
    raw = with_metadata(
        with_metavars(result("AES", "Cipher(...)"), TRANSFORMATION=transformation),
        parameters=["mode"],
    )
    finding = normalizer.normalize_result(raw, tmp_path)

    assert "mode" not in finding["assessment_evidence"]
    assert finding["unresolved_parameters"] == ["mode"]
    assert normalizer._strip_literal('rb"raw"') == "raw"


@pytest.mark.parametrize(
    ("metavars", "expected"),
    [
        ({"MODE": "AES.MODE_ECB"}, {"mode": "ECB"}),
        ({"MODE": "modes.GCM(iv)"}, {"mode": "GCM"}),
        ({"MODE": "'cbc'"}, {"mode": "CBC"}),
        ({"MODE": "chosen_mode"}, {}),
        (
            {"CIPHER": "'aes-256-gcm'"},
            {"parameter_set": "AES-256", "key_size_bits": 256, "mode": "GCM"},
        ),
        ({"CIPHER": "'des-ede3-cbc'"}, {"mode": "CBC"}),
        ({"CIPHER": "'AES-GCM'"}, {"mode": "GCM"}),
        ({"CIPHER": "algorithm"}, {}),
    ],
)
def test_mode_and_cipher_name_metavariables(tmp_path, metavars, expected):
    normalizer = load_script("normalize")
    evidence = normalizer.normalize_result(
        with_metavars(result("AES", "cipher(...)"), **metavars), tmp_path
    )["assessment_evidence"]
    observed = {
        key: value
        for key, value in evidence.items()
        if key in {"mode", "parameter_set", "key_size_bits"}
    }
    assert observed == expected


def test_static_metadata_parameters_and_integers(tmp_path):
    normalizer = load_script("normalize")
    evidence = normalizer.normalize_result(
        with_metadata(
            result("ECDSA", "p384::ecdsa::SigningKey::random(&mut rng)"),
            parameter_set="P-384",
            protocol="TLS 1.0",
            key_size_bits=384,
        ),
        tmp_path,
    )["assessment_evidence"]
    assert evidence["parameter_set"] == "P-384"
    assert evidence["group_order_bits"] == 384
    assert evidence["protocol"] == "TLS 1.0"
    assert evidence["key_size_bits"] == 384

    with pytest.raises(ValueError, match="positive integer"):
        normalizer.normalize_result(
            with_metadata(result("AES", "Aes256Gcm"), key_size_bits="256"), tmp_path
        )


def test_jca_rsa_transformation_reports_padding_but_no_block_mode(tmp_path):
    normalizer = load_script("normalize")
    raw = with_metavars(
        result("RSA", 'Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")'),
        TRANSFORMATION='"RSA/ECB/OAEPWithSHA-256AndMGF1Padding"',
    )
    evidence = normalizer.normalize_result(raw, tmp_path)["assessment_evidence"]

    assert "mode" not in evidence
    assert evidence["padding"] == "OAEPWithSHA-256AndMGF1Padding"
