"""Contract and corpus tests for the Opengrep rule packs.

The static checks always run. The corpus checks need the pinned Opengrep
binary: set OPENGREP_BIN (CI does) or put ``opengrep`` on PATH.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
ACTION = REPO / ".github" / "actions" / "enqrypta-opengrep"
RULES = ACTION / "rules"
FIXTURES = REPO / "tests" / "rules"
LANGUAGE_PACKS = ("inventory", "misuse")
LANGUAGES = {
    "java": {"*.java"},
    "python": {"*.py"},
    "go": {"*.go"},
    "javascript": {"*.js", "*.jsx", "*.mjs", "*.cjs", "*.ts", "*.tsx", "*.mts", "*.cts"},
    "rust": {"*.rs"},
}
# Algorithms the backend catalog classifies into a known family. Inventory
# findings become crypto assets, so a new name here needs a catalog entry first.
INVENTORY_ALGORITHMS = {
    "RSA", "ECDSA", "ECDH", "X25519", "ED25519", "DH", "AES", "SHA-1", "MD5", "ML-KEM", "ML-DSA",
}
ASSET_USAGES = {
    "signing", "encryption", "key_establishment", "hash", "mac", "random", "tls", "api",
    "storage", "unknown",
}
V6_FALLBACK_IDS = {
    "enqrypta.crypto.rsa", "enqrypta.crypto.ecdsa", "enqrypta.crypto.ecdh",
    "enqrypta.crypto.sha1", "enqrypta.crypto.md5", "enqrypta.crypto.aes",
    "enqrypta.crypto.ml-kem", "enqrypta.crypto.ml-dsa",
    "enqrypta.crypto.classical-key-establishment", "enqrypta.crypto.classical-signature",
    "enqrypta.crypto.pqc-kem-catalog", "enqrypta.crypto.pqc-signature-catalog",
}
# Prose and lockfiles mention algorithm names without using them.
NON_CODE_GLOBS = {"*.md", "*.mdx", "*.rst", "*.txt", "*.lock", "*.sum", "package-lock.json"}
ANNOTATION = re.compile(r"(?:#|//)\s*(ruleid|ok):\s*([a-z0-9.,\s-]+)$")


def load_normalizer():
    spec = importlib.util.spec_from_file_location("normalize", ACTION / "scripts" / "normalize.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pack_rules() -> list[tuple[str, str, dict]]:
    rules = []
    for pack in LANGUAGE_PACKS:
        for path in sorted((RULES / pack).glob("*.yml")):
            for rule in yaml.safe_load(path.read_text())["rules"]:
                rules.append((pack, path.stem, rule))
    return rules


def fixture_annotations(pack: str, language: str) -> dict[str, set[str]]:
    fixtures = list((FIXTURES / pack).glob(f"{language}.*"))
    assert fixtures, f"no fixture for rules/{pack}/{language}.yml"
    seen: dict[str, set[str]] = {}
    for fixture in fixtures:
        for line in fixture.read_text().splitlines():
            match = ANNOTATION.search(line.strip())
            if match:
                for rule_id in match.group(2).split(","):
                    seen.setdefault(rule_id.strip(), set()).add(match.group(1))
    return seen


def test_rule_packs_cover_the_five_languages():
    for pack in LANGUAGE_PACKS:
        assert {path.stem for path in (RULES / pack).glob("*.yml")} == set(LANGUAGES)


def test_language_pack_rules_follow_the_id_and_metadata_contract():
    normalizer = load_normalizer()
    ids = [rule["id"] for _, _, rule in pack_rules()]
    assert len(ids) == len(set(ids))
    for pack, language, rule in pack_rules():
        metadata = rule["metadata"]
        namespace = "crypto" if pack == "inventory" else "misuse"
        assert rule["id"] == metadata["enqrypta_rule_id"]
        assert rule["id"].startswith(f"enqrypta.{namespace}.{language}.")
        assert normalizer.REQUIRED_METADATA <= metadata.keys()
        assert metadata["language"] == language
        assert metadata["usage"] in ASSET_USAGES
        assert set(metadata.get("parameters", [])) <= normalizer.EVIDENCE_PARAMETERS
        assert {"quantum_risk", "target_algorithm"}.isdisjoint(metadata)
        if pack == "inventory":
            assert metadata.get("finding_kind", "inventory") == "inventory"
            assert metadata["algorithm"] in INVENTORY_ALGORITHMS, rule["id"]
        else:
            assert metadata["finding_kind"] == "misuse"
            assert normalizer.CWE_PATTERN.match(metadata["cwe"]), rule["id"]


def test_every_language_pack_rule_has_positive_and_negative_fixtures():
    for pack, language, rule in pack_rules():
        annotations = fixture_annotations(pack, language).get(rule["id"], set())
        assert annotations == {"ruleid", "ok"}, f"{rule['id']}: {sorted(annotations)}"


def test_fallback_keeps_v6_rule_ids_and_skips_language_pack_files():
    rules = yaml.safe_load((RULES / "fallback" / "generic.yml").read_text())["rules"]
    language_globs = set().union(*LANGUAGES.values())
    assert {rule["id"] for rule in rules} == V6_FALLBACK_IDS
    for rule in rules:
        assert rule["languages"] == ["generic"]
        assert "pattern-regex" in rule
        assert set(rule["paths"]["exclude"]) == language_globs | NON_CODE_GLOBS


# ── corpus checks with the pinned Opengrep binary ─────────────────────────

OPENGREP = os.environ.get("OPENGREP_BIN") or shutil.which("opengrep")
needs_opengrep = pytest.mark.skipif(not OPENGREP, reason="set OPENGREP_BIN to run corpus tests")


def opengrep(*args: str) -> dict:
    completed = subprocess.run(
        [OPENGREP, "scan", "--json", "--quiet", *args],
        cwd=REPO, capture_output=True, text=True, check=False,
    )
    assert completed.stdout, completed.stderr
    return json.loads(completed.stdout)


@needs_opengrep
def test_opengrep_corpus_passes_for_every_language_pack_rule():
    rules = RULES.relative_to(REPO).as_posix()
    report = opengrep("--test", "--config", rules, FIXTURES.relative_to(REPO).as_posix())

    assert report["config_with_errors"] == []
    # Regex fallback rules match their own annotation comments, so they are
    # covered by the static fallback test instead of a fixture.
    assert report["config_missing_tests"] == [f"{rules}/fallback/generic.yml"]
    checks = {
        rule_id: check
        for result in report["results"].values()
        for rule_id, check in result["checks"].items()
    }
    assert set(checks) == {rule["id"] for _, _, rule in pack_rules()}
    failed = {rule_id: check["matches"] for rule_id, check in checks.items() if not check["passed"]}
    assert failed == {}


@needs_opengrep
def test_scanning_the_corpus_normalizes_and_skips_fallback_rules(tmp_path):
    normalizer = load_normalizer()
    # Explicit file targets: directory scans skip ``tests/`` by Opengrep's default ignores.
    fixtures = sorted(path.relative_to(REPO).as_posix() for path in FIXTURES.rglob("*.*"))
    raw = opengrep("--config", RULES.relative_to(REPO).as_posix(), *fixtures)
    assert raw["errors"] == []
    findings = [normalizer.normalize_result(result, REPO) for result in raw["results"]]
    normalizer.assign_site_keys(raw["results"], findings)

    rule_ids = {finding["rule_id"] for finding in findings}
    assert rule_ids.isdisjoint(V6_FALLBACK_IDS)
    assert rule_ids == {rule["id"] for _, _, rule in pack_rules()}
    declared = {
        rule["id"]: set(rule["metadata"].get("parameters", [])) for _, _, rule in pack_rules()
    }
    for finding in findings:
        assert set(finding.get("unresolved_parameters", [])) <= declared[finding["rule_id"]]
        assert (finding["finding_kind"] == "misuse") == ("cwe" in finding)
        assert re.fullmatch(r"[0-9a-f]{64}", finding["site_key"])
