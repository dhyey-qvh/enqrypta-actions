# EnQrypta OpenGrep Action v5

This is the canonical EnQrypta crypto-scanning action. It runs the pinned OpenGrep
binary on the GitHub-hosted runner and sends observation-only schema `2.0` findings
to the EnQrypta API. Raw JSON and SARIF stay in the workflow artifact; source lines
are never included in the API payload.

The action reports stable rule IDs, repository-relative paths, locations, language,
algorithm family, primitive, usage, scanner severity, confidence, and limited
assessment evidence such as an exact matched parameter set. The API derives commit
identity, fingerprints, classification, quantum risk, migration targets, and
assessment recommendations.

## Consumer workflow

```yaml
name: EnQrypta Crypto Scan

on:
  workflow_dispatch:

permissions:
  contents: read
  id-token: write

jobs:
  scan:
    uses: dhyey-qvh/enqrypta-actions/.github/workflows/enqrypta-opengrep.yml@enqrypta-opengrep-workflow-v5
    with:
      api-url: https://api.enqrypta.example
```

Configure the API to trust the exact reusable-workflow ref and the commit behind the
immutable lightweight v5 tag:

```text
GITHUB_APP_WORKFLOW_REF=dhyey-qvh/enqrypta-actions/.github/workflows/enqrypta-opengrep.yml@enqrypta-opengrep-workflow-v5
GITHUB_OIDC_TRUSTED_WORKFLOW_REF=dhyey-qvh/enqrypta-actions/.github/workflows/enqrypta-opengrep.yml@refs/tags/enqrypta-opengrep-workflow-v5
GITHUB_OIDC_TRUSTED_WORKFLOW_SHA=<40-character-commit-sha>
```

Schema `1.0` and v4 payloads are intentionally incompatible with v5. Publish the v5
tag only after the API accepts schema `2.0`, then update consumers and OIDC trust as
one coordinated cutover.

## Schema 3.0 (unreleased, next major tag)

`main` emits findings schema `3.0`. Published tags `v1`–`v6` are unchanged and
keep sending their own schema. Release the next tag only after the API that
accepts `3.0` is deployed. Schema `3.0` adds, per finding:

- `finding_kind`: `inventory` or `misuse`. Rules with IDs under
  `enqrypta.misuse.*` must set `metadata.finding_kind: misuse` and
  `metadata.cwe` (for example `CWE-327`).
- `site_key`: SHA-256 of finding kind, file, whitespace-normalized matched text
  and its occurrence ordinal in the file. It survives line shifts; source text
  itself is never sent.
- `file_blob_sha`: Git blob SHA-1 of the scanned file (`git hash-object`).
- `unresolved_parameters`: parameters the rule declared but the match did not
  resolve to a literal.

The payload adds `rules_digest`, a SHA-256 over the rule files used.

### Rule metadata and metavariables

Parameters come only from literal values (with Opengrep constant propagation)
captured by these metavariables:

| Metavariable | Evidence |
|---|---|
| `$TRANSFORMATION` | `"AES_256/GCM/NoPadding"` → `parameter_set`, `mode`, `padding` |
| `$KEY_SIZE` / `$KEY_BYTES` | `key_size_bits` |
| `$CURVE` | `parameter_set`, `group_order_bits` for known curves |
| `$PARAMETER_SET` | `parameter_set` |
| `$MODE`, `$PADDING` | `mode`, `padding` |
| `$IV_BITS` / `$IV_BYTES` | `iv_length_bits` |
| `$TAG_BITS` / `$TAG_BYTES` | `tag_length_bits` |
| `$PROTOCOL` | `protocol` (normalized, e.g. `TLS 1.2`) |

`metadata.parameters` lists the evidence fields a rule expects (any of
`key_size_bits`, `group_order_bits`, `parameter_set`, `mode`, `padding`,
`iv_length_bits`, `tag_length_bits`, `protocol`). Static evidence may be set in
metadata: `iv_generation`, `protocol`, `mode`, `padding`.

## Development

```bash
python -m pip install -r requirements-dev.txt
ruff check .
pytest
```
