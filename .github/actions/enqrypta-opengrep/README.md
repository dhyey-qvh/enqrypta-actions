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

## Development

```bash
python -m pip install -r requirements-dev.txt
ruff check .
pytest
```
