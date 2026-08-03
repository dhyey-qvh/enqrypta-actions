# EnQrypta Opengrep Action

This composite Action scans the caller repository with the pinned EnQrypta
Opengrep rule pack. Source remains on the GitHub-hosted runner. The Action sends
only normalized finding metadata to the EnQrypta API and retains raw JSON/SARIF
as GitHub Actions artifacts.

## Onboarding A Demo Repository

1. Register the public repository through `POST /api/v1/agent/asset/repos`.
2. Publish an immutable `enqrypta-opengrep-workflow-v2` tag for this monorepo.
3. Mirror `.github/workflows/enqrypta-opengrep.yml` to
   `dhyey-qvh/enqrypta-actions` and publish the same immutable tag there.
4. Configure the API with the exact public reusable-workflow ref and its commit SHA:

```text
GITHUB_APP_WORKFLOW_REF=dhyey-qvh/enqrypta-actions/.github/workflows/enqrypta-opengrep.yml@enqrypta-opengrep-workflow-v2
GITHUB_OIDC_TRUSTED_WORKFLOW_REF=dhyey-qvh/enqrypta-actions/.github/workflows/enqrypta-opengrep.yml@refs/tags/enqrypta-opengrep-workflow-v2
GITHUB_OIDC_TRUSTED_WORKFLOW_SHA=<40-character-commit-sha>
```

5. Add this workflow to the demo repository:

```yaml
name: EnQrypta Crypto Scan

on:
  workflow_dispatch:

permissions:
  contents: read
  id-token: write

jobs:
  scan:
    uses: dhyey-qvh/enqrypta-actions/.github/workflows/enqrypta-opengrep.yml@enqrypta-opengrep-workflow-v2
    with:
      api-url: https://api.enqrypta.example
```

The registered repository's default branch must be selected when manually
running the workflow.
