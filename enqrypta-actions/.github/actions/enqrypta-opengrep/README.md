# EnQrypta Opengrep Action

This composite Action scans the caller repository with the pinned EnQrypta
Opengrep rule pack. Source remains on the GitHub-hosted runner. The Action sends
only normalized finding metadata to the EnQrypta API and retains raw JSON/SARIF
as GitHub Actions artifacts.

## Onboarding A Demo Repository

1. Register the public repository through `POST /api/v1/agent/asset/repos`.
2. Publish an immutable `enqrypta-opengrep-workflow-v1` tag for this monorepo.
3. Configure the API with the exact reusable-workflow ref and commit SHA:

```text
GITHUB_OIDC_TRUSTED_WORKFLOW_REF=qvh-inc/ai-monorepo/.github/workflows/enqrypta-opengrep.yml@refs/tags/enqrypta-opengrep-workflow-v1
GITHUB_OIDC_TRUSTED_WORKFLOW_SHA=<40-character-commit-sha>
```

4. Add this workflow to the demo repository:

```yaml
name: EnQrypta Crypto Scan

on:
  workflow_dispatch:

permissions:
  contents: read
  id-token: write

jobs:
  scan:
    uses: qvh-inc/ai-monorepo/.github/workflows/enqrypta-opengrep.yml@enqrypta-opengrep-workflow-v1
    with:
      api-url: https://api.enqrypta.example
```

The registered repository's default branch must be selected when manually
running the workflow.
