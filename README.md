# EnQrypta Actions

Canonical GitHub Actions and reusable workflows for EnQrypta.

- [OpenGrep action v5](.github/actions/enqrypta-opengrep/README.md)
- Reusable workflow: `.github/workflows/enqrypta-opengrep.yml`

Tags are immutable release boundaries. Consumers should pin the reusable workflow
to `enqrypta-opengrep-workflow-v5`; the workflow pins its internal composite action
to the same tag.

The next `enqrypta-opengrep-workflow-v6` source adds an optional `code-scan-id`
input. It binds the GitHub OIDC execution to an existing Enqrypta code launch
before scanning and includes the same ID when publishing findings. Existing
standalone and nightly calls can omit the input.

This source change does not publish the v6 tag. Release v6 before selecting it
in a deployment. Update `GITHUB_APP_WORKFLOW_REF`, the corresponding trusted OIDC
workflow ref and pinned workflow SHA together, and update each installed customer
workflow through its normal reviewed change. Do not move the existing v5 tag or
broaden OIDC trust to bypass the upgrade. The API keeps its existing v5 defaults;
its durable launch path rejects installed workflows that cannot forward the
launch ID. No live scan or release is performed by these source changes.

## v7: schema 3.0 and language rule packs

The `enqrypta-opengrep-workflow-v7` source emits findings schema `3.0` and scans
with per-language rule packs (see the action README). Inputs and outputs are
unchanged from v6. This source change does not publish the v7 tag.

Release order:

1. Deploy the API that accepts schema `3.0` (ai-monorepo migration
   `0041_code_finding_lineage` runs first). It keeps accepting `2.0` from v5/v6.
2. Tag the merged commit `enqrypta-opengrep-workflow-v7`. Never move v1–v6.
3. In the API deployment, add v7 next to v6. Both trust variables take a
   comma-separated list paired by position, so each ref is pinned to its own SHA:

   ```text
   GITHUB_OIDC_TRUSTED_WORKFLOW_REF=<...>@refs/tags/enqrypta-opengrep-workflow-v6,<...>@refs/tags/enqrypta-opengrep-workflow-v7
   GITHUB_OIDC_TRUSTED_WORKFLOW_SHA=<v6 commit sha>,<v7 commit sha>
   GITHUB_APP_WORKFLOW_REF=<...>@enqrypta-opengrep-workflow-v7
   ```

   Repositories installed on v6 keep scanning and launching correlated scans;
   they move to v7 when their workflow is reinstalled.

For correlated launches, the API allows 15 minutes for findings delivery after an
exact successful GitHub run's `updated_at`, falling back to 90 minutes from launch
creation when no execution callback is received. Expired delivery returns
`code_scan_results_not_delivered`; it never automatically dispatches another scan.
Uncertain submissions remain subject to reconciliation rather than this retry path.
