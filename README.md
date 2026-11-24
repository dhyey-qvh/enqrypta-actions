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

## v8: authenticated classification requests

The classification API's `/decide` requires a credential. From
`enqrypta-opengrep-workflow-v8`, every classification request carries a GitHub
Actions OIDC token for the audience `https://classification-api.enqrypta.com`
(input `classification-api-audience`). The job already grants
`id-token: write`; no secret is stored in this public repository or in customer
repositories. On v7 and earlier, classification requests are rejected, so key,
certificate and token findings are dropped; private-key findings are still kept.
Findings schema and API upload are unchanged.

Release order:

1. The classification API accepts GitHub OIDC tokens for that audience and
   requires `job_workflow_ref` to be this repository's
   `enqrypta-opengrep.yml` workflow at an `enqrypta-opengrep-workflow-v*` tag.
2. Tag the merged commit `enqrypta-opengrep-workflow-v8`. Never move v1–v7.
3. In the API deployment, append v8 and its commit SHA to both trust lists and
   set `GITHUB_APP_WORKFLOW_REF` to v8. Repositories move to v8 on reinstall.

## v9: PHP rule packs

`enqrypta-opengrep-workflow-v9` adds `rules/inventory/php.yml` (23 rules) and
`rules/misuse/php.yml` (22 rules, see the action README). PHP files no longer
get the v1–v6 name-based fallback findings: the first v9 scan of a PHP
repository reports call-level `enqrypta.crypto.php.*` / `enqrypta.misuse.php.*`
findings in place of `enqrypta.crypto.<algorithm>` word matches. Lineage records
those sites as removed and new, as v7 did for the first five languages. WordPress
core and Blade templates are no longer scanned. Findings schema, inputs and
outputs are unchanged.

Release order:

1. Tag the merged commit `enqrypta-opengrep-workflow-v9`. Never move v1–v8.
2. In the API deployment, append v9 and its commit SHA to both trust lists and
   set `GITHUB_APP_WORKFLOW_REF` to v9. Repositories move to v9 on reinstall.

## v10: random-number rules and schema 3.1

`enqrypta-opengrep-workflow-v10` adds random-number rules to every language pack
(see the action README): `enqrypta.crypto.<lang>.csprng` and
`enqrypta.crypto.<lang>.aws-kms-generate-random` inventory, and
`enqrypta.misuse.<lang>.short-random-token` (CWE-331). The payload moves to
findings schema `3.1`, which adds optional `random_source`, `output_length_bits`
and `token_purpose` to `assessment_evidence`. Inputs and outputs are unchanged.
The first v10 scan adds `CSPRNG` and `AWS-KMS-RANDOM` assets; lineage records the
rule change as a reclassification, not a code change.

Release order:

1. Deploy the API that accepts schema `3.1` (it keeps accepting `2.0` and `3.0`
   from v5–v9). An API without it rejects every v10 payload.
2. Tag the merged commit `enqrypta-opengrep-workflow-v10`. Never move v1–v9.
3. In the API deployment, append v10 and its commit SHA to both trust lists and
   set `GITHUB_APP_WORKFLOW_REF` to v10. Repositories move to v10 on reinstall.

For correlated launches, the API allows 15 minutes for findings delivery after an
exact successful GitHub run's `updated_at`, falling back to 90 minutes from launch
creation when no execution callback is received. Expired delivery returns
`code_scan_results_not_delivered`; it never automatically dispatches another scan.
Uncertain submissions remain subject to reconciliation rather than this retry path.
