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

## Schema 3.0 (v7)

The v7 source emits findings schema `3.0`. Published tags `v1`–`v6` are
unchanged and keep sending their own schema. Tag v7 only after the API that
accepts `3.0` is deployed; the release order is in the repository README. Schema `3.0` adds, per finding:

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

### Rule packs

`main` scans with every rule file under `rules/`:

| Path | What it covers |
|---|---|
| `rules/inventory/<language>.yml` | Crypto API calls in Java, Python, Go, JS/TS and Rust: algorithm, purpose (`usage`) and parameters |
| `rules/misuse/<language>.yml` | Weak ciphers (DES, 3DES, RC4, Blowfish), ECB, MD5/SHA-1 in signatures or MACs, non-crypto RNG for secrets, constant IVs and keys, disabled TLS verification, TLS below 1.2. Each carries a CWE |
| `rules/fallback/generic.yml` | The v1–v6 name-based regex rules, unchanged IDs, for other source and config files (Kotlin, C#, C/C++, PHP, YAML, ...). Files of the five languages are excluded, as are prose and lockfiles (`*.md`, `*.txt`, `*.lock`, ...), where an algorithm name is a mention, not a use |

Inventory rules only emit algorithms the API's catalog classifies (RSA, ECDSA,
ECDH, X25519, Ed25519, DH, AES, SHA-1, MD5, ML-KEM, ML-DSA), because inventory
findings become crypto assets. Purpose comes from the call: RSA key generation
alone is `usage: unknown`, RSA `encrypt` is `encryption`, RSA `sign` is
`signing`.

Known limits:

- JCA algorithm names (`Cipher.getInstance`) are matched on string literals; an
  algorithm passed through a variable is not detected at that call.
- Go `math/rand` is flagged only in files that do not also import `crypto/rand`
  (Go name resolution cannot tell the two apart).
- Rust bare type names (`SigningKey`) are matched only in files that `use` that
  exact type from its crate, scoped from the import to the end of the file.
- Opengrep's default ignores skip `tests/` and similar directories.
- Constant keys and IVs are reported as `SYMMETRIC-KEY` / `SYMMETRIC-CIPHER`:
  the cipher is often not known at the call that fixes the key or IV.

### Rule metadata and metavariables

Parameters come from literal values (with Opengrep constant propagation) or
from identifiers that name a known constant (`ec.SECP384R1()`, `AES.MODE_ECB`,
`tls.VersionTLS10`, `MLKEMParameterSpec.ml_kem_768`, `Aes256Gcm`), captured by
these metavariables:

| Metavariable | Evidence |
|---|---|
| `$TRANSFORMATION` | `"AES_256/GCM/NoPadding"` → `parameter_set`, `mode`, `padding` |
| `$CIPHER` | `"aes-256-gcm"`, `Cipher::aes_128_cbc()`, `Aes256Gcm` → `parameter_set` (`AES-256`, cipher and key size only), `key_size_bits`, `mode` |
| `$KEY_SIZE` / `$KEY_BYTES` | `key_size_bits` |
| `$CURVE` | `parameter_set`, `group_order_bits` for known curves |
| `$PARAMETER_SET` | `parameter_set` (`ML-KEM-768` from literals or BouncyCastle/RustCrypto constants) |
| `$MODE`, `$PADDING` | `mode`, `padding` |
| `$IV_BITS` / `$IV_BYTES` | `iv_length_bits` |
| `$TAG_BITS` / `$TAG_BYTES` | `tag_length_bits` |
| `$PROTOCOL` | `protocol` (normalized, e.g. `TLS 1.2`) |

`metadata.parameters` lists the evidence fields a rule expects (any of
`key_size_bits`, `group_order_bits`, `parameter_set`, `mode`, `padding`,
`iv_length_bits`, `tag_length_bits`, `protocol`); a declared field the match
does not resolve is reported in `unresolved_parameters`. Static evidence for
APIs that fix a value may be set in metadata: `iv_generation`, `protocol`,
`mode`, `padding`, `parameter_set`, and integer `key_size_bits`,
`tag_length_bits`, `iv_length_bits`. Metadata overrides values guessed from the
matched name.

### Rule corpus

Every language-pack rule has `ruleid:` and `ok:` fixtures in
`tests/rules/<pack>/<language>.*`. `tests/test_rule_packs.py` checks the rule
contract and, with `OPENGREP_BIN` set to the pinned binary, runs
`opengrep --test` and a full scan of the corpus through the normalizer. CI
installs the version and checksum pinned in `action.yml`.

## Development

```bash
python -m pip install -r requirements-dev.txt
ruff check .
pytest                                   # corpus tests skip without OPENGREP_BIN
OPENGREP_BIN=/path/to/opengrep pytest    # pinned Linux x86_64 binary from action.yml
```
