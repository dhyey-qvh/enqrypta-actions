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

### Schema 3.1 (v10): random-number evidence

The v10 source emits schema `3.1`, which adds three optional
`assessment_evidence` fields for random-number findings:

- `random_source`: `os`, `library`, `aws-kms` (from rule metadata; `aws-cloudhsm`
  and `unknown` are accepted but no rule sets them yet).
- `output_length_bits`: requested length, from a literal `$OUT_BYTES` / `$OUT_BITS`.
- `token_purpose`: `session_token`, `csrf`, `api_key`, `password_reset`, `nonce`,
  `otp` or `other`, read from the name the value is assigned to (a bound
  `$TARGET`, else the assignment on the matched line). Set only for findings with
  `primitive: random`; values not assigned to a secret-like name get none.

Tag v10 only after the API that accepts `3.1` is deployed.

### Rule packs

`main` scans with every rule file under `rules/`:

| Path | What it covers |
|---|---|
| `rules/inventory/<language>.yml` | Crypto API calls in Java, Python, Go, JS/TS, Rust and PHP: algorithm, purpose (`usage`) and parameters |
| `rules/misuse/<language>.yml` | Weak ciphers (DES, 3DES, RC4, Blowfish), ECB, MD5/SHA-1 in signatures or MACs, non-crypto RNG for secrets, random tokens under 16 bytes, constant IVs and keys, disabled TLS verification, TLS below 1.2. Each carries a CWE. PHP adds more (below) |
| `rules/artifacts/generic.yml` | PEM blocks, OpenSSH public keys and JWTs in any file, classified by the classification API (below) |
| `rules/fallback/generic.yml` | The v1–v6 name-based regex rules, unchanged IDs, for other source and config files (Kotlin, C#, C/C++, YAML, ...). Files of the six languages are excluded, as are prose and lockfiles (`*.md`, `*.txt`, `*.lock`, ...), where an algorithm name is a mention, not a use |

Inventory rules only emit algorithms the API's catalog classifies (RSA, ECDSA,
ECDH, X25519, Ed25519, DH, AES, SHA-1, MD5, ML-KEM, ML-DSA, CSPRNG,
AWS-KMS-RANDOM), because inventory
findings become crypto assets. Purpose comes from the call: RSA key generation
alone is `usage: unknown`, RSA `encrypt` is `encryption`, RSA `sign` is
`signing`.

Random-number rules (all six languages):

| Rule | What |
|---|---|
| `enqrypta.crypto.<lang>.csprng` | Secure generators: Python `secrets`, `os.urandom`, `SystemRandom`; Node `crypto.randomBytes`/`randomInt`/`randomUUID`, `getRandomValues`; Java `SecureRandom`; Go `crypto/rand`; PHP `random_bytes`/`random_int`/`sodium_randombytes_buf` (`csprng-openssl`: `openssl_random_pseudo_bytes`); Rust `OsRng`, `getrandom` (`csprng-thread-rng`: `rand::rng()`, `thread_rng()`, `rand::random()`). Algorithm `CSPRNG` |
| `enqrypta.crypto.<lang>.aws-kms-generate-random` | AWS KMS `GenerateRandom` through boto3, JS SDK v2/v3, Java SDK v1/v2, Go SDK v2, PHP and Rust SDKs. Algorithm `AWS-KMS-RANDOM`, `random_source: aws-kms` |
| `enqrypta.misuse.<lang>.short-random-token` | CWE-331: under 16 bytes requested for a value assigned to a token-like name (`token`, `session`, `sid`, `csrf`, `otp`, `api_key`, `secret`, `reset`, `verif`). Python `secrets.token_hex`/`token_urlsafe` are flagged under 16 bytes whatever the name; `token_bytes(12)` for a nonce is not |

Known limits:

- Random-token length is read from literals only; Go `make([]byte, n)` and
  Rust `[0u8; N]` buffers are recognised only when declared and filled in the
  same function. `token_purpose` reads the first line of a wrapped statement.
- `generate_random` / `generateRandom` are matched by method name with a
  `NumberOfBytes` argument (Python, PHP, JS v2) or by the request type (JS v3,
  Java, Go, Rust); a KMS call routed to a CloudHSM custom key store is reported
  as `aws-kms`.

- JCA algorithm names (`Cipher.getInstance`) are matched on string literals; an
  algorithm passed through a variable is not detected at that call.
- Go `math/rand` is flagged only in files that do not also import `crypto/rand`
  (Go name resolution cannot tell the two apart).
- Rust bare type names (`SigningKey`) are matched only in files that `use` that
  exact type from its crate, scoped from the import to the end of the file.
- Opengrep's default ignores skip `tests/` and similar directories.
- Constant keys and IVs are reported as `SYMMETRIC-KEY` / `SYMMETRIC-CIPHER`:
  the cipher is often not known at the call that fixes the key or IV.

### PHP

Inventory covers ext-openssl, ext-sodium, `hash`/`mhash`, phpseclib 2 and 3,
Laravel encryption (`Crypt`, `encrypt()`, `Encrypter`, `app.cipher`, Eloquent
`encrypted` casts), Laravel Passport, firebase/php-jwt, lcobucci/jwt,
web-token/jwt-framework and defuse/php-encryption. Besides the shared misuse
classes, PHP reports:

| Rule | CWE | What |
|---|---|---|
| `weak-key-size` | 326 | RSA/DH/DSA below 2048 bits, curves below 224 bits |
| `rsa-pkcs1v15-encryption` | 780 | RSA encryption with PKCS#1 v1.5 (the `openssl_public_encrypt` default) or no padding |
| `legacy-default-cipher` | 327 | `openssl_seal`/`openssl_open` without a cipher (RC4 before PHP 8.0), `openssl_pkcs7_encrypt` without a cipher or with RC2 |
| `insecure-mac-compare` | 208 | HMAC, `crypt()` or signature hashes compared with `==`/`===`/`strcmp` instead of `hash_equals` |
| `jwt-unsafe-verification` | 347 | php-jwt v5 allowing HMAC and RSA/ECDSA together (algorithm confusion), lcobucci unsecured signer |
| `mcrypt-use` | 327 | Any `mcrypt_*` call |
| `db-tls-verify-disabled` | 295 | MySQL server-certificate verification off, Postgres `sslmode` `disable`/`allow` |
| `weak-kdf` | 916 | PBKDF2 with MD5/SHA-1 or under 100,000 iterations, bcrypt cost under 10, MD5/DES `crypt()` salts |
| `weak-password-hash` | 916 | `md5`/`sha1`/`hash` of a password variable |
| `hardcoded-salt` | 760 | Literal salts in PBKDF2, `sodium_crypto_pwhash`, `crypt`, `password_hash` |

`sha1-signature` also reports `openssl_sign` without an algorithm (it defaults
to SHA-1) and `'digest_alg' => 'sha1'` certificate configuration;
`tls-verify-disabled` covers cURL, Guzzle, Symfony HttpClient, stream contexts,
PHPMailer, the Laravel HTTP client and the WordPress HTTP API.

Matching works for `md5()`, `MD5()` and `\md5()`, PHP 8 named arguments, and
values passed through a variable or class constant. Limits:

- `use` aliases are not resolved, so classes are matched by their last name
  segment (`RSA::createKey`, `Crypt::encrypt`); `use X as Y` is not followed.
- `openssl_sign`/`openssl_verify` and S/MIME signing are reported as RSA with
  confidence 0.7, and `openssl_pkey_derive` as ECDH with confidence 0.8: the key
  type is not visible at the call.
- Laravel `encrypt()`/`decrypt()` helpers are matched by name (confidence 0.8);
  a project function with the same name is also reported.
- Postgres `sslmode => 'prefer'` (Laravel's default) is not reported.
- WordPress core (`wp-includes/`, `wp-admin/`) and Blade templates are not
  scanned.

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
| `$JWS_ALG` | `parameter_set`, `group_order_bits` from a JWS ECDSA algorithm (`ES384` → `P-384`, lcobucci `Ecdsa\Sha512` → `P-521`) |
| `$OUT_BYTES` / `$OUT_BITS` | `output_length_bits` (random-number rules) |
| `$TARGET` | `token_purpose` (random-number rules that match the assignment) |

`metadata.parameters` lists the evidence fields a rule expects (any of
`key_size_bits`, `group_order_bits`, `parameter_set`, `mode`, `padding`,
`iv_length_bits`, `tag_length_bits`, `protocol`, `output_length_bits`); a declared field the match
does not resolve is reported in `unresolved_parameters`. Static evidence for
APIs that fix a value may be set in metadata: `iv_generation`, `protocol`,
`mode`, `padding`, `parameter_set`, `random_source`, and integer `key_size_bits`,
`tag_length_bits`, `iv_length_bits`. Metadata overrides values guessed from the
matched name.

### Artifact classification

`rules/artifacts/generic.yml` locates PEM blocks, OpenSSH public keys and JWTs in
any file. The action sends each distinct value to the EnQrypta classification
API (`classification-api-url`, on by default) and fills the finding from the
API's parsed `inventory`: algorithm, key size, curve or parameter set, and
whether it is a private key.

- **What leaves the runner:** the key, certificate or SSH key text, private keys
  included, and for a JWT only its header (`<header>..`). Nothing else from the
  repository is sent, and the value is never written to the findings payload;
  the finding carries its SHA-256 in `classification.artifact_sha256`.
- **Parser facts only:** requests carry no questions, so the API's model is
  never asked. A value the parser cannot identify is not reported as an
  inventory finding.
- **Private keys:** `enqrypta.misuse.artifact.private-key` (CWE-321) is reported
  from the PEM label alone, so it survives an API outage; the API adds the
  algorithm and key size when it can parse the key.
- **Failure handling:** a failed or blocked request never fails the scan.
  Requests stop after 3 consecutive failures; at most 200 distinct values of up
  to 16 KB are sent per scan.
- Set `classification-api-url: ""` to skip classification.

Classified findings add `classification` (`status`, `source`, `model_version`,
`artifact_sha256`, `is_private_key`, `encrypted`, `artifact_class`, `container`,
`evidence_strength`). The API must accept this field before the tag that sends
it is published.

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
