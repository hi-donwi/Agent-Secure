# Agent-Secure

A small deterministic CLI that turns an externally managed security policy and
pinned scanner binaries into one JSON verdict: **pass**, **findings**, or
**incomplete** (exit codes `0`, `1`, `2`). It does not reimplement vulnerability
databases — it orchestrates pinned external scanners and normalizes their
output without ever echoing secret values.

## Commands

```sh
agent-secure version
agent-secure doctor --root <repo> --policy <policy.json>   # verify scanners, no scan; 0 = verified, 2 = error
agent-secure scan   --root <repo> --policy <policy.json>   # snapshot + scan; JSON report on stdout
```

## Policy

The policy is written by the operator, **not** by the scanned repository. The
snapshot stage deliberately excludes `.gitleaks.toml`, `.gitleaksignore`, and
`osv-scanner.toml` so an untrusted checkout cannot weaken its own gate, and it
refuses to scan through symlinks. Tools are pinned by absolute path and
SHA-256; a mismatched digest aborts the scan as `incomplete`.

```json
{
  "version": 1,
  "allow_network": false,
  "scanners": ["gitleaks", "osv-scanner"],
  "tools": {
    "gitleaks":    { "path": "/usr/local/bin/gitleaks",    "sha256": "<64 hex>" },
    "osv-scanner": { "path": "/usr/local/bin/osv-scanner", "sha256": "<64 hex>" }
  }
}
```

`policies/example.json` is a starting template: copy it to a **private,
access-controlled** location and treat it as operator-owned configuration.
Unknown fields are rejected, so keep it exactly to the schema. Allow entries,
when present, must name `scanner`, `id`, `reason`, and `expires`
(`YYYY-MM-DD`); `file` is optional and must stay inside the repository.

Generate a policy with real paths and digests for the locally installed
scanners instead of computing them by hand:

```sh
scripts/bootstrap-policy.sh > /secure/location/policy.json   # operator-owned
agent-secure doctor --root <repo> --policy /secure/location/policy.json
```

Regenerate after every scanner upgrade — a stale digest is reported by
`doctor` as an error, never silently ignored.

`allow_network: false` runs OSV-Scanner with `--offline-vulnerabilities` from
a pre-fetched local database. Seed the cache once per machine/runner (the
download needs a scan target that has at least one lockfile):

```sh
osv-scanner scan source --offline-vulnerabilities --download-offline-databases \
  --format json -r <repo-with-lockfiles>
```

Set `allow_network: true` only for approved data; scanners otherwise run
without network access.

## Report contract

- `status`: `pass` | `findings` | `incomplete`
- A scanner that **errors, times out, or produces an unreadable report is
  `incomplete` (exit 2), never `pass`** — a failed scan cannot become a green
  gate.
- Findings carry only `id`, `scanner`, `severity`, `file`, `line`. Secret
  values, match snippets, and scanner stderr are deliberately dropped.
- Coverage is stated in the report: Git-visible working files only. Excluded
  files, Git history, the agent runtime sandbox, and live systems are not
  scanned.

## Verifying a scanner release

```sh
shasum -a 256 /path/to/gitleaks   # pin this digest in the policy
```

`gitleaks dir <root> --no-banner --redact --ignore-gitleaks-allow
--report-format json` must exit `1` with a JSON array for findings;
`osv-scanner scan source --format=json` must exit `1` with a results object.
Any other non-zero exit is a tool failure.

## Gating CI (reusable workflow)

`.github/workflows/agent-secure-gate.yml` is a `workflow_call` template that
product repos call after tagging a release. It downloads the engine binary and
both scanners, digest-verifies everything, generates the policy at runtime
(living only for the job), and fails the job on any verdict other than `pass`:

```yaml
jobs:
  security:
    uses: hi-donwi/Agent-Secure/.github/workflows/agent-secure-gate.yml@<PINNED_ENGINE_SHA>
    with:
      root: .
      engine_version: v0.1.2
      engine_sha256: 977bf6ea754b3a83619bdacc29164ad84b674d7ab9c41fc4d61e3fe6ed206071  # linux/amd64
      gitleaks_version: 8.30.1
      osv_scanner_version: 2.5.1
      allow_json: '[]'  # operator-scoped allow entries; reason and expiry are mandatory
```

Pin the workflow by commit SHA — a mutable `@main` would let the gate itself
be modified after review. `allow_network` is `true` inside the ephemeral
runner (OSV advisory lookup only); keep local runs offline per the policy
default.

## Development

```sh
go test ./...
go vet ./...
```

Tests use synthetic scanner fixtures only — no network, no real credentials.
