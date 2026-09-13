# Agent-Secure

A small deterministic CLI that turns an externally managed security policy and
pinned scanner binaries into one JSON verdict: **pass**, **findings**, or
**incomplete** (exit codes `0`, `1`, `2`). It does not reimplement vulnerability
databases — it orchestrates pinned external scanners and normalizes their
output without ever echoing secret values.

## Commands

```sh
agent-secure version
agent-secure doctor --root <repo> --policy <policy.json>   # verify scanners, no scan; exits 2 on any error
agent-secure scan   --root <repo> --policy <policy.json>   # snapshot + scan; JSON report on stdout
```

## Policy

The policy is written by the operator, **not** by the scanned repository. The
snapshot stage deliberately excludes `.gitleaks.toml`, `.gitleaksignore`, and
`osv-scanner.toml` so an untrusted checkout cannot weaken its own gate, and it
refuses to scan through symlinks. Tools are pinned by absolute path and
SHA-256; a mismatched digest aborts the scan as `incomplete`.```json
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
access-controlled** location, replace the placeholder digests with the SHA-256
of the exact binaries you ship (`shasum -a 256 <binary>`), and treat the file
as operator-owned configuration. Unknown fields are rejected, so keep it
exactly to the schema.

`allow_network: false` runs OSV-Scanner with `--offline-vulnerabilities` from a
pre-fetched local database; set it to `true` only for approved data.

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

`gitleaks dir <root> --no-banner --redact --report-format json` must exit `1`
with a JSON array for findings; `osv-scanner scan source --format=json` must
exit `1` with a results object. Any other non-zero exit is a tool failure.

## Development

```sh
go test ./...
go vet ./...
```

Tests use synthetic scanner fixtures only — no network, no real credentials.
