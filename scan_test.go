package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func scannerFixture(t *testing.T, script string) Tool {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scanner")
	data := []byte("#!/bin/sh\n" + script)
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return Tool{Path: path, SHA256: hex.EncodeToString(sum[:])}
}

func TestVersionReportsCurrentRelease(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := execute([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version failed: code=%d stderr=%q", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "agent-secure 0.1.3-dev" {
		t.Fatalf("stale version output: %q", stdout.String())
	}
}

func TestMissingRequiredScannerIsIncomplete(t *testing.T) {
	r := scan(context.Background(), t.TempDir(), Policy{Version: 1, Scanners: []string{"gitleaks"}, Tools: map[string]Tool{}}, "fixture")
	if r.Status != "incomplete" || r.ExitCode() != 2 {
		t.Fatalf("unexpected report: %+v", r)
	}
}

func TestChangedScannerDigestIsRejected(t *testing.T) {
	tool := scannerFixture(t, "exit 0\n")
	tool.SHA256 = strings.Repeat("0", 64)
	r := scan(context.Background(), t.TempDir(), Policy{Version: 1, Scanners: []string{"gitleaks"}, Tools: map[string]Tool{"gitleaks": tool}}, "fixture")
	if r.ExitCode() != 2 {
		t.Fatal("untrusted scanner accepted")
	}
}

func TestSecretValuesNeverEnterNormalizedReport(t *testing.T) {
	tool := scannerFixture(t, `while [ "$1" != "--report-path" ]; do shift; done
shift
printf '%s' '[{"RuleID":"synthetic","File":"example.txt","StartLine":4,"Secret":"DO_NOT_DISCLOSE","Match":"DO_NOT_DISCLOSE"}]' > "$1"
exit 1
`)
	r := scan(context.Background(), t.TempDir(), Policy{Version: 1, Scanners: []string{"gitleaks"}, Tools: map[string]Tool{"gitleaks": tool}}, "fixture")
	data, _ := json.Marshal(r)
	if r.ExitCode() != 1 || strings.Contains(string(data), "DO_NOT_DISCLOSE") || len(r.Findings) != 1 {
		t.Fatalf("bad normalized result: %s", data)
	}
}

func TestGitleaksFindingPathMustStayLocal(t *testing.T) {
	tool := scannerFixture(t, `while [ "$1" != "--report-path" ]; do shift; done
shift
printf '%s' '[{"RuleID":"synthetic","File":"../outside.txt","StartLine":4}]' > "$1"
exit 1
`)
	r := scan(context.Background(), t.TempDir(), Policy{Version: 1, Scanners: []string{"gitleaks"}, Tools: map[string]Tool{"gitleaks": tool}}, "fixture")
	if r.ExitCode() != 2 {
		t.Fatalf("escaped finding path accepted: %+v", r)
	}
}

func TestMalformedScannerReportIsIncomplete(t *testing.T) {
	tool := scannerFixture(t, "printf 'not json'\nexit 0\n")
	r := scan(context.Background(), t.TempDir(), Policy{Version: 1, Scanners: []string{"osv-scanner"}, Tools: map[string]Tool{"osv-scanner": tool}}, "fixture")
	if r.ExitCode() != 2 {
		t.Fatal("malformed report passed")
	}
}

func TestOSVFindingsAreNormalized(t *testing.T) {
	tool := scannerFixture(t, `printf '%s' '{"results":[{"packages":[{"vulnerabilities":[{"id":"GHSA-synthetic"}]}]}]}'
exit 1
`)
	r := scan(context.Background(), t.TempDir(), Policy{Version: 1, Scanners: []string{"osv-scanner"}, Tools: map[string]Tool{"osv-scanner": tool}}, "fixture")
	if r.ExitCode() != 1 || len(r.Findings) != 1 || r.Findings[0].ID != "GHSA-synthetic" {
		t.Fatalf("bad report: %+v", r)
	}
}

func TestScannerErrorsCannotBecomePass(t *testing.T) {
	tool := scannerFixture(t, "printf '{}'\nexit 42\n")
	r := scan(context.Background(), t.TempDir(), Policy{Version: 1, Scanners: []string{"osv-scanner"}, Tools: map[string]Tool{"osv-scanner": tool}}, "fixture")
	if r.ExitCode() != 2 {
		t.Fatal("scanner error passed")
	}
}

func TestScannerLogsAreNeverEchoedEvenWithDebugEnv(t *testing.T) {
	tool := scannerFixture(t, "printf 'SECRET_IN_STDERR' >&2\nexit 42\n")
	t.Setenv("AS_DEBUG", "1")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	policy := Policy{Version: 1, Scanners: []string{"osv-scanner"}, Tools: map[string]Tool{"osv-scanner": tool}}
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := exec.Command("git", "-C", root, "init", "-qb", "main").Run(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	code := execute([]string{"scan", "--root", root, "--policy", policyPath}, &stdout, &stderr)
	if code != 2 || strings.Contains(stderr.String(), "SECRET_IN_STDERR") {
		t.Fatalf("scanner stderr leaked: code=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
}

func TestCleanOSVReportPasses(t *testing.T) {
	tool := scannerFixture(t, "printf '{\"results\":[]}'\n")
	r := scan(context.Background(), t.TempDir(), Policy{Version: 1, Scanners: []string{"osv-scanner"}, Tools: map[string]Tool{"osv-scanner": tool}}, "fixture")
	if r.ExitCode() != 0 {
		t.Fatalf("clean report failed: %+v", r)
	}
}

func TestPolicyAllowSuppressesAndDiscloses(t *testing.T) {
	tool := scannerFixture(t, `while [ "$1" != "--report-path" ]; do shift; done
shift
printf '%s' '[{"RuleID":"synthetic","File":"fixtures.txt","StartLine":4}]' > "$1"
exit 1
`)
	policy := Policy{Version: 1, Scanners: []string{"gitleaks"},
		Tools: map[string]Tool{"gitleaks": tool},
		Allow: []Allow{{Scanner: "gitleaks", ID: "synthetic", File: "fixtures.txt", Reason: "test fixture, not a credential", Expires: "2999-12-31"}}}
	r := scan(context.Background(), t.TempDir(), policy, "fixture")
	if r.ExitCode() != 0 || len(r.Findings) != 0 || len(r.Allowed) != 1 || r.Allowed[0].Finding.File != "fixtures.txt" || r.Allowed[0].Reason == "" {
		t.Fatalf("allow list not applied: %+v", r)
	}
	data, _ := json.Marshal(r)
	if !strings.Contains(string(data), "fixtures.txt") {
		t.Fatal("allowed finding must stay visible in the report")
	}
}

func TestExpiredAllowStopsSuppressing(t *testing.T) {
	tool := scannerFixture(t, `while [ "$1" != "--report-path" ]; do shift; done
shift
printf '%s' '[{"RuleID":"synthetic","File":"a.txt","StartLine":1}]' > "$1"
exit 1
`)
	policy := Policy{Version: 1, Scanners: []string{"gitleaks"},
		Tools: map[string]Tool{"gitleaks": tool},
		Allow: []Allow{{Scanner: "gitleaks", ID: "synthetic", Reason: "historical", Expires: "2000-01-01"}}}
	r := scan(context.Background(), t.TempDir(), policy, "fixture")
	if r.ExitCode() != 1 || len(r.Findings) != 1 || len(r.Allowed) != 0 {
		t.Fatalf("expired allow still suppressed: %+v", r)
	}
}

func TestAllowWithoutReasonIsInvalid(t *testing.T) {
	p := Policy{Version: 1, Scanners: []string{"gitleaks"}, Tools: map[string]Tool{},
		Allow: []Allow{{Scanner: "gitleaks", ID: "x", Expires: "2999-12-31"}}}
	if err := validatePolicy(p); err == nil {
		t.Fatal("allow without reason accepted")
	}
}

func TestAllowWithoutExpiryIsInvalid(t *testing.T) {
	p := Policy{Version: 1, Scanners: []string{"gitleaks"}, Tools: map[string]Tool{},
		Allow: []Allow{{Scanner: "gitleaks", ID: "x", Reason: "historical"}}}
	if err := validatePolicy(p); err == nil {
		t.Fatal("allow without expiry accepted")
	}
}

func TestAllowRequiresKnownScannerAndLocalFile(t *testing.T) {
	for _, allow := range []Allow{
		{Scanner: "unknown", ID: "x", Reason: "historical", Expires: "2999-12-31"},
		{Scanner: "gitleaks", ID: "", Reason: "historical", Expires: "2999-12-31"},
		{Scanner: "gitleaks", ID: "x", File: "../escape", Reason: "historical", Expires: "2999-12-31"},
		{Scanner: "gitleaks", ID: "x", File: "/tmp/escape", Reason: "historical", Expires: "2999-12-31"},
		{Scanner: "gitleaks", ID: "x", Reason: "   ", Expires: "2999-12-31"},
	} {
		p := Policy{Version: 1, Scanners: []string{"gitleaks"}, Tools: map[string]Tool{},
			Allow: []Allow{allow}}
		if err := validatePolicy(p); err == nil {
			t.Fatalf("invalid allow accepted: %+v", allow)
		}
	}
}

func TestPolicyWithoutPinnedToolIsRejected(t *testing.T) {
	if err := validatePolicy(Policy{Version: 1, Scanners: []string{"gitleaks"}, Tools: map[string]Tool{}}); err == nil {
		t.Fatal("scanner without pinned tool accepted")
	}
}

func TestFutureAllowExpiresLater(t *testing.T) {
	tool := scannerFixture(t, `while [ "$1" != "--report-path" ]; do shift; done
shift
printf '%s' '[{"RuleID":"synthetic","File":"b.txt","StartLine":2}]' > "$1"
exit 1
`)
	policy := Policy{Version: 1, Scanners: []string{"gitleaks"},
		Tools: map[string]Tool{"gitleaks": tool},
		Allow: []Allow{{Scanner: "gitleaks", ID: "synthetic", Reason: "still valid", Expires: "2999-12-31"}}}
	r := scan(context.Background(), t.TempDir(), policy, "fixture")
	if r.ExitCode() != 0 || len(r.Allowed) != 1 {
		t.Fatalf("future-dated allow not applied: %+v", r)
	}
}

func TestGitleaksIgnoresRepositoryInlineAllowComments(t *testing.T) {
	tool := scannerFixture(t, `found=
for arg in "$@"; do
  if [ "$arg" = "--ignore-gitleaks-allow" ]; then found=1; fi
done
if [ -z "$found" ]; then exit 42; fi
while [ "$1" != "--report-path" ]; do shift; done
shift
printf '%s' '[]' > "$1"
`)
	r := scan(context.Background(), t.TempDir(), Policy{Version: 1, Scanners: []string{"gitleaks"}, Tools: map[string]Tool{"gitleaks": tool}}, "fixture")
	if r.ExitCode() != 0 {
		t.Fatalf("gitleaks was not run with --ignore-gitleaks-allow: %+v", r)
	}
}
