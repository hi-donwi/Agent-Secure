package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
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

func TestCleanOSVReportPasses(t *testing.T) {
	tool := scannerFixture(t, "printf '{\"results\":[]}'\n")
	r := scan(context.Background(), t.TempDir(), Policy{Version: 1, Scanners: []string{"osv-scanner"}, Tools: map[string]Tool{"osv-scanner": tool}}, "fixture")
	if r.ExitCode() != 0 {
		t.Fatalf("clean report failed: %+v", r)
	}
}
