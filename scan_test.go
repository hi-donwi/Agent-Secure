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
	if strings.TrimSpace(stdout.String()) != "agent-secure 0.1.4-dev" {
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

func TestScannerSymlinkIsRejected(t *testing.T) {
	real := scannerFixture(t, "exit 0\n")
	link := filepath.Join(t.TempDir(), "gitleaks")
	if err := os.Symlink(real.Path, link); err != nil {
		t.Fatal(err)
	}
	tool := Tool{Path: link, SHA256: real.SHA256}
	r := scan(context.Background(), t.TempDir(), Policy{Version: 1, Scanners: []string{"gitleaks"}, Tools: map[string]Tool{"gitleaks": tool}}, "fixture")
	if r.ExitCode() != 2 {
		t.Fatalf("symlink scanner accepted: %+v", r)
	}
	if r.Checks[0].Detail != "scanner is missing, non-executable or a symlink" {
		t.Fatalf("unexpected detail: %+v", r.Checks[0])
	}
}

func TestBootstrapPolicyResolvesSymlinkToRegularFile(t *testing.T) {
	dir := t.TempDir()
	gitleaks := scannerFixture(t, "exit 0\n")
	osv := scannerFixture(t, "exit 0\n")
	linkG := filepath.Join(dir, "gitleaks")
	linkO := filepath.Join(dir, "osv-scanner")
	if err := os.Symlink(gitleaks.Path, linkG); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(osv.Path, linkO); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("scripts/bootstrap-policy.sh", linkG, linkO).Output()
	if err != nil {
		t.Fatalf("bootstrap failed: %v\n%s", err, out)
	}
	var policy Policy
	if err := json.Unmarshal(out, &policy); err != nil {
		t.Fatalf("invalid policy JSON: %v\n%s", err, out)
	}
	wantG, err := filepath.EvalSymlinks(gitleaks.Path)
	if err != nil {
		t.Fatal(err)
	}
	wantO, err := filepath.EvalSymlinks(osv.Path)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Tools["gitleaks"].Path != wantG {
		t.Fatalf("gitleaks path not canonical: %q want %q", policy.Tools["gitleaks"].Path, wantG)
	}
	if policy.Tools["osv-scanner"].Path != wantO {
		t.Fatalf("osv-scanner path not canonical: %q want %q", policy.Tools["osv-scanner"].Path, wantO)
	}
	if policy.Tools["gitleaks"].Path == linkG || policy.Tools["osv-scanner"].Path == linkO {
		t.Fatal("bootstrap left a symlink path in the policy")
	}
	if err := verifyTool(policy.Tools["gitleaks"]); err != nil {
		t.Fatalf("bootstrapped gitleaks rejected: %v", err)
	}
	if err := verifyTool(policy.Tools["osv-scanner"]); err != nil {
		t.Fatalf("bootstrapped osv-scanner rejected: %v", err)
	}
}

func gitRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := exec.Command("git", "-C", root, "init", "-qb", "main").Run(); err != nil {
		t.Fatal(err)
	}
	return root
}

func gitAdd(t *testing.T, root string, names ...string) {
	t.Helper()
	args := append([]string{"-C", root, "add", "--"}, names...)
	if err := exec.Command("git", args...).Run(); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotCopiesGitVisibleFile(t *testing.T) {
	root := gitRepo(t)
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	gitAdd(t, root, "tracked.txt")
	target, cleanup, err := snapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	got, err := os.ReadFile(filepath.Join(target, "tracked.txt"))
	if err != nil || string(got) != "ok" {
		t.Fatalf("tracked file missing from snapshot: %s %v", got, err)
	}
}

func TestSnapshotRejectsSymlink(t *testing.T) {
	root := gitRepo(t)
	if err := os.WriteFile(filepath.Join(root, "real.txt"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.txt", filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	gitAdd(t, root, "real.txt", "link.txt")
	if _, _, err := snapshot(root); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink scan input accepted: %v", err)
	}
}

func TestSnapshotSkipsRepositoryScannerConfig(t *testing.T) {
	root := gitRepo(t)
	for _, name := range []string{".gitleaks.toml", ".gitleaksignore", "osv-scanner.toml", "keep.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	gitAdd(t, root, ".gitleaks.toml", ".gitleaksignore", "osv-scanner.toml", "keep.txt")
	target, cleanup, err := snapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, name := range []string{".gitleaks.toml", ".gitleaksignore", "osv-scanner.toml"} {
		if _, err := os.Stat(filepath.Join(target, name)); !os.IsNotExist(err) {
			t.Fatalf("scanner config %s leaked into snapshot", name)
		}
	}
	if _, err := os.Stat(filepath.Join(target, "keep.txt")); err != nil {
		t.Fatal("expected file missing from snapshot")
	}
}

func TestSnapshotSkipsGitignoredFile(t *testing.T) {
	root := gitRepo(t)
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("ignored.txt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ignored.txt"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "visible.txt"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	gitAdd(t, root, ".gitignore", "visible.txt")
	target, cleanup, err := snapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(target, "ignored.txt")); !os.IsNotExist(err) {
		t.Fatal("gitignored file leaked into snapshot")
	}
}

func TestSnapshotRejectsOversizedFile(t *testing.T) {
	root := gitRepo(t)
	path := filepath.Join(root, "big.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(20*1024*1024 + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	gitAdd(t, root, "big.bin")
	if _, _, err := snapshot(root); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized file accepted: %v", err)
	}
}

func writePolicyFile(t *testing.T, p Policy) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func seedOfflineOSVDatabase(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "osv-scanner", "Go"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "osv-scanner", "Go", "all.zip"), []byte("pk"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDoctorRejectsOfflineOSVWithoutDatabase(t *testing.T) {
	t.Setenv("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", t.TempDir())
	tool := scannerFixture(t, "exit 0\n")
	policyPath := writePolicyFile(t, Policy{Version: 1, Scanners: []string{"osv-scanner"}, Tools: map[string]Tool{"osv-scanner": tool}})
	var stdout, stderr bytes.Buffer
	code := execute([]string{"doctor", "--root", gitRepo(t), "--policy", policyPath}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("missing offline DB accepted: code=%d stdout=%s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "offline OSV database missing") {
		t.Fatalf("opaque doctor error: %s", stdout.String())
	}
}

func TestDoctorAcceptsOfflineOSVWhenDatabasePresent(t *testing.T) {
	t.Setenv("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", seedOfflineOSVDatabase(t))
	tool := scannerFixture(t, "exit 0\n")
	policyPath := writePolicyFile(t, Policy{Version: 1, Scanners: []string{"osv-scanner"}, Tools: map[string]Tool{"osv-scanner": tool}})
	var stdout, stderr bytes.Buffer
	code := execute([]string{"doctor", "--root", gitRepo(t), "--policy", policyPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("seeded offline DB rejected: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestDoctorSkipsOfflineOSVCheckWhenNetworkAllowed(t *testing.T) {
	t.Setenv("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", t.TempDir())
	tool := scannerFixture(t, "exit 0\n")
	policyPath := writePolicyFile(t, Policy{Version: 1, AllowNetwork: true, Scanners: []string{"osv-scanner"}, Tools: map[string]Tool{"osv-scanner": tool}})
	var stdout, stderr bytes.Buffer
	code := execute([]string{"doctor", "--root", gitRepo(t), "--policy", policyPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("network-allowed doctor failed: code=%d stdout=%s", code, stdout.String())
	}
}

func TestOfflineOSVStderrIsExplicit(t *testing.T) {
	tool := scannerFixture(t, "printf 'could not load db for Go ecosystem: unable to fetch OSV database: no offline version of the OSV database is available' >&2\nexit 127\n")
	r := scan(context.Background(), t.TempDir(), Policy{Version: 1, Scanners: []string{"osv-scanner"}, Tools: map[string]Tool{"osv-scanner": tool}}, "fixture")
	if r.ExitCode() != 2 {
		t.Fatalf("expected incomplete: %+v", r)
	}
	if r.Checks[0].Detail != "offline OSV database missing" {
		t.Fatalf("opaque scan error: %+v", r.Checks[0])
	}
}
