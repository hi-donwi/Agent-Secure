package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Tool struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Policy struct {
	Version      int             `json:"version"`
	AllowNetwork bool            `json:"allow_network"`
	Scanners     []string        `json:"scanners"`
	Tools        map[string]Tool `json:"tools"`
	Allow        []Allow         `json:"allow,omitempty"`
}

// Allow suppresses one finding class, decided by the policy owner — never by
// the scanned repository. A reason is mandatory so the policy stays auditable,
// and Expires (YYYY-MM-DD, inclusive) makes allowlists rot on purpose.
type Allow struct {
	Scanner string `json:"scanner"`
	ID      string `json:"id"`
	File    string `json:"file,omitempty"`
	Reason  string `json:"reason"`
	Expires string `json:"expires,omitempty"`
}

type AllowedFinding struct {
	Finding Finding `json:"finding"`
	Reason  string  `json:"reason"`
}
type Finding struct {
	ID       string `json:"id"`
	Scanner  string `json:"scanner"`
	Severity string `json:"severity"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
}
type Check struct {
	Scanner    string `json:"scanner"`
	Status     string `json:"status"`
	Detail     string `json:"detail,omitempty"`
	ToolSHA256 string `json:"tool_sha256,omitempty"`
}
type Report struct {
	Version      int              `json:"version"`
	Root         string           `json:"root"`
	PolicySHA256 string           `json:"policy_sha256"`
	Created      string           `json:"created"`
	Status       string           `json:"status"`
	Coverage     string           `json:"coverage"`
	Checks       []Check          `json:"checks"`
	Findings     []Finding        `json:"findings"`
	Allowed      []AllowedFinding `json:"allowed,omitempty"`
}

func (r Report) ExitCode() int {
	if r.Status == "incomplete" {
		return 2
	}
	if r.Status == "findings" {
		return 1
	}
	return 0
}

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validatePolicy(p Policy) error {
	if p.Version != 1 || len(p.Scanners) == 0 {
		return errors.New("policy requires version 1 and at least one scanner")
	}
	seen := map[string]bool{}
	for _, name := range p.Scanners {
		if (name != "gitleaks" && name != "osv-scanner") || seen[name] {
			return errors.New("unknown or duplicate scanner")
		}
		tool, ok := p.Tools[name]
		if !ok {
			return errors.New("policy does not pin a scanner binary for " + name)
		}
		if !filepath.IsAbs(tool.Path) || !digestPattern.MatchString(tool.SHA256) {
			return errors.New("scanner " + name + " needs an absolute path and pinned SHA-256")
		}
		seen[name] = true
	}
	for _, a := range p.Allow {
		if a.Scanner != "gitleaks" && a.Scanner != "osv-scanner" {
			return errors.New("allow entry has unknown scanner")
		}
		if a.ID == "" {
			return errors.New("allow entry requires an id")
		}
		if strings.TrimSpace(a.Reason) == "" {
			return errors.New("allow entry requires a reason")
		}
		if a.Expires == "" {
			return errors.New("allow entry requires an expiry")
		}
		if _, e := time.Parse("2006-01-02", a.Expires); e != nil {
			return fmt.Errorf("allow expiry %q must be YYYY-MM-DD", a.Expires)
		}
		if a.File != "" && !filepath.IsLocal(a.File) {
			return errors.New("allow entry file must be a local relative path")
		}
	}
	return nil
}

// todayInUTC is split out so the allow expiry test can freeze the clock.
var todayInUTC = func() string {
	return time.Now().UTC().Format("2006-01-02")
}

// filterAllowed drops findings the policy owner explicitly allowed and returns
// them separately for the report — allowed findings stay visible and auditable
// in every report, and expired allows stop suppressing silently.
func filterAllowed(findings []Finding, p Policy) (kept []Finding, allowed []AllowedFinding, err error) {
	for _, f := range findings {
		suppressed := false
		for _, a := range p.Allow {
			if a.Scanner != f.Scanner || a.ID != f.ID {
				continue
			}
			if a.File != "" && a.File != f.File {
				continue
			}
			if strings.TrimSpace(a.Reason) == "" {
				return nil, nil, errors.New("allow entry requires a reason")
			}
			if a.Expires == "" {
				return nil, nil, errors.New("allow entry requires an expiry")
			}
			if _, e := time.Parse("2006-01-02", a.Expires); e != nil {
				return nil, nil, fmt.Errorf("invalid allow expiry %q: must be YYYY-MM-DD", a.Expires)
			}
			if todayInUTC() > a.Expires {
				continue
			}
			suppressed = true
			allowed = append(allowed, AllowedFinding{Finding: f, Reason: a.Reason})
			break
		}
		if !suppressed {
			kept = append(kept, f)
		}
	}
	return kept, allowed, nil
}

func verifyTool(tool Tool) error {
	if !filepath.IsAbs(tool.Path) || !digestPattern.MatchString(tool.SHA256) {
		return errors.New("scanner needs an absolute path and pinned SHA-256")
	}
	info, err := os.Lstat(tool.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("scanner is missing, non-executable or a symlink")
	}
	source, err := os.Open(tool.Path)
	if err != nil {
		return errors.New("cannot read scanner")
	}
	defer source.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, source); err != nil {
		return errors.New("cannot hash scanner")
	}
	if hex.EncodeToString(hash.Sum(nil)) != tool.SHA256 {
		return errors.New("scanner digest mismatch")
	}
	return nil
}

// Tool output is bounded and never echoed. Normalizers only retain safe fields;
// Secret, Match, snippets and arbitrary scanner error text are deliberately absent.
type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 10*1024*1024 {
		return 0, errors.New("scanner output limit exceeded")
	}
	return b.Buffer.Write(data)
}

func runScanner(ctx context.Context, root, name string, tool Tool, network bool) ([]Finding, error) {
	temp, err := os.MkdirTemp("", "agent-secure-report-")
	if err != nil {
		return nil, errors.New("cannot create report directory")
	}
	defer os.RemoveAll(temp)
	reportFile := filepath.Join(temp, "report.json")
	var args []string
	switch name {
	case "gitleaks":
		args = []string{"dir", root, "--no-banner", "--redact=100", "--ignore-gitleaks-allow", "--report-format", "json", "--report-path", reportFile}
	case "osv-scanner":
		args = []string{"scan", "source", "--recursive", root, "--format=json", "--no-resolve"}
		if !network {
			args = append(args, "--offline-vulnerabilities")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool.Path, args...)
	cmd.Dir = temp // Do not load arbitrary project-local scanner configuration.
	// Keep HOME: the offline OSV databases are cached under it. Everything else
	// (credentials, shell config, project env) is dropped.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C", "TMPDIR=" + temp, "HOME=" + os.Getenv("HOME")}
	var output boundedBuffer
	var logs boundedBuffer
	cmd.Stdout = &output // osv-scanner writes the JSON report to stdout
	// stderr holds scanner logs; never echoed, but exit-code triage reads its tail.
	cmd.Stderr = &logs
	err = cmd.Run()
	exitCode := 0
	if err != nil {
		var exited *exec.ExitError
		if !errors.As(err, &exited) {
			return nil, errors.New("scanner could not complete")
		}
		exitCode = exited.ExitCode()
		if exitCode == 128 && name == "osv-scanner" && bytes.Contains(logs.Bytes(), []byte("No package sources found")) {
			return nil, nil // no manifest in the snapshot: nothing to check
		}
		if exitCode != 1 || ctx.Err() != nil {
			return nil, errors.New("scanner failed or timed out")
		}
	}
	var findings []Finding
	if name == "gitleaks" {
		info, err := os.Stat(reportFile)
		if err != nil || info.Size() > 10*1024*1024 {
			return nil, errors.New("missing or oversized secret scan report")
		}
		data, err := os.ReadFile(reportFile)
		if err != nil {
			return nil, errors.New("cannot read secret scan report")
		}
		var rows []struct {
			RuleID, File string
			StartLine    int
		}
		if err := json.Unmarshal(data, &rows); err != nil || !bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
			return nil, errors.New("invalid secret scan report")
		}
		for _, row := range rows {
			if row.RuleID == "" {
				return nil, errors.New("missing secret rule identifier")
			}
			file := row.File
			if filepath.IsAbs(file) {
				file, err = filepath.Rel(root, file)
				if err != nil {
					return nil, errors.New("invalid finding path")
				}
			}
			if !filepath.IsLocal(file) {
				return nil, errors.New("finding path escapes scan root")
			}
			findings = append(findings, Finding{ID: row.RuleID, Scanner: name, Severity: "high", File: file, Line: row.StartLine})
		}
	} else {
		var report struct {
			Results *[]struct {
				Packages []struct {
					Vulnerabilities []struct {
						ID string `json:"id"`
					} `json:"vulnerabilities"`
				} `json:"packages"`
			} `json:"results"`
		}
		if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.Results == nil {
			return nil, errors.New("invalid dependency scan report")
		}
		seen := map[string]bool{}
		for _, result := range *report.Results {
			for _, pkg := range result.Packages {
				for _, vuln := range pkg.Vulnerabilities {
					if vuln.ID == "" {
						return nil, errors.New("missing vulnerability identifier")
					}
					if !seen[vuln.ID] {
						findings = append(findings, Finding{ID: vuln.ID, Scanner: name, Severity: "unknown"})
						seen[vuln.ID] = true
					}
				}
			}
		}
	}
	if exitCode == 1 && len(findings) == 0 {
		return nil, errors.New("scanner exit and report disagree")
	}
	return findings, nil
}

func scan(ctx context.Context, root string, p Policy, policyDigest string) Report {
	report := Report{Version: 1, Root: root, PolicySHA256: policyDigest, Created: time.Now().UTC().Format(time.RFC3339),
		Status: "pass", Coverage: "Git-visible working files only; excluded files, history, runtime sandbox and live systems are not scanned.", Checks: []Check{}, Findings: []Finding{}}
	if err := validatePolicy(p); err != nil {
		report.Status = "incomplete"
		report.Checks = append(report.Checks, Check{Scanner: "policy", Status: "error", Detail: err.Error()})
		return report
	}
	for _, name := range p.Scanners {
		tool := p.Tools[name]
		check := Check{Scanner: name, Status: "pass", ToolSHA256: tool.SHA256}
		err := verifyTool(tool)
		var findings []Finding
		if err == nil {
			findings, err = runScanner(ctx, root, name, tool, p.AllowNetwork)
		}
		if err != nil {
			check.Status = "error"
			check.Detail = err.Error()
			report.Status = "incomplete"
		} else if len(findings) != 0 {
			kept, allowed, ferr := filterAllowed(findings, p)
			if ferr != nil {
				check.Status = "error"
				check.Detail = ferr.Error()
				report.Status = "incomplete"
			} else {
				report.Allowed = append(report.Allowed, allowed...)
				findings = kept
				if len(findings) != 0 {
					check.Status = "findings"
					if report.Status != "incomplete" {
						report.Status = "findings"
					}
					report.Findings = append(report.Findings, findings...)
				}
			}
		}
		report.Checks = append(report.Checks, check)
	}
	return report
}

func readPolicy(path string) (Policy, string, error) {
	var p Policy
	data, err := os.ReadFile(path)
	if err != nil {
		return p, "", errors.New("cannot read policy")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return p, "", errors.New("invalid policy schema")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return p, "", errors.New("trailing policy data")
	}
	if err := validatePolicy(p); err != nil {
		return p, "", err
	}
	sum := sha256.Sum256(data)
	return p, fmt.Sprintf("%x", sum), nil
}
