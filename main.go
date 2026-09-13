package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var version = "0.1.3-dev"

// snapshot exports only this repository's Git-visible working files. Nested
// repositories, ignored notes, scanner configuration and symlinks are not followed.
func snapshot(root string) (string, func(), error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	listing, err := cmd.Output()
	if err != nil {
		return "", nil, errors.New("root must be a Git repository")
	}
	target, err := os.MkdirTemp("", "agent-secure-source-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(target) }
	seen := map[string]bool{}
	var total int64
	for _, name := range strings.Split(string(listing), "\x00") {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if !filepath.IsLocal(name) {
			cleanup()
			return "", nil, errors.New("invalid repository path")
		}
		// Ignore repository-provided scanner configuration; policy is external.
		base := filepath.Base(name)
		if base == ".gitleaks.toml" || base == ".gitleaksignore" || base == "osv-scanner.toml" {
			continue
		}
		source := filepath.Join(root, name)
		resolved, err := filepath.EvalSymlinks(source)
		if os.IsNotExist(err) {
			continue
		} // tracked deletion
		if err != nil || resolved != source {
			cleanup()
			return "", nil, errors.New("symlink in scan input; scan coverage is incomplete")
		}
		info, err := os.Stat(source)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		if !info.Mode().IsRegular() {
			cleanup()
			return "", nil, errors.New("non-regular scan input")
		}
		total += info.Size()
		if info.Size() > 20*1024*1024 || total > 500*1024*1024 {
			cleanup()
			return "", nil, errors.New("scan input exceeds size limit")
		}
		destination := filepath.Join(target, name)
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			cleanup()
			return "", nil, err
		}
		input, err := os.Open(source)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if err != nil {
			input.Close()
			cleanup()
			return "", nil, err
		}
		_, copyErr := io.Copy(output, io.LimitReader(input, 20*1024*1024+1))
		input.Close()
		closeErr := output.Close()
		if copyErr != nil || closeErr != nil {
			cleanup()
			return "", nil, errors.New("cannot snapshot input")
		}
	}
	return target, cleanup, nil
}

func execute(args []string, out, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(out, "agent-secure "+version)
		return 0
	}
	if len(args) == 0 || (args[0] != "scan" && args[0] != "doctor") {
		fmt.Fprintln(stderr, "usage: agent-secure scan|doctor --root <repo> --policy <trusted-policy.json>")
		return 2
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository to scan")
	policyPath := flags.String("policy", "", "externally managed policy")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *root == "" || *policyPath == "" {
		return 2
	}
	absolute, err := filepath.Abs(*root)
	if err == nil {
		absolute, err = filepath.EvalSymlinks(absolute)
	}
	if err != nil {
		fmt.Fprintln(stderr, "invalid root")
		return 2
	}
	p, digest, err := readPolicy(*policyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if args[0] == "doctor" {
		report := Report{Version: 1, Root: absolute, PolicySHA256: digest, Status: "incomplete", Findings: []Finding{},
			Coverage: "Configuration inspection only; this CLI cannot verify an agent runtime sandbox.",
			Checks:   []Check{{Scanner: "sandbox", Status: "not_verified", Detail: "Enforce and test filesystem/network isolation in the agent runtime before confidential work."}}}
		for _, name := range p.Scanners {
			check := Check{Scanner: name, Status: "pass", ToolSHA256: p.Tools[name].SHA256}
			if err := verifyTool(p.Tools[name]); err != nil {
				check.Status = "error"
				check.Detail = err.Error()
			}
			report.Checks = append(report.Checks, check)
		}
		// Exit 0 only when every pinned scanner verified; CI gates on this.
		// "not_verified" (the sandbox check) is informational, not an error.
		doctorExit := 0
		for _, c := range report.Checks {
			if c.Status == "error" {
				doctorExit = 2
				break
			}
		}
		_ = json.NewEncoder(out).Encode(report)
		return doctorExit
	}
	source, cleanup, err := snapshot(absolute)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	defer cleanup()
	report := scan(context.Background(), source, p, digest)
	report.Root = absolute
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if encoder.Encode(report) != nil {
		return 2
	}
	return report.ExitCode()
}

func main() { os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr)) }
