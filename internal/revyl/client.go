// Package revyl is a thin wrapper around the `revyl` CLI binary. greenlight's
// runtime tier shells out to it to drive flow validations on real devices. The
// static scanners stay offline and zero-account; only `greenlight verify` reaches
// for this — that separation is deliberate.
package revyl

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Client invokes the revyl CLI.
type Client struct {
	Bin string
}

// NewClient locates the revyl binary: explicit path, then $PATH, then the
// default install location (~/.revyl/bin/revyl).
func NewClient(bin string) *Client {
	if bin != "" {
		return &Client{Bin: bin}
	}
	if p, err := exec.LookPath("revyl"); err == nil {
		return &Client{Bin: p}
	}
	if home, err := os.UserHomeDir(); err == nil {
		cand := filepath.Join(home, ".revyl", "bin", "revyl")
		if _, err := os.Stat(cand); err == nil {
			return &Client{Bin: cand}
		}
	}
	return &Client{Bin: "revyl"}
}

// Available returns an error if the revyl binary can't be found.
func (c *Client) Available() error {
	if _, err := exec.LookPath(c.Bin); err == nil {
		return nil
	}
	if _, err := os.Stat(c.Bin); err == nil {
		return nil
	}
	return fmt.Errorf("revyl CLI not found (looked for %q) — install it (https://docs.revyl.com) or pass --revyl <path>", c.Bin)
}

// EnsureTest creates or updates a Revyl test from a YAML file. Idempotent via
// --force; --no-open keeps it headless.
func (c *Client) EnsureTest(yamlPath string) (string, error) {
	out, err := c.run("test", "create", "--from-file", yamlPath, "--no-open", "--force")
	if err != nil {
		return out, fmt.Errorf("revyl test create failed: %w\n%s", err, strings.TrimSpace(out))
	}
	return out, nil
}

// RunOpts configures a single test run.
type RunOpts struct {
	DeviceModel string
	OSVersion   string
	Build       bool // build+upload before running
	Timeout     time.Duration
}

// RunResult is the outcome of a test run.
type RunResult struct {
	Passed     bool
	FailedStep string
	TaskID     string
	Raw        string
}

// RunTest runs a test by name and interprets the outcome. The JSON field names
// are best-effort across CLI versions; process exit code is the backstop signal.
func (c *Client) RunTest(name string, opts RunOpts) (RunResult, error) {
	args := []string{"test", "run", name, "--json"}
	if opts.DeviceModel != "" {
		args = append(args, "--device-model", opts.DeviceModel)
	}
	if opts.OSVersion != "" {
		args = append(args, "--os-version", opts.OSVersion)
	}
	if opts.Build {
		args = append(args, "--build")
	}
	if opts.Timeout > 0 {
		args = append(args, "--timeout", fmt.Sprintf("%d", int(opts.Timeout.Seconds())))
	}

	out, runErr := c.run(args...)
	res := RunResult{Raw: out}
	exitOK := runErr == nil

	var j runJSON
	if jsonStr := extractJSON(out); jsonStr != "" {
		_ = json.Unmarshal([]byte(jsonStr), &j)
	}
	res.TaskID = firstNonEmpty(j.TaskID, j.ID)

	verdict, decided := j.verdict()
	if decided {
		res.Passed = verdict
	} else {
		res.Passed = exitOK
	}
	if !res.Passed {
		res.FailedStep = j.firstFailedStep()
	}

	// Distinguish "the flow failed" (a real finding) from "couldn't run the flow"
	// (auth/build/device setup) — the latter must never read as a passed or
	// failed verdict.
	if runErr != nil && !decided && looksLikeSetupError(out) {
		return res, fmt.Errorf("revyl test run could not execute: %w\n%s", runErr, strings.TrimSpace(out))
	}
	return res, nil
}

// ReportShareURL returns a public shareable report link for the test's latest
// run, best-effort (empty string if unavailable).
func (c *Client) ReportShareURL(name string) string {
	out, err := c.run("test", "report", name, "--share")
	if err != nil {
		return ""
	}
	return firstURL(out)
}

func (c *Client) run(args ...string) (string, error) {
	cmd := exec.Command(c.Bin, args...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runJSON is a tolerant view of `revyl test run --json`.
type runJSON struct {
	Status  string `json:"status"`
	Outcome string `json:"outcome"`
	Result  string `json:"result"`
	Passed  *bool  `json:"passed"`
	Success *bool  `json:"success"`
	TaskID  string `json:"task_id"`
	ID      string `json:"id"`
	Steps   []struct {
		Status          string `json:"status"`
		Passed          *bool  `json:"passed"`
		Description     string `json:"description"`
		StepDescription string `json:"step_description"`
	} `json:"steps"`
}

func (j runJSON) verdict() (passed bool, decided bool) {
	if j.Passed != nil {
		return *j.Passed, true
	}
	if j.Success != nil {
		return *j.Success, true
	}
	for _, s := range []string{j.Status, j.Outcome, j.Result} {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "passed", "pass", "success", "succeeded", "completed", "complete", "green":
			return true, true
		case "failed", "fail", "failure", "error", "errored", "red":
			return false, true
		}
	}
	return false, false
}

func (j runJSON) firstFailedStep() string {
	for _, s := range j.Steps {
		bad := s.Passed != nil && !*s.Passed
		switch strings.ToLower(s.Status) {
		case "failed", "fail", "error", "errored":
			bad = true
		}
		if bad {
			return firstNonEmpty(s.StepDescription, s.Description)
		}
	}
	return ""
}

var (
	reJSONURL = regexp.MustCompile(`https?://[^\s"']+`)
)

func extractJSON(s string) string {
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i >= 0 && j > i {
		return s[i : j+1]
	}
	return ""
}

func firstURL(s string) string {
	return reJSONURL.FindString(s)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func looksLikeSetupError(s string) bool {
	l := strings.ToLower(s)
	for _, k := range []string{
		"not authenticated", "unauthorized", "please log in", "auth login",
		"no build", "build not found", "no device", "no runners", "not found",
		"quota", "permission denied", "forbidden", "could not connect",
	} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}
