// Package revyl is a thin wrapper around the `revyl` CLI binary. greenlight's
// runtime tier shells out to it to drive flow validations on cloud devices. The
// static scanners stay offline and zero-account; only `greenlight verify` reaches
// for this — that separation is deliberate.
package revyl

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Onboarding constants for the Revyl activation funnel — surfaced when a
// greenlight user reaches the runtime tier without a Revyl account.
const (
	SignupURL  = "https://app.revyl.ai/signup"
	InstallCmd = "curl -fsSL https://revyl.com/install.sh | sh"
	LoginCmd   = "revyl auth login"
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

// Authenticated reports whether the user has a usable Revyl session. Used to
// distinguish "needs to sign up / log in" from "the flow failed".
func (c *Client) Authenticated() bool {
	out, err := c.run("auth", "status")
	l := strings.ToLower(out)
	if strings.Contains(l, "not authenticated") || strings.Contains(l, "not logged in") ||
		strings.Contains(l, "no credentials") || strings.Contains(l, "please log in") {
		return false
	}
	if err != nil {
		return false
	}
	return strings.Contains(l, "authenticated") || strings.Contains(l, "logged in")
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

	// A non-exit error means revyl itself couldn't run (binary/IO problem) — a
	// hard error. A non-zero EXIT is just a failed test; let the report decide
	// whether that's a broken flow or a setup/launch failure. Never classify
	// from stdout keywords — that's what the structured report is for.
	if runErr != nil {
		var ee *exec.ExitError
		if !errors.As(runErr, &ee) {
			return res, fmt.Errorf("could not execute revyl test run: %w\n%s", runErr, strings.TrimSpace(out))
		}
	}
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

// ReportResult is the authoritative outcome of a test's latest execution,
// extracted from `revyl test report --json`. The verdict is Revyl's; the failing
// step's description and reason are the evidence a static scanner can't produce.
// StepsRun matters for honesty: a "failed" run that executed zero steps is a
// setup/launch failure, NOT a flow that broke.
type ReportResult struct {
	Decided      bool
	Passed       bool
	StepsRun     int
	FailedStep   string
	FailedReason string
	ReportURL    string
	DeviceModel  string
	OSVersion    string
}

// reportJSON mirrors the real `revyl test report --json` schema.
type reportJSON struct {
	SessionStatus string `json:"session_status"`
	Success       *bool  `json:"success"`
	TotalSteps    int    `json:"total_steps"`
	PassedSteps   int    `json:"passed_steps"`
	FailedSteps   int    `json:"failed_steps"`
	ReportURL     string `json:"report_url"`
	DeviceModel   string `json:"device_model"`
	OSVersion     string `json:"os_version"`
	Steps         []struct {
		Status                string `json:"status"`
		EffectiveStatus       string `json:"effective_status"`
		StepDescription       string `json:"step_description"`
		StatusReason          string `json:"status_reason"`
		EffectiveStatusReason string `json:"effective_status_reason"`
		ExecutionOrder        int    `json:"execution_order"`
	} `json:"steps"`
}

// Report fetches the latest execution report for a test and extracts the
// authoritative verdict plus the first failing step (description + reason).
func (c *Client) Report(name string) (ReportResult, error) {
	out, err := c.run("test", "report", name, "--json")
	if err != nil {
		return ReportResult{}, fmt.Errorf("revyl test report failed: %w\n%s", err, strings.TrimSpace(out))
	}
	return parseReport(out)
}

// parseReport extracts a verdict + failing-step evidence from the raw output of
// `revyl test report --json`. Factored out for testing against the real schema.
func parseReport(out string) (ReportResult, error) {
	var res ReportResult
	var j reportJSON
	if js := extractJSON(out); js != "" {
		if e := json.Unmarshal([]byte(js), &j); e != nil {
			return res, fmt.Errorf("could not parse report JSON: %w", e)
		}
	}

	res.ReportURL = j.ReportURL
	res.DeviceModel = j.DeviceModel
	res.OSVersion = j.OSVersion
	// StepsRun counts steps that actually executed (passed or failed). Zero means
	// the flow never ran a step — a setup/launch failure, not a broken flow.
	res.StepsRun = j.PassedSteps + j.FailedSteps

	// Prefer the explicit success boolean; fall back to session_status text.
	if j.Success != nil {
		res.Passed, res.Decided = *j.Success, true
	} else {
		switch strings.ToLower(strings.TrimSpace(j.SessionStatus)) {
		case "passed", "pass", "success", "succeeded", "completed", "complete", "green":
			res.Passed, res.Decided = true, true
		case "failed", "fail", "failure", "error", "errored", "red":
			res.Passed, res.Decided = false, true
		}
	}

	for _, s := range j.Steps {
		switch strings.ToLower(firstNonEmpty(s.EffectiveStatus, s.Status)) {
		case "failed", "fail", "error", "errored":
			res.FailedStep = s.StepDescription
			res.FailedReason = cleanReason(firstNonEmpty(s.StatusReason, s.EffectiveStatusReason))
			return res, nil
		}
	}
	return res, nil
}

// cleanReason trims Revyl's verbose step failure reason to a single readable line.
func cleanReason(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "Step execution failed: ")
	s = strings.TrimSpace(s)
	if len(s) > 180 {
		s = s[:177] + "..."
	}
	return s
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
