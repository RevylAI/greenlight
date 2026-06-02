package verify

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RevylAI/greenlight/internal/codescan"
	"github.com/RevylAI/greenlight/internal/revyl"
)

// Flow result statuses.
const (
	StatusVerified = "verified" // ran on-device and behaved correctly
	StatusFailed   = "failed"   // ran on-device and the flow broke (the catch)
	StatusSkipped  = "skipped"  // feature not claimed, or dry-run
	StatusError    = "error"    // could not run (build/device/setup)
	StatusPending  = "pending"  // claimed, but blocked behind Revyl sign-up
)

// Onboarding reasons — why the runtime tier needs the user to set up Revyl.
const (
	OnboardCLIMissing       = "cli-missing"
	OnboardNotAuthenticated = "not-authenticated"
)

// Onboarding is set when the user reached the runtime tier without a usable
// Revyl account. It drives the sign-up call-to-action — the greenlight->Revyl
// activation funnel.
type Onboarding struct {
	Reason  string `json:"reason"`
	Message string `json:"message,omitempty"`
}

// Config controls a verify run.
type Config struct {
	ProjectPath string
	BuildName   string            // Revyl registered build/app name (YAML build.name)
	Platform    string            // "ios" | "android"
	Flows       []string          // filter by flow ID; empty = all claimed
	Vars        map[string]string // test variables (email, password, …)
	DeviceModel string
	OSVersion   string
	Build       bool
	Timeout     time.Duration
	DryRun      bool
	RevylBin    string
}

// FlowResult is the per-flow outcome.
type FlowResult struct {
	Flow         Flow   `json:"-"`
	ID           string `json:"id"`
	Guideline    string `json:"guideline"`
	Title        string `json:"title"`
	Status       string `json:"status"`
	StaticPassed bool   `json:"static_passed"`
	FailedStep   string `json:"failed_step,omitempty"`
	FailedReason string `json:"failed_reason,omitempty"`
	ReportURL    string `json:"report_url,omitempty"`
	Detail       string `json:"detail,omitempty"`
	TaskID       string `json:"task_id,omitempty"`
	YAML         string `json:"-"`
}

// Summary aggregates flow outcomes.
type Summary struct {
	Total    int  `json:"total"` // flows that ran or attempted to run
	Verified int  `json:"verified"`
	Failed   int  `json:"failed"`
	Errored  int  `json:"errored"`
	Skipped  int  `json:"skipped"`
	Pending  int  `json:"pending"` // claimed but blocked behind Revyl sign-up
	Passed   bool `json:"passed"`  // true iff zero failed and zero errored
}

// Result is the full verify report.
type Result struct {
	ProjectPath string          `json:"project_path"`
	BuildName   string          `json:"build_name,omitempty"`
	Claims      codescan.Claims `json:"claims"`
	Flows       []FlowResult    `json:"flows"`
	Summary     Summary         `json:"summary"`
	Onboarding  *Onboarding     `json:"onboarding,omitempty"`
	DryRun      bool            `json:"dry_run"`
	Elapsed     time.Duration   `json:"-"`
}

// Run executes runtime flow validation: static pre-scan to learn what the app
// claims, then hand each claimed flow to the Revyl CLI to run on a device.
func Run(cfg Config) (*Result, error) {
	claims, err := codescan.DetectClaims(cfg.ProjectPath)
	if err != nil {
		return nil, fmt.Errorf("static pre-scan failed: %w", err)
	}

	platform := cfg.Platform
	if platform == "" {
		platform = "ios"
	}

	res := &Result{
		ProjectPath: cfg.ProjectPath,
		BuildName:   cfg.BuildName,
		Claims:      claims,
		DryRun:      cfg.DryRun,
	}

	selected := selectedSet(cfg.Flows)
	client := revyl.NewClient(cfg.RevylBin)

	// Only engage the Revyl runtime tier if at least one selected flow is
	// actually claimed. Otherwise there is nothing to verify, and we must not
	// prompt for sign-up/auth or show a CTA with 0 flows.
	anyClaimed := false
	for _, f := range AllFlows() {
		if (len(selected) == 0 || selected[f.ID]) && f.Claimed(claims) {
			anyClaimed = true
			break
		}
	}

	// Determine Revyl readiness once. If the user has no usable account, we
	// don't error per-flow: we surface a single sign-up call-to-action.
	if !cfg.DryRun && anyClaimed {
		if err := client.Available(); err != nil {
			res.Onboarding = &Onboarding{Reason: OnboardCLIMissing, Message: err.Error()}
		} else if !client.Authenticated() {
			res.Onboarding = &Onboarding{Reason: OnboardNotAuthenticated}
		}
	}

	// Resolve the build name to an app id once: `test create --app` needs it.
	var appID string
	var appIDErr error
	if res.Onboarding == nil && !cfg.DryRun && anyClaimed && cfg.BuildName != "" {
		appID, appIDErr = client.AppID(cfg.BuildName)
	}

	for _, f := range AllFlows() {
		if len(selected) > 0 && !selected[f.ID] {
			continue
		}
		fr := FlowResult{
			Flow:         f,
			ID:           f.ID,
			Guideline:    f.Guideline,
			Title:        f.Title,
			StaticPassed: f.StaticPassed(claims),
		}

		if !f.Claimed(claims) {
			fr.Status = StatusSkipped
			fr.Detail = "feature not detected in source — nothing to verify"
			res.Flows = append(res.Flows, fr)
			continue
		}

		// Unique test name per build: a stable name gets silently rebound to the
		// first app's build by `revyl test create --force`.
		tname := testName(cfg.BuildName, f.ID)
		// The displayed/dry-run YAML redacts secret vars; the executed YAML
		// (written to the temp file below) uses the real values.
		fr.YAML = renderTestYAML(f, tname, platform, cfg.BuildName, redactVarsMap(cfg.Vars))

		if cfg.DryRun {
			fr.Status = StatusSkipped
			fr.Detail = "dry-run — generated the test, did not execute on a device"
			res.Flows = append(res.Flows, fr)
			continue
		}

		// No usable Revyl account → pending behind sign-up (see res.Onboarding).
		if res.Onboarding != nil {
			fr.Status = StatusPending
			fr.Detail = "sign up for Revyl to validate this flow on a cloud device"
			res.Flows = append(res.Flows, fr)
			continue
		}

		if cfg.BuildName == "" {
			fr.Status = StatusError
			fr.Detail = "no --build-name provided; cannot map the test to a registered Revyl build"
			res.Flows = append(res.Flows, fr)
			continue
		}
		if appID == "" {
			fr.Status = StatusError
			fr.Detail = fmt.Sprintf("could not resolve a Revyl app for build name %q (check `revyl app list`)", cfg.BuildName)
			if appIDErr != nil {
				fr.Detail += ": " + appIDErr.Error()
			}
			res.Flows = append(res.Flows, fr)
			continue
		}

		realYAML := renderTestYAML(f, tname, platform, cfg.BuildName, cfg.Vars)
		path, werr := writeTempYAML(tname, realYAML)
		if werr != nil {
			fr.Status = StatusError
			fr.Detail = "could not stage test file: " + werr.Error()
			res.Flows = append(res.Flows, fr)
			continue
		}

		if _, cerr := client.EnsureTest(tname, path, appID); cerr != nil {
			fr.Status = StatusError
			fr.Detail = cerr.Error()
			cleanupTemp(path)
			res.Flows = append(res.Flows, fr)
			continue
		}

		run, rerr := client.RunTest(tname, revyl.RunOpts{
			DeviceModel: cfg.DeviceModel,
			OSVersion:   cfg.OSVersion,
			Build:       cfg.Build,
			Timeout:     cfg.Timeout,
		})
		cleanupTemp(path)
		fr.TaskID = run.TaskID

		if rerr != nil {
			fr.Status = StatusError
			fr.Detail = rerr.Error()
			res.Flows = append(res.Flows, fr)
			continue
		}

		// Enrich with the execution report: the verdict is Revyl's, and the
		// failing step + reason are the evidence. `revyl test run` can return a
		// moment before the report finalizes, so poll briefly until it settles.
		report, repErr := client.Report(tname)
		for tries := 0; repErr == nil && !report.Decided && tries < 12; tries++ {
			time.Sleep(3 * time.Second)
			report, repErr = client.Report(tname)
		}
		reportURL := firstNonEmptyStr(client.ReportShareURL(tname), report.ReportURL)

		switch {
		case !report.Decided:
			// The report never finalized (or couldn't be fetched): we can't
			// confirm the outcome either way, so don't claim VERIFIED or FAILED.
			fr.Status = StatusError
			fr.ReportURL = reportURL
			if repErr != nil {
				fr.Detail = "could not read the Revyl report: " + repErr.Error()
			} else {
				fr.Detail = "could not determine the outcome: the Revyl report did not finalize. Rerun, or open the report."
			}
		case report.Passed:
			fr.Status = StatusVerified
			fr.Detail = "flow ran on-device and behaved correctly"
		case report.StepsRun == 0:
			// No step actually executed: a setup/launch failure, not a broken
			// flow. Reporting it as a flow failure would be dishonest.
			fr.Status = StatusError
			fr.ReportURL = reportURL
			fr.Detail = "the flow could not run to completion on the cloud device: no steps executed (the app may have failed to launch, or the run aborted before the first step finished). See the report."
		default:
			// Report finalized as a failure with steps executed: a real flow break.
			// Redact secret --var values (passwords/tokens) that were inlined into
			// step text, so they don't leak into the terminal or JSON.
			fr.Status = StatusFailed
			fr.FailedStep = redactVars(firstNonEmptyStr(report.FailedStep, run.FailedStep), cfg.Vars)
			fr.FailedReason = redactVars(report.FailedReason, cfg.Vars)
			fr.ReportURL = reportURL
			fr.Detail = staticPassedMessage(f, claims, fr.FailedStep)
		}
		res.Flows = append(res.Flows, fr)
	}

	res.Summary = summarize(res.Flows)
	return res, nil
}

// staticPassedMessage frames the headline insight: static said ship it, runtime
// proved otherwise.
func staticPassedMessage(f Flow, c codescan.Claims, failedStep string) string {
	var b strings.Builder
	if f.StaticPassed(c) {
		fmt.Fprintf(&b, "Static analysis PASSED §%s — it found `%s` in your source and suppressed the warning, but the flow failed on a cloud device", f.Guideline, f.AntiPattern)
	} else {
		fmt.Fprintf(&b, "The §%s flow failed on a cloud device", f.Guideline)
	}
	if failedStep != "" {
		fmt.Fprintf(&b, " at %q", failedStep)
	}
	b.WriteString(". Apple exercises this flow manually during review.")
	return b.String()
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// redactVars replaces the values of sensitive --var entries (passwords, tokens,
// secrets) wherever they appear in a reported string, so inlined credentials
// don't leak into the terminal or JSON output.
func redactVars(s string, vars map[string]string) string {
	for k, v := range vars {
		if v != "" && isSensitiveKey(k) {
			s = strings.ReplaceAll(s, v, "[redacted]")
		}
	}
	return s
}

// redactVarsMap returns a copy of vars with sensitive values replaced, for the
// displayed/dry-run YAML (the executed YAML still uses the real values).
func redactVarsMap(vars map[string]string) map[string]string {
	if len(vars) == 0 {
		return vars
	}
	out := make(map[string]string, len(vars))
	for k, v := range vars {
		if v != "" && isSensitiveKey(k) {
			out[k] = "[redacted]"
		} else {
			out[k] = v
		}
	}
	return out
}

func isSensitiveKey(k string) bool {
	k = strings.ToLower(k)
	for _, marker := range []string{"pass", "secret", "token", "key", "cred", "auth", "pin", "otp"} {
		if strings.Contains(k, marker) {
			return true
		}
	}
	return false
}

// testName builds a per-build Revyl test name so the same flow run against two
// different apps never collides (a shared name gets rebound to the first build).
func testName(buildName, flowID string) string {
	b := slug(buildName)
	if b == "" {
		return "greenlight-" + flowID
	}
	return "greenlight-" + b + "-" + flowID
}

// slug lowercases and reduces a string to [a-z0-9-] for use in a test name.
func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func summarize(flows []FlowResult) Summary {
	s := Summary{}
	for _, f := range flows {
		switch f.Status {
		case StatusVerified:
			s.Total++
			s.Verified++
		case StatusFailed:
			s.Total++
			s.Failed++
		case StatusError:
			s.Total++
			s.Errored++
		case StatusSkipped:
			s.Skipped++
		case StatusPending:
			s.Pending++
		}
	}
	s.Passed = s.Failed == 0 && s.Errored == 0
	return s
}

func selectedSet(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			m[id] = true
		}
	}
	return m
}

func writeTempYAML(name, content string) (string, error) {
	dir, err := os.MkdirTemp("", "greenlight-verify-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return path, nil
}

func cleanupTemp(path string) {
	os.RemoveAll(filepath.Dir(path))
}
