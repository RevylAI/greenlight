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
	StatusError    = "error"    // could not run (auth/build/device/setup)
)

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
	Passed   bool `json:"passed"` // true iff zero failed and zero errored
}

// Result is the full verify report.
type Result struct {
	ProjectPath string          `json:"project_path"`
	BuildName   string          `json:"build_name,omitempty"`
	Claims      codescan.Claims `json:"claims"`
	Flows       []FlowResult    `json:"flows"`
	Summary     Summary         `json:"summary"`
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

		fr.YAML = renderTestYAML(f, platform, cfg.BuildName, cfg.Vars)

		if cfg.DryRun {
			fr.Status = StatusSkipped
			fr.Detail = "dry-run — generated the test, did not execute on a device"
			res.Flows = append(res.Flows, fr)
			continue
		}

		if cfg.BuildName == "" {
			fr.Status = StatusError
			fr.Detail = "no --build-name provided; cannot map the test to a registered Revyl build"
			res.Flows = append(res.Flows, fr)
			continue
		}
		if err := client.Available(); err != nil {
			fr.Status = StatusError
			fr.Detail = err.Error()
			res.Flows = append(res.Flows, fr)
			continue
		}

		path, werr := writeTempYAML(f.TestName, fr.YAML)
		if werr != nil {
			fr.Status = StatusError
			fr.Detail = "could not stage test file: " + werr.Error()
			res.Flows = append(res.Flows, fr)
			continue
		}

		if _, cerr := client.EnsureTest(path); cerr != nil {
			fr.Status = StatusError
			fr.Detail = cerr.Error()
			cleanupTemp(path)
			res.Flows = append(res.Flows, fr)
			continue
		}

		run, rerr := client.RunTest(f.TestName, revyl.RunOpts{
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

		if run.Passed {
			fr.Status = StatusVerified
			fr.Detail = "flow ran on-device and behaved correctly"
		} else {
			fr.Status = StatusFailed
			fr.FailedStep = run.FailedStep
			fr.ReportURL = client.ReportShareURL(f.TestName)
			fr.Detail = staticPassedMessage(f, claims, run.FailedStep)
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
		fmt.Fprintf(&b, "Static analysis PASSED §%s — it found `%s` in your source and suppressed the warning. ", f.Guideline, f.AntiPattern)
	} else {
		fmt.Fprintf(&b, "§%s ", f.Guideline)
	}
	b.WriteString("But the flow failed on a real device")
	if failedStep != "" {
		fmt.Fprintf(&b, " at: %q", failedStep)
	}
	b.WriteString(". Apple exercises this flow manually during review.")
	return b.String()
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
		return "", err
	}
	return path, nil
}

func cleanupTemp(path string) {
	os.RemoveAll(filepath.Dir(path))
}
