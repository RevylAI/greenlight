package preflight

import (
	"sync"
	"time"

	"github.com/RevylAI/greenlight/internal/codescan"
	"github.com/RevylAI/greenlight/internal/ipa"
	"github.com/RevylAI/greenlight/internal/privacy"
)

// Finding is the unified finding type across all scanners.
type Finding struct {
	Source    string `json:"source"`   // "codescan", "privacy", "ipa", "metadata"
	Severity  string `json:"severity"` // "CRITICAL", "WARN", "INFO"
	Guideline string `json:"guideline,omitempty"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Fix       string `json:"fix,omitempty"`
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
	Code      string `json:"code,omitempty"`
}

// Result holds the combined output from all scanners.
type Result struct {
	ProjectPath string        `json:"project_path"`
	IPAPath     string        `json:"ipa_path,omitempty"`
	Findings    []Finding     `json:"findings"`
	Summary     Summary       `json:"summary"`
	Elapsed     time.Duration `json:"elapsed"`

	// Incomplete is true when a requested sub-scanner failed to run, so the
	// results may be partial. CI gating (--exit-code) treats this as a failure.
	Incomplete bool `json:"incomplete,omitempty"`

	// Extra context from sub-scanners
	AppName        string   `json:"app_name,omitempty"`
	BundleID       string   `json:"bundle_id,omitempty"`
	HasPrivacyInfo bool     `json:"has_privacy_info"`
	DetectedAPIs   []string `json:"detected_apis,omitempty"`
	TrackingSDKs   []string `json:"tracking_sdks,omitempty"`
}

// Summary provides aggregate counts.
type Summary struct {
	Total    int  `json:"total"`
	Critical int  `json:"critical"`
	High     int  `json:"high"`
	Warns    int  `json:"warns"`
	Infos    int  `json:"infos"`
	Passed   bool `json:"passed"` // true if zero CRITICALs
}

// Run executes all scanners and returns a unified result.
func Run(projectPath string, ipaPath string, verbose bool) (*Result, error) {
	result := &Result{
		ProjectPath: projectPath,
		IPAPath:     ipaPath,
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)

	// Channel for collecting errors (non-fatal; we report what we can)
	errs := make(chan error, 4)

	// 1. Local metadata checks
	wg.Add(1)
	go func() {
		defer wg.Done()
		findings, meta := CheckLocalMetadata(projectPath)
		mu.Lock()
		result.Findings = append(result.Findings, findings...)
		if meta.AppName != "" {
			result.AppName = meta.AppName
		}
		if meta.BundleID != "" {
			result.BundleID = meta.BundleID
		}
		mu.Unlock()
	}()

	// 2. Code scan
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := codescan.NewScanner(projectPath, verbose)
		findings, err := scanner.Scan()
		if err != nil {
			errs <- err
			return
		}
		mu.Lock()
		for _, f := range findings {
			result.Findings = append(result.Findings, Finding{
				Source:    "codescan",
				Severity:  f.Severity.String(),
				Guideline: f.Guideline,
				Title:     f.Title,
				Detail:    f.Detail,
				Fix:       f.Fix,
				File:      f.File,
				Line:      f.Line,
				Code:      f.Code,
			})
		}
		mu.Unlock()
	}()

	// 3. Privacy scan
	wg.Add(1)
	go func() {
		defer wg.Done()
		privResult, err := privacy.Scan(projectPath)
		if err != nil {
			errs <- err
			return
		}
		mu.Lock()
		result.HasPrivacyInfo = privResult.HasPrivacyInfo
		result.DetectedAPIs = privResult.DetectedAPIs
		result.TrackingSDKs = privResult.TrackingSDKs
		for _, f := range privResult.Findings {
			result.Findings = append(result.Findings, Finding{
				Source:    "privacy",
				Severity:  f.Severity,
				Guideline: f.Guideline,
				Title:     f.Title,
				Detail:    f.Detail,
				Fix:       f.Fix,
				File:      f.File,
				Line:      f.Line,
			})
		}
		mu.Unlock()
	}()

	// 4. IPA inspection (if path provided)
	if ipaPath != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ipaResult, err := ipa.Inspect(ipaPath)
			if err != nil {
				errs <- err
				return
			}
			mu.Lock()
			if ipaResult.AppName != "" {
				result.AppName = ipaResult.AppName
			}
			if ipaResult.BundleID != "" {
				result.BundleID = ipaResult.BundleID
			}
			for _, f := range ipaResult.Findings {
				result.Findings = append(result.Findings, Finding{
					Source:    "ipa",
					Severity:  f.Severity,
					Guideline: f.Guideline,
					Title:     f.Title,
					Detail:    f.Detail,
					Fix:       f.Fix,
				})
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
	close(errs)

	// Deduplicate findings with the same title from different scanners
	result.Findings = dedup(result.Findings)

	// A sub-scanner that errored contributes zero findings; surface each failure
	// as a warning (appended after dedup so distinct failures aren't collapsed)
	// so a crashed scanner can't masquerade as a clean "no issues found".
	for err := range errs {
		result.Incomplete = true
		result.Findings = append(result.Findings, Finding{
			Source:   "scan",
			Severity: "WARN",
			Title:    "Scanner did not complete",
			Detail:   err.Error(),
			Fix:      "Results may be incomplete; re-run with --verbose for details.",
		})
	}

	// Compute summary
	result.Summary = computeSummary(result.Findings)

	return result, nil
}

func computeSummary(findings []Finding) Summary {
	s := Summary{}
	for _, f := range findings {
		s.Total++
		switch f.Severity {
		case "CRITICAL":
			s.Critical++
		case "HIGH":
			s.High++
		case "WARN":
			s.Warns++
		case "INFO":
			s.Infos++
		}
	}
	// Passed stays "no criticals" for backward compatibility; High findings are
	// surfaced separately and drive the NEEDS REVIEW headline / --exit-code.
	s.Passed = s.Critical == 0
	return s
}

// dedup removes findings with the same title, keeping the highest severity.
func dedup(findings []Finding) []Finding {
	seen := make(map[string]int) // title -> index in result
	var result []Finding

	sevRank := map[string]int{"CRITICAL": 4, "HIGH": 3, "WARN": 2, "INFO": 1}

	for _, f := range findings {
		if idx, ok := seen[f.Title]; ok {
			// Keep higher severity
			if sevRank[f.Severity] > sevRank[result[idx].Severity] {
				result[idx] = f
			}
			continue
		}
		seen[f.Title] = len(result)
		result = append(result, f)
	}
	return result
}
