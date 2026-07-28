package preflight

import (
	"fmt"
	"sync"
	"time"

	"github.com/RevylAI/greenlight/internal/codescan"
	"github.com/RevylAI/greenlight/internal/ipa"
	"github.com/RevylAI/greenlight/internal/playscan"
	"github.com/RevylAI/greenlight/internal/privacy"
)

// Finding is the unified finding type across all scanners.
type Finding struct {
	Source   string `json:"source"`   // "codescan", "privacy", "ipa", "metadata", "playscan"
	Severity string `json:"severity"` // "CRITICAL", "HIGH", "WARN", "INFO"
	// Guideline is an Apple review guideline section ("5.1.1") for iOS
	// findings, or a named Google Play policy ("Target API level") for Android
	// ones. Play policies are named rather than numbered.
	Guideline string `json:"guideline,omitempty"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Fix       string `json:"fix,omitempty"`
	// Doc links the policy or guideline page the finding is based on. Play
	// policy pages change often enough that citing the source is worth more
	// than a section number alone.
	Doc  string `json:"doc,omitempty"`
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	Code string `json:"code,omitempty"`
}

// Result holds the combined output from all scanners.
type Result struct {
	ProjectPath     string        `json:"project_path"`
	IPAPath         string        `json:"ipa_path,omitempty"`
	AndroidArtifact string        `json:"android_artifact,omitempty"`
	Findings        []Finding     `json:"findings"`
	Summary         Summary       `json:"summary"`
	Elapsed         time.Duration `json:"elapsed"`

	// Incomplete is true when a requested sub-scanner failed to run, so the
	// results may be partial. CI gating (--exit-code) treats this as a failure.
	Incomplete bool `json:"incomplete,omitempty"`

	// Extra context from sub-scanners
	AppName        string   `json:"app_name,omitempty"`
	BundleID       string   `json:"bundle_id,omitempty"`
	HasPrivacyInfo bool     `json:"has_privacy_info"`
	DetectedAPIs   []string `json:"detected_apis,omitempty"`
	TrackingSDKs   []string `json:"tracking_sdks,omitempty"`

	// Android context, populated when an Android project is detected.
	IsAndroid   bool   `json:"is_android,omitempty"`
	PackageName string `json:"package_name,omitempty"`
	TargetSDK   int    `json:"target_sdk,omitempty"`
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

// Run executes every applicable scanner. androidArtifact is an optional .apk or
// .aab: when set, the archive is scanned in addition to the source tree, because
// the two see different things (source resolves the Gradle model, the archive
// carries the merged manifest and the native libraries).
func Run(projectPath string, ipaPath string, androidArtifact string, verbose bool) (*Result, error) {
	result := &Result{
		ProjectPath:     projectPath,
		IPAPath:         ipaPath,
		AndroidArtifact: androidArtifact,
	}

	// Optional .greenlight.yml (rule overrides / ignores) for the code scan.
	cfg, err := codescan.LoadConfig(projectPath)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)

	// The Apple scanners run unless the project is unambiguously Android-only.
	// Skipping them there is what stops an Android repo being told it is
	// missing a PrivacyInfo.xcprivacy; anywhere else — including a project
	// that is both, and a project that is neither — they run exactly as before.
	isIOS, isAndroid := DetectPlatforms(projectPath)
	runApple := isIOS || !isAndroid
	result.IsAndroid = isAndroid

	// Channel for collecting errors (non-fatal; we report what we can).
	// Buffered above the number of possible senders: the channel is drained
	// only after wg.Wait(), so a full buffer would deadlock the scan.
	errs := make(chan error, 8)

	// 1. Local metadata checks
	if runApple {
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

	}

	// 2. Code scan
	if runApple {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanner := codescan.NewScannerWithConfig(projectPath, verbose, cfg)
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

	}

	// 3. Privacy scan
	if runApple {
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

	}

	// 4. Google Play policy scan (Android projects only).
	//
	// A cross-platform repo satisfies both this and runApple, so it is checked
	// against both stores in a single pass.
	if isAndroid || androidArtifact != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Source and archive are complementary, so when both are available
			// both run and their findings are merged.
			//
			// A failure in one does not discard the other: the error is recorded
			// (which marks the run incomplete) and whatever did scan is still
			// merged, so a broken --apk cannot silently erase the source
			// findings that already succeeded.
			var results []*playscan.ScanResult
			if isAndroid {
				playResult, err := playscan.Scan(projectPath)
				if err != nil {
					errs <- err
				} else {
					results = append(results, playResult)
				}
			}
			if androidArtifact != "" {
				archiveResult, err := playscan.ScanArchive(androidArtifact)
				if err != nil {
					errs <- err
				} else {
					results = append(results, archiveResult)
				}
			}

			mu.Lock()
			for _, playResult := range results {
				if playResult.PackageName != "" {
					result.PackageName = playResult.PackageName
				}
				if playResult.TargetSDK != 0 {
					result.TargetSDK = playResult.TargetSDK
				}
				for _, f := range playResult.Findings {
					result.Findings = append(result.Findings, Finding{
						Source:    "playscan",
						Severity:  f.Severity,
						Guideline: f.Policy,
						Title:     f.Title,
						Detail:    f.Detail,
						Fix:       f.Fix,
						Doc:       f.Doc,
						File:      f.File,
						Line:      f.Line,
					})
				}
			}
			mu.Unlock()
		}()
	}

	// 5. IPA inspection (if path provided)
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
