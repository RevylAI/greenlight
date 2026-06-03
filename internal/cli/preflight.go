package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/RevylAI/greenlight/internal/preflight"
	"github.com/RevylAI/greenlight/internal/verify"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	preflightIPA    string
	preflightFormat string
	preflightOutput string

	// Runtime tier (--verify): after the static checks, hand flow-dependent
	// guidelines to Revyl to validate on a cloud device.
	preflightVerify      bool
	preflightBuildName   string
	preflightArtifact    string
	preflightVarsRaw     []string
	preflightDeviceModel string
	preflightOSVersion   string
)

var preflightCmd = &cobra.Command{
	Use:   "preflight [path]",
	Short: "Run ALL checks on your project — one command, zero uploads",
	Long: `Run every greenlight check in a single command. No App Store Connect
account needed — everything runs locally on your source code and optional IPA.

Combines:
  • Code scan     — private APIs, hardcoded secrets, missing ATT, etc.
  • Privacy scan  — Required Reason APIs, PrivacyInfo.xcprivacy, tracking SDKs
  • Metadata scan — app.json / Info.plist completeness, icons, version, bundle ID
  • IPA inspect   — binary analysis (if --ipa is provided)

Add --verify to continue past the static checks and validate your flow-dependent
guidelines (account deletion, restore purchases, Sign in with Apple) on a REAL
device via Revyl — catching broken flows static analysis structurally can't.

Usage:
  greenlight preflight .
  greenlight preflight ./my-app --ipa build.ipa
  greenlight preflight /path/to/project --format json
  greenlight preflight . --verify --build-name "My App" --var email=qa@acme.com --var password=secret`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPreflight,
}

func init() {
	preflightCmd.Flags().StringVar(&preflightIPA, "ipa", "", "path to .ipa file for binary inspection")
	preflightCmd.Flags().StringVar(&preflightFormat, "format", "terminal", "output format: terminal, json")
	preflightCmd.Flags().StringVar(&preflightOutput, "output", "", "write report to file (stdout if omitted)")
	preflightCmd.Flags().BoolVar(&preflightVerify, "verify", false, "after static checks, validate flow-dependent guidelines on a cloud device via Revyl")
	preflightCmd.Flags().StringVar(&preflightBuildName, "build-name", "", "Revyl build/app name (for --verify)")
	preflightCmd.Flags().StringVar(&preflightArtifact, "artifact", "", "upload a prebuilt .app (iOS sim) or .apk (Android) to Revyl before --verify runs")
	preflightCmd.Flags().StringArrayVar(&preflightVarsRaw, "var", nil, "test variable for --verify, e.g. --var email=qa@acme.com (repeatable)")
	preflightCmd.Flags().StringVar(&preflightDeviceModel, "device-model", "", "device model for --verify, e.g. \"iPhone 16\"")
	preflightCmd.Flags().StringVar(&preflightOSVersion, "os-version", "", "OS version for --verify, e.g. \"iOS 26.2\"")
	rootCmd.AddCommand(preflightCmd)
}

func runPreflight(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	// Verify project path exists
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot access path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path must be a directory: %s", path)
	}

	// Verify IPA path if provided
	if preflightIPA != "" {
		if _, err := os.Stat(preflightIPA); os.IsNotExist(err) {
			return fmt.Errorf("IPA file not found: %s", preflightIPA)
		}
	}

	// Banner (suppressed for --format json so stdout stays valid JSON).
	if strings.ToLower(preflightFormat) != "json" {
		purple.Println("\n  greenlight preflight — every check, one command, zero uploads.")
		fmt.Printf("  Project: %s\n", path)
		if preflightIPA != "" {
			fmt.Printf("  IPA:     %s\n", preflightIPA)
		}
		scanners := []string{"metadata", "codescan", "privacy"}
		if preflightIPA != "" {
			scanners = append(scanners, "ipa")
		}
		fmt.Printf("  Checks:  %s\n\n", strings.Join(scanners, " + "))
	}

	// Run all checks
	start := time.Now()
	result, err := preflight.Run(path, preflightIPA, verbose)
	if err != nil {
		return fmt.Errorf("preflight failed: %w", err)
	}
	result.Elapsed = time.Since(start)

	// Output
	var output *os.File
	if preflightOutput != "" {
		output, err = os.Create(preflightOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	isJSON := strings.ToLower(preflightFormat) == "json"

	// Default path: static only — offline, zero-account, instant, and complete
	// on its own. The runtime tier is strictly opt-in; we only leave a light tip.
	if !preflightVerify {
		if isJSON {
			return writePreflightJSON(output, result)
		}
		if err := writePreflightTerminal(output, result); err != nil {
			return err
		}
		dim.Fprintln(output, "  Tip → 'greenlight preflight --verify' also runs your sign-in, purchase, and")
		dim.Fprintln(output, "        account-deletion flows on a Revyl cloud device to confirm they work.")
		fmt.Fprintln(output)
		return nil
	}

	// --verify: the static cycle runs, THEN Revyl runs the flows on a device.
	if preflightArtifact != "" {
		if preflightBuildName == "" {
			return fmt.Errorf("--artifact requires --build-name (to name or match the Revyl app for the uploaded build)")
		}
		// preflight's runtime tier is iOS-only (App Store), matching the
		// hardcoded Platform: "ios" passed to verify.Run below.
		if err := verify.ValidateArtifact(preflightArtifact, "ios"); err != nil {
			return err
		}
	}
	vstart := time.Now()
	vres, verr := verify.Run(verify.Config{
		ProjectPath: path,
		BuildName:   preflightBuildName,
		Platform:    "ios",
		Vars:        parseVars(preflightVarsRaw),
		DeviceModel: preflightDeviceModel,
		OSVersion:   preflightOSVersion,
		Artifact:    preflightArtifact,
	})
	if verr != nil {
		return fmt.Errorf("runtime validation failed: %w", verr)
	}
	vres.Elapsed = time.Since(vstart)

	if isJSON {
		return writeCombinedJSON(output, result, vres)
	}

	if err := writePreflightTerminal(output, result); err != nil {
		return err
	}
	fmt.Fprintln(output)
	purple.Fprintln(output, "  → Static checks done. Now validating the flows actually WORK, on a cloud device…")
	fmt.Fprintln(output)
	writeVerifyTerminal(output, vres)
	return nil
}

func writePreflightTerminal(w *os.File, result *preflight.Result) error {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen, color.Bold)

	// Show context
	if result.AppName != "" {
		fmt.Fprintf(w, "  App:     %s\n", result.AppName)
	}
	if result.BundleID != "" {
		fmt.Fprintf(w, "  Bundle:  %s\n", result.BundleID)
	}
	if result.HasPrivacyInfo {
		color.New(color.FgGreen).Fprint(w, "  ✓ ")
		fmt.Fprintln(w, "PrivacyInfo.xcprivacy found")
	}
	if len(result.DetectedAPIs) > 0 {
		fmt.Fprintf(w, "  APIs:    %s\n", strings.Join(result.DetectedAPIs, ", "))
	}
	if len(result.TrackingSDKs) > 0 {
		yellow.Fprint(w, "  Tracking: ")
		fmt.Fprintln(w, strings.Join(result.TrackingSDKs, ", "))
	}
	fmt.Fprintln(w)

	if len(result.Findings) == 0 {
		green.Fprintln(w, "  No issues found!")
		fmt.Fprintln(w)
		printPreflightFooter(w, result)
		return nil
	}

	// Sort: critical first, then warn, then info
	sort.Slice(result.Findings, func(i, j int) bool {
		sevRank := map[string]int{"CRITICAL": 3, "WARN": 2, "INFO": 1}
		ri, rj := sevRank[result.Findings[i].Severity], sevRank[result.Findings[j].Severity]
		if ri != rj {
			return ri > rj
		}
		return result.Findings[i].Source < result.Findings[j].Source
	})

	// Group by severity
	var criticals, warns, infos []preflight.Finding
	for _, f := range result.Findings {
		switch f.Severity {
		case "CRITICAL":
			criticals = append(criticals, f)
		case "WARN":
			warns = append(warns, f)
		case "INFO":
			infos = append(infos, f)
		}
	}

	if len(criticals) > 0 {
		red.Fprintln(w, "  CRITICAL — Will be rejected")
		fmt.Fprintln(w)
		for _, f := range criticals {
			printPreflightFinding(w, f)
		}
	}

	if len(warns) > 0 {
		yellow.Fprintln(w, "  WARNING — High rejection risk")
		fmt.Fprintln(w)
		for _, f := range warns {
			printPreflightFinding(w, f)
		}
	}

	if len(infos) > 0 {
		dim.Fprintln(w, "  INFO — Best practices")
		fmt.Fprintln(w)
		for _, f := range infos {
			printPreflightFinding(w, f)
		}
	}

	printPreflightFooter(w, result)
	return nil
}

func printPreflightFinding(w *os.File, f preflight.Finding) {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	greenC := color.New(color.FgGreen)
	bold := color.New(color.Bold)

	// Severity badge + source tag
	switch f.Severity {
	case "CRITICAL":
		red.Fprintf(w, "  [CRITICAL] ")
	case "WARN":
		yellow.Fprintf(w, "  [WARN]     ")
	case "INFO":
		dim.Fprintf(w, "  [INFO]     ")
	}

	// Source tag
	dim.Fprintf(w, "[%s] ", f.Source)

	// Guideline + title
	if f.Guideline != "" {
		bold.Fprintf(w, "§%s ", f.Guideline)
	}
	bold.Fprintln(w, f.Title)

	// Location
	if f.File != "" {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		dim.Fprintf(w, "             %s\n", loc)
	}

	// Code snippet
	if f.Code != "" {
		dim.Fprintf(w, "             > %s\n", truncate(f.Code, 80))
	}

	// Detail
	fmt.Fprintf(w, "             %s\n", f.Detail)

	// Fix
	if f.Fix != "" {
		greenC.Fprintf(w, "             Fix: ")
		fmt.Fprintln(w, f.Fix)
	}

	fmt.Fprintln(w)
}

func printPreflightFooter(w *os.File, result *preflight.Result) {
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)

	s := result.Summary

	dim.Fprintln(w, "  ─────────────────────────────────────────────")
	fmt.Fprintln(w)

	if s.Passed {
		green.Fprint(w, "  GREENLIT")
		fmt.Fprint(w, " — no critical issues found")
	} else {
		red.Fprint(w, "  NOT READY")
		fmt.Fprintf(w, " — %d critical issue(s) must be fixed", s.Critical)
	}
	fmt.Fprintln(w)

	if s.Total > 0 {
		fmt.Fprintf(w, "  %d findings: ", s.Total)
		if s.Critical > 0 {
			red.Fprintf(w, "%d critical  ", s.Critical)
		}
		if s.Warns > 0 {
			color.New(color.FgYellow).Fprintf(w, "%d warn  ", s.Warns)
		}
		if s.Infos > 0 {
			dim.Fprintf(w, "%d info", s.Infos)
		}
		fmt.Fprintln(w)
	}

	// Breakdown by scanner
	sources := make(map[string]int)
	for _, f := range result.Findings {
		sources[f.Source]++
	}
	if len(sources) > 0 {
		var parts []string
		for _, src := range []string{"metadata", "codescan", "privacy", "ipa"} {
			if n, ok := sources[src]; ok {
				parts = append(parts, fmt.Sprintf("%s: %d", src, n))
			}
		}
		dim.Fprintf(w, "  by scanner: %s\n", strings.Join(parts, "  "))
	}

	dim.Fprintf(w, "  completed in %s\n", result.Elapsed.Round(time.Millisecond))

	// Revyl attribution
	fmt.Fprintln(w)
	dim.Fprintln(w, "  ─────────────────────────────────────────────")
	fmt.Fprintf(w, "  Built by ")
	purple.Fprint(w, "Revyl")
	fmt.Fprintln(w, " — the mobile reliability platform")
	dim.Fprintln(w, "  Catch more than rejections. Catch bugs.")
	fmt.Fprint(w, "  ")
	color.New(color.Underline).Fprintln(w, "https://revyl.com")
	fmt.Fprintln(w)
}

func preflightJSONObject(result *preflight.Result) interface{} {
	return struct {
		ProjectPath    string              `json:"project_path"`
		IPAPath        string              `json:"ipa_path,omitempty"`
		AppName        string              `json:"app_name,omitempty"`
		BundleID       string              `json:"bundle_id,omitempty"`
		HasPrivacyInfo bool                `json:"has_privacy_info"`
		DetectedAPIs   []string            `json:"detected_apis,omitempty"`
		TrackingSDKs   []string            `json:"tracking_sdks,omitempty"`
		Findings       []preflight.Finding `json:"findings"`
		Summary        preflight.Summary   `json:"summary"`
		Elapsed        string              `json:"elapsed"`
	}{
		ProjectPath:    result.ProjectPath,
		IPAPath:        result.IPAPath,
		AppName:        result.AppName,
		BundleID:       result.BundleID,
		HasPrivacyInfo: result.HasPrivacyInfo,
		DetectedAPIs:   result.DetectedAPIs,
		TrackingSDKs:   result.TrackingSDKs,
		Findings:       result.Findings,
		Summary:        result.Summary,
		Elapsed:        result.Elapsed.Round(time.Millisecond).String(),
	}
}

func writePreflightJSON(w *os.File, result *preflight.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(preflightJSONObject(result))
}

// writeCombinedJSON emits the static result and the runtime (Revyl) result
// together under one object — used when --verify is chained with --format json.
func writeCombinedJSON(w *os.File, result *preflight.Result, vres *verify.Result) error {
	combined := struct {
		Static  interface{} `json:"static"`
		Runtime interface{} `json:"runtime"`
	}{
		Static:  preflightJSONObject(result),
		Runtime: verifyJSONObject(vres),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(combined)
}
