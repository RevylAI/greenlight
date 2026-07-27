package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/RevylAI/greenlight/internal/playscan"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	playscanFormat   string
	playscanOutput   string
	playscanExitCode bool
)

var playscanCmd = &cobra.Command{
	Use:   "playscan [path]",
	Short: "Scan an Android project against Google Play's policies",
	Long: `Check an Android app against Google Play's Developer Program Policies
and its published distribution deadlines, before you upload.

Checks:
  • Target API level      — the annual requirement that silently pulls apps
                            from distribution when missed
  • Play Billing Library  — versions past their support window
  • Restricted permissions — SMS, Call Log, All files access, QUERY_ALL_PACKAGES,
                            background location, broad photo/video access
  • Foreground services   — service types missing their required permission
  • Manifest requirements — android:exported, debuggable, cleartext traffic
  • Advertising ID        — ads SDK shipped without the AD_ID permission
  • Account deletion      — the in-app and web deletion requirement

Runs entirely offline. No Play Console account needed.

Scope: this reads the AndroidManifest.xml and Gradle files in your repo, which
is the pre-merge manifest. Permissions contributed by library manifests only
appear after the build merges them, so a clean scan is not proof of a clean
merged manifest.

Usage:
  greenlight playscan .
  greenlight playscan ./android --format json
  greenlight playscan . --exit-code`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPlayscan,
}

func init() {
	playscanCmd.Flags().StringVar(&playscanFormat, "format", "terminal", "output format: terminal, json")
	playscanCmd.Flags().StringVar(&playscanOutput, "output", "", "write report to file (stdout if omitted)")
	playscanCmd.Flags().BoolVar(&playscanExitCode, "exit-code", false, "exit non-zero on any CRITICAL or HIGH finding — for CI gating")
	rootCmd.AddCommand(playscanCmd)
}

func runPlayscan(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot access path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path must be a directory: %s", path)
	}

	isJSON := strings.ToLower(playscanFormat) == "json"
	if !isJSON {
		purple.Println("\n  greenlight playscan — know before you upload to Google Play.")
		fmt.Printf("  Project: %s\n\n", path)
	}

	start := time.Now()
	result, err := playscan.Scan(path)
	if err != nil {
		return fmt.Errorf("play scan failed: %w", err)
	}
	elapsed := time.Since(start)

	out := os.Stdout
	if playscanOutput != "" {
		out, err = os.Create(playscanOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer out.Close()
	}

	if isJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return err
		}
	} else {
		printPlayscanReport(out, result, elapsed)
	}

	if playscanExitCode {
		for _, f := range result.Findings {
			if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
				return ErrThreshold
			}
		}
	}
	return nil
}

func printPlayscanReport(w *os.File, result *playscan.ScanResult, elapsed time.Duration) {
	red := color.New(color.FgRed, color.Bold)
	hiYellow := color.New(color.FgHiYellow, color.Bold)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen, color.Bold)
	greenC := color.New(color.FgGreen)
	bold := color.New(color.Bold)

	if result.ManifestPath == "" && result.TargetSDK == 0 {
		dim.Fprintln(w, "  No Android project found at this path.")
		dim.Fprintln(w, "  Looked for AndroidManifest.xml and Gradle build files.")
		fmt.Fprintln(w)
		return
	}

	// Project context
	if result.PackageName != "" {
		fmt.Fprintf(w, "  Package:    %s\n", result.PackageName)
	}
	if result.TargetSDK > 0 {
		fmt.Fprintf(w, "  targetSdk:  %d\n", result.TargetSDK)
	}
	if result.ManifestPath != "" {
		fmt.Fprintf(w, "  Manifest:   %s\n", result.ManifestPath)
	}
	fmt.Fprintln(w)

	// Sort by severity, then policy, so the output is stable run to run.
	sevRank := map[string]int{"CRITICAL": 4, "HIGH": 3, "WARN": 2, "INFO": 1}
	findings := append([]playscan.Finding{}, result.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		if ri, rj := sevRank[findings[i].Severity], sevRank[findings[j].Severity]; ri != rj {
			return ri > rj
		}
		return findings[i].Policy < findings[j].Policy
	})

	var criticals, highs, warns, infos int
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL":
			criticals++
		case "HIGH":
			highs++
		case "WARN":
			warns++
		case "INFO":
			infos++
		}
	}

	lastSeverity := ""
	for _, f := range findings {
		if f.Severity != lastSeverity {
			switch f.Severity {
			case "CRITICAL":
				red.Fprintln(w, "  CRITICAL — Will be rejected or already losing distribution")
			case "HIGH":
				hiYellow.Fprintln(w, "  HIGH — Likely rejection")
			case "WARN":
				yellow.Fprintln(w, "  WARNING — Worth fixing")
			case "INFO":
				dim.Fprintln(w, "  INFO — Best practices")
			}
			fmt.Fprintln(w)
			lastSeverity = f.Severity
		}

		switch f.Severity {
		case "CRITICAL":
			red.Fprintf(w, "  [CRITICAL] ")
		case "HIGH":
			hiYellow.Fprintf(w, "  [HIGH]     ")
		case "WARN":
			yellow.Fprintf(w, "  [WARN]     ")
		case "INFO":
			dim.Fprintf(w, "  [INFO]     ")
		}
		if f.Policy != "" {
			bold.Fprintf(w, "%s: ", f.Policy)
		}
		bold.Fprintln(w, f.Title)

		if f.File != "" {
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			dim.Fprintf(w, "             %s\n", loc)
		}
		fmt.Fprintf(w, "             %s\n", f.Detail)
		if f.Fix != "" {
			greenC.Fprintf(w, "             Fix: ")
			fmt.Fprintln(w, f.Fix)
		}
		if f.Doc != "" {
			dim.Fprintf(w, "             %s\n", f.Doc)
		}
		fmt.Fprintln(w)
	}

	dim.Fprintln(w, "  ─────────────────────────────────────────────")
	fmt.Fprintln(w)

	switch {
	case criticals > 0:
		red.Fprint(w, "  NOT READY")
		fmt.Fprintf(w, " — %d critical, %d high, %d warnings\n", criticals, highs, warns)
	case highs > 0:
		hiYellow.Fprint(w, "  NEEDS REVIEW")
		fmt.Fprintf(w, " — %d high, %d warnings\n", highs, warns)
	default:
		green.Fprint(w, "  LOOKS GOOD")
		fmt.Fprintf(w, " — %d warnings, %d notes\n", warns, infos)
	}

	fmt.Fprintf(w, "  Scanned in %s\n\n", elapsed.Round(time.Millisecond))

	// Console-side obligations no static scan can see.
	dim.Fprintln(w, "  Not checkable from source — verify in Play Console:")
	dim.Fprintln(w, "    • Data safety form matches what the app actually collects")
	dim.Fprintln(w, "    • Advertising ID declaration, content rating, target audience")
	dim.Fprintf(w, "    • %s\n\n", playscan.DocAppContent)
}
