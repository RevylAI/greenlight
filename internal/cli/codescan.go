package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/RevylAI/greenlight/internal/codescan"
	"github.com/RevylAI/greenlight/internal/sarif"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const greenlightInfoURI = "https://github.com/RevylAI/greenlight"

var (
	codescanPath   string
	codescanFormat string
	codescanOutput string
)

var codescanCmd = &cobra.Command{
	Use:   "codescan [path]",
	Short: "Scan local project code for App Store rejection risks",
	Long: `Scan your local project for code patterns that commonly cause
App Store rejections. Works with Swift, Objective-C, React Native, and Expo.

No App Store Connect account needed — runs entirely offline.

Checks for:
  • Private API usage (CRITICAL)
  • Hardcoded secrets (CRITICAL)
  • External payment for digital goods (CRITICAL)
  • Dynamic code execution (CRITICAL)
  • Missing Sign in with Apple when using social login
  • Missing Restore Purchases for IAP
  • Missing ATT for ad/tracking SDKs
  • Account creation without deletion option
  • Placeholder content in strings
  • Platform references (Android, Google Play)
  • Hardcoded IPv4 addresses
  • Insecure HTTP URLs
  • Vague Info.plist purpose strings
  • Expo config issues`,
	Args: cobra.MaximumNArgs(1),
	RunE: runCodescan,
}

func init() {
	codescanCmd.Flags().StringVar(&codescanFormat, "format", "terminal", "output format: terminal, json, sarif")
	codescanCmd.Flags().StringVar(&codescanOutput, "output", "", "write report to file (stdout if omitted)")
	rootCmd.AddCommand(codescanCmd)
}

func runCodescan(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	// Verify path exists
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot access path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path must be a directory: %s", path)
	}

	// Banner (suppressed for machine formats so stdout stays valid JSON/SARIF).
	format := strings.ToLower(codescanFormat)
	if format != "json" && format != "sarif" {
		purple.Println("\n  greenlight codescan — find rejection risks in your code.")
		fmt.Printf("  Scanning: %s\n", path)
		fmt.Printf("  Format:   %s\n\n", codescanFormat)
	}

	// Run scan
	start := time.Now()
	scanner := codescan.NewScanner(path, verbose)
	findings, err := scanner.Scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	elapsed := time.Since(start)

	// Sort: critical first, then warn, then info
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		return findings[i].File < findings[j].File
	})

	// Output
	var output *os.File
	if codescanOutput != "" {
		output, err = os.Create(codescanOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	switch format {
	case "json":
		return writeCodescanJSON(output, findings, elapsed)
	case "sarif":
		return writeCodescanSARIF(output, findings)
	default:
		return writeCodescanTerminal(output, findings, elapsed)
	}
}

func writeCodescanSARIF(w *os.File, findings []codescan.Finding) error {
	sf := make([]sarif.Finding, 0, len(findings))
	for _, f := range findings {
		sf = append(sf, sarif.Finding{
			Severity:  f.Severity.String(),
			Title:     f.Title,
			Detail:    f.Detail,
			Guideline: f.Guideline,
			File:      f.File,
			Line:      f.Line,
		})
	}
	return sarif.Write(w, "greenlight", appVersion, greenlightInfoURI, sf)
}

func writeCodescanTerminal(w *os.File, findings []codescan.Finding, elapsed time.Duration) error {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen, color.Bold)

	if len(findings) == 0 {
		green.Fprintln(w, "  No issues found!")
		fmt.Fprintln(w)
		printCodescanFooter(w, 0, 0, 0, elapsed)
		return nil
	}

	// Group by severity
	var criticals, warns, infos []codescan.Finding
	for _, f := range findings {
		switch f.Severity {
		case codescan.SeverityCritical:
			criticals = append(criticals, f)
		case codescan.SeverityWarn:
			warns = append(warns, f)
		case codescan.SeverityInfo:
			infos = append(infos, f)
		}
	}

	if len(criticals) > 0 {
		red.Fprintln(w, "  CRITICAL — Will be rejected")
		fmt.Fprintln(w)
		for _, f := range criticals {
			printCodescanFinding(w, f)
		}
	}

	if len(warns) > 0 {
		yellow.Fprintln(w, "  WARNING — High rejection risk")
		fmt.Fprintln(w)
		for _, f := range warns {
			printCodescanFinding(w, f)
		}
	}

	if len(infos) > 0 {
		dim.Fprintln(w, "  INFO — Best practices")
		fmt.Fprintln(w)
		for _, f := range infos {
			printCodescanFinding(w, f)
		}
	}

	printCodescanFooter(w, len(criticals), len(warns), len(infos), elapsed)
	return nil
}

func printCodescanFinding(w *os.File, f codescan.Finding) {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)
	bold := color.New(color.Bold)

	// Severity badge
	switch f.Severity {
	case codescan.SeverityCritical:
		red.Fprintf(w, "  [CRITICAL] ")
	case codescan.SeverityWarn:
		yellow.Fprintf(w, "  [WARN]     ")
	case codescan.SeverityInfo:
		dim.Fprintf(w, "  [INFO]     ")
	}

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
		green.Fprintf(w, "             Fix: ")
		fmt.Fprintln(w, f.Fix)
	}

	fmt.Fprintln(w)
}

func printCodescanFooter(w *os.File, criticals, warns, infos int, elapsed time.Duration) {
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)

	total := criticals + warns + infos

	fmt.Fprintln(w)
	dim.Fprintln(w, "  ─────────────────────────────────────────────")
	fmt.Fprintln(w)

	if criticals == 0 {
		green.Fprint(w, "  GREENLIT")
		fmt.Fprint(w, " — no critical issues found")
	} else {
		red.Fprint(w, "  NOT READY")
		fmt.Fprintf(w, " — %d critical issue(s) must be fixed", criticals)
	}
	fmt.Fprintln(w)

	if total > 0 {
		fmt.Fprintf(w, "  %d findings: ", total)
		if criticals > 0 {
			red.Fprintf(w, "%d critical  ", criticals)
		}
		if warns > 0 {
			color.New(color.FgYellow).Fprintf(w, "%d warn  ", warns)
		}
		if infos > 0 {
			dim.Fprintf(w, "%d info", infos)
		}
		fmt.Fprintln(w)
	}

	dim.Fprintf(w, "  completed in %s\n", elapsed.Round(time.Millisecond))

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

func writeCodescanJSON(w *os.File, findings []codescan.Finding, elapsed time.Duration) error {
	result := struct {
		Findings []codescan.Finding `json:"findings"`
		Summary  codescan.Summary   `json:"summary"`
		Elapsed  string             `json:"elapsed"`
	}{
		Findings: findings,
		Summary:  codescan.ComputeSummary(findings, 0),
		Elapsed:  elapsed.Round(time.Millisecond).String(),
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
